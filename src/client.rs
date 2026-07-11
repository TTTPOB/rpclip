use age::ssh;
use age::{Decryptor, Encryptor};
use clap::{Parser, Subcommand};
use log::{error, info, warn};
use rpclip::auth;
use rpclip::{AgeEncryptedBlob, Challenge, RpClipClient, SetRequest, PROTOCOL_VERSION};
use serde::Deserialize;
use ssh_key::{PrivateKey, PublicKey};
use std::future::Future;
use std::path::Path;
use std::str::FromStr;
use tarpc::{client, context, tokio_serde::formats::Bincode};

const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Parser)]
struct Args {
    #[clap(short, long, value_name = "IP:PORT or UNIX SOCKET PATH")]
    server: Option<String>,
    #[clap(short, long)]
    config: Option<String>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Get,
    Set,
}

#[derive(Clone, Debug, Deserialize)]
struct Config {
    server_addr: String,
    #[serde(default)]
    ssh_key_path: Option<String>,
    #[serde(default)]
    ssh_pubkey_path: Option<String>,
    #[serde(default)]
    server_ssh_pubkey: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum ListenAddr {
    Tcp(String),
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

struct ClientCredentials {
    private_key_path: String,
    private_key: PrivateKey,
    public_key_line: String,
    server_public_key_line: String,
    server_public_key: PublicKey,
}

fn parse_listen_addr(addr: String) -> Result<ListenAddr, String> {
    if let Some(tcp_addr) = addr.strip_prefix("tcp://") {
        if tcp_addr.is_empty() {
            return Err("TCP server address cannot be empty".to_string());
        }
        return Ok(ListenAddr::Tcp(tcp_addr.to_string()));
    }

    let unix_path = addr.strip_prefix("unix://");
    let is_path = unix_path.is_some()
        || addr.starts_with('/')
        || addr.starts_with("./")
        || addr.starts_with("../")
        || addr.starts_with("~/");
    if is_path {
        #[cfg(unix)]
        {
            let path = unix_path.unwrap_or(&addr);
            if path.is_empty() {
                return Err("Unix socket path cannot be empty".to_string());
            }
            return Ok(ListenAddr::Unix(expand_tilde(path).into()));
        }
        #[cfg(not(unix))]
        {
            return Err("Unix domain sockets are not supported on this platform".to_string());
        }
    }

    Ok(ListenAddr::Tcp(addr))
}

async fn from_listen_addr(addr: ListenAddr) -> RpClipClient {
    match addr {
        ListenAddr::Tcp(addr) => RpClipClient::new(
            client::Config::default(),
            connect_with_timeout(
                tarpc::serde_transport::tcp::connect(addr, Bincode::default),
                CONNECT_TIMEOUT,
            )
            .await
            .unwrap_or_else(|e| {
                error!("Unable to connect to server: {}", e);
                std::process::exit(1);
            }),
        )
        .spawn(),
        #[cfg(unix)]
        ListenAddr::Unix(path) => RpClipClient::new(
            client::Config::default(),
            connect_with_timeout(
                tarpc::serde_transport::unix::connect(path, Bincode::default),
                CONNECT_TIMEOUT,
            )
            .await
            .unwrap_or_else(|e| {
                error!("Unable to connect to server: {}", e);
                std::process::exit(1);
            }),
        )
        .spawn(),
    }
}

async fn connect_with_timeout<T, E>(
    connect: impl Future<Output = Result<T, E>>,
    timeout: std::time::Duration,
) -> Result<T, String>
where
    E: std::fmt::Display,
{
    tokio::time::timeout(timeout, connect)
        .await
        .map_err(|_| format!("connection attempt timed out after {timeout:?}"))?
        .map_err(|e| e.to_string())
}

fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest).to_string_lossy().into_owned();
        }
    }
    path.to_string()
}

fn read_pubkey_line(path: &str) -> Result<String, String> {
    let path = expand_tilde(path);
    let content =
        std::fs::read_to_string(&path).map_err(|e| format!("read pubkey {}: {}", path, e))?;
    let line = content
        .lines()
        .next()
        .ok_or_else(|| "empty pubkey file".to_string())?;
    Ok(line.trim().to_string())
}

fn load_client_credentials(config: Option<&Config>) -> Result<ClientCredentials, String> {
    let private_key_path = expand_tilde(
        &config
            .and_then(|config| config.ssh_key_path.clone())
            .unwrap_or_else(|| "~/.ssh/id_ed25519".to_string()),
    );
    let public_key_path = config
        .and_then(|config| config.ssh_pubkey_path.clone())
        .unwrap_or_else(|| "~/.ssh/id_ed25519.pub".to_string());
    let public_key_line = read_pubkey_line(&public_key_path)?;
    let public_key = auth::parse_public_key(&public_key_line)?;
    let private_key = auth::read_private_key(Path::new(&private_key_path))?;
    if private_key.public_key().key_data() != public_key.key_data() {
        return Err("client SSH private and public keys do not match".to_string());
    }

    let server_public_key_line = config
        .and_then(|config| config.server_ssh_pubkey.clone())
        .ok_or_else(|| "server_ssh_pubkey is required in client config".to_string())?;
    let server_public_key = auth::parse_public_key(&server_public_key_line)
        .map_err(|e| format!("invalid server_ssh_pubkey: {e}"))?;

    Ok(ClientCredentials {
        private_key_path,
        private_key,
        public_key_line,
        server_public_key_line,
        server_public_key,
    })
}

async fn issue_challenge(
    client: &RpClipClient,
    client_public_key_line: String,
) -> Result<Challenge, String> {
    let challenge = client
        .issue_challenge(context::current(), client_public_key_line)
        .await
        .map_err(|e| format!("challenge RPC failed: {e}"))??;
    challenge
        .validate_version()
        .map_err(|e| format!("server returned incompatible challenge: {e}"))?;
    Ok(challenge)
}

fn encrypt_to_pubkey_line(pubkey_line: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let recipient =
        ssh::Recipient::from_str(pubkey_line).map_err(|e| format!("invalid recipient: {:?}", e))?;
    let recipients: Vec<&dyn age::Recipient> = vec![&recipient as &dyn age::Recipient];
    let encryptor = Encryptor::with_recipients(recipients.into_iter())
        .map_err(|e| format!("encryptor: {}", e))?;
    let mut out = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut out)
        .map_err(|e| format!("wrap_output: {}", e))?;
    use std::io::Write;
    writer
        .write_all(plaintext)
        .map_err(|e| format!("write: {}", e))?;
    writer.finish().map_err(|e| format!("finish: {}", e))?;
    Ok(out)
}

fn decrypt_with_private_key_path(
    private_key_path: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let private_key_path = expand_tilde(private_key_path);
    let key_bytes = std::fs::read(&private_key_path)
        .map_err(|e| format!("read key {}: {}", private_key_path, e))?;
    let identity = ssh::Identity::from_buffer(
        std::io::Cursor::new(key_bytes),
        Some(private_key_path.clone()),
    )
    .map_err(|e| format!("identity parse: {:?}", e))?;
    let decryptor = Decryptor::new(ciphertext).map_err(|e| format!("decryptor: {}", e))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| format!("decrypt: {}", e))?;
    use std::io::Read;
    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| format!("read: {}", e))?;
    Ok(plaintext)
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let args = Args::parse();
    let server = match (args.server.clone(), args.config.clone()) {
        (Some(server), _) => {
            info!("Using server address from command line");
            server
        }
        (_, Some(config)) => {
            info!("Using server address from config file");
            let config: Config =
                serde_yaml::from_str(&std::fs::read_to_string(config).unwrap()).unwrap();
            config.server_addr
        }
        _ => {
            info!("Both server address and config file not provided, using default config file");
            let default_config_file = dirs::config_dir()
                .unwrap()
                .join("rpclip")
                .join("config.yaml");
            if default_config_file.exists() {
                let config: Config =
                    serde_yaml::from_str(&std::fs::read_to_string(default_config_file).unwrap())
                        .unwrap();
                config.server_addr
            } else {
                warn!("No server address provided, using default server address");
                "127.0.0.1:6667".to_string()
            }
        }
    };
    let server = parse_listen_addr(server).unwrap_or_else(|e| {
        error!("Invalid server address: {}", e);
        std::process::exit(1);
    });
    info!("Connecting to server at {:?}", server);
    let client = from_listen_addr(server).await;

    // Load config again if available for crypto fields
    let mut cfg: Option<Config> = None;
    if let Some(config_path) = args.config {
        let content = std::fs::read_to_string(&config_path).unwrap_or_default();
        if !content.is_empty() {
            cfg = serde_yaml::from_str(&content).ok();
        }
    } else {
        let default_config_file = dirs::config_dir()
            .unwrap()
            .join("rpclip")
            .join("config.yaml");
        if default_config_file.exists() {
            let content = std::fs::read_to_string(&default_config_file).unwrap_or_default();
            cfg = serde_yaml::from_str(&content).ok();
        }
    }
    let credentials = load_client_credentials(cfg.as_ref()).unwrap_or_else(|e| {
        error!("Failed to load client authentication credentials: {e}");
        std::process::exit(1);
    });

    match &args.command {
        Commands::Get => {
            let challenge =
                match issue_challenge(&client, credentials.public_key_line.clone()).await {
                    Ok(challenge) => challenge,
                    Err(e) => {
                        error!("Server refused authentication challenge: {e}");
                        std::process::exit(1);
                    }
                };
            let auth_request = auth::sign_get_request(
                &credentials.private_key,
                credentials.public_key_line.clone(),
                challenge,
            )
            .unwrap_or_else(|e| {
                error!("Failed to sign get request: {e}");
                std::process::exit(1);
            });

            let response = match client
                .get_clip(context::current(), auth_request.clone())
                .await
            {
                Ok(Ok(response)) => response,
                Ok(Err(e)) => {
                    error!("Server failed to get clipboard: {}", e);
                    std::process::exit(1);
                }
                Err(e) => {
                    error!("Clipboard RPC failed: {}", e);
                    std::process::exit(1);
                }
            };
            if let Err(e) =
                auth::verify_get_response(&credentials.server_public_key, &auth_request, &response)
            {
                error!("Server clipboard response failed authentication: {e}");
                std::process::exit(1);
            }

            let plaintext = match decrypt_with_private_key_path(
                &credentials.private_key_path,
                &response.blob.data,
            ) {
                Ok(p) => p,
                Err(e) => {
                    error!("Failed to decrypt clipboard: {}", e);
                    std::process::exit(1);
                }
            };
            let text = String::from_utf8_lossy(&plaintext).to_string();
            let text = rpclip::line_end::to_platform_line_ending(&text);
            print!("{}", text);
        }
        Commands::Set => {
            use std::io::Read;
            let mut text = String::new();
            if let Err(e) = std::io::stdin().lock().read_to_string(&mut text) {
                error!("Failed to read stdin: {}", e);
                std::process::exit(1);
            }

            let ciphertext = match encrypt_to_pubkey_line(
                &credentials.server_public_key_line,
                text.as_bytes(),
            ) {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to encrypt for server: {}", e);
                    std::process::exit(1);
                }
            };

            let blob = AgeEncryptedBlob {
                ver: PROTOCOL_VERSION,
                data: ciphertext,
            };
            let challenge =
                match issue_challenge(&client, credentials.public_key_line.clone()).await {
                    Ok(challenge) => challenge,
                    Err(e) => {
                        error!("Server refused authentication challenge: {e}");
                        std::process::exit(1);
                    }
                };
            let auth_request = auth::sign_set_request(
                &credentials.private_key,
                credentials.public_key_line.clone(),
                challenge,
                &blob,
            )
            .unwrap_or_else(|e| {
                error!("Failed to sign set request: {e}");
                std::process::exit(1);
            });
            let request = SetRequest {
                auth: auth_request,
                blob,
            };
            match client.set_clip(context::current(), request).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    error!("Server failed to set clipboard: {}", e);
                    std::process::exit(1);
                }
                Err(e) => {
                    error!("Clipboard RPC failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connection_attempt_times_out() {
        let connect = std::future::pending::<Result<(), std::io::Error>>();

        let error = connect_with_timeout(connect, std::time::Duration::from_millis(1))
            .await
            .unwrap_err();

        assert_eq!(error, "connection attempt timed out after 1ms");
    }

    #[test]
    fn parses_tcp_addresses_and_hostnames() {
        assert_eq!(
            parse_listen_addr("127.0.0.1:6667".to_string()).unwrap(),
            ListenAddr::Tcp("127.0.0.1:6667".to_string())
        );
        assert_eq!(
            parse_listen_addr("tcp://localhost:6667".to_string()).unwrap(),
            ListenAddr::Tcp("localhost:6667".to_string())
        );
    }

    #[cfg(unix)]
    #[test]
    fn parses_explicit_and_path_like_unix_addresses() {
        assert_eq!(
            parse_listen_addr("unix:///tmp/rpclip.sock".to_string()).unwrap(),
            ListenAddr::Unix("/tmp/rpclip.sock".into())
        );
        assert_eq!(
            parse_listen_addr("./rpclip.sock".to_string()).unwrap(),
            ListenAddr::Unix("./rpclip.sock".into())
        );
    }
}
