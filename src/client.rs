use age::ssh;
use age::{Decryptor, Encryptor};
use clap::{Parser, Subcommand};
use log::{error, info, warn};
use rpclip::auth;
use rpclip::{
    read_clipboard_payload, validate_encrypted_clipboard_payload_len, AgeEncryptedBlob, Challenge,
    ClipboardOperation, RpClipClient, SetRequest, PROTOCOL_VERSION,
};
use serde::Deserialize;
use ssh_key::{PrivateKey, PublicKey};
use std::future::Future;
use std::io::Read;
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
    public_key: PublicKey,
    public_key_line: String,
    server_public_key_line: String,
    server_public_key: PublicKey,
}

enum PreparedCommand {
    Get,
    Set(AgeEncryptedBlob),
}

struct PreparedClient {
    server: ListenAddr,
    credentials: ClientCredentials,
    command: PreparedCommand,
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
        public_key,
        public_key_line,
        server_public_key_line,
        server_public_key,
    })
}

async fn issue_challenge(
    client: &RpClipClient,
    credentials: &ClientCredentials,
    operation: ClipboardOperation,
) -> Result<Challenge, String> {
    let request = auth::make_challenge_request(credentials.public_key_line.clone(), operation);
    let challenge = client
        .issue_challenge(context::current(), request)
        .await
        .map_err(|e| format!("challenge RPC failed: {e}"))??;
    challenge
        .validate_version()
        .map_err(|e| format!("server returned incompatible challenge: {e}"))?;
    auth::verify_server_challenge(
        &credentials.server_public_key,
        &challenge,
        &credentials.public_key,
        operation,
    )
    .map_err(|e| format!("server challenge failed authentication: {e}"))?;
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

fn load_config(config_path: Option<&str>) -> Result<Option<Config>, String> {
    let path = match config_path {
        Some(path) => Some(std::path::PathBuf::from(expand_tilde(path))),
        None => dirs::config_dir().map(|dir| dir.join("rpclip").join("config.yaml")),
    };
    let Some(path) = path else {
        return Ok(None);
    };
    if config_path.is_none() && !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("read config {}: {e}", path.display()))?;
    serde_yaml::from_str(&content)
        .map(Some)
        .map_err(|e| format!("parse config {}: {e}", path.display()))
}

fn prepare_client(args: Args, stdin: &mut impl Read) -> Result<PreparedClient, String> {
    let config = load_config(args.config.as_deref())?;
    let server_addr = match args.server {
        Some(server) => {
            info!("Using server address from command line");
            server
        }
        None => config
            .as_ref()
            .map(|config| {
                info!("Using server address from config file");
                config.server_addr.clone()
            })
            .unwrap_or_else(|| {
                warn!("No server address provided, using default server address");
                "127.0.0.1:6667".to_string()
            }),
    };
    let server = parse_listen_addr(server_addr)?;
    let credentials = load_client_credentials(config.as_ref())?;
    let command = match args.command {
        Commands::Get => PreparedCommand::Get,
        Commands::Set => {
            let plaintext =
                read_clipboard_payload(stdin).map_err(|e| format!("read stdin: {e}"))?;
            std::str::from_utf8(&plaintext).map_err(|e| format!("read stdin: {e}"))?;
            let ciphertext =
                encrypt_to_pubkey_line(&credentials.server_public_key_line, &plaintext)?;
            validate_encrypted_clipboard_payload_len(ciphertext.len())?;
            PreparedCommand::Set(AgeEncryptedBlob {
                ver: PROTOCOL_VERSION,
                data: ciphertext,
            })
        }
    };
    Ok(PreparedClient {
        server,
        credentials,
        command,
    })
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
    read_clipboard_payload(&mut reader).map_err(|e| format!("read: {e}"))
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let args = Args::parse();
    let prepared = prepare_client(args, &mut std::io::stdin().lock()).unwrap_or_else(|e| {
        error!("Failed to prepare client request: {e}");
        std::process::exit(1);
    });
    info!("Connecting to server at {:?}", prepared.server);
    let client = from_listen_addr(prepared.server).await;
    let credentials = prepared.credentials;

    match prepared.command {
        PreparedCommand::Get => {
            let challenge =
                match issue_challenge(&client, &credentials, ClipboardOperation::Get).await {
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
            if let Err(e) = validate_encrypted_clipboard_payload_len(response.blob.data.len()) {
                error!("Server clipboard response exceeds payload limit: {e}");
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
        PreparedCommand::Set(blob) => {
            let challenge =
                match issue_challenge(&client, &credentials, ClipboardOperation::Set).await {
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
            match client.set_clip(context::current(), request.clone()).await {
                Ok(Ok(response)) => {
                    if let Err(e) = auth::verify_set_response(
                        &credentials.server_public_key,
                        &request,
                        &response,
                    ) {
                        error!("Server set response failed authentication: {e}");
                        std::process::exit(1);
                    }
                }
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
    use rpclip::{
        validate_encrypted_clipboard_payload_len, MAX_CLIPBOARD_PAYLOAD_BYTES,
        MAX_ENCRYPTED_CLIPBOARD_PAYLOAD_BYTES,
    };
    use ssh_key::{Algorithm, LineEnding};
    use std::io::Cursor;
    use std::time::{Duration, Instant};

    struct DelayedReader {
        inner: Cursor<Vec<u8>>,
        delay: Duration,
        delayed: bool,
    }

    impl Read for DelayedReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if !self.delayed {
                std::thread::sleep(self.delay);
                self.delayed = true;
            }
            self.inner.read(buffer)
        }
    }

    fn write_test_key(dir: &std::path::Path, name: &str) -> (String, String) {
        let private = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).unwrap();
        let private_path = dir.join(name);
        let public_path = dir.join(format!("{name}.pub"));
        let public_line = private.public_key().to_openssh().unwrap();
        std::fs::write(&private_path, private.to_openssh(LineEnding::LF).unwrap()).unwrap();
        std::fs::write(&public_path, format!("{public_line}\n")).unwrap();
        (private_path.to_string_lossy().into_owned(), public_line)
    }

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

    #[test]
    fn prepares_slow_set_input_before_connecting() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let server_addr = listener.local_addr().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (client_private_path, client_public_line) =
            write_test_key(dir.path(), "client_ed25519");
        let (_, server_public_line) = write_test_key(dir.path(), "server_ed25519");
        let client_public_path = format!("{client_private_path}.pub");
        let config_path = dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            format!(
                "server_addr: \"{server_addr}\"\nssh_key_path: \"{client_private_path}\"\nssh_pubkey_path: \"{client_public_path}\"\nserver_ssh_pubkey: \"{server_public_line}\"\n"
            ),
        )
        .unwrap();
        let args = Args {
            server: None,
            config: Some(config_path.to_string_lossy().into_owned()),
            command: Commands::Set,
        };
        let delay = Duration::from_millis(25);
        let mut input = DelayedReader {
            inner: Cursor::new(b"slow stdin".to_vec()),
            delay,
            delayed: false,
        };

        let started = Instant::now();
        let prepared = prepare_client(args, &mut input).unwrap();
        assert!(started.elapsed() >= delay);
        assert!(matches!(prepared.command, PreparedCommand::Set(_)));
        assert_eq!(
            auth::parse_public_key(&client_public_line)
                .unwrap()
                .key_data(),
            prepared.credentials.public_key.key_data()
        );
        assert!(matches!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn reports_preparation_errors_without_connecting() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let args = Args {
            server: Some(listener.local_addr().unwrap().to_string()),
            config: Some("missing-config.yaml".to_string()),
            command: Commands::Get,
        };

        assert!(prepare_client(args, &mut std::io::empty()).is_err());
        assert!(matches!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn rejects_decrypted_clipboard_above_limit() {
        let dir = tempfile::tempdir().unwrap();
        let (private_key_path, public_key_line) = write_test_key(dir.path(), "client_ed25519");
        let plaintext = vec![b'x'; MAX_CLIPBOARD_PAYLOAD_BYTES + 1];
        let ciphertext = encrypt_to_pubkey_line(&public_key_line, &plaintext).unwrap();

        assert!(
            decrypt_with_private_key_path(&private_key_path, &ciphertext)
                .unwrap_err()
                .contains("clipboard payload exceeds")
        );
    }

    #[test]
    fn encrypts_maximum_clipboard_within_encrypted_limit() {
        let dir = tempfile::tempdir().unwrap();
        let (_, public_key_line) = write_test_key(dir.path(), "server_ed25519");
        let plaintext = vec![b'x'; MAX_CLIPBOARD_PAYLOAD_BYTES];
        let ciphertext = encrypt_to_pubkey_line(&public_key_line, &plaintext).unwrap();

        assert!(ciphertext.len() <= MAX_ENCRYPTED_CLIPBOARD_PAYLOAD_BYTES);
        validate_encrypted_clipboard_payload_len(ciphertext.len()).unwrap();
    }
}
