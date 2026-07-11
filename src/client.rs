use age::ssh;
use age::{Decryptor, Encryptor};
use clap::{Parser, Subcommand};
use log::{error, info, warn};
use rpclip::{AgeEncryptedBlob, RpClipClient};
use serde::Deserialize;
use std::str::FromStr;
use std::{io::BufRead, net::SocketAddr};
use tarpc::{client, context, tokio_serde::formats::Bincode};

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

#[derive(Debug)]
enum ListenAddr {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

impl From<String> for ListenAddr {
    fn from(addr: String) -> Self {
        match addr.parse() {
            Ok(addr) => ListenAddr::Tcp(addr),
            Err(_) => {
                #[cfg(unix)]
                {
                    ListenAddr::Unix(addr.into())
                }
                #[cfg(not(unix))]
                {
                    error!("Unix domain sockets are not supported on this platform");
                    std::process::exit(1);
                }
            }
        }
    }
}

async fn from_listen_addr(addr: ListenAddr) -> RpClipClient {
    match addr {
        ListenAddr::Tcp(addr) => RpClipClient::new(
            client::Config::default(),
            tarpc::serde_transport::tcp::connect(addr, Bincode::default)
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
            tarpc::serde_transport::unix::connect(path, Bincode::default)
                .await
                .unwrap_or_else(|e| {
                    error!("Unable to connect to server: {}", e);
                    std::process::exit(1);
                }),
        )
        .spawn(),
    }
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
    let server: ListenAddr = server.into();
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

    match &args.command {
        Commands::Get => {
            // Determine our public and private key paths
            let ssh_priv = cfg
                .as_ref()
                .and_then(|c| c.ssh_key_path.clone())
                .unwrap_or_else(|| "~/.ssh/id_ed25519".to_string());
            let ssh_pub = cfg
                .as_ref()
                .and_then(|c| c.ssh_pubkey_path.clone())
                .unwrap_or_else(|| "~/.ssh/id_ed25519.pub".to_string());

            let pubkey_line = match read_pubkey_line(&ssh_pub) {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to read SSH public key: {}", e);
                    std::process::exit(1);
                }
            };

            let blob = client
                .get_clip(context::current(), pubkey_line)
                .await
                .unwrap();

            let plaintext = match decrypt_with_private_key_path(&ssh_priv, &blob.data) {
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
            // Read stdin
            let content: Vec<String> = std::io::stdin()
                .lock()
                .lines()
                .map(|line| line.unwrap())
                .collect();
            let text = content.join("\n");

            // Load server recipient from config
            let server_recipient = cfg
                .as_ref()
                .and_then(|c| c.server_ssh_pubkey.clone())
                .unwrap_or_else(|| {
                    error!("server_ssh_pubkey is required in config for 'set'");
                    std::process::exit(1);
                });

            let ciphertext = match encrypt_to_pubkey_line(&server_recipient, text.as_bytes()) {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to encrypt for server: {}", e);
                    std::process::exit(1);
                }
            };

            let blob = AgeEncryptedBlob {
                ver: 1,
                data: ciphertext,
            };
            match client.set_clip(context::current(), blob).await {
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
