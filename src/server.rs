use arboard::Clipboard;
use clap::Parser;
use futures::prelude::*;
use log::{error, info};
use rpclip::{AgeEncryptedBlob, RpClip};
use std::{net::SocketAddr, sync::Arc};
use tarpc::{
    context,
    server::{self, Channel},
    tokio_serde::formats::Bincode,
};
use tokio::sync::Mutex;
use std::str::FromStr;
use age::{Encryptor, Decryptor};
use age::ssh;
use std::io::Write as _;

#[derive(Parser)]
struct Args {
    #[arg(short, long, value_name = "IP:PORT", required = true)]
    address: Option<String>,
    /// Path to server's SSH private key (OpenSSH format). Defaults to ~/.ssh/id_ed25519
    #[arg(long)]
    ssh_key_path: Option<String>,
}

#[derive(Clone)]
struct RpClipServer {
    clipboard: Arc<Mutex<Clipboard>>,
    ssh_key_path: String,
}

impl RpClip for RpClipServer {
    async fn get_clip(self, _: context::Context, client_ssh_pubkey_line: String) -> AgeEncryptedBlob {
        let text = match self.clipboard.lock().await.get_text() {
            Ok(text) => {
                info!("server got clipboard text (len={} bytes)", text.len());
                text
            }
            Err(_) => {
                error!("server failed to open system clipboard");
                String::from("server failed to open system clipboard")
            }
        };

        // Encrypt to client's SSH public key
        let recipient = match ssh::Recipient::from_str(&client_ssh_pubkey_line) {
            Ok(r) => r,
            Err(e) => {
                error!("invalid client ssh pubkey: {:?}", e);
                return AgeEncryptedBlob { ver: 1, data: Vec::new() };
            }
        };
        let recipients: Vec<&dyn age::Recipient> = vec![&recipient as &dyn age::Recipient];
        let encryptor = match Encryptor::with_recipients(recipients.into_iter()) {
            Ok(e) => e,
            Err(e) => {
                error!("encryptor error: {}", e);
                return AgeEncryptedBlob { ver: 1, data: Vec::new() };
            }
        };
        let mut out = Vec::new();
        match encryptor.wrap_output(&mut out) {
            Ok(mut writer) => {
                use std::io::Write;
                if let Err(e) = writer.write_all(text.as_bytes()) {
                    error!("encrypt write error: {}", e);
                }
                if let Err(e) = writer.finish() {
                    error!("encrypt finish error: {}", e);
                }
            }
            Err(e) => {
                error!("wrap_output error: {}", e);
            }
        }

        AgeEncryptedBlob { ver: 1, data: out }
    }

    async fn set_clip(self, _: context::Context, blob: AgeEncryptedBlob) {
        // Decrypt with server's SSH private key
        let key_path = expand_tilde(&self.ssh_key_path);
        let key_bytes = match std::fs::read(&key_path) {
            Ok(b) => b,
            Err(e) => {
                error!("failed to read ssh key {}: {}", key_path, e);
                return;
            }
        };
        let identity = match ssh::Identity::from_buffer(std::io::Cursor::new(key_bytes), Some(key_path.clone())) {
            Ok(i) => i,
            Err(e) => {
                error!("failed to parse ssh identity {}: {:?}", key_path, e);
                return;
            }
        };
        let decryptor = match Decryptor::new(&blob.data[..]) {
            Ok(d) => d,
            Err(e) => {
                error!("decryptor error: {}", e);
                return;
            }
        };
        let mut reader = match decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity)) {
            Ok(r) => r,
            Err(e) => {
                error!("decrypt error: {}", e);
                return;
            }
        };
        use std::io::Read;
        let mut plaintext = Vec::new();
        if let Err(e) = reader.read_to_end(&mut plaintext) {
            error!("decrypt read error: {}", e);
            return;
        }

        let text = match String::from_utf8(plaintext) {
            Ok(s) => s,
            Err(e) => {
                error!("utf8 error: {}", e);
                return;
            }
        };

        if let Err(_) = self
            .clipboard
            .lock()
            .await
            .set_text(rpclip::line_end::to_platform_line_ending(&text))
        {
            error!("server failed to set clipboard text");
        } else {
            info!("server set clipboard text (len={} bytes)", text.len());
        }
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

#[tokio::main]
async fn main() {
    env_logger::init();
    // Parse command line arguments
    let args = Args::parse();
    let listen_addr: SocketAddr = match args.address {
        Some(addr) => addr.parse().expect("Invalid address"),
        None => {
            info!("No address provided, using default address");
            "[::1]:6667".parse().expect("Invalid address")
        }
    };

    let listener = tarpc::serde_transport::tcp::listen(&listen_addr, Bincode::default)
        .await
        .unwrap();
    info!("Listening on: {}", listen_addr);

    let clipboard = Arc::new(Mutex::new(Clipboard::new().unwrap()));
    let ssh_key_path = args
        .ssh_key_path
        .unwrap_or_else(|| "~/.ssh/id_ed25519".to_string());
    info!("Clipboard server started");
    listener
        .filter_map(|r| future::ready(r.ok()))
        .map(server::BaseChannel::with_defaults)
        .map(|channel| {
            let rpserver = RpClipServer { clipboard: clipboard.clone(), ssh_key_path: ssh_key_path.clone() };
            channel.execute(rpserver.serve()).for_each(|x| async {
                tokio::spawn(x);
                info!("New client connected");
            })
        })
        .buffer_unordered(10)
        .for_each(|_| async {}) // discard the result of the `map`
        .await;
}
