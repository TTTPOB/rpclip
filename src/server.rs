use age::ssh;
use age::{Decryptor, Encryptor};
use arboard::Clipboard;
use clap::Parser;
use futures::prelude::*;
use log::{error, info};
use rpclip::{AgeEncryptedBlob, RpClip};
use std::str::FromStr;
use std::{net::SocketAddr, sync::Arc};
use tarpc::{
    context,
    server::{self, Channel},
    tokio_serde::formats::Bincode,
};
use tokio::sync::Mutex;

#[derive(Parser)]
struct Args {
    #[arg(short, long, value_name = "IP:PORT", required = true)]
    address: Vec<SocketAddr>,
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
    async fn get_clip(
        self,
        _: context::Context,
        client_ssh_pubkey_line: String,
    ) -> Result<AgeEncryptedBlob, String> {
        let text = match self.clipboard.lock().await.get_text() {
            Ok(text) => {
                info!("server got clipboard text (len={} bytes)", text.len());
                text
            }
            Err(e) => {
                error!("server failed to open system clipboard: {e}");
                return Err(format!("failed to read system clipboard: {e}"));
            }
        };

        // Encrypt to client's SSH public key
        let recipient = match ssh::Recipient::from_str(&client_ssh_pubkey_line) {
            Ok(r) => r,
            Err(e) => {
                error!("invalid client ssh pubkey: {:?}", e);
                return Err(format!("invalid client SSH public key: {e:?}"));
            }
        };
        let recipients: Vec<&dyn age::Recipient> = vec![&recipient as &dyn age::Recipient];
        let encryptor = match Encryptor::with_recipients(recipients.into_iter()) {
            Ok(e) => e,
            Err(e) => {
                error!("encryptor error: {}", e);
                return Err(format!("failed to initialize clipboard encryption: {e}"));
            }
        };
        let mut out = Vec::new();
        let mut writer = match encryptor.wrap_output(&mut out) {
            Ok(writer) => writer,
            Err(e) => {
                error!("wrap_output error: {}", e);
                return Err(format!("failed to initialize encrypted response: {e}"));
            }
        };
        use std::io::Write;
        if let Err(e) = writer.write_all(text.as_bytes()) {
            error!("encrypt write error: {}", e);
            return Err(format!("failed to encrypt clipboard data: {e}"));
        }
        if let Err(e) = writer.finish() {
            error!("encrypt finish error: {}", e);
            return Err(format!("failed to finish clipboard encryption: {e}"));
        }

        Ok(AgeEncryptedBlob { ver: 1, data: out })
    }

    async fn set_clip(self, _: context::Context, blob: AgeEncryptedBlob) -> Result<(), String> {
        // Decrypt with server's SSH private key
        let key_path = expand_tilde(&self.ssh_key_path);
        let key_bytes = match std::fs::read(&key_path) {
            Ok(b) => b,
            Err(e) => {
                error!("failed to read ssh key {}: {}", key_path, e);
                return Err(format!("failed to read server SSH key: {e}"));
            }
        };
        let identity = match ssh::Identity::from_buffer(
            std::io::Cursor::new(key_bytes),
            Some(key_path.clone()),
        ) {
            Ok(i) => i,
            Err(e) => {
                error!("failed to parse ssh identity {}: {:?}", key_path, e);
                return Err(format!("failed to parse server SSH identity: {e:?}"));
            }
        };
        let decryptor = match Decryptor::new(&blob.data[..]) {
            Ok(d) => d,
            Err(e) => {
                error!("decryptor error: {}", e);
                return Err(format!("failed to read encrypted clipboard data: {e}"));
            }
        };
        let mut reader = match decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity)) {
            Ok(r) => r,
            Err(e) => {
                error!("decrypt error: {}", e);
                return Err(format!("failed to decrypt clipboard data: {e}"));
            }
        };
        use std::io::Read;
        let mut plaintext = Vec::new();
        if let Err(e) = reader.read_to_end(&mut plaintext) {
            error!("decrypt read error: {}", e);
            return Err(format!("failed to decrypt clipboard data: {e}"));
        }

        let text = match String::from_utf8(plaintext) {
            Ok(s) => s,
            Err(e) => {
                error!("utf8 error: {}", e);
                return Err(format!("clipboard data is not valid UTF-8: {e}"));
            }
        };

        if let Err(e) = self
            .clipboard
            .lock()
            .await
            .set_text(rpclip::line_end::to_platform_line_ending(&text))
        {
            error!("server failed to set clipboard text: {e}");
            Err(format!("failed to set system clipboard: {e}"))
        } else {
            info!("server set clipboard text (len={} bytes)", text.len());
            Ok(())
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
    let mut listeners = Vec::with_capacity(args.address.len());
    for listen_addr in args.address {
        let listener = tarpc::serde_transport::tcp::listen(&listen_addr, Bincode::default)
            .await
            .unwrap_or_else(|e| panic!("Failed to listen on {listen_addr}: {e}"));
        info!("Listening on: {}", listen_addr);
        listeners.push(listener);
    }

    let clipboard = Arc::new(Mutex::new(Clipboard::new().unwrap()));
    let ssh_key_path = args
        .ssh_key_path
        .unwrap_or_else(|| "~/.ssh/id_ed25519".to_string());
    info!("Clipboard server started");
    futures::stream::select_all(listeners)
        .filter_map(|r| future::ready(r.ok()))
        .map(server::BaseChannel::with_defaults)
        .map(|channel| {
            let rpserver = RpClipServer {
                clipboard: clipboard.clone(),
                ssh_key_path: ssh_key_path.clone(),
            };
            channel.execute(rpserver.serve()).for_each(|x| async {
                tokio::spawn(x);
                info!("New client connected");
            })
        })
        .buffer_unordered(10)
        .for_each(|_| async {}) // discard the result of the `map`
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_multiple_listen_addresses() {
        let args = Args::try_parse_from([
            "rpclip-server",
            "--address",
            "127.0.0.1:6667",
            "--address",
            "[::1]:6667",
        ])
        .unwrap();

        assert_eq!(
            args.address,
            [
                "127.0.0.1:6667".parse().unwrap(),
                "[::1]:6667".parse().unwrap(),
            ]
        );
    }
}
