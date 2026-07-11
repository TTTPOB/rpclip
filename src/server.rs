use age::ssh;
use age::{Decryptor, Encryptor};
use arboard::Clipboard;
use clap::Parser;
use futures::prelude::*;
use log::{error, info};
use rpclip::auth::{self, AuthorizedClients, ChallengeStore, CHALLENGE_TTL};
use rpclip::{
    AgeEncryptedBlob, AuthRequest, Challenge, RpClip, SetRequest, SignedClipboard, PROTOCOL_VERSION,
};
use ssh_key::{PrivateKey, PublicKey};
use std::str::FromStr;
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tarpc::{
    context,
    server::{self, Channel},
    tokio_serde::formats::Bincode,
};

#[derive(Parser)]
struct Args {
    #[arg(short, long, value_name = "IP:PORT", required = true)]
    address: Vec<SocketAddr>,
    /// Path to server's SSH private key (OpenSSH format). Defaults to ~/.ssh/id_ed25519
    #[arg(long)]
    ssh_key_path: Option<String>,
    /// OpenSSH authorized_keys file. Defaults to ~/.ssh/authorized_keys
    #[arg(long)]
    authorized_keys_path: Option<String>,
}

#[derive(Clone)]
struct RpClipServer {
    clipboard: Arc<Mutex<Clipboard>>,
    ssh_key_path: String,
    private_key: Arc<PrivateKey>,
    authorized_clients: Arc<AuthorizedClients>,
    challenges: Arc<ChallengeStore>,
}

impl RpClip for RpClipServer {
    async fn issue_challenge(
        self,
        _: context::Context,
        client_ssh_pubkey_line: String,
    ) -> Result<Challenge, String> {
        let public_key = self.authorize_client(&client_ssh_pubkey_line)?;
        self.challenges.issue(&public_key)
    }

    async fn get_clip(
        self,
        _: context::Context,
        auth_request: AuthRequest,
    ) -> Result<SignedClipboard, String> {
        let public_key = self.authenticate_get(&auth_request)?;
        self.challenges
            .consume(&auth_request.challenge, &public_key)?;

        let clipboard = self.clipboard.clone();
        let private_key = self.private_key.clone();
        tokio::task::spawn_blocking(move || {
            let blob = encrypt_clipboard(clipboard, auth_request.client_ssh_pubkey.clone())?;
            auth::sign_get_response(&private_key, &auth_request, blob)
        })
        .await
        .map_err(|e| format!("clipboard worker failed: {e}"))?
    }

    async fn set_clip(self, _: context::Context, request: SetRequest) -> Result<(), String> {
        let public_key = self.authenticate_set(&request)?;
        self.challenges
            .consume(&request.auth.challenge, &public_key)?;

        let clipboard = self.clipboard.clone();
        let ssh_key_path = self.ssh_key_path.clone();
        tokio::task::spawn_blocking(move || {
            decrypt_and_set_clipboard(clipboard, ssh_key_path, request.blob)
        })
        .await
        .map_err(|e| format!("clipboard worker failed: {e}"))?
    }
}

impl RpClipServer {
    fn authorize_client(&self, public_key_line: &str) -> Result<PublicKey, String> {
        let public_key = auth::parse_public_key(public_key_line)?;
        self.authorized_clients.authorize(&public_key)?;
        Ok(public_key)
    }

    fn authenticate_get(&self, request: &AuthRequest) -> Result<PublicKey, String> {
        let public_key = self.authorize_client(&request.client_ssh_pubkey)?;
        auth::verify_get_request(&public_key, request)?;
        Ok(public_key)
    }

    fn authenticate_set(&self, request: &SetRequest) -> Result<PublicKey, String> {
        let public_key = self.authorize_client(&request.auth.client_ssh_pubkey)?;
        auth::verify_set_request(&public_key, &request.auth, &request.blob)?;
        Ok(public_key)
    }
}

fn encrypt_clipboard(
    clipboard: Arc<Mutex<Clipboard>>,
    client_ssh_pubkey_line: String,
) -> Result<AgeEncryptedBlob, String> {
    let text = match clipboard
        .lock()
        .map_err(|_| "clipboard lock is poisoned".to_string())?
        .get_text()
    {
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

    Ok(AgeEncryptedBlob {
        ver: PROTOCOL_VERSION,
        data: out,
    })
}

fn decrypt_and_set_clipboard(
    clipboard: Arc<Mutex<Clipboard>>,
    ssh_key_path: String,
    blob: AgeEncryptedBlob,
) -> Result<(), String> {
    let key_path = expand_tilde(&ssh_key_path);
    let key_bytes = match std::fs::read(&key_path) {
        Ok(b) => b,
        Err(e) => {
            error!("failed to read ssh key {}: {}", key_path, e);
            return Err(format!("failed to read server SSH key: {e}"));
        }
    };
    let identity =
        match ssh::Identity::from_buffer(std::io::Cursor::new(key_bytes), Some(key_path.clone())) {
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

    if let Err(e) = clipboard
        .lock()
        .map_err(|_| "clipboard lock is poisoned".to_string())?
        .set_text(rpclip::line_end::to_platform_line_ending(&text))
    {
        error!("server failed to set clipboard text: {e}");
        Err(format!("failed to set system clipboard: {e}"))
    } else {
        info!("server set clipboard text (len={} bytes)", text.len());
        Ok(())
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

fn load_server_security(
    ssh_key_path: Option<String>,
    authorized_keys_path: Option<String>,
) -> Result<(String, Arc<PrivateKey>, Arc<AuthorizedClients>), String> {
    let ssh_key_path =
        expand_tilde(&ssh_key_path.unwrap_or_else(|| "~/.ssh/id_ed25519".to_string()));
    let authorized_keys_path = PathBuf::from(expand_tilde(
        &authorized_keys_path.unwrap_or_else(|| "~/.ssh/authorized_keys".to_string()),
    ));
    let private_key = auth::read_private_key(PathBuf::from(&ssh_key_path).as_path())?;
    let authorized_clients = AuthorizedClients::read_file(&authorized_keys_path)?;
    info!(
        "Loaded client authorization keys from {}",
        authorized_keys_path.display()
    );
    Ok((
        ssh_key_path,
        Arc::new(private_key),
        Arc::new(authorized_clients),
    ))
}

#[tokio::main]
async fn main() {
    env_logger::init();
    // Parse command line arguments
    let args = Args::parse();
    let (ssh_key_path, private_key, authorized_clients) =
        load_server_security(args.ssh_key_path, args.authorized_keys_path).unwrap_or_else(|e| {
            error!("Unable to initialize server authentication: {e}");
            std::process::exit(1);
        });
    let mut listeners = Vec::with_capacity(args.address.len());
    for listen_addr in args.address {
        let listener = tarpc::serde_transport::tcp::listen(&listen_addr, Bincode::default)
            .await
            .unwrap_or_else(|e| panic!("Failed to listen on {listen_addr}: {e}"));
        info!("Listening on: {}", listen_addr);
        listeners.push(listener);
    }

    let clipboard = Arc::new(Mutex::new(
        tokio::task::spawn_blocking(Clipboard::new)
            .await
            .expect("clipboard worker failed")
            .expect("failed to initialize system clipboard"),
    ));
    let challenges = Arc::new(ChallengeStore::new(CHALLENGE_TTL));
    info!("Clipboard server started");
    futures::stream::select_all(listeners)
        .filter_map(|result| {
            future::ready(match result {
                Ok(transport) => Some(transport),
                Err(e) => {
                    error!("Failed to accept client connection: {e}");
                    None
                }
            })
        })
        .map(server::BaseChannel::with_defaults)
        .map(|channel| {
            let rpserver = RpClipServer {
                clipboard: clipboard.clone(),
                ssh_key_path: ssh_key_path.clone(),
                private_key: private_key.clone(),
                authorized_clients: authorized_clients.clone(),
                challenges: challenges.clone(),
            };
            channel.execute(rpserver.serve()).for_each(|x| async {
                tokio::spawn(x);
                info!("New client connected");
            })
        })
        .buffer_unordered(10)
        .for_each(|_| async {})
        .await;
    error!("All server listeners stopped");
    std::process::exit(1);
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
            "--authorized-keys-path",
            "authorized_keys",
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
