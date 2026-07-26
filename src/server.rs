use age::ssh;
use age::{Decryptor, Encryptor};
use arboard::Clipboard;
use clap::Parser;
use futures::prelude::*;
use log::{error, info};
use rpclip::auth::{self, AuthorizedClients, ChallengeStore, ServerAuthenticator};
use rpclip::{
    read_clipboard_payload, validate_clipboard_payload_len,
    validate_encrypted_clipboard_payload_len, AgeEncryptedBlob, AuthRequest, Challenge,
    ChallengeRequest, RpClip, SetRequest, SignedClipboard, SignedSetResponse, PROTOCOL_VERSION,
};
use std::str::FromStr;
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tarpc::{
    context,
    server::{self, incoming::Incoming},
    tokio_serde::formats::Bincode,
};

const MAX_OPEN_CHANNELS: u32 = 64;
const MAX_CONCURRENT_REQUESTS_PER_CHANNEL: usize = 8;
const MAX_CONCURRENT_CLIPBOARD_OPERATIONS: usize = 1;
const CHANNEL_LIFETIME: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Parser)]
struct Args {
    #[arg(short, long, value_name = "IP:PORT", required = true)]
    address: Vec<SocketAddr>,
    /// Unencrypted Ed25519 server private key. Defaults to ~/.ssh/id_ed25519
    #[arg(long)]
    ssh_key_path: Option<String>,
    /// OpenSSH authorized_keys file containing clients allowed to use RpClip
    #[arg(long, value_name = "PATH")]
    authorized_keys_path: String,
}

#[derive(Clone)]
struct RpClipServer {
    clipboard: Arc<Mutex<Clipboard>>,
    clipboard_operation_permits: Arc<tokio::sync::Semaphore>,
    ssh_key_bytes: Arc<Vec<u8>>,
    authenticator: Arc<ServerAuthenticator>,
}

impl RpClip for RpClipServer {
    async fn issue_challenge(
        self,
        _: context::Context,
        request: ChallengeRequest,
    ) -> Result<Challenge, String> {
        self.authenticator.issue_challenge(&request)
    }

    async fn get_clip(
        self,
        _: context::Context,
        auth_request: AuthRequest,
    ) -> Result<SignedClipboard, String> {
        self.authenticator.authenticate_get(&auth_request)?;

        let clipboard = self.clipboard.clone();
        let authenticator = self.authenticator.clone();
        run_clipboard_operation(self.clipboard_operation_permits.clone(), move || {
            let blob = encrypt_clipboard(clipboard, auth_request.client_ssh_pubkey.clone())?;
            authenticator.sign_get_response(&auth_request, blob)
        })
        .await
    }

    async fn set_clip(
        self,
        _: context::Context,
        request: SetRequest,
    ) -> Result<SignedSetResponse, String> {
        validate_encrypted_clipboard_payload_len(request.blob.data.len())?;
        self.authenticator.authenticate_set(&request)?;
        let response = self.authenticator.sign_set_response(&request)?;

        let clipboard = self.clipboard.clone();
        let ssh_key_bytes = self.ssh_key_bytes.clone();
        let blob = request.blob;
        run_clipboard_operation(self.clipboard_operation_permits.clone(), move || {
            decrypt_and_set_clipboard(clipboard, ssh_key_bytes, blob)
        })
        .await?;
        Ok(response)
    }
}

async fn run_clipboard_operation<T>(
    permits: Arc<tokio::sync::Semaphore>,
    operation: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String>
where
    T: Send + 'static,
{
    // Waiting requests can be canceled before they enter Tokio's blocking pool.
    let permit = permits
        .acquire_owned()
        .await
        .map_err(|_| "clipboard operation limiter was closed".to_string())?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation()
    })
    .await
    .map_err(|e| format!("clipboard worker failed: {e}"))?
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
    validate_clipboard_payload_len(text.len())?;

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
    validate_encrypted_clipboard_payload_len(out.len())?;

    Ok(AgeEncryptedBlob {
        ver: PROTOCOL_VERSION,
        data: out,
    })
}

fn decrypt_and_set_clipboard(
    clipboard: Arc<Mutex<Clipboard>>,
    ssh_key_bytes: Arc<Vec<u8>>,
    blob: AgeEncryptedBlob,
) -> Result<(), String> {
    let text = decrypt_blob(&ssh_key_bytes, &blob)?;

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

fn decrypt_blob(ssh_key_bytes: &[u8], blob: &AgeEncryptedBlob) -> Result<String, String> {
    let identity = ssh::Identity::from_buffer(
        std::io::Cursor::new(ssh_key_bytes),
        Some("cached server SSH key".to_string()),
    )
    .map_err(|e| format!("failed to parse cached server SSH identity: {e:?}"))?;
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
    let plaintext = read_clipboard_payload(&mut reader).map_err(|e| {
        error!("decrypt read error: {e}");
        format!("failed to decrypt clipboard data: {e}")
    })?;

    match String::from_utf8(plaintext) {
        Ok(s) => Ok(s),
        Err(e) => {
            error!("utf8 error: {}", e);
            Err(format!("clipboard data is not valid UTF-8: {e}"))
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

fn load_server_security(
    ssh_key_path: Option<String>,
    authorized_keys_path: String,
) -> Result<(Arc<Vec<u8>>, Arc<ServerAuthenticator>), String> {
    let ssh_key_path =
        expand_tilde(&ssh_key_path.unwrap_or_else(|| "~/.ssh/id_ed25519".to_string()));
    let authorized_keys_path = PathBuf::from(expand_tilde(&authorized_keys_path));
    let key_snapshot = auth::read_server_key_snapshot(PathBuf::from(&ssh_key_path).as_path())?;
    let authorized_clients = AuthorizedClients::read_file(&authorized_keys_path)?;
    info!(
        "Loaded client authorization keys from {}",
        authorized_keys_path.display()
    );
    let authenticator = ServerAuthenticator::new(
        Arc::new(key_snapshot.private_key),
        Arc::new(authorized_clients),
        Arc::new(ChallengeStore::new()),
    )?;
    Ok((key_snapshot.encoded, Arc::new(authenticator)))
}

async fn drive_channel_for_lifetime<C, R>(channel: C, lifetime: std::time::Duration) -> bool
where
    C: Stream<Item = R>,
    R: std::future::Future<Output = ()> + Send + 'static,
{
    let drive = async move {
        futures::pin_mut!(channel);
        let mut requests = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                request = channel.next() => match request {
                    Some(request) => {
                        requests.spawn(request);
                    }
                    None => break,
                },
                Some(_) = requests.join_next(), if !requests.is_empty() => {}
            }
        }
    };
    tokio::time::timeout(lifetime, drive).await.is_err()
}

async fn spawn_incoming_with_lifetime(
    incoming: impl Stream<
        Item = impl Stream<Item = impl std::future::Future<Output = ()> + Send + 'static>
                   + Send
                   + 'static,
    >,
    lifetime: std::time::Duration,
) {
    futures::pin_mut!(incoming);
    while let Some(channel) = incoming.next().await {
        tokio::spawn(async move {
            if drive_channel_for_lifetime(channel, lifetime).await {
                info!("Closed RPC channel after reaching its lifetime limit");
            }
        });
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    // Parse command line arguments
    let args = Args::parse();
    let (ssh_key_bytes, authenticator) =
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
    info!("Clipboard server started");
    let rpserver = RpClipServer {
        clipboard,
        clipboard_operation_permits: Arc::new(tokio::sync::Semaphore::new(
            MAX_CONCURRENT_CLIPBOARD_OPERATIONS,
        )),
        ssh_key_bytes,
        authenticator,
    };
    let incoming = futures::stream::select_all(listeners)
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
        .max_channels_per_key(MAX_OPEN_CHANNELS, |_| "global")
        .max_concurrent_requests_per_channel(MAX_CONCURRENT_REQUESTS_PER_CHANNEL)
        .execute(rpserver.serve());
    spawn_incoming_with_lifetime(incoming, CHANNEL_LIFETIME).await;
    error!("All server listeners stopped");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{Algorithm, LineEnding, PrivateKey};
    use std::sync::atomic::{AtomicBool, Ordering};

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
        assert_eq!(args.authorized_keys_path, "authorized_keys");
    }

    #[test]
    fn requires_authorized_keys_path() {
        let error = match Args::try_parse_from(["rpclip-server", "--address", "127.0.0.1:6667"]) {
            Ok(_) => panic!("missing authorized keys path was accepted"),
            Err(error) => error,
        };

        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[tokio::test]
    async fn closes_idle_channels_after_lifetime() {
        let idle = futures::stream::pending::<std::future::Ready<()>>();
        assert!(drive_channel_for_lifetime(idle, std::time::Duration::from_millis(1)).await);
    }

    #[tokio::test]
    async fn cancels_in_flight_requests_at_channel_lifetime() {
        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let request_dropped = dropped.clone();
        let request = async move {
            let _drop_flag = DropFlag(request_dropped);
            std::future::pending::<()>().await;
        };
        let channel = futures::stream::iter([request]).chain(futures::stream::pending());
        assert!(drive_channel_for_lifetime(channel, std::time::Duration::from_millis(1)).await);
        tokio::task::yield_now().await;
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn channel_timeout_cancels_queued_clipboard_operation() {
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let running = tokio::spawn(run_clipboard_operation(permits.clone(), move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Ok(())
        }));
        started_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();

        let queued_started = Arc::new(AtomicBool::new(false));
        let queued_operation_started = queued_started.clone();
        let queued = async move {
            let _ = run_clipboard_operation(permits, move || {
                queued_operation_started.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;
        };
        let channel = futures::stream::iter([queued]).chain(futures::stream::pending());
        assert!(drive_channel_for_lifetime(channel, std::time::Duration::from_millis(1)).await);

        release_tx.send(()).unwrap();
        running.await.unwrap().unwrap();
        tokio::task::yield_now().await;
        assert!(!queued_started.load(Ordering::SeqCst));
    }

    #[test]
    fn cached_server_key_survives_key_file_replacement() {
        let mut rng = rand_core::OsRng;
        let original = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
        let replacement = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id_ed25519");
        std::fs::write(&path, original.to_openssh(LineEnding::LF).unwrap()).unwrap();
        let snapshot = auth::read_server_key_snapshot(&path).unwrap();

        let public_key_line = original.public_key().to_openssh().unwrap();
        let recipient = ssh::Recipient::from_str(&public_key_line).unwrap();
        let recipients: Vec<&dyn age::Recipient> = vec![&recipient];
        let encryptor = Encryptor::with_recipients(recipients.into_iter()).unwrap();
        let mut encrypted = Vec::new();
        let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
        use std::io::Write;
        writer.write_all(b"cached identity").unwrap();
        writer.finish().unwrap();

        std::fs::write(&path, replacement.to_openssh(LineEnding::LF).unwrap()).unwrap();
        let blob = AgeEncryptedBlob {
            ver: PROTOCOL_VERSION,
            data: encrypted,
        };
        assert_eq!(
            decrypt_blob(snapshot.encoded.as_slice(), &blob).unwrap(),
            "cached identity"
        );
    }

    #[test]
    fn rejects_decrypted_clipboard_above_limit() {
        let mut rng = rand_core::OsRng;
        let private = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
        let public_key_line = private.public_key().to_openssh().unwrap();
        let recipient = ssh::Recipient::from_str(&public_key_line).unwrap();
        let recipients: Vec<&dyn age::Recipient> = vec![&recipient];
        let encryptor = Encryptor::with_recipients(recipients.into_iter()).unwrap();
        let mut encrypted = Vec::new();
        let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
        use std::io::Write;
        writer
            .write_all(&vec![b'x'; rpclip::MAX_CLIPBOARD_PAYLOAD_BYTES + 1])
            .unwrap();
        writer.finish().unwrap();
        let blob = AgeEncryptedBlob {
            ver: PROTOCOL_VERSION,
            data: encrypted,
        };

        assert!(decrypt_blob(
            private.to_openssh(LineEnding::LF).unwrap().as_bytes(),
            &blob
        )
        .unwrap_err()
        .contains("clipboard payload exceeds"));
    }
}
