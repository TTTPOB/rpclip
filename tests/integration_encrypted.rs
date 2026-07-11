use std::str::FromStr;
use std::time::Duration;

use age::ssh;
use age::{Decryptor, Encryptor};
use futures::StreamExt;
use rpclip::{AgeEncryptedBlob, RpClip, RpClipClient};
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use tarpc::server::Channel;
use tarpc::{client, context, tokio_serde::formats::Bincode};
use tokio::task::JoinHandle;

// Minimal clipboard for tests (avoids system clipboard)
#[derive(Default, Clone)]
struct TestClipboard(std::sync::Arc<tokio::sync::Mutex<String>>);
impl TestClipboard {
    fn new() -> Self {
        Self(Default::default())
    }
    async fn get_text(&self) -> String {
        self.0.lock().await.clone()
    }
    async fn set_text(&self, text: String) {
        *self.0.lock().await = text;
    }
}

#[derive(Clone)]
struct TestServer {
    clipboard: TestClipboard,
    ssh_key_path: String,
}

impl RpClip for TestServer {
    async fn get_clip(
        self,
        _: context::Context,
        client_ssh_pubkey_line: String,
    ) -> AgeEncryptedBlob {
        let text = self.clipboard.get_text().await;
        let recipient =
            ssh::Recipient::from_str(&client_ssh_pubkey_line).expect("client pubkey parse");
        let recipients: Vec<&dyn age::Recipient> = vec![&recipient as &dyn age::Recipient];
        let encryptor = Encryptor::with_recipients(recipients.into_iter()).expect("encryptor");
        let mut out = Vec::new();
        let mut writer = encryptor.wrap_output(&mut out).expect("wrap_output");
        use std::io::Write;
        writer.write_all(text.as_bytes()).expect("write");
        writer.finish().expect("finish");
        AgeEncryptedBlob { ver: 1, data: out }
    }

    async fn set_clip(self, _: context::Context, blob: AgeEncryptedBlob) {
        let key_bytes = std::fs::read(&self.ssh_key_path).expect("read server key");
        let identity = ssh::Identity::from_buffer(
            std::io::Cursor::new(key_bytes),
            Some(self.ssh_key_path.clone()),
        )
        .expect("identity parse");
        let decryptor = Decryptor::new(&blob.data[..]).expect("decryptor");
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .expect("decrypt");
        use std::io::Read;
        let mut plaintext = Vec::new();
        reader.read_to_end(&mut plaintext).expect("read");
        let text = String::from_utf8(plaintext).expect("utf8");
        self.clipboard
            .set_text(rpclip::line_end::to_platform_line_ending(&text))
            .await;
    }
}

async fn start_test_server(
    addr: std::net::SocketAddr,
    ssh_key_path: String,
    clipboard: TestClipboard,
) -> JoinHandle<()> {
    let listener = tarpc::serde_transport::tcp::listen(&addr, Bincode::default)
        .await
        .expect("listen");
    tokio::spawn(async move {
        listener
            .filter_map(|r| futures::future::ready(r.ok()))
            .map(tarpc::server::BaseChannel::with_defaults)
            .map(|channel| {
                let rpserver = TestServer {
                    clipboard: clipboard.clone(),
                    ssh_key_path: ssh_key_path.clone(),
                };
                channel.execute(rpserver.serve()).for_each(|x| async {
                    tokio::spawn(x);
                })
            })
            .buffer_unordered(10)
            .for_each(|_| async {})
            .await;
    })
}

fn gen_ssh_keypair(dir: &std::path::Path, name: &str) -> (String, String) {
    let mut rng = rand_core::OsRng;
    let private = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("generate key");
    let public = private.public_key().clone();
    let priv_text = private.to_openssh(LineEnding::LF).expect("priv openssh");
    let pub_text = public.to_openssh().expect("pub openssh");
    let priv_path = dir.join(name);
    let pub_path = dir.join(format!("{}.pub", name));
    std::fs::write(&priv_path, priv_text).expect("write priv");
    std::fs::write(&pub_path, format!("{}\n", pub_text)).expect("write pub");
    (priv_path.to_string_lossy().to_string(), pub_text)
}

#[tokio::test]
async fn encrypted_round_trip() {
    // Temp dir and keys
    let td = tempfile::tempdir().expect("tempdir");
    let (server_key_path, server_pub_line) = gen_ssh_keypair(td.path(), "server_id_ed25519");
    let (client_key_path, client_pub_line) = gen_ssh_keypair(td.path(), "client_id_ed25519");

    // Random port
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 0");
    let addr = std_listener.local_addr().unwrap();
    drop(std_listener);

    // Start server
    let clipboard = TestClipboard::new();
    let _server_handle = start_test_server(addr, server_key_path.clone(), clipboard.clone()).await;

    // Connect client
    let client = RpClipClient::new(
        client::Config::default(),
        tarpc::serde_transport::tcp::connect(addr, Bincode::default)
            .await
            .expect("connect"),
    )
    .spawn();

    // Encrypt a message to server and set
    let plaintext = "hello integration\\nsecond line";
    let recipient = ssh::Recipient::from_str(&server_pub_line).expect("server recipient");
    let recipients: Vec<&dyn age::Recipient> = vec![&recipient as &dyn age::Recipient];
    let encryptor = Encryptor::with_recipients(recipients.into_iter()).expect("encryptor");
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out).expect("wrap output");
    use std::io::Write;
    writer.write_all(plaintext.as_bytes()).expect("write");
    writer.finish().expect("finish");
    let blob = AgeEncryptedBlob { ver: 1, data: out };
    client
        .set_clip(context::current(), blob)
        .await
        .expect("set_clip");

    // Give the server a moment to process
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Request get encrypted to client key and decrypt
    let blob = client
        .get_clip(context::current(), client_pub_line.clone())
        .await
        .expect("get_clip");

    let key_bytes = std::fs::read(&client_key_path).expect("read client key");
    let identity = ssh::Identity::from_buffer(
        std::io::Cursor::new(key_bytes),
        Some(client_key_path.clone()),
    )
    .expect("identity parse");
    let decryptor = Decryptor::new(&blob.data[..]).expect("decryptor");
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .expect("decrypt");
    use std::io::Read;
    let mut decrypted = Vec::new();
    reader.read_to_end(&mut decrypted).expect("read");
    let decrypted = String::from_utf8(decrypted).expect("utf8");

    // Compare after server-normalization
    let expected = rpclip::line_end::to_platform_line_ending(plaintext);
    assert_eq!(decrypted, expected);
}
