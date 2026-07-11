use std::str::FromStr;
use std::time::Duration;

use age::ssh;
use age::{Decryptor, Encryptor};
use futures::StreamExt;
use rpclip::auth::{self, AuthorizedClients, ChallengeStore};
use rpclip::{
    AgeEncryptedBlob, AuthRequest, Challenge, RpClip, RpClipClient, SetRequest, SignedClipboard,
    PROTOCOL_VERSION,
};
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use std::sync::Arc;
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
    private_key: Arc<PrivateKey>,
    authorized_clients: Arc<AuthorizedClients>,
    challenges: Arc<ChallengeStore>,
}

impl RpClip for TestServer {
    async fn issue_challenge(
        self,
        _: context::Context,
        client_ssh_pubkey_line: String,
    ) -> Result<Challenge, String> {
        let public_key = auth::parse_public_key(&client_ssh_pubkey_line)?;
        self.authorized_clients.authorize(&public_key)?;
        self.challenges.issue(&public_key)
    }

    async fn get_clip(
        self,
        _: context::Context,
        auth_request: AuthRequest,
    ) -> Result<SignedClipboard, String> {
        let public_key = auth::parse_public_key(&auth_request.client_ssh_pubkey)?;
        self.authorized_clients.authorize(&public_key)?;
        auth::verify_get_request(&public_key, &auth_request)?;
        self.challenges
            .consume(&auth_request.challenge, &public_key)?;

        let text = self.clipboard.get_text().await;
        let recipient =
            ssh::Recipient::from_str(&auth_request.client_ssh_pubkey).expect("client pubkey parse");
        let recipients: Vec<&dyn age::Recipient> = vec![&recipient as &dyn age::Recipient];
        let encryptor = Encryptor::with_recipients(recipients.into_iter()).expect("encryptor");
        let mut out = Vec::new();
        let mut writer = encryptor.wrap_output(&mut out).expect("wrap_output");
        use std::io::Write;
        writer.write_all(text.as_bytes()).expect("write");
        writer.finish().expect("finish");
        let blob = AgeEncryptedBlob {
            ver: PROTOCOL_VERSION,
            data: out,
        };
        auth::sign_get_response(&self.private_key, &auth_request, blob)
    }

    async fn set_clip(self, _: context::Context, request: SetRequest) -> Result<(), String> {
        let public_key = auth::parse_public_key(&request.auth.client_ssh_pubkey)?;
        self.authorized_clients.authorize(&public_key)?;
        auth::verify_set_request(&public_key, &request.auth, &request.blob)?;
        self.challenges
            .consume(&request.auth.challenge, &public_key)?;
        request.blob.validate_version()?;

        let key_bytes = std::fs::read(&self.ssh_key_path).expect("read server key");
        let identity = ssh::Identity::from_buffer(
            std::io::Cursor::new(key_bytes),
            Some(self.ssh_key_path.clone()),
        )
        .expect("identity parse");
        let decryptor = Decryptor::new(&request.blob.data[..]).expect("decryptor");
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
        Ok(())
    }
}

async fn start_test_server(
    addr: std::net::SocketAddr,
    ssh_key_path: String,
    private_key: Arc<PrivateKey>,
    authorized_clients: Arc<AuthorizedClients>,
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
                    private_key: private_key.clone(),
                    authorized_clients: authorized_clients.clone(),
                    challenges: Arc::new(ChallengeStore::default()),
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
    let client_private_key =
        PrivateKey::read_openssh_file(std::path::Path::new(&client_key_path)).expect("client key");
    let server_private_key = Arc::new(
        PrivateKey::read_openssh_file(std::path::Path::new(&server_key_path)).expect("server key"),
    );
    let authorized_keys_path = td.path().join("authorized_keys");
    std::fs::write(
        &authorized_keys_path,
        format!("{client_pub_line} integration client\n"),
    )
    .expect("write authorized keys");
    let authorized_clients = Arc::new(
        AuthorizedClients::read_file(&authorized_keys_path).expect("read authorized clients"),
    );

    // Random port
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 0");
    let addr = std_listener.local_addr().unwrap();
    drop(std_listener);

    // Start server
    let clipboard = TestClipboard::new();
    let _server_handle = start_test_server(
        addr,
        server_key_path.clone(),
        server_private_key.clone(),
        authorized_clients,
        clipboard.clone(),
    )
    .await;

    // Connect client
    let client = RpClipClient::new(
        client::Config::default(),
        tarpc::serde_transport::tcp::connect(addr, Bincode::default)
            .await
            .expect("connect"),
    )
    .spawn();

    // Encrypt a message to server and set
    let plaintext = "hello integration\nsecond line\n";
    let recipient = ssh::Recipient::from_str(&server_pub_line).expect("server recipient");
    let recipients: Vec<&dyn age::Recipient> = vec![&recipient as &dyn age::Recipient];
    let encryptor = Encryptor::with_recipients(recipients.into_iter()).expect("encryptor");
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out).expect("wrap output");
    use std::io::Write;
    writer.write_all(plaintext.as_bytes()).expect("write");
    writer.finish().expect("finish");
    let blob = AgeEncryptedBlob {
        ver: PROTOCOL_VERSION,
        data: out,
    };
    let challenge = client
        .issue_challenge(context::current(), client_pub_line.clone())
        .await
        .expect("challenge RPC")
        .expect("challenge");
    let set_auth = auth::sign_set_request(
        &client_private_key,
        client_pub_line.clone(),
        challenge,
        &blob,
    )
    .expect("sign set request");
    client
        .set_clip(
            context::current(),
            SetRequest {
                auth: set_auth,
                blob,
            },
        )
        .await
        .expect("set_clip RPC")
        .expect("server set_clip");

    // Give the server a moment to process
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Request get encrypted to client key and decrypt
    let challenge = client
        .issue_challenge(context::current(), client_pub_line.clone())
        .await
        .expect("challenge RPC")
        .expect("challenge");
    let get_auth = auth::sign_get_request(&client_private_key, client_pub_line.clone(), challenge)
        .expect("sign get request");
    let response = client
        .get_clip(context::current(), get_auth.clone())
        .await
        .expect("get_clip RPC")
        .expect("server get_clip");
    let server_public_key = auth::parse_public_key(&server_pub_line).expect("server public key");
    auth::verify_get_response(&server_public_key, &get_auth, &response)
        .expect("verify server response");

    let key_bytes = std::fs::read(&client_key_path).expect("read client key");
    let identity = ssh::Identity::from_buffer(
        std::io::Cursor::new(key_bytes),
        Some(client_key_path.clone()),
    )
    .expect("identity parse");
    let decryptor = Decryptor::new(&response.blob.data[..]).expect("decryptor");
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
