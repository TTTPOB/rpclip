use bincode::Options;
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use ssh_key::{Algorithm, AuthorizedKeys, HashAlg, PrivateKey, PublicKey, SshSig};
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::{
    AgeEncryptedBlob, AuthRequest, Challenge, ChallengeRequest, ClipboardOperation, SetRequest,
    SignedClipboard, SignedSetResponse, PROTOCOL_VERSION,
};

pub const SIGNATURE_NAMESPACE: &str = "rpclip-auth";
pub const CHALLENGE_SIGNATURE_NAMESPACE: &str = "rpclip-challenge";
pub const CHALLENGE_TTL: Duration = Duration::from_secs(30);
const MAX_OUTSTANDING_CHALLENGES: usize = 1024;
const MAX_CHALLENGES_PER_CLIENT_OPERATION: usize = 4;
const MAX_PREAUTH_NONCES_PER_CLIENT: usize = 64;
const PREAUTH_MAX_AGE: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Serialize)]
enum SignedOperation {
    GetRequest = 1,
    SetRequest = 2,
    GetResponse = 3,
    SetResponse = 4,
}

#[derive(Serialize)]
struct ChallengeSigningEnvelope<'a> {
    format: &'static [u8],
    protocol_version: u8,
    operation: ClipboardOperation,
    client_ssh_pubkey: &'a str,
    client_nonce: &'a [u8; 32],
    issued_at_unix_seconds: u64,
}

#[derive(Serialize)]
struct SigningEnvelope<'a> {
    format: &'static [u8],
    protocol_version: u8,
    operation: SignedOperation,
    challenge: &'a Challenge,
    client_ssh_pubkey: &'a str,
    payload: &'a [u8],
}

fn signing_bytes(
    operation: SignedOperation,
    challenge: &Challenge,
    client_ssh_pubkey: &str,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let envelope = SigningEnvelope {
        format: b"rpclip-signature-v1",
        protocol_version: PROTOCOL_VERSION,
        operation,
        challenge,
        client_ssh_pubkey,
        payload,
    };

    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&envelope)
        .map_err(|e| format!("failed to encode signature input: {e}"))
}

fn challenge_signing_bytes(request: &ChallengeRequest) -> Result<Vec<u8>, String> {
    let envelope = ChallengeSigningEnvelope {
        format: b"rpclip-challenge-signature-v1",
        protocol_version: PROTOCOL_VERSION,
        operation: request.operation,
        client_ssh_pubkey: &request.client_ssh_pubkey,
        client_nonce: &request.client_nonce,
        issued_at_unix_seconds: request.issued_at_unix_seconds,
    };
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&envelope)
        .map_err(|e| format!("failed to encode challenge signature input: {e}"))
}

pub fn parse_public_key(line: &str) -> Result<PublicKey, String> {
    let public_key =
        PublicKey::from_openssh(line).map_err(|e| format!("invalid SSH public key: {e}"))?;
    validate_age_recipient(line)?;
    Ok(public_key)
}

fn validate_age_recipient(line: &str) -> Result<(), String> {
    age::ssh::Recipient::from_str(line)
        .map(|_| ())
        .map_err(|e| format!("SSH public key cannot be used as an age recipient: {e:?}"))
}

pub fn read_private_key(path: &Path) -> Result<PrivateKey, String> {
    let private_key = PrivateKey::read_openssh_file(path)
        .map_err(|e| format!("failed to read SSH private key {}: {e}", path.display()))?;
    if private_key.is_encrypted() {
        return Err(format!(
            "SSH private key {} is encrypted; passphrase-protected keys are not supported",
            path.display()
        ));
    }
    ensure_age_compatible(private_key.algorithm())?;
    Ok(private_key)
}

pub fn read_server_private_key(path: &Path) -> Result<PrivateKey, String> {
    let private_key = read_private_key(path)?;
    if private_key.algorithm() != Algorithm::Ed25519 {
        return Err(format!(
            "server SSH private key {} must use Ed25519",
            path.display()
        ));
    }
    Ok(private_key)
}

fn ensure_age_compatible(algorithm: Algorithm) -> Result<(), String> {
    match algorithm {
        Algorithm::Ed25519 | Algorithm::Rsa { .. } => Ok(()),
        algorithm => Err(format!(
            "SSH key algorithm {algorithm} cannot be used for age encryption"
        )),
    }
}

fn sign(private_key: &PrivateKey, namespace: &str, message: &[u8]) -> Result<String, String> {
    private_key
        .sign(namespace, HashAlg::Sha512, message)
        .map(|signature| signature.to_string())
        .map_err(|e| format!("failed to sign request: {e}"))
}

fn verify(
    public_key: &PublicKey,
    namespace: &str,
    message: &[u8],
    signature: &str,
) -> Result<(), String> {
    let signature = signature
        .parse::<SshSig>()
        .map_err(|e| format!("invalid SSH signature: {e}"))?;
    public_key
        .verify(namespace, message, &signature)
        .map_err(|e| format!("SSH signature verification failed: {e}"))
}

pub fn sign_challenge_request(
    private_key: &PrivateKey,
    client_ssh_pubkey: String,
    operation: ClipboardOperation,
) -> Result<ChallengeRequest, String> {
    let mut request = ChallengeRequest {
        ver: PROTOCOL_VERSION,
        operation,
        client_ssh_pubkey,
        client_nonce: [0; 32],
        issued_at_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch".to_string())?
            .as_secs(),
        signature: String::new(),
    };
    OsRng.fill_bytes(&mut request.client_nonce);
    let message = challenge_signing_bytes(&request)?;
    request.signature = sign(private_key, CHALLENGE_SIGNATURE_NAMESPACE, &message)?;
    Ok(request)
}

pub fn verify_challenge_request(
    public_key: &PublicKey,
    request: &ChallengeRequest,
) -> Result<(), String> {
    request.validate_version()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_string())?
        .as_secs();
    if now.abs_diff(request.issued_at_unix_seconds) > PREAUTH_MAX_AGE.as_secs() {
        return Err("challenge request timestamp is outside the allowed window".to_string());
    }
    let message = challenge_signing_bytes(request)?;
    verify(
        public_key,
        CHALLENGE_SIGNATURE_NAMESPACE,
        &message,
        &request.signature,
    )
}

pub fn sign_get_request(
    private_key: &PrivateKey,
    client_ssh_pubkey: String,
    challenge: Challenge,
) -> Result<AuthRequest, String> {
    challenge.validate_version()?;
    let message = signing_bytes(
        SignedOperation::GetRequest,
        &challenge,
        &client_ssh_pubkey,
        &[],
    )?;
    Ok(AuthRequest {
        ver: PROTOCOL_VERSION,
        client_ssh_pubkey,
        challenge,
        signature: sign(private_key, SIGNATURE_NAMESPACE, &message)?,
    })
}

pub fn sign_set_request(
    private_key: &PrivateKey,
    client_ssh_pubkey: String,
    challenge: Challenge,
    blob: &AgeEncryptedBlob,
) -> Result<AuthRequest, String> {
    challenge.validate_version()?;
    blob.validate_version()?;
    let message = signing_bytes(
        SignedOperation::SetRequest,
        &challenge,
        &client_ssh_pubkey,
        &blob.data,
    )?;
    Ok(AuthRequest {
        ver: PROTOCOL_VERSION,
        client_ssh_pubkey,
        challenge,
        signature: sign(private_key, SIGNATURE_NAMESPACE, &message)?,
    })
}

pub fn verify_get_request(public_key: &PublicKey, auth: &AuthRequest) -> Result<(), String> {
    auth.validate_version()?;
    let message = signing_bytes(
        SignedOperation::GetRequest,
        &auth.challenge,
        &auth.client_ssh_pubkey,
        &[],
    )?;
    verify(public_key, SIGNATURE_NAMESPACE, &message, &auth.signature)
}

pub fn verify_set_request(
    public_key: &PublicKey,
    auth: &AuthRequest,
    blob: &AgeEncryptedBlob,
) -> Result<(), String> {
    auth.validate_version()?;
    blob.validate_version()?;
    let message = signing_bytes(
        SignedOperation::SetRequest,
        &auth.challenge,
        &auth.client_ssh_pubkey,
        &blob.data,
    )?;
    verify(public_key, SIGNATURE_NAMESPACE, &message, &auth.signature)
}

pub fn sign_get_response(
    private_key: &PrivateKey,
    auth: &AuthRequest,
    blob: AgeEncryptedBlob,
) -> Result<SignedClipboard, String> {
    auth.validate_version()?;
    blob.validate_version()?;
    let message = signing_bytes(
        SignedOperation::GetResponse,
        &auth.challenge,
        &auth.client_ssh_pubkey,
        &blob.data,
    )?;
    Ok(SignedClipboard {
        ver: PROTOCOL_VERSION,
        blob,
        signature: sign(private_key, SIGNATURE_NAMESPACE, &message)?,
    })
}

pub fn verify_get_response(
    server_public_key: &PublicKey,
    auth: &AuthRequest,
    response: &SignedClipboard,
) -> Result<(), String> {
    response.validate_version()?;
    let message = signing_bytes(
        SignedOperation::GetResponse,
        &auth.challenge,
        &auth.client_ssh_pubkey,
        &response.blob.data,
    )?;
    verify(
        server_public_key,
        SIGNATURE_NAMESPACE,
        &message,
        &response.signature,
    )
}

pub fn sign_set_response(
    private_key: &PrivateKey,
    request: &SetRequest,
) -> Result<SignedSetResponse, String> {
    request.auth.validate_version()?;
    request.blob.validate_version()?;
    let message = signing_bytes(
        SignedOperation::SetResponse,
        &request.auth.challenge,
        &request.auth.client_ssh_pubkey,
        &request.blob.data,
    )?;
    Ok(SignedSetResponse {
        ver: PROTOCOL_VERSION,
        signature: sign(private_key, SIGNATURE_NAMESPACE, &message)?,
    })
}

pub fn verify_set_response(
    server_public_key: &PublicKey,
    request: &SetRequest,
    response: &SignedSetResponse,
) -> Result<(), String> {
    response.validate_version()?;
    let message = signing_bytes(
        SignedOperation::SetResponse,
        &request.auth.challenge,
        &request.auth.client_ssh_pubkey,
        &request.blob.data,
    )?;
    verify(
        server_public_key,
        SIGNATURE_NAMESPACE,
        &message,
        &response.signature,
    )
}

#[derive(Clone)]
pub struct AuthorizedClients {
    keys: Vec<PublicKey>,
}

impl AuthorizedClients {
    pub fn read_file(path: &Path) -> Result<Self, String> {
        let entries = AuthorizedKeys::read_file(path)
            .map_err(|e| format!("failed to read authorized keys {}: {e}", path.display()))?;
        if entries.is_empty() {
            return Err(format!(
                "authorized keys file {} contains no keys",
                path.display()
            ));
        }

        let mut keys = Vec::with_capacity(entries.len());
        for entry in entries {
            if !entry.config_opts().is_empty() {
                return Err(format!(
                    "authorized key options are not supported safely: {}",
                    entry.config_opts()
                ));
            }
            validate_age_recipient(
                &entry
                    .public_key()
                    .to_openssh()
                    .map_err(|e| format!("failed to encode authorized key: {e}"))?,
            )?;
            keys.push(entry.public_key().clone());
        }

        Ok(Self { keys })
    }

    pub fn authorize(&self, public_key: &PublicKey) -> Result<(), String> {
        if self
            .keys
            .iter()
            .any(|authorized| authorized.key_data() == public_key.key_data())
        {
            Ok(())
        } else {
            Err("client SSH public key is not authorized".to_string())
        }
    }
}

struct ChallengeRecord {
    client_fingerprint: String,
    operation: ClipboardOperation,
    issued_at: Instant,
    expires_at: Instant,
}

pub struct ChallengeStore {
    entries: Mutex<HashMap<[u8; 32], ChallengeRecord>>,
    used_client_nonces: Mutex<HashMap<(String, [u8; 32]), Instant>>,
    ttl: Duration,
}

impl ChallengeStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            used_client_nonces: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    pub fn issue(
        &self,
        client_public_key: &PublicKey,
        operation: ClipboardOperation,
        client_nonce: [u8; 32],
    ) -> Result<Challenge, String> {
        let now = Instant::now();
        let fingerprint = client_public_key.fingerprint(HashAlg::Sha256).to_string();
        let mut used_client_nonces = self
            .used_client_nonces
            .lock()
            .map_err(|_| "pre-authentication nonce store lock is poisoned".to_string())?;
        used_client_nonces.retain(|_, expires_at| *expires_at > now);
        if used_client_nonces.contains_key(&(fingerprint.clone(), client_nonce)) {
            return Err("challenge request nonce has already been used".to_string());
        }
        let client_nonce_count = used_client_nonces
            .keys()
            .filter(|(client, _)| client == &fingerprint)
            .count();
        if client_nonce_count >= MAX_PREAUTH_NONCES_PER_CLIENT {
            return Err("too many recent challenge requests for this client key".to_string());
        }
        used_client_nonces.insert((fingerprint.clone(), client_nonce), now + PREAUTH_MAX_AGE);
        drop(used_client_nonces);

        let mut entries = self
            .entries
            .lock()
            .map_err(|_| "challenge store lock is poisoned".to_string())?;
        entries.retain(|_, record| record.expires_at > now);
        let mut matching: Vec<_> = entries
            .iter()
            .filter(|(_, record)| {
                record.client_fingerprint == fingerprint && record.operation == operation
            })
            .map(|(nonce, record)| (*nonce, record.issued_at))
            .collect();
        matching.sort_by_key(|(_, issued_at)| *issued_at);
        let remove_count = matching
            .len()
            .saturating_sub(MAX_CHALLENGES_PER_CLIENT_OPERATION - 1);
        for (nonce, _) in matching.into_iter().take(remove_count) {
            entries.remove(&nonce);
        }
        if entries.len() >= MAX_OUTSTANDING_CHALLENGES {
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, record)| record.issued_at)
                .map(|(nonce, _)| *nonce)
            {
                entries.remove(&oldest);
            }
        }

        let nonce = loop {
            let mut nonce = [0_u8; 32];
            OsRng.fill_bytes(&mut nonce);
            if !entries.contains_key(&nonce) {
                break nonce;
            }
        };
        entries.insert(
            nonce,
            ChallengeRecord {
                client_fingerprint: fingerprint,
                operation,
                issued_at: now,
                expires_at: now + self.ttl,
            },
        );
        Ok(Challenge {
            ver: PROTOCOL_VERSION,
            nonce,
        })
    }

    pub fn consume(
        &self,
        challenge: &Challenge,
        client_public_key: &PublicKey,
        operation: ClipboardOperation,
    ) -> Result<(), String> {
        challenge.validate_version()?;
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| "challenge store lock is poisoned".to_string())?;
        let Some(record) = entries.get(&challenge.nonce) else {
            return Err("authentication challenge is unknown or already used".to_string());
        };
        if record.expires_at <= now {
            entries.remove(&challenge.nonce);
            return Err("authentication challenge has expired".to_string());
        }
        let fingerprint = client_public_key.fingerprint(HashAlg::Sha256).to_string();
        if record.client_fingerprint != fingerprint {
            return Err("authentication challenge belongs to another client key".to_string());
        }
        if record.operation != operation {
            return Err("authentication challenge belongs to another operation".to_string());
        }
        entries.remove(&challenge.nonce);
        Ok(())
    }
}

impl Default for ChallengeStore {
    fn default() -> Self {
        Self::new(CHALLENGE_TTL)
    }
}

#[derive(Clone)]
pub struct ServerAuthenticator {
    private_key: Arc<PrivateKey>,
    authorized_clients: Arc<AuthorizedClients>,
    challenges: Arc<ChallengeStore>,
}

impl ServerAuthenticator {
    pub fn new(
        private_key: Arc<PrivateKey>,
        authorized_clients: Arc<AuthorizedClients>,
        challenges: Arc<ChallengeStore>,
    ) -> Result<Self, String> {
        if private_key.algorithm() != Algorithm::Ed25519 {
            return Err("server SSH private key must use Ed25519".to_string());
        }
        Ok(Self {
            private_key,
            authorized_clients,
            challenges,
        })
    }

    pub fn issue_challenge(&self, request: &ChallengeRequest) -> Result<Challenge, String> {
        let public_key = parse_public_key(&request.client_ssh_pubkey)?;
        self.authorized_clients.authorize(&public_key)?;
        verify_challenge_request(&public_key, request)?;
        self.challenges
            .issue(&public_key, request.operation, request.client_nonce)
    }

    pub fn authenticate_get(&self, request: &AuthRequest) -> Result<PublicKey, String> {
        let public_key = self.authorize(&request.client_ssh_pubkey)?;
        verify_get_request(&public_key, request)?;
        self.challenges
            .consume(&request.challenge, &public_key, ClipboardOperation::Get)?;
        Ok(public_key)
    }

    pub fn authenticate_set(&self, request: &SetRequest) -> Result<PublicKey, String> {
        let public_key = self.authorize(&request.auth.client_ssh_pubkey)?;
        verify_set_request(&public_key, &request.auth, &request.blob)?;
        self.challenges.consume(
            &request.auth.challenge,
            &public_key,
            ClipboardOperation::Set,
        )?;
        Ok(public_key)
    }

    pub fn sign_get_response(
        &self,
        request: &AuthRequest,
        blob: AgeEncryptedBlob,
    ) -> Result<SignedClipboard, String> {
        sign_get_response(&self.private_key, request, blob)
    }

    pub fn sign_set_response(&self, request: &SetRequest) -> Result<SignedSetResponse, String> {
        sign_set_response(&self.private_key, request)
    }

    fn authorize(&self, public_key_line: &str) -> Result<PublicKey, String> {
        let public_key = parse_public_key(public_key_line)?;
        self.authorized_clients.authorize(&public_key)?;
        Ok(public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{EcdsaCurve, LineEnding, PrivateKey};

    fn keypair() -> PrivateKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("generate key")
    }

    fn challenge(byte: u8) -> Challenge {
        Challenge {
            ver: PROTOCOL_VERSION,
            nonce: [byte; 32],
        }
    }

    fn blob(data: &[u8]) -> AgeEncryptedBlob {
        AgeEncryptedBlob {
            ver: PROTOCOL_VERSION,
            data: data.to_vec(),
        }
    }

    fn authorized_clients(key: &PrivateKey) -> Arc<AuthorizedClients> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("authorized_keys");
        std::fs::write(
            &path,
            format!("{} client\n", key.public_key().to_openssh().unwrap()),
        )
        .expect("write authorized keys");
        Arc::new(AuthorizedClients::read_file(&path).expect("authorized clients"))
    }

    fn authenticator(client: &PrivateKey, server: &PrivateKey) -> ServerAuthenticator {
        ServerAuthenticator::new(
            Arc::new(server.clone()),
            authorized_clients(client),
            Arc::new(ChallengeStore::default()),
        )
        .expect("server authenticator")
    }

    #[test]
    fn authorizes_listed_keys_and_rejects_other_keys() {
        let listed = keypair();
        let second_listed = keypair();
        let other = keypair();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("authorized_keys");
        std::fs::write(
            &path,
            format!(
                "{} client with a comment\n{} second client\n",
                listed.public_key().to_openssh().expect("public key"),
                second_listed.public_key().to_openssh().expect("public key"),
            ),
        )
        .expect("write authorized keys");

        let authorized = AuthorizedClients::read_file(&path).expect("parse authorized keys");
        assert!(authorized.authorize(listed.public_key()).is_ok());
        assert!(authorized.authorize(second_listed.public_key()).is_ok());
        assert_eq!(
            authorized.authorize(other.public_key()),
            Err("client SSH public key is not authorized".to_string())
        );
    }

    #[test]
    fn rejects_authorized_key_options_that_cannot_be_enforced() {
        let key = keypair();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("authorized_keys");
        std::fs::write(
            &path,
            format!(
                "from=\"10.0.0.1\",no-port-forwarding {} restricted client\n",
                key.public_key().to_openssh().expect("public key")
            ),
        )
        .expect("write authorized keys");

        let error = match AuthorizedClients::read_file(&path) {
            Ok(_) => panic!("options should be rejected"),
            Err(error) => error,
        };
        assert!(error.contains("authorized key options are not supported safely"));
    }

    #[test]
    fn rejects_keys_that_age_cannot_use() {
        let ecdsa = PrivateKey::random(
            &mut OsRng,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        )
        .expect("generate ECDSA key");
        let public_key_line = ecdsa.public_key().to_openssh().expect("public key");

        let error = parse_public_key(&public_key_line).expect_err("ECDSA should be rejected");
        assert!(error.contains("cannot be used as an age recipient"));
    }

    #[test]
    fn rejects_weak_rsa_key_accepted_by_openssh_parser() {
        let line = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDeUHcr1y8DvAKSO3A3B1sznHOq62fn4rMHoT0IlBG+QN+ve4sjMm5HpI1t4nptWg3o8ncQxqKyYa0VJzfmqu/JBXJbQnqoqsEMCEBJhsKEKlKreqjcd1SLFfb+fNIr3+pgdqorwWG6dW7NOn3tkzoOPqRp9tZ8u3TDuhvst6Wv2w==";
        assert!(PublicKey::from_openssh(line).is_ok());

        let error = parse_public_key(line).expect_err("weak RSA key should be rejected");
        assert!(error.contains("cannot be used as an age recipient"));
    }

    #[test]
    fn rejects_wrong_signature_and_operation_confusion() {
        let claimed = keypair();
        let signer = keypair();
        let client_line = claimed.public_key().to_openssh().expect("public key");
        let request = sign_get_request(&signer, client_line, challenge(1)).expect("sign request");
        assert!(verify_get_request(claimed.public_key(), &request).is_err());

        let request = sign_get_request(
            &claimed,
            claimed.public_key().to_openssh().expect("public key"),
            challenge(2),
        )
        .expect("sign request");
        assert!(verify_set_request(claimed.public_key(), &request, &blob(b"payload")).is_err());

        let payload = blob(b"payload");
        let request = sign_set_request(
            &claimed,
            claimed.public_key().to_openssh().expect("public key"),
            challenge(3),
            &payload,
        )
        .expect("sign request");
        assert!(verify_get_request(claimed.public_key(), &request).is_err());
    }

    #[test]
    fn challenge_request_proves_key_possession_and_binds_operation() {
        let client = keypair();
        let other = keypair();
        let mut request = sign_challenge_request(
            &client,
            client.public_key().to_openssh().expect("public key"),
            ClipboardOperation::Get,
        )
        .expect("sign challenge request");
        assert!(verify_challenge_request(client.public_key(), &request).is_ok());
        assert!(verify_challenge_request(other.public_key(), &request).is_err());

        request.operation = ClipboardOperation::Set;
        assert!(verify_challenge_request(client.public_key(), &request).is_err());
    }

    #[test]
    fn production_authenticator_rejects_challenge_replay_concurrently() {
        let client = keypair();
        let server = keypair();
        let authenticator = Arc::new(authenticator(&client, &server));
        let challenge_request = sign_challenge_request(
            &client,
            client.public_key().to_openssh().expect("public key"),
            ClipboardOperation::Get,
        )
        .expect("sign challenge request");
        let challenge = authenticator
            .issue_challenge(&challenge_request)
            .expect("issue challenge");
        assert_eq!(
            authenticator
                .issue_challenge(&challenge_request)
                .expect_err("pre-authentication replay should fail"),
            "challenge request nonce has already been used"
        );
        let request = sign_get_request(&client, challenge_request.client_ssh_pubkey, challenge)
            .expect("sign get request");

        let handles: Vec<_> = (0..2)
            .map(|_| {
                let authenticator = authenticator.clone();
                let request = request.clone();
                std::thread::spawn(move || authenticator.authenticate_get(&request))
            })
            .collect();
        let success_count = handles
            .into_iter()
            .map(|handle| handle.join().expect("authentication thread"))
            .filter(Result::is_ok)
            .count();
        assert_eq!(success_count, 1);
    }

    #[test]
    fn production_authenticator_rejects_unauthorized_and_invalid_preauthentication() {
        let client = keypair();
        let server = keypair();
        let other = keypair();
        let authenticator = authenticator(&client, &server);

        let unauthorized = sign_challenge_request(
            &other,
            other.public_key().to_openssh().expect("public key"),
            ClipboardOperation::Get,
        )
        .expect("sign unauthorized request");
        assert!(authenticator.issue_challenge(&unauthorized).is_err());

        let invalid = sign_challenge_request(
            &other,
            client.public_key().to_openssh().expect("public key"),
            ClipboardOperation::Get,
        )
        .expect("sign invalid request");
        assert!(authenticator.issue_challenge(&invalid).is_err());
    }

    #[test]
    fn rejects_tampered_set_payload() {
        let client = keypair();
        let original = blob(b"original");
        let request = sign_set_request(
            &client,
            client.public_key().to_openssh().expect("public key"),
            challenge(4),
            &original,
        )
        .expect("sign request");

        assert!(verify_set_request(client.public_key(), &request, &blob(b"tampered")).is_err());
    }

    #[test]
    fn consumes_challenges_once_and_rejects_expired_challenges() {
        let client = keypair();
        let store = ChallengeStore::new(Duration::from_secs(30));
        let issued = store
            .issue(client.public_key(), ClipboardOperation::Get, [1; 32])
            .expect("issue challenge");
        assert!(store
            .consume(&issued, client.public_key(), ClipboardOperation::Get)
            .is_ok());
        assert_eq!(
            store.consume(&issued, client.public_key(), ClipboardOperation::Get),
            Err("authentication challenge is unknown or already used".to_string())
        );

        let expiring_store = ChallengeStore::new(Duration::ZERO);
        let expired = expiring_store
            .issue(client.public_key(), ClipboardOperation::Get, [2; 32])
            .expect("issue expiring challenge");
        assert_eq!(
            expiring_store.consume(&expired, client.public_key(), ClipboardOperation::Get),
            Err("authentication challenge has expired".to_string())
        );
    }

    #[test]
    fn limits_outstanding_challenges_per_client_operation() {
        let client = keypair();
        let store = ChallengeStore::default();
        let challenges: Vec<_> = (0..=MAX_CHALLENGES_PER_CLIENT_OPERATION)
            .map(|index| {
                store
                    .issue(
                        client.public_key(),
                        ClipboardOperation::Set,
                        [index as u8; 32],
                    )
                    .expect("issue challenge")
            })
            .collect();

        assert!(store
            .consume(&challenges[0], client.public_key(), ClipboardOperation::Set,)
            .is_err());
        assert!(store
            .consume(
                challenges.last().unwrap(),
                client.public_key(),
                ClipboardOperation::Set,
            )
            .is_ok());
    }

    #[test]
    fn rejects_tampered_server_response() {
        let client = keypair();
        let server = keypair();
        let request = sign_get_request(
            &client,
            client.public_key().to_openssh().expect("public key"),
            challenge(5),
        )
        .expect("sign request");
        let mut response =
            sign_get_response(&server, &request, blob(b"clipboard")).expect("sign response");
        assert!(verify_get_response(server.public_key(), &request, &response).is_ok());

        response.blob.data[0] ^= 1;
        assert!(verify_get_response(server.public_key(), &request, &response).is_err());

        let other_server = keypair();
        let response = sign_get_response(&other_server, &request, blob(b"clipboard"))
            .expect("sign response with wrong key");
        assert!(verify_get_response(server.public_key(), &request, &response).is_err());
    }

    #[test]
    fn set_response_binds_client_challenge_and_ciphertext() {
        let client = keypair();
        let server = keypair();
        let clipboard = blob(b"ciphertext");
        let auth = sign_set_request(
            &client,
            client.public_key().to_openssh().expect("public key"),
            challenge(6),
            &clipboard,
        )
        .expect("sign set request");
        let request = SetRequest {
            auth,
            blob: clipboard,
        };
        let response = sign_set_response(&server, &request).expect("sign set response");
        assert!(verify_set_response(server.public_key(), &request, &response).is_ok());

        let mut tampered = request.clone();
        tampered.blob.data.push(0);
        assert!(verify_set_response(server.public_key(), &tampered, &response).is_err());
    }

    #[test]
    fn reads_private_key_file() {
        let key = keypair();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("id_ed25519");
        std::fs::write(&path, key.to_openssh(LineEnding::LF).expect("private key"))
            .expect("write private key");

        let parsed = read_private_key(&path).expect("read private key");
        assert_eq!(parsed.public_key().key_data(), key.public_key().key_data());
    }

    #[test]
    fn server_private_key_requires_ed25519() {
        let rsa = PrivateKey::from(
            ssh_key::private::RsaKeypair::random(&mut OsRng, 2048).expect("generate RSA key"),
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("id_rsa");
        std::fs::write(&path, rsa.to_openssh(LineEnding::LF).expect("private key"))
            .expect("write private key");

        let error = read_server_private_key(&path).expect_err("RSA server key should be rejected");
        assert!(error.contains("must use Ed25519"));

        let client = keypair();
        assert!(ServerAuthenticator::new(
            Arc::new(rsa),
            authorized_clients(&client),
            Arc::new(ChallengeStore::default()),
        )
        .is_err());
    }
}
