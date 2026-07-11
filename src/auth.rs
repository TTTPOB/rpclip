use bincode::Options;
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use ssh_key::{Algorithm, AuthorizedKeys, HashAlg, PrivateKey, PublicKey, SshSig};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::{AgeEncryptedBlob, AuthRequest, Challenge, SignedClipboard, PROTOCOL_VERSION};

pub const SIGNATURE_NAMESPACE: &str = "rpclip-auth";
pub const CHALLENGE_TTL: Duration = Duration::from_secs(30);
const MAX_OUTSTANDING_CHALLENGES: usize = 1024;

#[derive(Clone, Copy, Debug, Serialize)]
enum SignedOperation {
    GetRequest = 1,
    SetRequest = 2,
    GetResponse = 3,
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

pub fn parse_public_key(line: &str) -> Result<PublicKey, String> {
    let public_key =
        PublicKey::from_openssh(line).map_err(|e| format!("invalid SSH public key: {e}"))?;
    ensure_age_compatible(public_key.algorithm())?;
    Ok(public_key)
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

fn ensure_age_compatible(algorithm: Algorithm) -> Result<(), String> {
    match algorithm {
        Algorithm::Ed25519 | Algorithm::Rsa { .. } => Ok(()),
        algorithm => Err(format!(
            "SSH key algorithm {algorithm} cannot be used for age encryption"
        )),
    }
}

fn sign(private_key: &PrivateKey, message: &[u8]) -> Result<String, String> {
    private_key
        .sign(SIGNATURE_NAMESPACE, HashAlg::Sha512, message)
        .map(|signature| signature.to_string())
        .map_err(|e| format!("failed to sign request: {e}"))
}

fn verify(public_key: &PublicKey, message: &[u8], signature: &str) -> Result<(), String> {
    let signature = signature
        .parse::<SshSig>()
        .map_err(|e| format!("invalid SSH signature: {e}"))?;
    public_key
        .verify(SIGNATURE_NAMESPACE, message, &signature)
        .map_err(|e| format!("SSH signature verification failed: {e}"))
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
        signature: sign(private_key, &message)?,
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
        signature: sign(private_key, &message)?,
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
    verify(public_key, &message, &auth.signature)
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
    verify(public_key, &message, &auth.signature)
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
        signature: sign(private_key, &message)?,
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
    verify(server_public_key, &message, &response.signature)
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
            ensure_age_compatible(entry.public_key().algorithm())?;
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
    expires_at: Instant,
}

pub struct ChallengeStore {
    entries: Mutex<HashMap<[u8; 32], ChallengeRecord>>,
    ttl: Duration,
}

impl ChallengeStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    pub fn issue(&self, client_public_key: &PublicKey) -> Result<Challenge, String> {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| "challenge store lock is poisoned".to_string())?;
        entries.retain(|_, record| record.expires_at > now);
        if entries.len() >= MAX_OUTSTANDING_CHALLENGES {
            return Err("too many outstanding authentication challenges".to_string());
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
                client_fingerprint: client_public_key.fingerprint(HashAlg::Sha256).to_string(),
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
        entries.remove(&challenge.nonce);
        Ok(())
    }
}

impl Default for ChallengeStore {
    fn default() -> Self {
        Self::new(CHALLENGE_TTL)
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
        assert!(error.contains("cannot be used for age encryption"));
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
        let issued = store.issue(client.public_key()).expect("issue challenge");
        assert!(store.consume(&issued, client.public_key()).is_ok());
        assert_eq!(
            store.consume(&issued, client.public_key()),
            Err("authentication challenge is unknown or already used".to_string())
        );

        let expiring_store = ChallengeStore::new(Duration::ZERO);
        let expired = expiring_store
            .issue(client.public_key())
            .expect("issue expiring challenge");
        assert_eq!(
            expiring_store.consume(&expired, client.public_key()),
            Err("authentication challenge has expired".to_string())
        );
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
    fn reads_private_key_file() {
        let key = keypair();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("id_ed25519");
        std::fs::write(&path, key.to_openssh(LineEnding::LF).expect("private key"))
            .expect("write private key");

        let parsed = read_private_key(&path).expect("read private key");
        assert_eq!(parsed.public_key().key_data(), key.public_key().key_data());
    }
}
