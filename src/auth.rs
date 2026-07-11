use bincode::Options;
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use ssh_key::{Algorithm, AuthorizedKeys, HashAlg, PrivateKey, PublicKey, SshSig};
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{
    AgeEncryptedBlob, AuthRequest, Challenge, ChallengeRequest, ClipboardOperation, SetRequest,
    SignedClipboard, SignedSetResponse, PROTOCOL_VERSION,
};

pub const SIGNATURE_NAMESPACE: &str = "rpclip-auth";
pub const CHALLENGE_SIGNATURE_NAMESPACE: &str = "rpclip-challenge-cookie";
pub const CHALLENGE_TTL: Duration = Duration::from_secs(30);
const MAX_USED_CHALLENGES: usize = 1024;

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
    client_fingerprint: &'a str,
    nonce: &'a [u8; 32],
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
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

fn challenge_signing_bytes(challenge: &Challenge) -> Result<Vec<u8>, String> {
    let envelope = ChallengeSigningEnvelope {
        format: b"rpclip-challenge-cookie-v1",
        protocol_version: PROTOCOL_VERSION,
        operation: challenge.operation,
        client_fingerprint: &challenge.client_fingerprint,
        nonce: &challenge.nonce,
        issued_at_unix_seconds: challenge.issued_at_unix_seconds,
        expires_at_unix_seconds: challenge.expires_at_unix_seconds,
    };
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&envelope)
        .map_err(|e| format!("failed to encode challenge signature input: {e}"))
}

pub fn parse_public_key(line: &str) -> Result<PublicKey, String> {
    let public_key =
        PublicKey::from_openssh(line).map_err(|e| format!("invalid SSH public key: {e}"))?;
    ensure_ed25519(public_key.algorithm())?;
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
    ensure_ed25519(private_key.algorithm())?;
    Ok(private_key)
}

pub fn read_server_private_key(path: &Path) -> Result<PrivateKey, String> {
    read_server_key_snapshot(path).map(|snapshot| snapshot.private_key)
}

pub struct ServerKeySnapshot {
    pub private_key: PrivateKey,
    pub encoded: Arc<Vec<u8>>,
}

pub fn read_server_key_snapshot(path: &Path) -> Result<ServerKeySnapshot, String> {
    let encoded = std::fs::read(path)
        .map_err(|e| format!("failed to read SSH private key {}: {e}", path.display()))?;
    let private_key = PrivateKey::from_openssh(&encoded)
        .map_err(|e| format!("failed to parse SSH private key {}: {e}", path.display()))?;
    if private_key.is_encrypted() {
        return Err(format!(
            "SSH private key {} is encrypted; passphrase-protected keys are not supported",
            path.display()
        ));
    }
    if private_key.algorithm() != Algorithm::Ed25519 {
        return Err(format!(
            "server SSH private key {} must use Ed25519",
            path.display()
        ));
    }
    age::ssh::Identity::from_buffer(
        std::io::Cursor::new(&encoded),
        Some(path.display().to_string()),
    )
    .map_err(|e| format!("failed to parse server key as an age identity: {e:?}"))?;
    Ok(ServerKeySnapshot {
        private_key,
        encoded: Arc::new(encoded),
    })
}

fn ensure_ed25519(algorithm: Algorithm) -> Result<(), String> {
    if algorithm == Algorithm::Ed25519 {
        Ok(())
    } else {
        Err(format!(
            "SSH key algorithm {algorithm} is unsupported; rpclip requires Ed25519"
        ))
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

pub fn make_challenge_request(
    client_ssh_pubkey: String,
    operation: ClipboardOperation,
) -> ChallengeRequest {
    ChallengeRequest {
        ver: PROTOCOL_VERSION,
        operation,
        client_ssh_pubkey,
    }
}

pub fn verify_server_challenge(
    server_public_key: &PublicKey,
    challenge: &Challenge,
    client_public_key: &PublicKey,
    operation: ClipboardOperation,
) -> Result<(), String> {
    challenge.validate_version()?;
    if challenge.operation != operation {
        return Err("server challenge belongs to another operation".to_string());
    }
    let fingerprint = client_public_key.fingerprint(HashAlg::Sha256).to_string();
    if challenge.client_fingerprint != fingerprint {
        return Err("server challenge belongs to another client key".to_string());
    }
    let message = challenge_signing_bytes(challenge)?;
    verify(
        server_public_key,
        CHALLENGE_SIGNATURE_NAMESPACE,
        &message,
        &challenge.signature,
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
            ensure_ed25519(entry.public_key().algorithm())?;
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

    fn fingerprints(&self) -> impl Iterator<Item = String> + '_ {
        self.keys
            .iter()
            .map(|key| key.fingerprint(HashAlg::Sha256).to_string())
    }
}

#[derive(Clone, Copy)]
struct RateLimitConfig {
    global_capacity: u32,
    global_refill_per_second: f64,
    client_capacity: u32,
    client_refill_per_second: f64,
}

const CHALLENGE_RATE_LIMIT: RateLimitConfig = RateLimitConfig {
    global_capacity: 32,
    global_refill_per_second: 8.0,
    client_capacity: 4,
    client_refill_per_second: 1.0,
};

struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_per_second: f64,
    last_refill: std::time::Instant,
}

impl TokenBucket {
    fn new(capacity: u32, refill_per_second: f64, now: std::time::Instant) -> Self {
        Self {
            tokens: capacity as f64,
            capacity: capacity as f64,
            refill_per_second,
            last_refill: now,
        }
    }

    fn refill(&mut self, now: std::time::Instant) {
        let elapsed = now.saturating_duration_since(self.last_refill);
        self.tokens =
            (self.tokens + elapsed.as_secs_f64() * self.refill_per_second).min(self.capacity);
        self.last_refill = now;
    }

    fn has_token(&self) -> bool {
        self.tokens >= 1.0
    }

    fn consume(&mut self) {
        self.tokens -= 1.0;
    }
}

struct ChallengeRateState {
    global: TokenBucket,
    clients: HashMap<String, TokenBucket>,
}

struct ChallengeRateLimiter {
    state: Mutex<ChallengeRateState>,
}

impl ChallengeRateLimiter {
    fn new(
        fingerprints: impl IntoIterator<Item = String>,
        config: RateLimitConfig,
        now: std::time::Instant,
    ) -> Self {
        let clients = fingerprints
            .into_iter()
            .map(|fingerprint| {
                (
                    fingerprint,
                    TokenBucket::new(config.client_capacity, config.client_refill_per_second, now),
                )
            })
            .collect();
        Self {
            state: Mutex::new(ChallengeRateState {
                global: TokenBucket::new(
                    config.global_capacity,
                    config.global_refill_per_second,
                    now,
                ),
                clients,
            }),
        }
    }

    fn check(&self, fingerprint: &str) -> Result<(), String> {
        self.check_at(fingerprint, std::time::Instant::now())
    }

    fn check_at(&self, fingerprint: &str, now: std::time::Instant) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "challenge rate limiter lock is poisoned".to_string())?;
        let ChallengeRateState { global, clients } = &mut *state;
        global.refill(now);
        let client = clients
            .get_mut(fingerprint)
            .ok_or_else(|| "client SSH public key has no challenge rate bucket".to_string())?;
        client.refill(now);
        if !client.has_token() {
            return Err("challenge rate limit exceeded for client key".to_string());
        }
        if !global.has_token() {
            return Err("global challenge rate limit exceeded".to_string());
        }
        client.consume();
        global.consume();
        Ok(())
    }
}

pub struct ChallengeStore {
    used_nonces: Mutex<HashMap<[u8; 32], u64>>,
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self {
            used_nonces: Mutex::new(HashMap::new()),
        }
    }

    pub fn consume(&self, challenge: &Challenge, now_unix_seconds: u64) -> Result<(), String> {
        let mut used_nonces = self
            .used_nonces
            .lock()
            .map_err(|_| "used challenge cache lock is poisoned".to_string())?;
        used_nonces.retain(|_, expires_at| *expires_at >= now_unix_seconds);
        if used_nonces.contains_key(&challenge.nonce) {
            return Err("authentication challenge has already been used".to_string());
        }
        if used_nonces.len() >= MAX_USED_CHALLENGES {
            return Err("used challenge cache is full".to_string());
        }
        used_nonces.insert(challenge.nonce, challenge.expires_at_unix_seconds);
        Ok(())
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.used_nonces.lock().unwrap().len()
    }
}

impl Default for ChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct ServerAuthenticator {
    private_key: Arc<PrivateKey>,
    authorized_clients: Arc<AuthorizedClients>,
    challenges: Arc<ChallengeStore>,
    challenge_rate_limiter: Arc<ChallengeRateLimiter>,
    #[cfg(test)]
    challenge_signature_count: Arc<std::sync::atomic::AtomicUsize>,
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
        let challenge_rate_limiter = Arc::new(ChallengeRateLimiter::new(
            authorized_clients.fingerprints(),
            CHALLENGE_RATE_LIMIT,
            std::time::Instant::now(),
        ));
        Ok(Self {
            private_key,
            authorized_clients,
            challenges,
            challenge_rate_limiter,
            #[cfg(test)]
            challenge_signature_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    pub fn issue_challenge(&self, request: &ChallengeRequest) -> Result<Challenge, String> {
        request.validate_version()?;
        let public_key = parse_public_key(&request.client_ssh_pubkey)?;
        self.authorized_clients.authorize(&public_key)?;
        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
        self.challenge_rate_limiter.check(&fingerprint)?;
        let now = unix_time_seconds()?;
        let mut challenge = Challenge {
            ver: PROTOCOL_VERSION,
            operation: request.operation,
            client_fingerprint: fingerprint,
            nonce: [0; 32],
            issued_at_unix_seconds: now,
            expires_at_unix_seconds: now + CHALLENGE_TTL.as_secs(),
            signature: String::new(),
        };
        OsRng.fill_bytes(&mut challenge.nonce);
        let message = challenge_signing_bytes(&challenge)?;
        #[cfg(test)]
        self.challenge_signature_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        challenge.signature = sign(&self.private_key, CHALLENGE_SIGNATURE_NAMESPACE, &message)?;
        Ok(challenge)
    }

    #[cfg(test)]
    fn challenge_signature_count(&self) -> usize {
        self.challenge_signature_count
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn authenticate_get(&self, request: &AuthRequest) -> Result<PublicKey, String> {
        let public_key = self.authorize(&request.client_ssh_pubkey)?;
        self.verify_challenge(&request.challenge, &public_key, ClipboardOperation::Get)?;
        verify_get_request(&public_key, request)?;
        self.challenges
            .consume(&request.challenge, unix_time_seconds()?)?;
        Ok(public_key)
    }

    pub fn authenticate_set(&self, request: &SetRequest) -> Result<PublicKey, String> {
        let public_key = self.authorize(&request.auth.client_ssh_pubkey)?;
        self.verify_challenge(
            &request.auth.challenge,
            &public_key,
            ClipboardOperation::Set,
        )?;
        verify_set_request(&public_key, &request.auth, &request.blob)?;
        self.challenges
            .consume(&request.auth.challenge, unix_time_seconds()?)?;
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

    fn verify_challenge(
        &self,
        challenge: &Challenge,
        client_public_key: &PublicKey,
        operation: ClipboardOperation,
    ) -> Result<(), String> {
        verify_server_challenge(
            self.private_key.public_key(),
            challenge,
            client_public_key,
            operation,
        )?;
        let now = unix_time_seconds()?;
        if challenge.issued_at_unix_seconds > now {
            return Err("authentication challenge was issued in the future".to_string());
        }
        if challenge.expires_at_unix_seconds < now {
            return Err("authentication challenge has expired".to_string());
        }
        if challenge.expires_at_unix_seconds
            != challenge.issued_at_unix_seconds + CHALLENGE_TTL.as_secs()
        {
            return Err("authentication challenge has an invalid lifetime".to_string());
        }
        Ok(())
    }
}

fn unix_time_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before the Unix epoch".to_string())
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
            operation: ClipboardOperation::Get,
            client_fingerprint: "test-client".to_string(),
            nonce: [byte; 32],
            issued_at_unix_seconds: 1,
            expires_at_unix_seconds: 2,
            signature: "test-cookie-signature".to_string(),
        }
    }

    fn blob(data: &[u8]) -> AgeEncryptedBlob {
        AgeEncryptedBlob {
            ver: PROTOCOL_VERSION,
            data: data.to_vec(),
        }
    }

    fn authorized_clients(key: &PrivateKey) -> Arc<AuthorizedClients> {
        authorized_clients_for(&[key])
    }

    fn authorized_clients_for(keys: &[&PrivateKey]) -> Arc<AuthorizedClients> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("authorized_keys");
        let contents = keys
            .iter()
            .map(|key| format!("{} client\n", key.public_key().to_openssh().unwrap()))
            .collect::<String>();
        std::fs::write(&path, contents).expect("write authorized keys");
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
    fn challenge_rate_limiter_enforces_burst_and_refill() {
        let now = std::time::Instant::now();
        let limiter = ChallengeRateLimiter::new(
            ["client-a".to_string()],
            RateLimitConfig {
                global_capacity: 10,
                global_refill_per_second: 10.0,
                client_capacity: 2,
                client_refill_per_second: 1.0,
            },
            now,
        );

        assert!(limiter.check_at("client-a", now).is_ok());
        assert!(limiter.check_at("client-a", now).is_ok());
        assert_eq!(
            limiter.check_at("client-a", now),
            Err("challenge rate limit exceeded for client key".to_string())
        );
        assert!(limiter
            .check_at("client-a", now + Duration::from_secs(1))
            .is_ok());
    }

    #[test]
    fn client_rate_buckets_are_isolated_but_share_global_limit() {
        let now = std::time::Instant::now();
        let limiter = ChallengeRateLimiter::new(
            ["client-a".to_string(), "client-b".to_string()],
            RateLimitConfig {
                global_capacity: 3,
                global_refill_per_second: 0.0,
                client_capacity: 2,
                client_refill_per_second: 0.0,
            },
            now,
        );

        assert!(limiter.check_at("client-a", now).is_ok());
        assert!(limiter.check_at("client-a", now).is_ok());
        assert!(limiter.check_at("client-a", now).is_err());
        assert!(limiter.check_at("client-b", now).is_ok());
        assert_eq!(
            limiter.check_at("client-b", now),
            Err("global challenge rate limit exceeded".to_string())
        );
    }

    #[test]
    fn challenge_rate_check_is_atomic_under_concurrency() {
        let now = std::time::Instant::now();
        let limiter = Arc::new(ChallengeRateLimiter::new(
            ["client".to_string()],
            RateLimitConfig {
                global_capacity: 1,
                global_refill_per_second: 0.0,
                client_capacity: 1,
                client_refill_per_second: 0.0,
            },
            now,
        ));
        let successes = (0..8)
            .map(|_| {
                let limiter = limiter.clone();
                std::thread::spawn(move || limiter.check_at("client", now))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|thread| thread.join().unwrap().ok())
            .count();
        assert_eq!(successes, 1);
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
        assert!(error.contains("requires Ed25519"));
    }

    #[test]
    fn rejects_rsa_client_key_accepted_by_openssh_parser() {
        let line = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDeUHcr1y8DvAKSO3A3B1sznHOq62fn4rMHoT0IlBG+QN+ve4sjMm5HpI1t4nptWg3o8ncQxqKyYa0VJzfmqu/JBXJbQnqoqsEMCEBJhsKEKlKreqjcd1SLFfb+fNIr3+pgdqorwWG6dW7NOn3tkzoOPqRp9tZ8u3TDuhvst6Wv2w==";
        assert!(PublicKey::from_openssh(line).is_ok());

        let error = parse_public_key(line).expect_err("RSA client key should be rejected");
        assert!(error.contains("requires Ed25519"));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authorized_keys");
        std::fs::write(&path, format!("{line} rsa-client\n")).unwrap();
        let error = match AuthorizedClients::read_file(&path) {
            Ok(_) => panic!("RSA authorization key should be rejected"),
            Err(error) => error,
        };
        assert!(error.contains("requires Ed25519"));
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
    fn server_challenge_is_signed_and_binds_operation_and_client() {
        let client = keypair();
        let server = keypair();
        let other = keypair();
        let authenticator = authenticator(&client, &server);
        let request = make_challenge_request(
            client.public_key().to_openssh().expect("public key"),
            ClipboardOperation::Get,
        );
        let mut challenge = authenticator
            .issue_challenge(&request)
            .expect("issue challenge");
        assert_eq!(authenticator.challenges.len(), 0);
        assert!(verify_server_challenge(
            server.public_key(),
            &challenge,
            client.public_key(),
            ClipboardOperation::Get,
        )
        .is_ok());
        assert!(verify_server_challenge(
            server.public_key(),
            &challenge,
            other.public_key(),
            ClipboardOperation::Get,
        )
        .is_err());
        assert!(verify_server_challenge(
            server.public_key(),
            &challenge,
            client.public_key(),
            ClipboardOperation::Set,
        )
        .is_err());

        challenge.nonce[0] ^= 1;
        assert!(verify_server_challenge(
            server.public_key(),
            &challenge,
            client.public_key(),
            ClipboardOperation::Get,
        )
        .is_err());
    }

    #[test]
    fn rate_limited_challenge_request_skips_signature_work() {
        let client = keypair();
        let server = keypair();
        let authenticator = authenticator(&client, &server);
        let request = make_challenge_request(
            client.public_key().to_openssh().unwrap(),
            ClipboardOperation::Get,
        );

        for _ in 0..CHALLENGE_RATE_LIMIT.client_capacity {
            authenticator.issue_challenge(&request).unwrap();
        }
        assert_eq!(
            authenticator.issue_challenge(&request).unwrap_err(),
            "challenge rate limit exceeded for client key"
        );
        assert_eq!(
            authenticator.challenge_signature_count(),
            CHALLENGE_RATE_LIMIT.client_capacity as usize
        );
        assert_eq!(authenticator.challenges.len(), 0);
    }

    #[test]
    fn production_authenticator_rejects_challenge_replay_concurrently() {
        let client = keypair();
        let server = keypair();
        let authenticator = Arc::new(authenticator(&client, &server));
        let challenge_request = make_challenge_request(
            client.public_key().to_openssh().expect("public key"),
            ClipboardOperation::Get,
        );
        let challenge = authenticator
            .issue_challenge(&challenge_request)
            .expect("issue challenge");
        assert_eq!(authenticator.challenges.len(), 0);
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
        assert_eq!(authenticator.challenges.len(), 1);
    }

    #[test]
    fn production_authenticator_rejects_unauthorized_challenge_requests() {
        let client = keypair();
        let server = keypair();
        let other = keypair();
        let authenticator = authenticator(&client, &server);

        let unauthorized = make_challenge_request(
            other.public_key().to_openssh().expect("public key"),
            ClipboardOperation::Get,
        );
        assert!(authenticator.issue_challenge(&unauthorized).is_err());
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
    fn consumes_challenges_once() {
        let store = ChallengeStore::new();
        let issued = Challenge {
            expires_at_unix_seconds: 20,
            ..challenge(1)
        };
        assert!(store.consume(&issued, 10).is_ok());
        assert_eq!(
            store.consume(&issued, 10),
            Err("authentication challenge has already been used".to_string())
        );
    }

    #[test]
    fn production_authenticator_rejects_expired_challenge() {
        let client = keypair();
        let server = keypair();
        let authenticator = authenticator(&client, &server);
        let now = unix_time_seconds().unwrap();
        let mut expired = Challenge {
            ver: PROTOCOL_VERSION,
            operation: ClipboardOperation::Get,
            client_fingerprint: client.public_key().fingerprint(HashAlg::Sha256).to_string(),
            nonce: [9; 32],
            issued_at_unix_seconds: now - CHALLENGE_TTL.as_secs() - 1,
            expires_at_unix_seconds: now - 1,
            signature: String::new(),
        };
        expired.signature = sign(
            &server,
            CHALLENGE_SIGNATURE_NAMESPACE,
            &challenge_signing_bytes(&expired).unwrap(),
        )
        .unwrap();
        let request =
            sign_get_request(&client, client.public_key().to_openssh().unwrap(), expired).unwrap();

        assert_eq!(
            authenticator.authenticate_get(&request).unwrap_err(),
            "authentication challenge has expired"
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

        let error = read_private_key(&path).expect_err("RSA client key should be rejected");
        assert!(error.contains("requires Ed25519"));
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
