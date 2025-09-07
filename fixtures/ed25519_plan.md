note: when you need specific api using, consult context7 mcp using library id /str4d/rage
# RpClip - Always-On Encryption with age (SSH Ed25519 Keys)

This update revises the proposal to require always-on encryption using the existing SSH Ed25519 keys present on both client and server machines. No separate RpClip key material is introduced. If not specified, keys are loaded from the default OpenSSH paths: `~/.ssh/id_ed25519` (private) and `~/.ssh/id_ed25519.pub` (public). The server must error and exit if its SSH keys are not available.

## Summary
- Use SSH Ed25519 keypairs for identity on both client and server via the `age` crate (enable the `ssh` feature to use OpenSSH keys directly).
- Encryption is always enabled. Plaintext RPCs are removed (or hard-rejected). Breaking change version bump is expected.
- Client must know and pin the server's SSH Ed25519 public key (OpenSSH format) to prevent MITM; no plaintext key discovery RPC.
- Encrypted Get: client sends its SSH Ed25519 pubkey line; server encrypts to that key using age; client decrypts with its SSH private key.
- Encrypted Set: client encrypts to server SSH Ed25519 pubkey using age; server decrypts with its SSH private key and sets the clipboard.

Why age? It provides a simple, modern, audited envelope format using X25519-wrapped file keys and AEAD-authenticated payloads, with first-class support for OpenSSH keys (when the `ssh` feature is enabled). We avoid bespoke crypto and key conversions entirely.


## Configuration
Keep configuration minimal; reuse SSH keys and standard formats; when parsing path, consider ~ cross-platform expansion.

### Client config (default: `~/.config/rpclip/config.yaml`)
```yaml
server_addr: "127.0.0.1:6667"  # or a Unix socket path on Unix

# Optional: override default SSH key paths
ssh_key_path: "~/.ssh/id_ed25519"
ssh_pubkey_path: "~/.ssh/id_ed25519.pub"

# Required: server SSH Ed25519 public key, in OpenSSH format
# e.g., "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... comment"
server_ssh_pubkey: "ssh-ed25519 AAAA..."
```

Notes:
- The client must have its own SSH Ed25519 keypair available locally. If the private key is passphrase-protected, the client will prompt for a passphrase (or accept it via env var/flag).
- The server's public key must be pinned in the client config (no plaintext discovery RPC).

### Server config (default: `~/.config/rpclip/server.yaml`)
```yaml
listen_addr: "[::1]:6667"      # or a Unix socket path on Unix

# Optional: override default SSH key paths
ssh_key_path: "~/.ssh/id_ed25519"
ssh_pubkey_path: "~/.ssh/id_ed25519.pub"

authorization:
  allow_any_client: true        # if false, restrict to the allowlist
  # Accept OpenSSH public key lines for convenience (copy from client's id_ed25519.pub)
  allowed_client_ssh_pubkeys:
    - "ssh-ed25519 AAAA... client1@host"
    - "ssh-ed25519 AAAA... client2@host"
```

Requirements and defaults:
- Server must have both `ssh_key_path` and `ssh_pubkey_path` present; otherwise it errors and exits.
- By default, both sides use `~/.ssh/id_ed25519` and `~/.ssh/id_ed25519.pub`.


## Protocol Changes
We will enforce encryption-only RPCs. This is a breaking change and warrants a version bump (e.g., to 0.2.0).

Replace the existing plaintext interface with age-encrypted variants only (payload is age file bytes, unarmored/binary):
```rust
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AgeEncryptedBlob {
    pub ver: u8,      // protocol version, e.g., 1
    pub data: Vec<u8> // raw age file bytes (binary)
}

#[tarpc::service]
pub trait RpClip {
    // Client provides its SSH public key line; server returns age-encrypted ciphertext
    async fn get_clip(client_ssh_pubkey_line: String) -> AgeEncryptedBlob;

    // Client sends ciphertext encrypted for the server
    async fn set_clip(blob: AgeEncryptedBlob);
}
```

Notes:
- The previous plaintext methods are removed. If temporary compatibility is desired, the server can keep stubs that return an error like "encryption required" but this proposal assumes removal.
- No RPC for server pubkey discovery; clients must pin the server key via config.


## Crypto Design
age envelope encryption with SSH recipients:
- Envelope: age format, using an ephemeral file key wrapped to one or more recipients; payload is AEAD-authenticated.
- Recipients: OpenSSH public keys (e.g., `ssh-ed25519 AAAA...`) parsed via `age::ssh` (enable `ssh` feature).
- Identities: OpenSSH private keys loaded via `age::ssh`, including passphrase-protected keys (prompt via callback or config).
- Wire format: unarmored (binary) age file bytes in the RPC struct to avoid base64 overhead. No armored wire format is planned; use normal logging/Debug on wrapper types for troubleshooting.

Pseudocode (illustrative API usage):
```rust
// Encrypt to a recipient (server or client) using OpenSSH public key line
use age::{Encryptor, Recipient};
use age::ssh;

let recipient = ssh::Recipient::from_str("ssh-ed25519 AAAA... comment")?;
let encryptor = Encryptor::with_recipients(vec![recipient])?;
let mut out = Vec::new();
let mut writer = encryptor.wrap_output(&mut out)?; // binary (no armor)
writer.write_all(plaintext_bytes)?;
writer.finish()?;

// Decrypt using an OpenSSH private key
use age::{Decryptor, Identity};
let identity = ssh::Identity::from_path("~/.ssh/id_ed25519")?; // prompt if needed
let decryptor = Decryptor::new(out.as_slice())?;
let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn Identity))?;
let mut plaintext = Vec::new();
reader.read_to_end(&mut plaintext)?;
```


## Flows
Assume both sides have SSH Ed25519 keypairs. The client pins the server SSH Ed25519 public key via config.

1) Client Get (encrypted)
- Client:
  - Load its SSH Ed25519 private key (prompt for passphrase if needed).
  - Call `get_clip(client_ssh_pubkey_line)` with its OpenSSH public key line.
- Server:
  - Authorize: if allowlist enabled, check `client_ssh_pubkey_line` against configured keys.
  - Read system clipboard, normalize line endings as today.
  - Parse recipient from `client_ssh_pubkey_line` via `age::ssh::Recipient`.
  - Encrypt clipboard bytes using `age::Encryptor::with_recipients([...])` to a binary age payload.
  - Return `AgeEncryptedBlob { ver: 1, data }`.
- Client:
  - Decrypt using `age::Decryptor` with its SSH identity and print.

2) Client Set (encrypted)
- Client:
  - Read stdin, normalize line endings as today.
  - Parse server recipient from pinned `server_ssh_pubkey` via `age::ssh::Recipient`.
  - Encrypt to server using `age::Encryptor` and send `AgeEncryptedBlob { ver: 1, data }`.
- Server:
  - Load SSH identity from `ssh_key_path` (prompt if passphrase-protected).
  - Decrypt with `age::Decryptor` and set clipboard.


## Code Changes (High-Level)
Focused edits to existing files:

- Cargo.toml
  - Add dependency:
    - `age = { version = "0.11", features = ["ssh"] }`

- src/lib.rs
  - Replace plaintext RPCs with the encrypted-only interface shown above.
  - Add `AgeEncryptedBlob` type.

- src/server.rs
  - Add `--config` for server config path (optional).
  - Load SSH keys from `ssh_key_path` and `ssh_pubkey_path` (default to `~/.ssh/id_ed25519` and `.pub`). If missing, log error and exit.
  - Parse allowlist entries as OpenSSH public key lines.
  - Implement encrypted RPCs only; reject or remove plaintext methods.
  - Use `age::ssh::Identity` for decryption and `age::ssh::Recipient` for encryption.

- src/client.rs
  - Extend `Config` with `ssh_key_path`, `ssh_pubkey_path`, and `server_ssh_pubkey`.
  - Load SSH private/public key (prompt for passphrase if needed). Zeroize sensitive buffers.
  - For `get`: call encrypted method, decrypt with `age::Decryptor`, print.
  - For `set`: encrypt with `age::Encryptor` to pinned server key and send blob.

- Optional: thin helper wrappers around `age` usage (parsing OpenSSH lines, encrypt/decrypt stream handling).


## Backward Compatibility and Migration
- Breaking change: encryption is always on; plaintext methods are removed. Bump crate to 0.2.0.
- Migration steps:
  1) Ensure the server has `~/.ssh/id_ed25519` and `~/.ssh/id_ed25519.pub` (or set overrides). If absent, generate via `ssh-keygen -t ed25519`.
  2) On the client, ensure an SSH Ed25519 key exists (or create one).
  3) Add the server's SSH public key (OpenSSH line) to the client config `server_ssh_pubkey`.
  4) Optionally configure server `authorization.allowed_client_ssh_pubkeys` to restrict access.


## Testing Strategy
- Unit tests:
  - OpenSSH key parsing via `age::ssh` (public and private), including passphrase-protected keys.
  - Encrypt/decrypt round-trips using age (binary output).
- Integration tests (Tokio):
  - Start server with temp SSH keys; run client get/set encrypted; verify content.
  - Authorization enabled: unauthorized client key rejected.
- End-to-end manual test:
  - Generate separate SSH Ed25519 keypairs for server and client; configure server to allow the client's public key; pin server's public key on the client. Run server and client and verify get/set across different keys.


## Security Considerations
- Server must error if SSH keys are missing.
- Passphrase handling: prompt securely; optionally read from `RPCLIP_SSH_PASSPHRASE`; zeroize buffers.
- Authorization: allowlist prevents arbitrary clients from accessing clipboard.
- Transport remains unauthenticated; content is confidential and integrity-protected. UDS still preferred when possible.
- Avoid bespoke crypto; rely on `age` for ephemeral keys and AEAD; prefer unarmored wire format.


## Open Questions / Alternatives
- Server key pinning UX: accept full OpenSSH line, base64 key only, or fingerprint. Proposal uses full line for easy copy/paste.
- known_hosts integration: automatically match `server_addr` to a key in `~/.ssh/known_hosts` as an optional convenience (future work).
- ssh-agent support: use agent to sign/derive without reading private key directly (future work).


## Estimated Work Breakdown
1) SSH key parsing (client/server) + prompts: 3-4 hours
2) Crypto helper module + tests: 3-5 hours
3) Service API changes (encrypted-only) and plumbing: 3-4 hours
4) Client flow updates (get/set): 2-3 hours
5) Server flow updates (get/set): 2-3 hours
6) Integration tests + docs: 3-4 hours

No implementation in this change; this file is a proposal and implementation plan only.
