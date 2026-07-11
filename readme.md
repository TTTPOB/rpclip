# RpClip

RpClip is a Rust-based clipboard synchronization tool that lets you share clipboard content between a server and a client over a network. Traffic is end‑to‑end encrypted using age with SSH keys. This doc shows how to run the server/client and use SSH remote port forwarding.

## Install

On Windows, run this from PowerShell to install the latest server and client for the current user:

```pwsh
& ([scriptblock]::Create((Invoke-RestMethod https://raw.githubusercontent.com/tttpob/rpclip/refs/heads/master/install_windows.ps1)))
```

The installer places both executables in `%LOCALAPPDATA%\Programs\RpClip\bin` and adds that directory to the user PATH. Pass `-Version v0.3.0`, `-InstallDir <PATH>`, or `-NoPathUpdate` when needed.

You can also run `cargo install --git https://github.com/tttpob/rpclip.git` with a Rust toolchain, or download binaries from Releases.

### Linux Client
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/tttpob/rpclip/refs/heads/master/install_linux_client.sh)
```

## Running the Server
```pwsh
rpclip-server --address 127.0.0.1:6667 --address '[::1]:6667' --authorized-keys-path ~/.config/rpclip/authorized_keys
```
Usually the server runs on your local Windows machine. The server uses `~/.ssh/id_ed25519` by default to decrypt incoming data and sign operation results. The server key must be an unencrypted Ed25519 OpenSSH private key. RpClip reads and validates the key once at startup, so key rotation requires a server restart. RpClip does not support passphrase-protected server keys. Override the path with `--ssh-key-path <PATH>`.

The server requires an explicit OpenSSH authorization file. Keep a dedicated file when SSH login access and clipboard access should differ:

```pwsh
rpclip-server `
  --address 127.0.0.1:6667 `
  --authorized-keys-path ~/.config/rpclip/authorized_keys
```

The authorization file accepts multiple Ed25519 OpenSSH public keys and comments. RpClip rejects RSA, ECDSA, entries with OpenSSH options, and keys that age cannot parse. It cannot enforce restrictions such as `from=`, `command=`, or `expiry-time=`. The server exits at startup when the file is missing, empty, malformed, or contains an unsupported entry.

You can explicitly pass `~/.ssh/authorized_keys` when every SSH-authorized key should also receive clipboard access. RpClip never selects that file implicitly.

## Setting Up SSH Remote Port Forwarding
To communicate with the server from a remote client through SSH, set up remote port forwarding. On your SSH client machine, run:
```bash
ssh -R 6667:localhost:6667 user@ssh_server
```
Replace user@ssh_server with your SSH server's username and address. This command forwards the port 6667 from the SSH server to the local machine where the RpClip server is running.

Note, you can also use unix socket to communicate with the server, just replace the address with the socket file path. This adds some security to the communication.

You can also add the ssh host to your `~/.ssh/config` file so that you don't need to type the address every time:
```bash
Host ssh_server
    HostName ssh_server
    User user
    RemoteForward 6667 localhost:6667
```

or (with the unix socket)
```bash
Host ssh_server
    HostName ssh_server
    User user
    RemoteForward /tmp/rpclip.sock localhost:6667
```

## Running the Client
After setting up port forwarding, you can run the client on the SSH server to communicate with the local RpClip server. Navigate to the target/release directory and execute:
``` bash
rpclip-client get
```
or
```bash
cat something | rpclip-client set
```

The `get` command fetches the current clipboard content from the server (local windows computer), and the `set` command updates the server's clipboard with the content piped into the client.

The `set` client loads its configuration and keys, reads stdin to EOF, and encrypts the complete payload before it opens the RPC connection. Slow producers can take as long as they need before the server's channel lifetime starts.

## Configuration
The client supports configuration through a file. By default it loads `~/.config/rpclip/config.yaml` (or pass `--config <PATH>`). Both `get` and `set` use the client key to sign requests. Both commands also require the server public key so the client can verify clipboard responses and encrypt clipboard updates:
```yaml
server_addr: "tcp://127.0.0.1:6667"    # or unix:///tmp/rpclip.sock on Linux
# Optional: client key paths (defaults shown)
ssh_key_path: "~/.ssh/id_ed25519"
ssh_pubkey_path: "~/.ssh/id_ed25519.pub"
# Required: server's SSH public key (OpenSSH one-line format)
server_ssh_pubkey: "ssh-ed25519 AAAAC3... user@host"
```
The client private key must use an unencrypted Ed25519 OpenSSH format. RpClip reads the key file itself and does not use `ssh-agent` or prompt for a passphrase. RpClip rejects RSA and ECDSA client keys.

You can also pass `--server <ADDRESS>` to override `server_addr`. Use `tcp://HOST:PORT` or `unix://PATH` to select the transport explicitly. Existing numeric TCP addresses and path-like Unix socket addresses remain supported. If neither flag nor config is provided, the client uses `127.0.0.1:6667`.

If you used the Linux installer script, wrapper commands are available: `rpc` (send/set) and `rpp` (receive/get).

## Authentication

For each operation, the server checks the requested client key against the authorization file and returns a signed, self-contained challenge. The challenge binds the protocol version, operation, canonical client fingerprint, random nonce, and server issue and expiry times. The client verifies the challenge with `server_ssh_pubkey`, then signs the complete challenge and operation payload. The server verifies both signatures and consumes the nonce once. Challenge requests do not allocate pending server state, and a captured operation cannot authorize another operation or replay the same clipboard update.

For `get`, the server encrypts the clipboard to the client key and signs the response with its private key. For `set`, the server signs the successful result and binds it to the client's identity, challenge, and ciphertext. The client verifies either success response against `server_ssh_pubkey` before it prints data or exits successfully. Protocol version 5 changes the RPC schema, so version 5 clients require a version 5 server.

The server limits itself to 64 open RPC channels, eight concurrent requests per channel, and a 15-second channel lifetime. Challenge signing allows a burst of four requests per authorized key and refills one token per second. A global bucket allows a burst of 32 and refills eight tokens per second. Someone who knows an authorized public key can consume that key's challenge allowance; the global bucket bounds server signing work. RpClip targets loopback and SSH-forwarded use with short-lived clients. A peer that maintains an active connection flood can still deny service; restrict the listening address and SSH access at deployment time.
