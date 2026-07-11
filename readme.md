# RpClip

RpClip is a Rust-based clipboard synchronization tool that lets you share clipboard content between a server and a client over a network. Traffic is end‑to‑end encrypted using age with SSH keys. This doc shows how to run the server/client and use SSH remote port forwarding.

## Install

You can:
1. `cargo install --git https://github.com/tttpob/rpclip.git` (requires Rust toolchain)
2. Download from Releases for your arch/platform

### Or you are setting up linux client
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/tttpob/rpclip/refs/heads/master/install_linux_client.sh)
```

## Running the Server
```pwsh
rpclip-server --address 127.0.0.1:6667 --address '[::1]:6667'
```
Usually the server runs on your local Windows machine. The server uses `~/.ssh/id_ed25519` by default to decrypt incoming data and sign operation results. The server key must be an unencrypted Ed25519 OpenSSH private key. RpClip does not support passphrase-protected server keys. Override the path with `--ssh-key-path <PATH>`.

The server uses the OpenSSH authorization file for the running account by default. Linux and regular Windows users use `~/.ssh/authorized_keys`. A Windows account running with an administrator token uses `%ProgramData%\ssh\administrators_authorized_keys`, matching the Windows OpenSSH administrator configuration. Use a dedicated file when the SSH login list and clipboard access list should differ:

```pwsh
rpclip-server `
  --address 127.0.0.1:6667 `
  --authorized-keys-path ~/.config/rpclip/authorized_keys
```

The authorization file accepts multiple OpenSSH public keys and comments. RpClip rejects entries with OpenSSH options because it cannot enforce restrictions such as `from=`, `command=`, or `expiry-time=`. The server exits at startup when the file is missing, empty, malformed, contains options, or contains a key algorithm that age cannot use. RpClip currently accepts Ed25519 and RSA authorization keys.

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
The client private key must use an unencrypted OpenSSH format. RpClip reads the key file itself and does not use `ssh-agent` or prompt for a passphrase. Client Ed25519 keys work for signing and age encryption. RpClip also accepts RSA client keys when age accepts their size.

You can also pass `--server <ADDRESS>` to override `server_addr`. Use `tcp://HOST:PORT` or `unix://PATH` to select the transport explicitly. Existing numeric TCP addresses and path-like Unix socket addresses remain supported. If neither flag nor config is provided, the client uses `127.0.0.1:6667`.

If you used the Linux installer script, wrapper commands are available: `rpc` (send/set) and `rpp` (receive/get).

## Authentication

For each operation, the client first signs a fresh client nonce, the protocol version, operation, and client public key. The server verifies this proof of private-key possession before it issues a random challenge. The challenge expires after 30 seconds. The client signs the challenge and operation payload, and the server consumes the challenge once. A captured request cannot authorize another operation or replay the same clipboard update.

For `get`, the server encrypts the clipboard to the client key and signs the response with its private key. For `set`, the server signs the successful result and binds it to the client's identity, challenge, and ciphertext. The client verifies either success response against `server_ssh_pubkey` before it prints data or exits successfully. Protocol version 4 changes the RPC schema, so version 4 clients require a version 4 server.
