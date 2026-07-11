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
rpclip-server --address '[::1]:6667'
```
Usually the server runs on your local Windows machine. The server uses `~/.ssh/id_ed25519` by default to decrypt incoming data; override with `--ssh-key-path <PATH>` if needed.

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
The client supports configuration through a file. By default it loads `~/.config/rpclip/config.yaml` (or pass `--config <PATH>`). The configuration should specify the server address and, for encryption, SSH key details:
```yaml
server_addr: "tcp://127.0.0.1:6667"    # or unix:///tmp/rpclip.sock on Linux
# Optional: client key paths used for `get` (defaults shown)
ssh_key_path: "~/.ssh/id_ed25519"
ssh_pubkey_path: "~/.ssh/id_ed25519.pub"
# Required for `set`: server's SSH public key (OpenSSH one-line format)
server_ssh_pubkey: "ssh-ed25519 AAAAC3... user@host"
```
You can also pass `--server <ADDRESS>` to override `server_addr`. Use `tcp://HOST:PORT` or `unix://PATH` to select the transport explicitly. Existing numeric TCP addresses and path-like Unix socket addresses remain supported. If neither flag nor config is provided, the client uses `127.0.0.1:6667`.

If you used the Linux installer script, wrapper commands are available: `rpc` (send/set) and `rpp` (receive/get).
