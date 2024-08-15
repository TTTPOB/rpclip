# RpClip

RpClip is a Rust-based clipboard synchronization tool that allows you to share clipboard content between a server and a client over a network. This document provides instructions on how to use the RpClip server and client, including an example of running the server on a local Windows computer and the client on an SSH server, communicating through SSH remote port forwarding.

## Install

You can:
1. `cargo install --git https://github.com/tttpob/rpclip.git`, this requires you have rust toolchain installed.
2. download from release, choose the right arch and platform to download.

## Running the Server
To run the server on a local Windows computer, open a command prompt or PowerShell window, navigate to the project's target/release directory, and execute:

This command starts the server listening on all interfaces at port 6667. You can replace 0.0.0.0:6667 with your desired IP address and port.

## Setting Up SSH Remote Port Forwarding
To communicate with the server from a remote client through SSH, set up remote port forwarding. On your SSH client machine, run:
```bash
ssh -R 6667:localhost:6667 user@ssh_server
```
Replace user@ssh_server with your SSH server's username and address. This command forwards the port 6667 from the SSH server to the local machine where the RpClip server is running.

## Running the Client
After setting up port forwarding, you can run the client on the SSH server to communicate with the local RpClip server. Navigate to the target/release directory and execute:
``` bash
rpclip-client--server 127.0.0.1:6667 get
```
or
```bash
cat something | rpclip-client--server 127.0.0.1:6667 get
```

The `get` command fetches the current clipboard content from the server (local windows computer), and the `set` command updates the server's clipboard with the content piped into the client.

## Configuration
The client supports configuration through a file. By default, it looks for `config.yaml` in the system's configuration directory. The configuration file should specify the server address:
```yaml
server_addr: "127.0.0.1:6667"
```
If the configuration file exists and no server address is provided through the command line, the client uses the address from the configuration file.
