#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
use clap::{Parser, Subcommand};
use log::{error, info, warn};
use rpclip::RpClipClient;
use serde::Deserialize;
use std::{io::BufRead, net::SocketAddr};
use tarpc::{client, context, tokio_serde::formats::Bincode};

#[derive(Parser)]
struct Args {
    #[clap(short, long, value_name = "IP:PORT")]
    server: Option<String>,
    #[clap(short, long)]
    config: Option<String>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Get,
    Set,
}

#[derive(Clone, Debug, Deserialize)]
struct Config {
    server_addr: String,
}

#[derive(Debug)]
enum ListenAddr {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

impl From<String> for ListenAddr {
    fn from(addr: String) -> Self {
        match addr.parse() {
            Ok(addr) => ListenAddr::Tcp(addr),
            Err(_) => {
                #[cfg(unix)]
                {
                    ListenAddr::Unix(addr.into())
                }
                #[cfg(not(unix))]
                {
                    error!("Unix domain sockets are not supported on this platform");
                    std::process::exit(1);
                }
            }
        }
    }
}

async fn from_listen_addr(addr: ListenAddr) -> RpClipClient {
    match addr {
        ListenAddr::Tcp(addr) => RpClipClient::new(
            client::Config::default(),
            tarpc::serde_transport::tcp::connect(addr, Bincode::default)
                .await
                .unwrap_or_else(|e| {
                    error!("Unable to connect to server: {}", e);
                    std::process::exit(1);
                }),
        )
        .spawn(),
        #[cfg(unix)]
        ListenAddr::Unix(path) => RpClipClient::new(
            client::Config::default(),
            tarpc::serde_transport::unix::connect(path, Bincode::default)
                .await
                .unwrap_or_else(|e| {
                    error!("Unable to connect to server: {}", e);
                    std::process::exit(1);
                }),
        )
        .spawn(),
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let args = Args::parse();
    let server = match (args.server, args.config) {
        (Some(server), _) => {
            info!("Using server address from command line");
            server
        }
        (_, Some(config)) => {
            info!("Using server address from config file");
            let config: Config =
                serde_yaml::from_str(&std::fs::read_to_string(config).unwrap()).unwrap();
            config.server_addr
        }
        _ => {
            info!("Both server address and config file not provided, using default config file");
            let default_config_file = dirs::config_dir()
                .unwrap()
                .join("rpclip")
                .join("config.yaml");
            if default_config_file.exists() {
                let config: Config =
                    serde_yaml::from_str(&std::fs::read_to_string(default_config_file).unwrap())
                        .unwrap();
                config.server_addr
            } else {
                warn!("No server address provided, using default server address");
                "127.0.0.1:6667".to_string()
            }
        }
    };
    let server: ListenAddr = server.into();
    info!("Connecting to server at {:?}", server);
    let client = from_listen_addr(server).await;

    match &args.command {
        Commands::Get => {
            let text = client.get_clip(context::current()).await.unwrap();
            let text = rpclip::line_end::to_platform_line_ending(&text);
            print!("{}", text);
        }
        Commands::Set => {
            // read from stdin
            let content: Vec<String> = std::io::stdin()
                .lock()
                .lines()
                .map(|line| line.unwrap())
                .collect();
            client
                .set_clip(context::current(), content.join("\n"))
                .await
                .unwrap();
        }
    }
}
