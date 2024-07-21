use clap::Parser;
use rpclip::RpClipClient;
use serde::Deserialize;
use std::net::SocketAddr;
use tarpc::{client, context, tokio_serde::formats::Bincode};

#[derive(Parser)]
struct Args {
    #[clap(short, long, value_name = "IP:PORT")]
    server: Option<String>,
    #[clap(short, long)]
    config: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct Config {
    server_addr: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let mut server: SocketAddr = "127.0.0.1:6667".parse().unwrap();
    let default_config_file = dirs::config_dir()
        .unwrap()
        .join("rpclip")
        .join("config.toml");
    // if default_config_file not exist or not readable and no server_addr and no config provided
    if !default_config_file.exists() && args.server.is_none() && args.config.is_none() {
        eprintln!(
            "No server address provided and no config file found at {:?}",
            default_config_file
        );
        eprintln!("using default server address: {}", server);
    } else if args.server.is_none() && args.config.is_none() {
        let config: Config =
            serde_yaml::from_str(&std::fs::read_to_string(default_config_file).unwrap()).unwrap();
        server = config.server_addr.parse().unwrap();
    } else if args.server.is_some() {
        eprintln!("Both server address and config file provided, using server address");
        server = args.server.unwrap().parse().unwrap();
    } else {
        eprintln!("using specified config file");
        let config: Config =
            serde_yaml::from_str(&std::fs::read_to_string(args.config.unwrap()).unwrap()).unwrap();
        server = config.server_addr.parse().unwrap();
    }

    // if no server_addr provided and config file provided

    let transport = tarpc::serde_transport::tcp::connect(server, Bincode::default);

    let client = RpClipClient::new(
        client::Config::default(),
        transport.await.expect("Unable to connect"),
    )
    .spawn();

    let res = client
        .get_clip(context::current())
        .await
        .expect("Unable to get clip");
    let res = rpclip::line_end::to_platform_line_ending(&res);
    println!("{}", res);
}
