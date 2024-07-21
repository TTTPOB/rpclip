use clap::Parser;
use rpclip::RpClipClient;
use std::net::SocketAddr;
use tarpc::{client, context, tokio_serde::formats::Bincode};

#[derive(Parser)]
struct Args {
    #[clap(short, long, value_name = "IP:PORT", required = true)]
    server_addr: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let server_addr: SocketAddr = args.server_addr.parse().unwrap();
    let transport = tarpc::serde_transport::tcp::connect(server_addr, Bincode::default);

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
