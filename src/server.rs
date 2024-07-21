use arboard::Clipboard;
use clap::Parser;
use futures::prelude::*;
use rpclip::RpClip;
use std::{net::SocketAddr, sync::Arc};
use tarpc::{
    context,
    server::{self, Channel},
    tokio_serde::formats::Bincode,
};
use tokio::sync::Mutex;

#[derive(Parser)]
struct Args {
    #[arg(short, long, value_name = "IP:PORT", required = true)]
    address: String,
}

#[derive(Clone)]
struct RpClipServer(Arc<Mutex<Clipboard>>);
impl RpClip for RpClipServer {
    async fn get_clip(self, _: context::Context) -> String {
        match self.0.lock().await.get_text() {
            Ok(text) => text,
            Err(_) => String::from("server failed to open system clipboard"),
        }
    }
    async fn set_clip(self, _: context::Context, text: String) {
        if let Err(_) = self
            .0
            .lock()
            .await
            .set_text(rpclip::line_end::to_platform_line_ending(&text))
        {
            eprintln!("server failed to open system clipboard");
        }
    }
}

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let args = Args::parse();
    let listen_addr: SocketAddr = args.address.parse().unwrap();

    let listener = tarpc::serde_transport::tcp::listen(&listen_addr, Bincode::default)
        .await
        .unwrap();
    let clipboard = Arc::new(Mutex::new(Clipboard::new().unwrap()));
    listener
        .filter_map(|r| future::ready(r.ok()))
        .map(server::BaseChannel::with_defaults)
        .map(|channel| {
            let rpserver = RpClipServer(clipboard.clone());
            channel.execute(rpserver.serve()).for_each(|x| async {
                tokio::spawn(x);
            })
        })
        .buffer_unordered(10)
        .for_each(|_| async {}) // discard the result of the `map`
        .await;
}
