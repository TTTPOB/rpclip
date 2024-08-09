#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
use arboard::Clipboard;
use clap::Parser;
use futures::prelude::*;
use log::{error, info};
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
    address: Option<String>,
}

#[derive(Clone)]
struct RpClipServer(Arc<Mutex<Clipboard>>);
impl RpClip for RpClipServer {
    async fn get_clip(self, _: context::Context) -> String {
        match self.0.lock().await.get_text() {
            Ok(text) => {
                info!("server got clipboard text: {}", text);
                text
            }
            Err(_) => {
                error!("server failed to open system clipboard");
                String::from("server failed to open system clipboard")
            }
        }
    }
    async fn set_clip(self, _: context::Context, text: String) {
        if let Err(_) = self
            .0
            .lock()
            .await
            .set_text(rpclip::line_end::to_platform_line_ending(&text))
        {
            error!("server failed to set clipboard text");
        } else {
            info!("server set clipboard text: {}", text);
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    // Parse command line arguments
    let args = Args::parse();
    let listen_addr: SocketAddr = match args.address {
        Some(addr) => addr.parse().expect("Invalid address"),
        None => {
            info!("No address provided, using default address");
            "[::1]:6667".parse().expect("Invalid address")
        }
    };

    let listener = tarpc::serde_transport::tcp::listen(&listen_addr, Bincode::default)
        .await
        .unwrap();
    info!("Listening on: {}", listen_addr);

    let clipboard = Arc::new(Mutex::new(Clipboard::new().unwrap()));
    info!("Clipboard server started");
    listener
        .filter_map(|r| future::ready(r.ok()))
        .map(server::BaseChannel::with_defaults)
        .map(|channel| {
            let rpserver = RpClipServer(clipboard.clone());
            channel.execute(rpserver.serve()).for_each(|x| async {
                tokio::spawn(x);
                info!("New client connected");
            })
        })
        .buffer_unordered(10)
        .for_each(|_| async {}) // discard the result of the `map`
        .await;
}
