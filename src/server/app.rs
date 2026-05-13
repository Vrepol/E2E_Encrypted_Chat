use anyhow::Result;
use clap::Parser;
use futures_util::FutureExt;
use std::{
    collections::HashMap,
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;

use crate::{
    config::{DEFAULT_SERVER_PASSWORD, DEFAULT_SERVER_PORT},
    crypto::pwd_hash,
};

use super::{connection::handle_client, invite::Invites, room::Rooms};

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value_t = DEFAULT_SERVER_PORT)]
    port: u16,
    #[arg(short = 'k', default_value_t = String::from(DEFAULT_SERVER_PASSWORD))]
    password: String,
}

pub async fn run_from_cli() -> Result<()> {
    let args = Args::parse();
    run(args.port, args.password).await
}

pub async fn run(port: u16, password: String) -> Result<()> {
    let server_pwd_hash = pwd_hash(&password);

    let bind_addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&bind_addr).await?;
    println!("🛰️  MISTV server listening on {}", bind_addr);

    let rooms: Rooms = Arc::new(Mutex::new(HashMap::new()));
    let invites: Invites = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (socket, addr) = listener.accept().await?;
        let rooms_clone = rooms.clone();
        let invites_clone = invites.clone();

        tokio::spawn(
            AssertUnwindSafe(async move {
                if let Err(e) =
                    handle_client(socket, rooms_clone, invites_clone, server_pwd_hash).await
                {
                    eprintln!("客户端 {} 出错：{:#}", addr, e);
                }
            })
            .catch_unwind()
            .map(move |res| {
                if let Err(panic) = res {
                    eprintln!("子任务 for {} panic 已捕获：{:?}", addr, panic);
                }
            }),
        );
    }
}
