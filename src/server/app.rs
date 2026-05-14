use anyhow::Result;
use clap::Parser;
use futures_util::FutureExt;
use std::{
    collections::HashMap,
    panic::AssertUnwindSafe,
    path::Path,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;

use crate::{
    config::{DEFAULT_SERVER_PASSWORD, DEFAULT_SERVER_PORT},
    crypto::pwd_hash,
};

use super::{connection::handle_client, invite::Invites, logging::ServerLogger, room::Rooms};

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value_t = DEFAULT_SERVER_PORT)]
    port: u16,
    #[arg(short = 'k', default_value_t = String::from(DEFAULT_SERVER_PASSWORD))]
    password: String,
    #[arg(long)]
    log_file: Option<std::path::PathBuf>,
}

pub async fn run_from_cli() -> Result<()> {
    let args = Args::parse();
    let logger = match args.log_file {
        Some(path) => ServerLogger::with_file(path)?,
        None => ServerLogger::stdout_only(),
    };
    run_with_logger(args.port, args.password, logger).await
}

pub async fn run(port: u16, password: String) -> Result<()> {
    run_with_logger(port, password, ServerLogger::stdout_only()).await
}

pub async fn run_with_listener(listener: TcpListener, password: String) -> Result<()> {
    run_with_bound_listener(listener, password, ServerLogger::stdout_only()).await
}

pub async fn run_with_log_file(
    port: u16,
    password: String,
    log_file: impl AsRef<Path>,
) -> Result<()> {
    run_with_logger(port, password, ServerLogger::with_file(log_file)?).await
}

pub async fn run_with_listener_and_log_file(
    listener: TcpListener,
    password: String,
    log_file: impl AsRef<Path>,
) -> Result<()> {
    run_with_bound_listener(listener, password, ServerLogger::with_file(log_file)?).await
}

pub(crate) async fn run_with_logger(
    port: u16,
    password: String,
    logger: ServerLogger,
) -> Result<()> {
    let bind_addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&bind_addr).await?;
    run_with_bound_listener(listener, password, logger).await
}

pub(crate) async fn run_with_bound_listener(
    listener: TcpListener,
    password: String,
    logger: ServerLogger,
) -> Result<()> {
    let server_pwd_hash = pwd_hash(&password);
    logger.info(
        "server",
        format!("listening addr={}", listener.local_addr()?),
    );

    let rooms: Rooms = Arc::new(Mutex::new(HashMap::new()));
    let invites: Invites = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (socket, addr) = listener.accept().await?;
        let rooms_clone = rooms.clone();
        let invites_clone = invites.clone();
        let logger_clone = logger.clone();
        let panic_logger = logger.clone();
        logger.info("conn", format!("accepted peer={addr}"));

        tokio::spawn(
            AssertUnwindSafe(async move {
                if let Err(e) = handle_client(
                    socket,
                    rooms_clone,
                    invites_clone,
                    server_pwd_hash,
                    logger_clone.clone(),
                    addr.to_string(),
                )
                .await
                {
                    logger_clone.error("conn", format!("peer={addr} error={e:#}"));
                }
            })
            .catch_unwind()
            .map(move |res| {
                if let Err(panic) = res {
                    panic_logger.error("panic", format!("peer={addr} payload={panic:?}"));
                }
            }),
        );
    }
}
