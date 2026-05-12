#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rust_chat::server::app::run_from_cli().await
}
