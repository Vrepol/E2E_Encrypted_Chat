#[tokio::main]
async fn main() -> anyhow::Result<()> {
    mistv::server::app::run_from_cli().await
}
