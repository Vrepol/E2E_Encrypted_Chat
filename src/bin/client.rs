#[tokio::main]
async fn main() -> anyhow::Result<()> {
    mistv::client::app::run().await
}
