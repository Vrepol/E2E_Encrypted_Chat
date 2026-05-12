#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rust_chat::client::app::run().await
}
