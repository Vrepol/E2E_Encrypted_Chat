use std::sync::{Arc, Mutex as StdMutex};

use anyhow::Result;
use tokio::net::tcp::OwnedWriteHalf;

use crate::crypto::TransportCrypto;

use super::packet::{transport_seal_line, write_cipher_line};

pub async fn send_ping(
    writer: &mut OwnedWriteHalf,
    transport: &Arc<StdMutex<TransportCrypto>>,
) -> Result<()> {
    let ping_cipher = transport_seal_line(transport, "/ping")
        .ok_or_else(|| anyhow::anyhow!("Transport state unavailable"))?;
    write_cipher_line(writer, &ping_cipher).await
}

#[cfg(test)]
mod tests {
    use super::send_ping;
    use crate::crypto::{TransportCrypto, TransportSide};
    use std::sync::{Arc, Mutex};
    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
    };

    #[tokio::test]
    async fn heartbeat_write_failure_returns_error() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept should succeed");
            drop(socket);
        });

        let stream = TcpStream::connect(addr)
            .await
            .expect("client stream should connect");
        let (_, mut writer) = stream.into_split();
        server.await.expect("server task should finish");
        writer.shutdown().await.expect("shutdown should succeed");
        let transport = Arc::new(Mutex::new(TransportCrypto::new(
            [9u8; 32],
            TransportSide::Client,
        )));

        let err = send_ping(&mut writer, &transport)
            .await
            .expect_err("closed peer should produce write error");
        assert!(!err.to_string().is_empty());
    }
}
