use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex as StdMutex},
};

use anyhow::{anyhow, Result};
use tokio::{
    net::tcp::OwnedWriteHalf,
    sync::{Mutex, Notify},
    time::{timeout, Duration},
};

use crate::{
    crypto::{TransportCrypto, TransportOpenResult},
    protocol::{build_transport_packet_line, parse_ack_line},
};

pub const PACKET_ACK_TIMEOUT_MS: u64 = 4500;
pub const PACKET_RETRY_LIMIT: usize = 2;

#[derive(Default)]
pub struct AckRegistry {
    state: Mutex<AckState>,
}

#[derive(Default)]
struct AckState {
    waiters: HashMap<String, Arc<Notify>>,
    acked: HashSet<String>,
}

impl AckRegistry {
    pub async fn subscribe(&self, packet_id: &str) -> Arc<Notify> {
        let mut state = self.state.lock().await;
        state
            .waiters
            .entry(packet_id.to_string())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    pub async fn is_acked(&self, packet_id: &str) -> bool {
        let state = self.state.lock().await;
        state.acked.contains(packet_id)
    }

    pub async fn mark_acked(&self, packet_id: &str) {
        let mut state = self.state.lock().await;
        state.acked.insert(packet_id.to_string());
        if let Some(waiter) = state.waiters.get(packet_id) {
            waiter.notify_waiters();
        }
    }

    pub async fn finish(&self, packet_id: &str) {
        let mut state = self.state.lock().await;
        state.waiters.remove(packet_id);
        state.acked.remove(packet_id);
    }
}

pub async fn send_transport_payload_with_ack(
    writer: &mut OwnedWriteHalf,
    packet_id: &str,
    payload: &str,
    transport: &Arc<StdMutex<TransportCrypto>>,
    ack_registry: Arc<AckRegistry>,
) -> Result<()> {
    let transport_line = build_transport_packet_line(packet_id, payload);
    let cipher_line = transport_seal_line(transport, &transport_line)
        .ok_or_else(|| anyhow!("Transport state unavailable"))?;
    let timeout_duration = Duration::from_millis(PACKET_ACK_TIMEOUT_MS);

    for _attempt in 0..=PACKET_RETRY_LIMIT {
        let notify = ack_registry.subscribe(packet_id).await;
        write_cipher_line(writer, &cipher_line).await?;

        if ack_registry.is_acked(packet_id).await {
            ack_registry.finish(packet_id).await;
            return Ok(());
        }

        let ack_result = timeout(
            timeout_duration,
            wait_for_ack(packet_id, notify, ack_registry.clone()),
        )
        .await;
        if ack_result.is_ok() {
            ack_registry.finish(packet_id).await;
            return Ok(());
        }
    }

    ack_registry.finish(packet_id).await;
    Err(anyhow!("ACK timeout for packet {packet_id}"))
}

pub async fn send_transport_payload_now(
    writer: &mut OwnedWriteHalf,
    packet_id: &str,
    payload: &str,
    transport: &Arc<StdMutex<TransportCrypto>>,
) -> Result<()> {
    let transport_line = build_transport_packet_line(packet_id, payload);
    let cipher_line = transport_seal_line(transport, &transport_line)
        .ok_or_else(|| anyhow!("Transport state unavailable"))?;
    write_cipher_line(writer, &cipher_line).await
}

pub async fn write_cipher_line(writer: &mut OwnedWriteHalf, cipher_line: &str) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    writer.write_all(cipher_line.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    Ok(())
}

pub fn transport_open_line(
    transport: &Arc<StdMutex<TransportCrypto>>,
    cipher_line: &str,
) -> Option<TransportOpenResult> {
    let mut guard = transport.lock().ok()?;
    guard.open(cipher_line)
}

pub fn transport_seal_line(
    transport: &Arc<StdMutex<TransportCrypto>>,
    plain: &str,
) -> Option<String> {
    let mut guard = transport.lock().ok()?;
    Some(guard.seal(plain))
}

pub fn should_drop_transport_control_message(plain: &str) -> bool {
    plain == "/ping_ack"
        || plain == "/ping"
        || plain == "OK"
        || plain.starts_with("OK ")
        || plain.starts_with("INVITE_OK ")
}

pub fn maybe_mark_ack(_ack_registry: &AckRegistry, plain: &str) -> Option<String> {
    parse_ack_line(plain).map(ToOwned::to_owned)
}

async fn wait_for_ack(packet_id: &str, notify: Arc<Notify>, ack_registry: Arc<AckRegistry>) {
    loop {
        if ack_registry.is_acked(packet_id).await {
            return;
        }
        notify.notified().await;
    }
}

#[cfg(test)]
mod tests {
    use super::{send_transport_payload_with_ack, AckRegistry, PACKET_RETRY_LIMIT};
    use crate::crypto::{TransportCrypto, TransportSide};
    use std::sync::{Arc, Mutex};
    use tokio::{
        io::AsyncBufReadExt,
        net::{TcpListener, TcpStream},
    };

    #[tokio::test]
    async fn ack_registry_lifecycle() {
        let registry = AckRegistry::default();
        let _ = registry.subscribe("packet-1").await;
        assert!(!registry.is_acked("packet-1").await);
        registry.mark_acked("packet-1").await;
        assert!(registry.is_acked("packet-1").await);
        registry.finish("packet-1").await;
        assert!(!registry.is_acked("packet-1").await);
    }

    #[tokio::test]
    async fn send_with_ack_retries_expected_times() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");
        let reader = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept should succeed");
            let mut lines = tokio::io::BufReader::new(socket).lines();
            let mut count = 0usize;
            while lines
                .next_line()
                .await
                .expect("read should succeed")
                .is_some()
            {
                count += 1;
                if count > PACKET_RETRY_LIMIT + 1 {
                    break;
                }
            }
            count
        });

        let stream = TcpStream::connect(addr)
            .await
            .expect("client stream should connect");
        let (_, mut writer) = stream.into_split();
        let transport = Arc::new(Mutex::new(TransportCrypto::new(
            [7u8; 32],
            TransportSide::Client,
        )));
        let registry = Arc::new(AckRegistry::default());

        let err = send_transport_payload_with_ack(
            &mut writer,
            "packet-1",
            "/RMSG payload",
            &transport,
            registry,
        )
        .await
        .expect_err("missing ack should timeout");
        assert!(err.to_string().contains("ACK timeout"));

        drop(writer);
        let count = reader.await.expect("reader should complete");
        assert_eq!(count, PACKET_RETRY_LIMIT + 1);
    }
}
