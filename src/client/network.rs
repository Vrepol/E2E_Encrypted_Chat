use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{anyhow, Result};
use sha2::{Digest as ShaDigest, Sha256};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt, BufReader, Lines},
    net::tcp::OwnedReadHalf,
    sync::{
        mpsc::{UnboundedReceiver, UnboundedSender},
        Mutex, Notify,
    },
    time::{interval, timeout, Duration, MissedTickBehavior},
};
use tokio::net::tcp::OwnedWriteHalf;

use super::crypto::{seal, server_open, server_seal};
use super::utils::{
    build_attachment_chunk_line, build_attachment_meta_line, build_local_notice_line,
    build_local_transfer_begin_line, build_local_transfer_done_line,
    build_local_transfer_failed_line, build_local_transfer_progress_line,
    build_transport_packet_line, classify_outgoing_input, file_name_or_default,
    infer_attachment_kind, packet_id_for_attachment_chunk, packet_id_for_attachment_meta,
    packet_id_for_text, parse_ack_line, OutgoingPayload, ATTACHMENT_CHUNK_SIZE,
    PACKET_ACK_TIMEOUT_MS, PACKET_RETRY_LIMIT,
};

#[derive(Default)]
struct AckRegistry {
    state: Mutex<AckState>,
}

#[derive(Default)]
struct AckState {
    waiters: HashMap<String, Arc<Notify>>,
    acked: HashSet<String>,
}

impl AckRegistry {
    async fn subscribe(&self, packet_id: &str) -> Arc<Notify> {
        let mut state = self.state.lock().await;
        state
            .waiters
            .entry(packet_id.to_string())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    async fn is_acked(&self, packet_id: &str) -> bool {
        let state = self.state.lock().await;
        state.acked.contains(packet_id)
    }

    async fn mark_acked(&self, packet_id: &str) {
        let mut state = self.state.lock().await;
        state.acked.insert(packet_id.to_string());
        if let Some(waiter) = state.waiters.get(packet_id) {
            waiter.notify_waiters();
        }
    }

    async fn finish(&self, packet_id: &str) {
        let mut state = self.state.lock().await;
        state.waiters.remove(packet_id);
        state.acked.remove(packet_id);
    }
}

struct AttachmentJob {
    path: PathBuf,
    transfer_id: String,
    file_name: String,
    total_size: u64,
    total_chunks: usize,
    sha256_hex: String,
    next_chunk_index: usize,
    file: File,
    meta_sent: bool,
}

pub async fn chat_loop(
    lines: Lines<BufReader<OwnedReadHalf>>,
    mut writer: OwnedWriteHalf,
    net_tx: UnboundedSender<String>,
    mut out_rx: UnboundedReceiver<String>,
) -> Result<()> {
    let mut hb = interval(Duration::from_secs(30));
    let mut send_pump = interval(Duration::from_millis(5));
    send_pump.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let ack_registry = Arc::new(AckRegistry::default());
    let read_ack_registry = ack_registry.clone();
    let read_net_tx = net_tx.clone();
    let mut pending_uploads = VecDeque::<PathBuf>::new();
    let mut active_upload: Option<AttachmentJob> = None;

    let reader = tokio::spawn(async move {
        let mut lines = lines;
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if line == "/ping_ack" || line == "$$ping$$" {
                        continue;
                    }

                    let Some(plain) = server_open(&line) else {
                        continue;
                    };

                    if let Some(packet_id) = parse_ack_line(&plain) {
                        read_ack_registry.mark_acked(packet_id).await;
                        continue;
                    }

                    read_net_tx.send(plain).ok();
                }
                Ok(None) => break,
                Err(e) => {
                    read_net_tx
                        .send(build_local_notice_line(&format!("连接断开: {e}")))
                        .ok();
                    break;
                }
            }
        }
    });

    loop {
        tokio::select! {
            biased;

            msg = out_rx.recv() => {
                match msg {
                    Some(text) if text == "//~``~//" => {
                        writer.shutdown().await?;
                        break;
                    }
                    Some(text) => {
                        if let Err(err) = handle_outgoing_input(
                            &mut writer,
                            &text,
                            &net_tx,
                            ack_registry.clone(),
                            &mut pending_uploads,
                        ).await {
                            net_tx.send(build_local_notice_line(&format!("发送失败: {err}"))).ok();
                        }
                    }
                    None => {
                        writer.shutdown().await?;
                        break;
                    }
                }
            }

            _ = send_pump.tick(), if active_upload.is_some() || !pending_uploads.is_empty() => {
                pump_attachment_upload(
                    &mut writer,
                    &net_tx,
                    ack_registry.clone(),
                    &mut pending_uploads,
                    &mut active_upload,
                ).await;
            }

            _ = hb.tick() => {
                if writer.write_all(b"$$ping$$\n").await.is_err() {
                    break;
                }
            }
        }
    }

    reader.abort();
    Ok(())
}

async fn handle_outgoing_input(
    writer: &mut OwnedWriteHalf,
    text: &str,
    net_tx: &UnboundedSender<String>,
    ack_registry: Arc<AckRegistry>,
    pending_uploads: &mut VecDeque<PathBuf>,
) -> Result<()> {
    match classify_outgoing_input(text)? {
        OutgoingPayload::Text(plain) => {
            let packet_id = packet_id_for_text();
            send_room_payload_with_ack(writer, &packet_id, &plain, ack_registry).await
        }
        OutgoingPayload::AttachmentPath(path) => {
            pending_uploads.push_back(path);
            net_tx
                .send(build_local_notice_line("附件已加入发送队列"))
                .ok();
            Ok(())
        }
    }
}

async fn pump_attachment_upload(
    writer: &mut OwnedWriteHalf,
    net_tx: &UnboundedSender<String>,
    ack_registry: Arc<AckRegistry>,
    pending_uploads: &mut VecDeque<PathBuf>,
    active_upload: &mut Option<AttachmentJob>,
) {
    if active_upload.is_none() {
        let Some(path) = pending_uploads.pop_front() else {
            return;
        };
        match initialize_attachment_job(&path).await {
            Ok(job) => {
                net_tx
                    .send(build_local_transfer_begin_line(
                        &job.transfer_id,
                        &job.file_name,
                        job.total_chunks,
                        job.total_size,
                    ))
                    .ok();
                *active_upload = Some(job);
            }
            Err(err) => {
                net_tx
                    .send(build_local_notice_line(&format!(
                        "附件初始化失败 {}: {err}",
                        path.display()
                    )))
                    .ok();
                return;
            }
        }
    }

    let Some(job) = active_upload.as_mut() else {
        return;
    };

    if !job.meta_sent {
        let meta_line = build_attachment_meta_line(
            &job.transfer_id,
            infer_attachment_kind(&job.path),
            &job.file_name,
            job.total_size,
            job.total_chunks,
            &job.sha256_hex,
        );
        let packet_id = packet_id_for_attachment_meta(&job.transfer_id);
        match send_room_payload_with_ack(writer, &packet_id, &meta_line, ack_registry.clone()).await {
            Ok(_) => {
                job.meta_sent = true;
                if job.total_chunks == 0 {
                    net_tx.send(build_local_transfer_done_line(&job.transfer_id)).ok();
                    *active_upload = None;
                }
            }
            Err(err) => {
                net_tx
                    .send(build_local_transfer_failed_line(&job.transfer_id, &err.to_string()))
                    .ok();
                *active_upload = None;
            }
        }
        return;
    }

    if job.next_chunk_index >= job.total_chunks {
        net_tx.send(build_local_transfer_done_line(&job.transfer_id)).ok();
        *active_upload = None;
        return;
    }

    let mut buf = vec![0u8; ATTACHMENT_CHUNK_SIZE];
    let read = match job.file.read(&mut buf).await {
        Ok(read) => read,
        Err(err) => {
            net_tx
                .send(build_local_transfer_failed_line(&job.transfer_id, &err.to_string()))
                .ok();
            *active_upload = None;
            return;
        }
    };

    if read == 0 {
        net_tx.send(build_local_transfer_done_line(&job.transfer_id)).ok();
        *active_upload = None;
        return;
    }

    let chunk_line = build_attachment_chunk_line(&job.transfer_id, job.next_chunk_index, &buf[..read]);
    let packet_id = packet_id_for_attachment_chunk(&job.transfer_id, job.next_chunk_index);
    match send_room_payload_with_ack(writer, &packet_id, &chunk_line, ack_registry.clone()).await {
        Ok(_) => {
            job.next_chunk_index += 1;
            net_tx
                .send(build_local_transfer_progress_line(
                    &job.transfer_id,
                    job.next_chunk_index,
                    job.total_chunks,
                ))
                .ok();
            if job.next_chunk_index >= job.total_chunks {
                net_tx.send(build_local_transfer_done_line(&job.transfer_id)).ok();
                *active_upload = None;
            }
        }
        Err(err) => {
            net_tx
                .send(build_local_transfer_failed_line(&job.transfer_id, &err.to_string()))
                .ok();
            *active_upload = None;
        }
    }
}

async fn initialize_attachment_job(path: &Path) -> Result<AttachmentJob> {
    let metadata = tokio::fs::metadata(path).await?;
    if !metadata.is_file() {
        return Err(anyhow!("Path is not a file: {}", path.display()));
    }

    let total_size = metadata.len();
    let total_chunks = if total_size == 0 {
        0
    } else {
        usize::try_from(total_size)?.div_ceil(ATTACHMENT_CHUNK_SIZE)
    };
    let file_name = file_name_or_default(path);
    let sha256_hex = hash_file(path).await?;
    let file = File::open(path).await?;

    Ok(AttachmentJob {
        path: path.to_path_buf(),
        transfer_id: uuid::Uuid::new_v4().simple().to_string(),
        file_name,
        total_size,
        total_chunks,
        sha256_hex,
        next_chunk_index: 0,
        file,
        meta_sent: false,
    })
}

async fn send_room_payload_with_ack(
    writer: &mut OwnedWriteHalf,
    packet_id: &str,
    plain: &str,
    ack_registry: Arc<AckRegistry>,
) -> Result<()> {
    let room_cipher = seal(plain);
    let transport_line = build_transport_packet_line(packet_id, &room_cipher);
    let cipher_line = server_seal(transport_line);
    let timeout_duration = Duration::from_millis(PACKET_ACK_TIMEOUT_MS);

    for _attempt in 0..=PACKET_RETRY_LIMIT {
        let notify = ack_registry.subscribe(packet_id).await;
        writer.write_all(cipher_line.as_bytes()).await?;
        writer.write_all(b"\n").await?;

        if ack_registry.is_acked(packet_id).await {
            ack_registry.finish(packet_id).await;
            return Ok(());
        }

        let ack_result =
            timeout(timeout_duration, wait_for_ack(packet_id, notify, ack_registry.clone())).await;
        if ack_result.is_ok() {
            ack_registry.finish(packet_id).await;
            return Ok(());
        }
    }

    ack_registry.finish(packet_id).await;
    Err(anyhow!("ACK timeout for packet {packet_id}"))
}

async fn wait_for_ack(packet_id: &str, notify: Arc<Notify>, ack_registry: Arc<AckRegistry>) {
    loop {
        if ack_registry.is_acked(packet_id).await {
            return;
        }
        notify.notified().await;
    }
}

async fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).await?;
    let mut buf = vec![0u8; ATTACHMENT_CHUNK_SIZE];
    let mut hasher = Sha256::new();

    loop {
        let read = file.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }

    Ok(hex::encode(hasher.finalize()))
}
