use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{anyhow, Result};
use sha2::{Digest as ShaDigest, Sha256};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt, BufReader, Lines},
    net::tcp::OwnedReadHalf,
    sync::{
        mpsc::{UnboundedReceiver, UnboundedSender},
        Mutex, Notify,
    },
    task::JoinHandle,
    time::{interval, timeout, Duration, Instant, MissedTickBehavior},
};

use super::attachment_store::AttachmentStore;
use super::crypto::{RoomCryptoState, TransportOpenResult};
use super::handshake::SharedTransportCrypto;
use super::utils::{
    build_attachment_chunk_line, build_attachment_meta_line, build_local_echo_attachment_line,
    build_local_echo_text_line, build_local_notice_line, build_local_transfer_begin_line,
    build_local_transfer_done_line, build_local_transfer_failed_line,
    build_local_transfer_progress_line, build_server_invite_request_line,
    build_transport_packet_line, classify_outgoing_input, create_invitation, create_invite_blob,
    file_name_or_default, infer_attachment_kind, packet_id_for_attachment_chunk,
    packet_id_for_attachment_meta, packet_id_for_text, parse_ack_line, parse_invite_error_line,
    parse_invite_token_line, parse_local_invite_request_line, parse_local_ui_event,
    OutgoingPayload, ATTACHMENT_CHUNK_SIZE, ATTACHMENT_WINDOW_SIZE, PACKET_ACK_TIMEOUT_MS,
    PACKET_RETRY_LIMIT,
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

#[derive(Default)]
struct InviteRegistry {
    state: Mutex<InviteState>,
}

#[derive(Default)]
struct InviteState {
    pending: HashMap<String, PendingInvite>,
}

struct PendingInvite {
    notify: Arc<Notify>,
    server_addr: String,
    blob_key_b64: String,
    response: Option<Result<(String, i64), String>>,
}

impl InviteRegistry {
    async fn register(
        &self,
        request_id: String,
        server_addr: String,
        blob_key_b64: String,
    ) -> Arc<Notify> {
        let notify = Arc::new(Notify::new());
        let mut state = self.state.lock().await;
        state.pending.insert(
            request_id,
            PendingInvite {
                notify: notify.clone(),
                server_addr,
                blob_key_b64,
                response: None,
            },
        );
        notify
    }

    async fn resolve_success(&self, request_id: &str, token: String, expires_at: i64) {
        let mut state = self.state.lock().await;
        if let Some(pending) = state.pending.get_mut(request_id) {
            pending.response = Some(Ok((token, expires_at)));
            pending.notify.notify_waiters();
        }
    }

    async fn resolve_error(&self, request_id: &str, reason: String) {
        let mut state = self.state.lock().await;
        if let Some(pending) = state.pending.get_mut(request_id) {
            pending.response = Some(Err(reason));
            pending.notify.notify_waiters();
        }
    }

    async fn take_result(
        &self,
        request_id: &str,
    ) -> Option<(String, String, Result<(String, i64), String>)> {
        let mut state = self.state.lock().await;
        let pending = state.pending.remove(request_id)?;
        Some((pending.server_addr, pending.blob_key_b64, pending.response?))
    }

    async fn has_response(&self, request_id: &str) -> bool {
        let state = self.state.lock().await;
        state
            .pending
            .get(request_id)
            .and_then(|p| p.response.as_ref())
            .is_some()
    }

    async fn drop_request(&self, request_id: &str) {
        let mut state = self.state.lock().await;
        state.pending.remove(request_id);
    }
}

struct AttachmentJob {
    path: PathBuf,
    transfer_id: String,
    file_name: String,
    total_size: u64,
    total_chunks: usize,
    next_chunk_index: usize,
    acked_chunks: usize,
    file: File,
    meta_sent: bool,
    meta_packet_id: String,
    meta_line: String,
    meta_attempts: usize,
    meta_last_sent_at: Option<Instant>,
    in_flight: Vec<InFlightChunk>,
}

struct InFlightChunk {
    packet_id: String,
    chunk_line: String,
    chunk_index: usize,
    attempts: usize,
    last_sent_at: Instant,
}

struct PreparingUpload {
    path: PathBuf,
    task: JoinHandle<Result<AttachmentJob>>,
}

pub async fn chat_loop(
    lines: Lines<BufReader<OwnedReadHalf>>,
    mut writer: OwnedWriteHalf,
    net_tx: UnboundedSender<String>,
    mut out_rx: UnboundedReceiver<String>,
    room_crypto: RoomCryptoState,
    transport: SharedTransportCrypto,
    attachment_store: Arc<AttachmentStore>,
) -> Result<()> {
    let mut hb = interval(Duration::from_secs(30));
    let mut send_pump = interval(Duration::from_millis(5));
    send_pump.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let ack_registry = Arc::new(AckRegistry::default());
    let invite_registry = Arc::new(InviteRegistry::default());
    let read_ack_registry = ack_registry.clone();
    let read_invite_registry = invite_registry.clone();
    let read_net_tx = net_tx.clone();
    let read_transport = transport.clone();
    let mut pending_uploads = VecDeque::<PathBuf>::new();
    let mut active_upload: Option<AttachmentJob> = None;
    let mut preparing_upload: Option<PreparingUpload> = None;

    let reader = tokio::spawn(async move {
        let mut lines = lines;
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    let Some(open_result) = transport_open_line(&read_transport, &line) else {
                        continue;
                    };
                    let plain = match open_result {
                        TransportOpenResult::Fresh(plain) => plain,
                        TransportOpenResult::Duplicate(_) => continue,
                    };

                    if should_drop_transport_control_message(&plain) {
                        continue;
                    }

                    if let Some(packet_id) = parse_ack_line(&plain) {
                        read_ack_registry.mark_acked(packet_id).await;
                        continue;
                    }
                    if let Some((request_id, token, expires_at)) = parse_invite_token_line(&plain) {
                        read_invite_registry
                            .resolve_success(&request_id, token, expires_at)
                            .await;
                        continue;
                    }
                    if let Some((request_id, reason)) = parse_invite_error_line(&plain) {
                        read_invite_registry
                            .resolve_error(&request_id, reason)
                            .await;
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
                            &room_crypto,
                            transport.clone(),
                            ack_registry.clone(),
                            invite_registry.clone(),
                            &mut pending_uploads,
                            attachment_store.clone(),
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

            _ = send_pump.tick(), if active_upload.is_some() || preparing_upload.is_some() || !pending_uploads.is_empty() => {
                pump_attachment_upload(
                    &mut writer,
                    &net_tx,
                    &room_crypto,
                    transport.clone(),
                    ack_registry.clone(),
                    &mut pending_uploads,
                    &mut preparing_upload,
                    &mut active_upload,
                    attachment_store.clone(),
                ).await;
            }

            _ = hb.tick() => {
                let ping_cipher = match transport_seal_line(&transport, "/ping") {
                    Some(line) => line,
                    None => break,
                };
                if write_cipher_line(&mut writer, &ping_cipher).await.is_err() {
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
    room_crypto: &RoomCryptoState,
    transport: SharedTransportCrypto,
    ack_registry: Arc<AckRegistry>,
    invite_registry: Arc<InviteRegistry>,
    pending_uploads: &mut VecDeque<PathBuf>,
    _attachment_store: Arc<AttachmentStore>,
) -> Result<()> {
    if parse_local_ui_event(text).is_some() {
        net_tx.send(text.to_string()).ok();
        return Ok(());
    }

    if let Some(req) = parse_local_invite_request_line(text) {
        return handle_invite_request(
            writer,
            net_tx,
            transport,
            ack_registry,
            invite_registry,
            req,
        )
        .await;
    }

    match classify_outgoing_input(text)? {
        OutgoingPayload::Text(plain) => {
            let packet_id = packet_id_for_text();
            send_room_payload_with_ack(
                writer,
                &packet_id,
                &plain,
                room_crypto,
                transport,
                ack_registry,
            )
            .await?;
            net_tx.send(build_local_echo_text_line(&plain)).ok();
            Ok(())
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

async fn handle_invite_request(
    writer: &mut OwnedWriteHalf,
    net_tx: &UnboundedSender<String>,
    transport: SharedTransportCrypto,
    ack_registry: Arc<AckRegistry>,
    invite_registry: Arc<InviteRegistry>,
    req: super::utils::LocalInviteRequest,
) -> Result<()> {
    let (blob_b64, blob_key_b64) =
        create_invite_blob(req.room_id.clone(), req.room_credential.clone())?;
    let notify = invite_registry
        .register(
            req.request_id.clone(),
            req.server_addr.clone(),
            blob_key_b64,
        )
        .await;

    let server_line = build_server_invite_request_line(
        &req.request_id,
        &req.room_id,
        &req.owner_capability,
        &blob_b64,
    );
    let packet_id = packet_id_for_text();
    if let Err(err) =
        send_server_payload_with_ack(writer, &packet_id, &server_line, transport, ack_registry)
            .await
    {
        invite_registry.drop_request(&req.request_id).await;
        return Err(err);
    }

    let wait_result = timeout(
        Duration::from_secs(5),
        wait_for_invite_response(&req.request_id, notify, invite_registry.clone()),
    )
    .await;

    if wait_result.is_err() {
        invite_registry.drop_request(&req.request_id).await;
        return Err(anyhow!("Invite token timeout"));
    }

    let Some((server_addr, blob_key_b64, response)) =
        invite_registry.take_result(&req.request_id).await
    else {
        return Err(anyhow!("Invite response missing"));
    };

    match response {
        Ok((token_secret_b64, _expires_at)) => {
            let invite = create_invitation(server_addr, token_secret_b64, blob_key_b64)?;
            net_tx.send(build_local_notice_line(&invite)).ok();
            Ok(())
        }
        Err(reason) => Err(anyhow!("Invite request rejected: {reason}")),
    }
}

async fn wait_for_invite_response(
    request_id: &str,
    notify: Arc<Notify>,
    invite_registry: Arc<InviteRegistry>,
) {
    loop {
        if invite_registry.has_response(request_id).await {
            return;
        }
        notify.notified().await;
    }
}

async fn pump_attachment_upload(
    writer: &mut OwnedWriteHalf,
    net_tx: &UnboundedSender<String>,
    room_crypto: &RoomCryptoState,
    transport: SharedTransportCrypto,
    ack_registry: Arc<AckRegistry>,
    pending_uploads: &mut VecDeque<PathBuf>,
    preparing_upload: &mut Option<PreparingUpload>,
    active_upload: &mut Option<AttachmentJob>,
    attachment_store: Arc<AttachmentStore>,
) {
    if active_upload.is_none() {
        if let Some(preparing) = preparing_upload.as_ref() {
            if !preparing.task.is_finished() {
                return;
            }
        }

        if let Some(preparing) = preparing_upload.take() {
            match preparing.task.await {
                Ok(Ok(job)) => {
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
                Ok(Err(err)) => {
                    net_tx
                        .send(build_local_notice_line(&format!(
                            "附件初始化失败 {}: {err}",
                            preparing.path.display()
                        )))
                        .ok();
                }
                Err(err) => {
                    net_tx
                        .send(build_local_notice_line(&format!(
                            "附件初始化任务失败 {}: {err}",
                            preparing.path.display()
                        )))
                        .ok();
                }
            }
            if active_upload.is_none() {
                return;
            }
        }

        let Some(path) = pending_uploads.pop_front() else {
            return;
        };
        let prep_path = path.clone();
        *preparing_upload = Some(PreparingUpload {
            path,
            task: tokio::spawn(async move { initialize_attachment_job_owned(prep_path).await }),
        });
        return;
    }

    let Some(job) = active_upload.as_mut() else {
        return;
    };

    if !job.meta_sent {
        match process_attachment_meta(
            writer,
            room_crypto,
            transport.clone(),
            ack_registry.clone(),
            job,
        )
        .await
        {
            Ok(true) => {
                if job.total_chunks == 0 {
                    if let Err(err) =
                        emit_local_attachment_echo(net_tx, attachment_store.as_ref(), job).await
                    {
                        net_tx
                            .send(build_local_notice_line(&format!("附件本地回显失败: {err}")))
                            .ok();
                    }
                    net_tx
                        .send(build_local_transfer_done_line(&job.transfer_id))
                        .ok();
                    *active_upload = None;
                }
            }
            Ok(false) => {}
            Err(err) => {
                ack_registry.finish(&job.meta_packet_id).await;
                net_tx
                    .send(build_local_transfer_failed_line(
                        &job.transfer_id,
                        &err.to_string(),
                    ))
                    .ok();
                *active_upload = None;
            }
        }
        return;
    }

    if let Err(err) = process_attachment_window(
        writer,
        net_tx,
        room_crypto,
        transport,
        ack_registry.clone(),
        job,
    )
    .await
    {
        cleanup_attachment_window(ack_registry.clone(), job).await;
        net_tx
            .send(build_local_transfer_failed_line(
                &job.transfer_id,
                &err.to_string(),
            ))
            .ok();
        *active_upload = None;
        return;
    }

    if job.acked_chunks >= job.total_chunks
        && job.next_chunk_index >= job.total_chunks
        && job.in_flight.is_empty()
    {
        if let Err(err) = emit_local_attachment_echo(net_tx, attachment_store.as_ref(), job).await {
            net_tx
                .send(build_local_notice_line(&format!("附件本地回显失败: {err}")))
                .ok();
        }
        net_tx
            .send(build_local_transfer_done_line(&job.transfer_id))
            .ok();
        *active_upload = None;
    }
}

async fn process_attachment_window(
    writer: &mut OwnedWriteHalf,
    net_tx: &UnboundedSender<String>,
    room_crypto: &RoomCryptoState,
    transport: SharedTransportCrypto,
    ack_registry: Arc<AckRegistry>,
    job: &mut AttachmentJob,
) -> Result<()> {
    let max_attempts = PACKET_RETRY_LIMIT + 1;
    let mut idx = 0;

    while idx < job.in_flight.len() {
        let packet_id = job.in_flight[idx].packet_id.clone();
        if ack_registry.is_acked(&packet_id).await {
            ack_registry.finish(&packet_id).await;
            job.acked_chunks += 1;
            job.in_flight.remove(idx);
            net_tx
                .send(build_local_transfer_progress_line(
                    &job.transfer_id,
                    job.acked_chunks,
                    job.total_chunks,
                ))
                .ok();
            continue;
        }

        if job.in_flight[idx].last_sent_at.elapsed() >= Duration::from_millis(PACKET_ACK_TIMEOUT_MS)
        {
            if job.in_flight[idx].attempts >= max_attempts {
                let failed_chunk = job.in_flight[idx].chunk_index;
                return Err(anyhow!(
                    "ACK timeout for chunk {} of {}",
                    failed_chunk + 1,
                    job.total_chunks
                ));
            }

            send_room_payload_now(
                writer,
                &job.in_flight[idx].packet_id,
                &job.in_flight[idx].chunk_line,
                room_crypto,
                transport.clone(),
            )
            .await?;
            job.in_flight[idx].attempts += 1;
            job.in_flight[idx].last_sent_at = Instant::now();
        }

        idx += 1;
    }

    while job.in_flight.len() < ATTACHMENT_WINDOW_SIZE && job.next_chunk_index < job.total_chunks {
        let chunk_index = job.next_chunk_index;
        let mut buf = vec![0u8; ATTACHMENT_CHUNK_SIZE];
        let read = job.file.read(&mut buf).await?;
        if read == 0 {
            return Err(anyhow!(
                "Unexpected EOF while reading attachment {}",
                job.file_name
            ));
        }

        let chunk_line = build_attachment_chunk_line(&job.transfer_id, chunk_index, &buf[..read]);
        let packet_id = packet_id_for_attachment_chunk(&job.transfer_id, chunk_index);
        send_room_payload_now(
            writer,
            &packet_id,
            &chunk_line,
            room_crypto,
            transport.clone(),
        )
        .await?;
        job.in_flight.push(InFlightChunk {
            packet_id,
            chunk_line,
            chunk_index,
            attempts: 1,
            last_sent_at: Instant::now(),
        });
        job.next_chunk_index += 1;
    }

    Ok(())
}

async fn cleanup_attachment_window(ack_registry: Arc<AckRegistry>, job: &AttachmentJob) {
    for chunk in &job.in_flight {
        ack_registry.finish(&chunk.packet_id).await;
    }
}

async fn initialize_attachment_job_owned(path: PathBuf) -> Result<AttachmentJob> {
    let metadata = tokio::fs::metadata(&path).await?;
    if !metadata.is_file() {
        return Err(anyhow!("Path is not a file: {}", path.display()));
    }

    let total_size = metadata.len();
    let total_chunks = if total_size == 0 {
        0
    } else {
        usize::try_from(total_size)?.div_ceil(ATTACHMENT_CHUNK_SIZE)
    };
    let file_name = file_name_or_default(&path);
    let sha256_hex = hash_file(&path).await?;
    let file = File::open(&path).await?;
    let transfer_id = uuid::Uuid::new_v4().simple().to_string();

    Ok(AttachmentJob {
        meta_packet_id: packet_id_for_attachment_meta(&transfer_id),
        meta_line: build_attachment_meta_line(
            &transfer_id,
            infer_attachment_kind(&path),
            &file_name,
            total_size,
            total_chunks,
            &sha256_hex,
        ),
        path,
        transfer_id,
        file_name,
        total_size,
        total_chunks,
        next_chunk_index: 0,
        acked_chunks: 0,
        file,
        meta_sent: false,
        meta_attempts: 0,
        meta_last_sent_at: None,
        in_flight: Vec::new(),
    })
}

async fn process_attachment_meta(
    writer: &mut OwnedWriteHalf,
    room_crypto: &RoomCryptoState,
    transport: SharedTransportCrypto,
    ack_registry: Arc<AckRegistry>,
    job: &mut AttachmentJob,
) -> Result<bool> {
    let max_attempts = PACKET_RETRY_LIMIT + 1;

    if ack_registry.is_acked(&job.meta_packet_id).await {
        ack_registry.finish(&job.meta_packet_id).await;
        job.meta_sent = true;
        return Ok(true);
    }

    let should_send = match job.meta_last_sent_at {
        None => true,
        Some(last_sent_at)
            if last_sent_at.elapsed() >= Duration::from_millis(PACKET_ACK_TIMEOUT_MS) =>
        {
            if job.meta_attempts >= max_attempts {
                ack_registry.finish(&job.meta_packet_id).await;
                return Err(anyhow!("ACK timeout for attachment metadata"));
            }
            true
        }
        Some(_) => false,
    };

    if should_send {
        ack_registry.subscribe(&job.meta_packet_id).await;
        send_room_payload_now(
            writer,
            &job.meta_packet_id,
            &job.meta_line,
            room_crypto,
            transport,
        )
        .await?;
        job.meta_attempts += 1;
        job.meta_last_sent_at = Some(Instant::now());
    }

    Ok(false)
}

async fn emit_local_attachment_echo(
    net_tx: &UnboundedSender<String>,
    attachment_store: &AttachmentStore,
    job: &AttachmentJob,
) -> Result<()> {
    let bytes = tokio::fs::read(&job.path).await?;
    let attachment_id = attachment_store.store_attachment(&job.file_name, &bytes)?;
    net_tx
        .send(build_local_echo_attachment_line(
            &attachment_id,
            &job.file_name,
            job.total_size,
            infer_attachment_kind(&job.path),
        ))
        .ok();
    Ok(())
}

async fn send_room_payload_with_ack(
    writer: &mut OwnedWriteHalf,
    packet_id: &str,
    plain: &str,
    room_crypto: &RoomCryptoState,
    transport: SharedTransportCrypto,
    ack_registry: Arc<AckRegistry>,
) -> Result<()> {
    let room_cipher = room_crypto.seal(plain);
    send_transport_payload_with_ack(writer, packet_id, &room_cipher, transport, ack_registry).await
}

async fn send_room_payload_now(
    writer: &mut OwnedWriteHalf,
    packet_id: &str,
    plain: &str,
    room_crypto: &RoomCryptoState,
    transport: SharedTransportCrypto,
) -> Result<()> {
    let room_cipher = room_crypto.seal(plain);
    send_transport_payload_now(writer, packet_id, &room_cipher, transport).await
}

async fn send_server_payload_with_ack(
    writer: &mut OwnedWriteHalf,
    packet_id: &str,
    plain: &str,
    transport: SharedTransportCrypto,
    ack_registry: Arc<AckRegistry>,
) -> Result<()> {
    send_transport_payload_with_ack(writer, packet_id, plain, transport, ack_registry).await
}

async fn send_transport_payload_with_ack(
    writer: &mut OwnedWriteHalf,
    packet_id: &str,
    payload: &str,
    transport: SharedTransportCrypto,
    ack_registry: Arc<AckRegistry>,
) -> Result<()> {
    let transport_line = build_transport_packet_line(packet_id, payload);
    let cipher_line = transport_seal_line(&transport, &transport_line)
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

async fn send_transport_payload_now(
    writer: &mut OwnedWriteHalf,
    packet_id: &str,
    payload: &str,
    transport: SharedTransportCrypto,
) -> Result<()> {
    let transport_line = build_transport_packet_line(packet_id, payload);
    let cipher_line = transport_seal_line(&transport, &transport_line)
        .ok_or_else(|| anyhow!("Transport state unavailable"))?;
    write_cipher_line(writer, &cipher_line).await
}

async fn write_cipher_line(writer: &mut OwnedWriteHalf, cipher_line: &str) -> Result<()> {
    writer.write_all(cipher_line.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    Ok(())
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

fn transport_open_line(
    transport: &SharedTransportCrypto,
    cipher_line: &str,
) -> Option<TransportOpenResult> {
    let mut guard = transport.lock().ok()?;
    guard.open(cipher_line)
}

fn transport_seal_line(transport: &SharedTransportCrypto, plain: &str) -> Option<String> {
    let mut guard = transport.lock().ok()?;
    Some(guard.seal(plain))
}

fn should_drop_transport_control_message(plain: &str) -> bool {
    plain == "/ping_ack"
        || plain == "/ping"
        || plain == "OK"
        || plain.starts_with("OK ")
        || plain.starts_with("INVITE_OK ")
}
