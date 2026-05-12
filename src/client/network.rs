use std::{collections::HashMap, collections::VecDeque, path::PathBuf, sync::Arc};

use anyhow::{anyhow, Result};
use tokio::{
    io::{BufReader, Lines},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::{
        mpsc::{UnboundedReceiver, UnboundedSender},
        Mutex, Notify,
    },
    time::{interval, timeout, Duration, MissedTickBehavior},
};

use crate::{
    attachments::{sender, store::AttachmentStore},
    client::{
        input::{classify_outgoing_input, OutgoingPayload},
        session::{SharedGroupCrypto, SharedTransportCrypto},
    },
    crypto::{
        encrypt_message,
        invite::{create_invitation, create_invite_blob},
        SecureMessageType, TransportOpenResult,
    },
    protocol::{
        build_local_echo_text_line, build_local_notice_line, build_rmsg_line,
        build_server_invite_request_line, is_epoch_control_line, parse_ack_line,
        parse_invite_error_line, parse_invite_token_line, parse_local_invite_request_line,
        parse_local_ui_event, LocalInviteRequest,
    },
    transport::{
        heartbeat::send_ping,
        packet::{
            send_transport_payload_with_ack, should_drop_transport_control_message,
            transport_open_line, AckRegistry,
        },
    },
};

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

pub async fn chat_loop(
    lines: Lines<BufReader<OwnedReadHalf>>,
    mut writer: OwnedWriteHalf,
    net_tx: UnboundedSender<String>,
    mut out_rx: UnboundedReceiver<String>,
    group_crypto: SharedGroupCrypto,
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
    let mut active_upload = None;
    let mut preparing_upload = None;

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
                        use tokio::io::AsyncWriteExt;
                        writer.shutdown().await?;
                        break;
                    }
                    Some(text) => {
                        if let Err(err) = handle_outgoing_input(
                            &mut writer,
                            &text,
                            &net_tx,
                            group_crypto.clone(),
                            transport.clone(),
                            ack_registry.clone(),
                            invite_registry.clone(),
                            &mut pending_uploads,
                        ).await {
                            net_tx.send(build_local_notice_line(&format!("发送失败: {err}"))).ok();
                        }
                    }
                    None => {
                        use tokio::io::AsyncWriteExt;
                        writer.shutdown().await?;
                        break;
                    }
                }
            }

            _ = send_pump.tick(), if active_upload.is_some() || preparing_upload.is_some() || !pending_uploads.is_empty() => {
                sender::pump_attachment_upload(
                    &mut writer,
                    &net_tx,
                    &group_crypto,
                    &transport,
                    ack_registry.clone(),
                    &mut pending_uploads,
                    &mut preparing_upload,
                    &mut active_upload,
                    attachment_store.clone(),
                ).await;
            }

            _ = hb.tick() => {
                if send_ping(&mut writer, &transport).await.is_err() {
                    break;
                }
            }
        }
    }

    reader.abort();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_outgoing_input(
    writer: &mut OwnedWriteHalf,
    text: &str,
    net_tx: &UnboundedSender<String>,
    group_crypto: SharedGroupCrypto,
    transport: SharedTransportCrypto,
    ack_registry: Arc<AckRegistry>,
    invite_registry: Arc<InviteRegistry>,
    pending_uploads: &mut VecDeque<PathBuf>,
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
            let packet_id = format!("msg-{}", uuid::Uuid::new_v4().simple());
            if is_epoch_control_line(&plain) {
                send_transport_payload_with_ack(
                    writer,
                    &packet_id,
                    &plain,
                    &transport,
                    ack_registry,
                )
                .await?;
                return Ok(());
            }
            let secure_line = {
                let mut guard = group_crypto
                    .lock()
                    .map_err(|_| anyhow!("Group crypto state unavailable"))?;
                let encrypted =
                    encrypt_message(&mut guard, SecureMessageType::Text, plain.as_bytes())?;
                build_rmsg_line(&encrypted)?
            };
            send_transport_payload_with_ack(
                writer,
                &packet_id,
                &secure_line,
                &transport,
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
    req: LocalInviteRequest,
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
    let packet_id = format!("msg-{}", uuid::Uuid::new_v4().simple());
    if let Err(err) =
        send_transport_payload_with_ack(writer, &packet_id, &server_line, &transport, ack_registry)
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
