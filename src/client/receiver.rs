use std::collections::HashMap;

use chrono::Local;
use sha2::{Digest as ShaDigest, Sha256};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::client::utils::{
    decrypt_file_chunk2, parse_attachment_frame, parse_display_body, parse_epoch_commit_line,
    parse_key_announce_line, parse_local_ui_event, parse_member_list_line, parse_rmsg_line,
    render_transfer_line, sanitize_attachment_name, AttachmentFrame, AttachmentMeta,
    EncryptedAttachmentChunk, LocalUiEvent, MemberIdentity,
};

use super::attachment_store::AttachmentStore;
use super::crypto::{decrypt_message, zeroize, EpochCommit};
use super::handshake::SharedGroupCrypto;
use super::notifier;

const DRAIN_BATCH_LIMIT: usize = 128;
const PENDING_EPOCH_COMMIT_LIMIT: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentKind {
    Image,
    File,
}

impl AttachmentKind {
    pub fn as_protocol_tag(self) -> &'static str {
        match self {
            AttachmentKind::Image => "img",
            AttachmentKind::File => "file",
        }
    }

    pub fn from_protocol_tag(tag: &str) -> Option<Self> {
        match tag {
            "img" => Some(AttachmentKind::Image),
            "file" => Some(AttachmentKind::File),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ChatMessage {
    Text(String),
    Attachment {
        attachment_id: String,
        sender: String,
        ts: String,
        name: String,
        size: u64,
        kind: AttachmentKind,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStage {
    Active,
    Done,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Sending,
    Receiving,
}

#[derive(Debug, Clone)]
pub struct TransferStatus {
    pub transfer_id: String,
    pub file_name: String,
    pub total_chunks: usize,
    pub acked_chunks: usize,
    pub total_size: u64,
    pub direction: TransferDirection,
    pub stage: TransferStage,
    pub detail: Option<String>,
}

#[derive(Default)]
pub struct TransferUiState {
    order: Vec<String>,
    transfers: HashMap<String, TransferStatus>,
}

impl TransferUiState {
    pub fn apply(&mut self, event: LocalUiEvent) -> Option<String> {
        match event {
            LocalUiEvent::TransferBegin {
                transfer_id,
                file_name,
                total_chunks,
                total_size,
            } => {
                if !self.order.contains(&transfer_id) {
                    self.order.push(transfer_id.clone());
                }
                self.transfers.insert(
                    transfer_id.clone(),
                    TransferStatus {
                        transfer_id,
                        file_name,
                        total_chunks,
                        acked_chunks: 0,
                        total_size,
                        direction: TransferDirection::Sending,
                        stage: TransferStage::Active,
                        detail: None,
                    },
                );
                None
            }
            LocalUiEvent::TransferProgress {
                transfer_id,
                acked_chunks,
                total_chunks,
            } => {
                if let Some(status) = self.transfers.get_mut(&transfer_id) {
                    status.acked_chunks = acked_chunks;
                    status.total_chunks = total_chunks;
                    status.stage = TransferStage::Active;
                    status.detail = None;
                }
                None
            }
            LocalUiEvent::TransferDone { transfer_id } => {
                if let Some(status) = self.transfers.get_mut(&transfer_id) {
                    status.acked_chunks = status.total_chunks;
                    status.stage = TransferStage::Done;
                    status.detail = Some("server acked".to_string());
                }
                None
            }
            LocalUiEvent::TransferFailed {
                transfer_id,
                reason,
            } => {
                let file_name = if let Some(status) = self.transfers.get_mut(&transfer_id) {
                    status.stage = TransferStage::Failed;
                    status.detail = Some(reason.clone());
                    status.file_name.clone()
                } else {
                    transfer_id.clone()
                };
                Some(format!("传输失败: {file_name} - {reason}"))
            }
            LocalUiEvent::EchoText { .. } | LocalUiEvent::EchoAttachment { .. } => None,
            LocalUiEvent::Notice(message) => Some(message),
        }
    }

    pub fn begin_incoming(
        &mut self,
        transfer_id: String,
        file_name: String,
        total_chunks: usize,
        total_size: u64,
    ) {
        if !self.order.contains(&transfer_id) {
            self.order.push(transfer_id.clone());
        }
        self.transfers.insert(
            transfer_id.clone(),
            TransferStatus {
                transfer_id,
                file_name,
                total_chunks,
                acked_chunks: 0,
                total_size,
                direction: TransferDirection::Receiving,
                stage: TransferStage::Active,
                detail: None,
            },
        );
    }

    pub fn progress_incoming(
        &mut self,
        transfer_id: &str,
        received_chunks: usize,
        total_chunks: usize,
    ) {
        if let Some(status) = self.transfers.get_mut(transfer_id) {
            status.acked_chunks = received_chunks;
            status.total_chunks = total_chunks;
            status.stage = TransferStage::Active;
            status.detail = None;
        }
    }

    pub fn finish_incoming(&mut self, transfer_id: &str) {
        if let Some(status) = self.transfers.get_mut(transfer_id) {
            status.acked_chunks = status.total_chunks;
            status.stage = TransferStage::Done;
            status.detail = Some("received".to_string());
        }
    }

    pub fn fail_incoming(&mut self, transfer_id: &str, reason: &str) {
        if let Some(status) = self.transfers.get_mut(transfer_id) {
            status.stage = TransferStage::Failed;
            status.detail = Some(reason.to_string());
        }
    }

    pub fn lines(&self, limit: usize) -> Vec<String> {
        let mut lines = Vec::new();

        for transfer_id in self.order.iter().rev().take(limit) {
            if let Some(status) = self.transfers.get(transfer_id) {
                lines.push(render_transfer_line(
                    &status.file_name,
                    status.total_size,
                    status.direction,
                    status.stage,
                    status.acked_chunks,
                    status.total_chunks,
                    status.detail.as_deref(),
                ));
            }
        }

        lines
    }
}

#[derive(Default)]
pub struct ReceiverState {
    incoming: HashMap<String, IncomingAttachment>,
    pending_epoch_commits: Vec<EpochCommit>,
}

struct IncomingAttachment {
    sender: String,
    file_name: String,
    total_size: u64,
    total_chunks: usize,
    sha256_hex: String,
    kind: AttachmentKind,
    file_key: [u8; 32],
    nonce_base: [u8; 8],
    chunks: Vec<Option<Vec<u8>>>,
    received_chunks: usize,
}

impl Drop for IncomingAttachment {
    fn drop(&mut self) {
        zeroize(&mut self.file_key);
        zeroize(&mut self.nonce_base);
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DrainOutcome {
    pub member_list_changed: bool,
    pub phase2_action_needed: bool,
}

pub fn drain_messages(
    net_rx: &mut UnboundedReceiver<String>,
    messages: &mut Vec<ChatMessage>,
    my_name: &str,
    group_crypto: &SharedGroupCrypto,
    attachment_store: &AttachmentStore,
    members: &mut Vec<MemberIdentity>,
    receiver_state: &mut ReceiverState,
    transfer_ui_state: &mut TransferUiState,
) -> DrainOutcome {
    let mut outcome = DrainOutcome::default();
    let mut processed = 0usize;

    while let Ok(line) = net_rx.try_recv() {
        processed += 1;

        if should_drop_unframed_control_line(&line) {
            if processed >= DRAIN_BATCH_LIMIT {
                break;
            }
            continue;
        }

        if let Some(parsed_members) = parse_member_list_line(&line) {
            members.clear();
            members.extend(parsed_members.clone());
            if let Ok(mut guard) = group_crypto.lock() {
                let _ = guard.replace_members(
                    parsed_members
                        .iter()
                        .map(|member| (member.member_id.clone(), member.nickname.clone())),
                );
                retry_pending_epoch_commits(receiver_state, &mut guard);
            }
            outcome.member_list_changed = true;
            outcome.phase2_action_needed = true;
            if processed >= DRAIN_BATCH_LIMIT {
                break;
            }
            continue;
        }

        if let Some(event) = parse_local_ui_event(&line) {
            let hms = Local::now().format("%H:%M:%S").to_string();
            if let Some(message) =
                handle_local_ui_event(event, my_name, attachment_store, transfer_ui_state, &hms)
            {
                push_message(messages, message);
            }
            continue;
        }

        let hms = Local::now().format("%H:%M:%S").to_string();
        let (outer_sender, raw_body) = parse_display_body(&line);
        if let Some(announce) = parse_key_announce_line(&raw_body) {
            if let Ok(mut guard) = group_crypto.lock() {
                if guard.apply_key_announce(&announce).unwrap_or(false) {
                    outcome.phase2_action_needed = true;
                }
                retry_pending_epoch_commits(receiver_state, &mut guard);
            }
            if processed >= DRAIN_BATCH_LIMIT {
                break;
            }
            continue;
        }
        if let Some(commit) = parse_epoch_commit_line(&raw_body) {
            if let Ok(mut guard) = group_crypto.lock() {
                if guard.apply_epoch_commit(&commit).is_err() {
                    queue_pending_epoch_commit(receiver_state, commit);
                }
            }
            if processed >= DRAIN_BATCH_LIMIT {
                break;
            }
            continue;
        }
        if let Some(AttachmentFrame::EncryptedChunk(chunk)) = parse_attachment_frame(&raw_body) {
            let result = append_encrypted_attachment_chunk(
                receiver_state,
                chunk,
                attachment_store,
                transfer_ui_state,
                &hms,
            );
            if let Some(message) = attachment_result_to_message(result, &hms) {
                if outer_sender != my_name {
                    notifier::notify();
                }
                push_message(messages, message);
            }
            if processed >= DRAIN_BATCH_LIMIT {
                break;
            }
            continue;
        }
        let decrypted = parse_rmsg_line(&raw_body).and_then(|encrypted| {
            let mut guard = group_crypto.lock().ok()?;
            decrypt_message(&mut guard, &encrypted)
                .ok()
                .and_then(|message| {
                    let body = String::from_utf8(message.plaintext).ok()?;
                    let sender = guard
                        .member_display_name(&message.header.sender_id)
                        .unwrap_or_else(|| outer_sender.clone());
                    Some((sender, message.header.msg_type, body))
                })
        });

        let (sender, body) = match decrypted {
            Some((sender, _msg_type, body)) => (sender, body),
            None if raw_body.starts_with("/RMSG ") => {
                if processed >= DRAIN_BATCH_LIMIT {
                    break;
                }
                continue;
            }
            None if line.starts_with("⚡ ") => ("System".to_string(), line),
            None => {
                if processed >= DRAIN_BATCH_LIMIT {
                    break;
                }
                continue;
            }
        };

        let result = match parse_attachment_frame(&body) {
            Some(AttachmentFrame::Meta(meta)) => register_attachment(
                receiver_state,
                sender.clone(),
                meta,
                attachment_store,
                transfer_ui_state,
                &hms,
            ),
            Some(AttachmentFrame::EncryptedChunk(chunk)) => append_encrypted_attachment_chunk(
                receiver_state,
                chunk,
                attachment_store,
                transfer_ui_state,
                &hms,
            ),
            None => Ok(Some(ChatMessage::Text(format_text_message(
                &sender, &body, &hms,
            )))),
        };

        let Some(message) = attachment_result_to_message(result, &hms) else {
            continue;
        };

        if sender != my_name {
            notifier::notify();
        }
        push_message(messages, message);

        if processed >= DRAIN_BATCH_LIMIT {
            break;
        }
    }

    outcome
}

fn attachment_result_to_message(
    result: Result<Option<ChatMessage>, String>,
    hms: &str,
) -> Option<ChatMessage> {
    match result {
        Ok(message) => message,
        Err(err) => Some(ChatMessage::Text(format!("[System] [{hms}] {err}"))),
    }
}

fn queue_pending_epoch_commit(receiver_state: &mut ReceiverState, commit: EpochCommit) {
    if receiver_state
        .pending_epoch_commits
        .iter()
        .any(|pending| pending == &commit)
    {
        return;
    }
    receiver_state.pending_epoch_commits.push(commit);
    if receiver_state.pending_epoch_commits.len() > PENDING_EPOCH_COMMIT_LIMIT {
        receiver_state.pending_epoch_commits.remove(0);
    }
}

fn retry_pending_epoch_commits(
    receiver_state: &mut ReceiverState,
    group_crypto: &mut super::crypto::GroupCryptoState,
) {
    let mut idx = 0;
    while idx < receiver_state.pending_epoch_commits.len() {
        let commit = receiver_state.pending_epoch_commits[idx].clone();
        match group_crypto.apply_epoch_commit(&commit) {
            Ok(true) | Ok(false) => {
                receiver_state.pending_epoch_commits.remove(idx);
            }
            Err(_) => {
                idx += 1;
            }
        }
    }
}

fn register_attachment(
    receiver_state: &mut ReceiverState,
    sender: String,
    meta: AttachmentMeta,
    attachment_store: &AttachmentStore,
    transfer_ui_state: &mut TransferUiState,
    hms: &str,
) -> Result<Option<ChatMessage>, String> {
    transfer_ui_state.begin_incoming(
        meta.transfer_id.clone(),
        meta.file_name.clone(),
        meta.total_chunks,
        meta.total_size,
    );

    let incoming = IncomingAttachment {
        sender,
        file_name: meta.file_name,
        total_size: meta.total_size,
        total_chunks: meta.total_chunks,
        sha256_hex: meta.sha256_hex,
        kind: meta.kind,
        file_key: meta.file_key,
        nonce_base: meta.nonce_base,
        chunks: vec![None; meta.total_chunks],
        received_chunks: 0,
    };

    if meta.total_chunks == 0 {
        let result = finalize_attachment(meta.transfer_id.clone(), incoming, attachment_store, hms);
        return match result {
            Ok(message) => {
                transfer_ui_state.finish_incoming(&meta.transfer_id);
                Ok(Some(message))
            }
            Err(err) => {
                transfer_ui_state.fail_incoming(&meta.transfer_id, &err);
                Err(err)
            }
        };
    }

    receiver_state.incoming.insert(meta.transfer_id, incoming);
    Ok(None)
}

fn append_encrypted_attachment_chunk(
    receiver_state: &mut ReceiverState,
    encrypted_chunk: EncryptedAttachmentChunk,
    attachment_store: &AttachmentStore,
    transfer_ui_state: &mut TransferUiState,
    hms: &str,
) -> Result<Option<ChatMessage>, String> {
    let (file_key, nonce_base) = {
        let Some(incoming) = receiver_state.incoming.get(&encrypted_chunk.transfer_id) else {
            return Ok(None);
        };
        (incoming.file_key, incoming.nonce_base)
    };
    let data = decrypt_file_chunk2(&encrypted_chunk, &file_key, &nonce_base)
        .map_err(|err| err.to_string())?;
    append_attachment_chunk(
        receiver_state,
        encrypted_chunk.transfer_id,
        encrypted_chunk.index,
        data,
        attachment_store,
        transfer_ui_state,
        hms,
    )
}

fn append_attachment_chunk(
    receiver_state: &mut ReceiverState,
    transfer_id: String,
    index: usize,
    data: Vec<u8>,
    attachment_store: &AttachmentStore,
    transfer_ui_state: &mut TransferUiState,
    hms: &str,
) -> Result<Option<ChatMessage>, String> {
    let mut ready = false;
    let (received_chunks, total_chunks);

    {
        let Some(incoming) = receiver_state.incoming.get_mut(&transfer_id) else {
            return Ok(None);
        };

        if index >= incoming.total_chunks {
            return Err(format!("Attachment chunk out of range: {}", index));
        }

        if incoming.chunks[index].is_none() {
            incoming.chunks[index] = Some(data);
            incoming.received_chunks += 1;
        }

        (received_chunks, total_chunks) = (incoming.received_chunks, incoming.total_chunks);

        if incoming.received_chunks == incoming.total_chunks {
            ready = true;
        }
    }

    transfer_ui_state.progress_incoming(&transfer_id, received_chunks, total_chunks);

    if !ready {
        return Ok(None);
    }

    let incoming = receiver_state
        .incoming
        .remove(&transfer_id)
        .ok_or_else(|| "Attachment state missing during finalize".to_string())?;

    let result = finalize_attachment(transfer_id.clone(), incoming, attachment_store, hms);
    match result {
        Ok(message) => {
            transfer_ui_state.finish_incoming(&transfer_id);
            Ok(Some(message))
        }
        Err(err) => {
            transfer_ui_state.fail_incoming(&transfer_id, &err);
            Err(err)
        }
    }
}

fn finalize_attachment(
    transfer_id: String,
    mut incoming: IncomingAttachment,
    attachment_store: &AttachmentStore,
    hms: &str,
) -> Result<ChatMessage, String> {
    let mut hasher = Sha256::new();
    let mut plain_bytes = Vec::with_capacity(incoming.total_size as usize);
    let mut written_size = 0u64;
    let safe_name = sanitize_attachment_name(&incoming.file_name);

    for chunk in std::mem::take(&mut incoming.chunks) {
        let chunk = chunk.ok_or_else(|| {
            format!("Attachment {transfer_id} is incomplete, missing one or more chunks")
        })?;
        written_size = written_size.saturating_add(chunk.len() as u64);
        hasher.update(&chunk);
        plain_bytes.extend_from_slice(&chunk);
    }

    if written_size != incoming.total_size {
        return Err(format!(
            "Attachment size mismatch: expected {}, got {}",
            incoming.total_size, written_size
        ));
    }

    let digest = hex::encode(hasher.finalize());
    if digest != incoming.sha256_hex {
        return Err(format!(
            "Attachment checksum mismatch for {}",
            incoming.file_name
        ));
    }

    let attachment_id = attachment_store
        .store_attachment(&safe_name, &plain_bytes)
        .map_err(|e| e.to_string())?;

    Ok(ChatMessage::Attachment {
        attachment_id,
        sender: std::mem::take(&mut incoming.sender),
        ts: hms.to_string(),
        name: safe_name,
        size: written_size,
        kind: incoming.kind,
    })
}

fn format_text_message(sender: &str, body: &str, hms: &str) -> String {
    format!("[{sender}] [{hms}] {body}")
}

fn handle_local_ui_event(
    event: LocalUiEvent,
    my_name: &str,
    _attachment_store: &AttachmentStore,
    transfer_ui_state: &mut TransferUiState,
    hms: &str,
) -> Option<ChatMessage> {
    match event {
        LocalUiEvent::EchoText { body } => {
            Some(ChatMessage::Text(format_text_message(my_name, &body, hms)))
        }
        LocalUiEvent::EchoAttachment {
            attachment_id,
            file_name,
            total_size,
            kind,
        } => Some(ChatMessage::Attachment {
            attachment_id,
            sender: my_name.to_string(),
            ts: hms.to_string(),
            name: file_name,
            size: total_size,
            kind,
        }),
        other => transfer_ui_state
            .apply(other)
            .map(|notice| ChatMessage::Text(format!("[System] [{hms}] {notice}"))),
    }
}

fn push_message(messages: &mut Vec<ChatMessage>, message: ChatMessage) {
    messages.push(message);

    if messages.len() > 500 {
        messages.drain(..100);
    }
}

fn should_drop_unframed_control_line(line: &str) -> bool {
    !line.starts_with('[')
        && (line == "/ping_ack"
            || line == "/ping"
            || line == "OK"
            || line.starts_with("OK ")
            || line.starts_with("/ACK ")
            || line.starts_with("INVITE_OK "))
}
