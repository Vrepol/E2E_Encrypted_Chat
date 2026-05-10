use std::{
    collections::HashMap,
};

use base64::{engine::general_purpose, Engine as _};
use chrono::Local;
use sha2::{Digest as ShaDigest, Sha256};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::client::utils::{
    parse_attachment_frame, parse_local_ui_event, parse_text_img, render_transfer_line,
    sanitize_attachment_name, AttachmentChunk, AttachmentFrame, AttachmentMeta, LocalUiEvent,
};

use super::attachment_store::AttachmentStore;
use super::crypto::RoomCryptoState;
use super::notifier;

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
    Sending,
    Done,
    Failed,
}

#[derive(Debug, Clone)]
pub struct TransferStatus {
    pub transfer_id: String,
    pub file_name: String,
    pub total_chunks: usize,
    pub acked_chunks: usize,
    pub total_size: u64,
    pub stage: TransferStage,
    pub detail: Option<String>,
}

#[derive(Default)]
pub struct TransferUiState {
    order: Vec<String>,
    outgoing: HashMap<String, TransferStatus>,
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
                self.outgoing.insert(
                    transfer_id.clone(),
                    TransferStatus {
                        transfer_id,
                        file_name,
                        total_chunks,
                        acked_chunks: 0,
                        total_size,
                        stage: TransferStage::Sending,
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
                if let Some(status) = self.outgoing.get_mut(&transfer_id) {
                    status.acked_chunks = acked_chunks;
                    status.total_chunks = total_chunks;
                    status.stage = TransferStage::Sending;
                    status.detail = None;
                }
                None
            }
            LocalUiEvent::TransferDone { transfer_id } => {
                if let Some(status) = self.outgoing.get_mut(&transfer_id) {
                    status.acked_chunks = status.total_chunks;
                    status.stage = TransferStage::Done;
                    status.detail = Some("server acked".to_string());
                }
                None
            }
            LocalUiEvent::TransferFailed { transfer_id, reason } => {
                let file_name = if let Some(status) = self.outgoing.get_mut(&transfer_id) {
                    status.stage = TransferStage::Failed;
                    status.detail = Some(reason.clone());
                    status.file_name.clone()
                } else {
                    transfer_id.clone()
                };
                Some(format!("传输失败: {file_name} - {reason}"))
            }
            LocalUiEvent::Notice(message) => Some(message),
        }
    }

    pub fn lines(&self, limit: usize) -> Vec<String> {
        let mut lines = Vec::new();

        for transfer_id in self.order.iter().rev().take(limit) {
            if let Some(status) = self.outgoing.get(transfer_id) {
                lines.push(render_transfer_line(
                    &status.file_name,
                    status.total_size,
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
}

struct IncomingAttachment {
    sender: String,
    file_name: String,
    total_size: u64,
    total_chunks: usize,
    sha256_hex: String,
    kind: AttachmentKind,
    chunks: Vec<Option<Vec<u8>>>,
    received_chunks: usize,
}

pub fn drain_messages(
    net_rx: &mut UnboundedReceiver<String>,
    messages: &mut Vec<ChatMessage>,
    my_name: &str,
    room_crypto: &RoomCryptoState,
    attachment_store: &AttachmentStore,
    members: &mut Vec<String>,
    receiver_state: &mut ReceiverState,
    transfer_ui_state: &mut TransferUiState,
) {
    while let Ok(line) = net_rx.try_recv() {
        if should_drop_unframed_control_line(&line) {
            continue;
        }

        if line.starts_with("/member_list ") {
            members.clear();
            members.extend(
                line["/member_list ".len()..]
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string()),
            );
            continue;
        }

        if let Some(event) = parse_local_ui_event(&line) {
            if let Some(notice) = transfer_ui_state.apply(event) {
                let hms = Local::now().format("%H:%M:%S").to_string();
                push_message(messages, ChatMessage::Text(format!("[System] [{hms}] {notice}")));
            }
            continue;
        }

        let (sender, body) = parse_text_img(&line, room_crypto);
        let hms = Local::now().format("%H:%M:%S").to_string();

        let result = match parse_attachment_frame(&body) {
            Some(AttachmentFrame::Meta(meta)) => {
                register_attachment(receiver_state, sender.clone(), meta, attachment_store, &hms)
            }
            Some(AttachmentFrame::Chunk(chunk)) => {
                append_attachment_chunk(receiver_state, chunk, attachment_store, &hms)
            }
            None if body.starts_with("/IMGDATA") => {
                Ok(decode_legacy_image(&sender, &body, attachment_store, &hms))
            }
            None => Ok(Some(ChatMessage::Text(format_text_message(&sender, &body, &hms)))),
        };

        let Some(message) = (match result {
            Ok(message) => message,
            Err(err) => Some(ChatMessage::Text(format!("[System] [{hms}] {err}"))),
        }) else {
            continue;
        };

        if sender != my_name {
            notifier::notify();
        }
        push_message(messages, message);
    }
}

fn register_attachment(
    receiver_state: &mut ReceiverState,
    sender: String,
    meta: AttachmentMeta,
    attachment_store: &AttachmentStore,
    hms: &str,
) -> Result<Option<ChatMessage>, String> {
    let incoming = IncomingAttachment {
        sender,
        file_name: meta.file_name,
        total_size: meta.total_size,
        total_chunks: meta.total_chunks,
        sha256_hex: meta.sha256_hex,
        kind: meta.kind,
        chunks: vec![None; meta.total_chunks],
        received_chunks: 0,
    };

    if meta.total_chunks == 0 {
        return finalize_attachment(meta.transfer_id, incoming, attachment_store, hms).map(Some);
    }

    receiver_state.incoming.insert(meta.transfer_id, incoming);
    Ok(None)
}

fn append_attachment_chunk(
    receiver_state: &mut ReceiverState,
    chunk: AttachmentChunk,
    attachment_store: &AttachmentStore,
    hms: &str,
) -> Result<Option<ChatMessage>, String> {
    let mut ready = false;

    {
        let Some(incoming) = receiver_state.incoming.get_mut(&chunk.transfer_id) else {
            return Ok(None);
        };

        if chunk.index >= incoming.total_chunks {
            return Err(format!("Attachment chunk out of range: {}", chunk.index));
        }

        if incoming.chunks[chunk.index].is_none() {
            incoming.chunks[chunk.index] = Some(chunk.data);
            incoming.received_chunks += 1;
        }

        if incoming.received_chunks == incoming.total_chunks {
            ready = true;
        }
    }

    if !ready {
        return Ok(None);
    }

    let incoming = receiver_state
        .incoming
        .remove(&chunk.transfer_id)
        .ok_or_else(|| "Attachment state missing during finalize".to_string())?;

    finalize_attachment(chunk.transfer_id, incoming, attachment_store, hms).map(Some)
}

fn finalize_attachment(
    transfer_id: String,
    incoming: IncomingAttachment,
    attachment_store: &AttachmentStore,
    hms: &str,
) -> Result<ChatMessage, String> {
    let mut hasher = Sha256::new();
    let mut plain_bytes = Vec::with_capacity(incoming.total_size as usize);
    let mut written_size = 0u64;
    let safe_name = sanitize_attachment_name(&incoming.file_name);

    for chunk in incoming.chunks {
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
        return Err(format!("Attachment checksum mismatch for {}", incoming.file_name));
    }

    let attachment_id = attachment_store
        .store_attachment(&safe_name, &plain_bytes)
        .map_err(|e| e.to_string())?;

    Ok(ChatMessage::Attachment {
        attachment_id,
        sender: incoming.sender,
        ts: hms.to_string(),
        name: safe_name,
        size: written_size,
        kind: incoming.kind,
    })
}

fn decode_legacy_image(
    sender: &str,
    body: &str,
    attachment_store: &AttachmentStore,
    hms: &str,
) -> Option<ChatMessage> {
    let b64_data = &body["/IMGDATA".len()..];
    let bytes = general_purpose::STANDARD.decode(b64_data).ok()?;
    let attachment_id = attachment_store.store_attachment("clipboard.png", &bytes).ok()?;

    Some(ChatMessage::Attachment {
        attachment_id,
        sender: sender.to_string(),
        ts: hms.to_string(),
        name: "clipboard.png".to_string(),
        size: bytes.len() as u64,
        kind: AttachmentKind::Image,
    })
}

fn format_text_message(sender: &str, body: &str, hms: &str) -> String {
    format!("[{sender}] [{hms}] {body}")
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
