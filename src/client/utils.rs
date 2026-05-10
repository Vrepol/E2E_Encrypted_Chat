use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use base64::{
    engine::general_purpose,
    engine::general_purpose::URL_SAFE_NO_PAD,
    Engine as _,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use image::{
    codecs::png::PngEncoder,
    ColorType,
    ImageEncoder,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use tokio::fs;
use uuid::Uuid;

use super::crypto::RoomCryptoState;
use super::receiver::{AttachmentKind, ChatMessage, TransferStage};

pub const HELP_TEXT: &str = r#"快捷键与命令说明：

• Ctrl+X       → 智能贴入剪贴板文本/图片/文件
• Ctrl+C       → 复制当前选中消息
• Ctrl+Z       → 撤销输入框
• Ctrl+A       → 清空输入框
• Ctrl+I       → 生成邀请码
• /send <path> → 发送任意文件
• ←/→          → 移动光标（Ctrl+← 跳3字符，Ctrl+→ 跳至末尾）
• ↑/↓          → 列表选上下（Ctrl+↑ 跳 5 条，Ctrl+↓ 跳到底部）
• Tab          → 打开选中行的附件
• Esc          → 退出房间"#;

pub const HELP_TEXT_EN: &str = r#"Keyboard Shortcuts and Command Descriptions:

• Ctrl+X       → Smart paste clipboard text/image/files
• Ctrl+C       → Copy the currently selected message
• Ctrl+Z       → Undo in input box
• Ctrl+A       → Clear input box
• Ctrl+I       → Generate invite code
• /send <path> → Send any file as attachment
• ←/→          → Move cursor (Ctrl+← jump 3 characters, Ctrl+→ jump to end)
• ↑/↓          → Navigate list up/down (Ctrl+↑ jump 5 items, Ctrl+↓ jump to bottom)
• Tab          → Open the attachment in the selected row
• Esc          → Exit room"#;

pub const ATTACHMENT_CHUNK_SIZE: usize = 32 * 1024;
pub const ATTACHMENT_WINDOW_SIZE: usize = 3;
pub const PACKET_ACK_TIMEOUT_MS: u64 = 4500;
pub const PACKET_RETRY_LIMIT: usize = 2;
pub const INVITE_TTL_SECS: i64 = 600;
const EMPTY_FIELD_SENTINEL: &str = "~";

pub fn handshake_writeall_macro(line: String) -> Vec<u8> {
    let mut buf = line.into_bytes();
    buf.push(b'\n');
    buf
}

pub fn parse_text_img(line: &str, room_crypto: &RoomCryptoState) -> (String, String) {
    let (name, after_name) = if let Some(start) = line.find('[') {
        if let Some(end_rel) = line[start + 1..].find(']') {
            let end = start + 1 + end_rel;
            let name = line[start + 1..end].to_owned();
            let rest = &line[end + 1..];
            (name, rest)
        } else {
            ("???".into(), line)
        }
    } else {
        ("???".into(), line)
    };

    let body_slice = after_name.trim_start();
    let body_plain = room_crypto
        .open(body_slice)
        .unwrap_or_else(|| body_slice.to_owned());

    (name, body_plain)
}

pub fn parse_name_body(msg: &ChatMessage) -> (String, String, String) {
    match msg {
        ChatMessage::Text(line) => {
            let (name, after_name) = if let Some(start) = line.find('[') {
                if let Some(end_rel) = line[start + 1..].find(']') {
                    let end = start + 1 + end_rel;
                    let name = line[start + 1..end].to_owned();
                    let rest = &line[end + 1..];
                    (name, rest)
                } else {
                    ("???".into(), line.as_str())
                }
            } else {
                ("???".into(), line.as_str())
            };

            let (time, after_time) = if let Some(start) = after_name.find('[') {
                if let Some(end_rel) = after_name[start + 1..].find(']') {
                    let end = start + 1 + end_rel;
                    let time = after_name[start + 1..end].to_owned();
                    let rest = &after_name[end + 1..];
                    (time, rest)
                } else {
                    ("??:??:??".into(), after_name)
                }
            } else {
                ("??:??:??".into(), after_name)
            };

            let body_plain = after_time.trim_start().to_owned();
            (name, time, body_plain)
        }
        ChatMessage::Attachment {
            sender,
            ts,
            name,
            size,
            kind,
            ..
        } => {
            let label = match kind {
                AttachmentKind::Image => "图片",
                AttachmentKind::File => "文件",
            };
            let body = format!("[{}] {} ({})", label, name, format_file_size(*size));
            (sender.to_string(), ts.to_string(), body)
        }
    }
}

#[derive(Debug, Clone)]
pub enum OutgoingPayload {
    Text(String),
    AttachmentPath(PathBuf),
}

#[derive(Debug, Clone)]
pub struct AttachmentMeta {
    pub transfer_id: String,
    pub kind: AttachmentKind,
    pub file_name: String,
    pub total_size: u64,
    pub total_chunks: usize,
    pub sha256_hex: String,
}

#[derive(Debug, Clone)]
pub struct AttachmentChunk {
    pub transfer_id: String,
    pub index: usize,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum AttachmentFrame {
    Meta(AttachmentMeta),
    Chunk(AttachmentChunk),
}

#[derive(Debug, Clone)]
pub enum LocalUiEvent {
    TransferBegin {
        transfer_id: String,
        file_name: String,
        total_chunks: usize,
        total_size: u64,
    },
    TransferProgress {
        transfer_id: String,
        acked_chunks: usize,
        total_chunks: usize,
    },
    TransferDone {
        transfer_id: String,
    },
    TransferFailed {
        transfer_id: String,
        reason: String,
    },
    Notice(String),
}

pub fn classify_outgoing_input(msg: &str) -> Result<OutgoingPayload> {
    if is_attachment_protocol_line(msg) {
        return Ok(OutgoingPayload::Text(msg.to_string()));
    }

    if let Some(path) = explicit_send_path(msg)? {
        return Ok(OutgoingPayload::AttachmentPath(path));
    }

    let trimmed = msg.trim();
    let path = Path::new(trimmed);
    if path.is_file() {
        return Ok(OutgoingPayload::AttachmentPath(path.to_path_buf()));
    }

    Ok(OutgoingPayload::Text(msg.to_string()))
}

pub fn is_attachment_protocol_line(line: &str) -> bool {
    line.starts_with("/FILEMETA ") || line.starts_with("/FILECHUNK ")
}

pub fn infer_attachment_kind(path: &Path) -> AttachmentKind {
    let ext = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase());

    match ext.as_deref() {
        Some("png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp") => AttachmentKind::Image,
        _ => AttachmentKind::File,
    }
}

pub fn file_name_or_default(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "attachment.bin".to_string())
}

pub fn build_attachment_frames_from_bytes(
    file_name: &str,
    bytes: &[u8],
    kind: AttachmentKind,
) -> Result<Vec<String>> {
    let transfer_id = Uuid::new_v4().simple().to_string();
    let total_chunks = if bytes.is_empty() {
        0
    } else {
        bytes.len().div_ceil(ATTACHMENT_CHUNK_SIZE)
    };
    let sha256_hex = hex::encode(Sha256::digest(bytes));

    let mut frames = Vec::with_capacity(total_chunks + 1);
    frames.push(build_attachment_meta_line(
        &transfer_id,
        kind,
        file_name,
        bytes.len() as u64,
        total_chunks,
        &sha256_hex,
    ));

    for (index, chunk) in bytes.chunks(ATTACHMENT_CHUNK_SIZE).enumerate() {
        frames.push(build_attachment_chunk_line(&transfer_id, index, chunk));
    }

    Ok(frames)
}

pub fn build_attachment_meta_line(
    transfer_id: &str,
    kind: AttachmentKind,
    file_name: &str,
    total_size: u64,
    total_chunks: usize,
    sha256_hex: &str,
) -> String {
    let name_b64 = URL_SAFE_NO_PAD.encode(file_name.as_bytes());
    format!(
        "/FILEMETA {transfer_id} {} {name_b64} {total_size} {total_chunks} {sha256_hex}",
        kind.as_protocol_tag()
    )
}

pub fn build_attachment_chunk_line(transfer_id: &str, index: usize, chunk: &[u8]) -> String {
    let data_b64 = general_purpose::STANDARD.encode(chunk);
    format!("/FILECHUNK {transfer_id} {index} {data_b64}")
}

pub fn parse_attachment_frame(body: &str) -> Option<AttachmentFrame> {
    let mut parts = body.split_whitespace();
    match parts.next()? {
        "/FILEMETA" => {
            let transfer_id = parts.next()?.to_string();
            let kind = AttachmentKind::from_protocol_tag(parts.next()?)?;
            let file_name = String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next()?).ok()?).ok()?;
            let total_size = parts.next()?.parse().ok()?;
            let total_chunks = parts.next()?.parse().ok()?;
            let sha256_hex = parts.next()?.to_string();

            Some(AttachmentFrame::Meta(AttachmentMeta {
                transfer_id,
                kind,
                file_name,
                total_size,
                total_chunks,
                sha256_hex,
            }))
        }
        "/FILECHUNK" => {
            let transfer_id = parts.next()?.to_string();
            let index = parts.next()?.parse().ok()?;
            let data = general_purpose::STANDARD.decode(parts.next()?).ok()?;

            Some(AttachmentFrame::Chunk(AttachmentChunk {
                transfer_id,
                index,
                data,
            }))
        }
        _ => None,
    }
}

pub fn build_transport_packet_line(packet_id: &str, room_cipher: &str) -> String {
    let payload_b64 = URL_SAFE_NO_PAD.encode(room_cipher.as_bytes());
    format!("/PKT {packet_id} {payload_b64}")
}

pub fn parse_transport_packet_line(line: &str) -> Option<(String, String)> {
    let mut parts = line.split_whitespace();
    let head = parts.next()?;
    if head != "/PKT" {
        return None;
    }

    let packet_id = parts.next()?.to_string();
    let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next()?).ok()?).ok()?;
    Some((packet_id, payload))
}

pub fn build_ack_line(packet_id: &str) -> String {
    format!("/ACK {packet_id}")
}

pub fn parse_ack_line(line: &str) -> Option<&str> {
    line.strip_prefix("/ACK ")
        .map(str::trim)
        .filter(|id| !id.is_empty())
}

pub fn packet_id_for_text() -> String {
    format!("msg-{}", Uuid::new_v4().simple())
}

pub fn packet_id_for_attachment_meta(transfer_id: &str) -> String {
    format!("att-{transfer_id}-meta")
}

pub fn packet_id_for_attachment_chunk(transfer_id: &str, index: usize) -> String {
    format!("att-{transfer_id}-chunk-{index}")
}

pub fn build_local_transfer_begin_line(
    transfer_id: &str,
    file_name: &str,
    total_chunks: usize,
    total_size: u64,
) -> String {
    let file_b64 = URL_SAFE_NO_PAD.encode(file_name.as_bytes());
    format!("/LOCALTX BEGIN {transfer_id} {file_b64} {total_chunks} {total_size}")
}

pub fn build_local_transfer_progress_line(
    transfer_id: &str,
    acked_chunks: usize,
    total_chunks: usize,
) -> String {
    format!("/LOCALTX PROGRESS {transfer_id} {acked_chunks} {total_chunks}")
}

pub fn build_local_transfer_done_line(transfer_id: &str) -> String {
    format!("/LOCALTX DONE {transfer_id}")
}

pub fn build_local_transfer_failed_line(transfer_id: &str, reason: &str) -> String {
    let reason_b64 = URL_SAFE_NO_PAD.encode(reason.as_bytes());
    format!("/LOCALTX FAIL {transfer_id} {reason_b64}")
}

pub fn build_local_notice_line(message: &str) -> String {
    let msg_b64 = URL_SAFE_NO_PAD.encode(message.as_bytes());
    format!("/LOCALNOTICE {msg_b64}")
}

fn encode_optional_url_field(value: &str) -> String {
    if value.is_empty() {
        EMPTY_FIELD_SENTINEL.to_string()
    } else {
        URL_SAFE_NO_PAD.encode(value.as_bytes())
    }
}

fn decode_optional_url_field(value: &str) -> Option<String> {
    if value == EMPTY_FIELD_SENTINEL {
        Some(String::new())
    } else {
        String::from_utf8(URL_SAFE_NO_PAD.decode(value).ok()?).ok()
    }
}

pub fn build_local_invite_request_line(
    server_addr: &str,
    room_id: &str,
    room_credential: &str,
    owner_capability: &str,
) -> String {
    let request_id = Uuid::new_v4().simple().to_string();
    let server_b64 = encode_optional_url_field(server_addr);
    let room_b64 = URL_SAFE_NO_PAD.encode(room_id.as_bytes());
    let room_credential_b64 = encode_optional_url_field(room_credential);
    let owner_b64 = URL_SAFE_NO_PAD.encode(owner_capability.as_bytes());

    format!(
        "/LOCALINVITE REQUEST {request_id} {server_b64} {room_b64} {room_credential_b64} {owner_b64}"
    )
}

#[derive(Debug, Clone)]
pub struct LocalInviteRequest {
    pub request_id: String,
    pub server_addr: String,
    pub room_id: String,
    pub room_credential: String,
    pub owner_capability: String,
}

pub fn parse_local_invite_request_line(line: &str) -> Option<LocalInviteRequest> {
    let mut parts = line.split_whitespace();
    if parts.next()? != "/LOCALINVITE" || parts.next()? != "REQUEST" {
        return None;
    }

    let request_id = parts.next()?.to_string();
    let server_addr = decode_optional_url_field(parts.next()?)?;
    let room_id = String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next()?).ok()?).ok()?;
    let room_credential = decode_optional_url_field(parts.next()?)?;
    let owner_capability = String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next()?).ok()?).ok()?;

    Some(LocalInviteRequest {
        request_id,
        server_addr,
        room_id,
        room_credential,
        owner_capability,
    })
}

pub fn build_server_invite_request_line(
    request_id: &str,
    room_id: &str,
    owner_capability: &str,
    blob_b64: &str,
) -> String {
    let room_b64 = URL_SAFE_NO_PAD.encode(room_id.as_bytes());
    let owner_b64 = URL_SAFE_NO_PAD.encode(owner_capability.as_bytes());
    format!("/INVITE_REQUEST {request_id} {room_b64} {owner_b64} {blob_b64}")
}

#[derive(Debug, Clone)]
pub struct ServerInviteRequest {
    pub request_id: String,
    pub room_id: String,
    pub owner_capability: String,
    pub blob_b64: String,
}

pub fn parse_server_invite_request_line(line: &str) -> Option<ServerInviteRequest> {
    let mut parts = line.split_whitespace();
    if parts.next()? != "/INVITE_REQUEST" {
        return None;
    }

    let request_id = parts.next()?.to_string();
    let room_id = String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next()?).ok()?).ok()?;
    let owner_capability = String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next()?).ok()?).ok()?;
    let blob_b64 = parts.next()?.to_string();
    Some(ServerInviteRequest {
        request_id,
        room_id,
        owner_capability,
        blob_b64,
    })
}

pub fn build_invite_token_line(request_id: &str, token_secret_b64: &str, expires_at: i64) -> String {
    format!("/INVITE_TOKEN {request_id} {token_secret_b64} {expires_at}")
}

pub fn parse_invite_token_line(line: &str) -> Option<(String, String, i64)> {
    let mut parts = line.split_whitespace();
    if parts.next()? != "/INVITE_TOKEN" {
        return None;
    }

    let request_id = parts.next()?.to_string();
    let token_secret_b64 = parts.next()?.to_string();
    let expires_at = parts.next()?.parse().ok()?;
    Some((request_id, token_secret_b64, expires_at))
}

pub fn build_invite_error_line(request_id: &str, reason: &str) -> String {
    let reason_b64 = URL_SAFE_NO_PAD.encode(reason.as_bytes());
    format!("/INVITE_ERROR {request_id} {reason_b64}")
}

pub fn parse_invite_error_line(line: &str) -> Option<(String, String)> {
    let mut parts = line.split_whitespace();
    if parts.next()? != "/INVITE_ERROR" {
        return None;
    }

    let request_id = parts.next()?.to_string();
    let reason = String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next()?).ok()?).ok()?;
    Some((request_id, reason))
}

pub fn build_auth_hello_line(client_nonce_hex: &str) -> String {
    format!("/AUTH_HELLO {client_nonce_hex}")
}

pub fn parse_auth_hello_line(line: &str) -> Option<String> {
    line.strip_prefix("/AUTH_HELLO ")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub fn build_auth_challenge_line(server_nonce_hex: &str) -> String {
    format!("/AUTH_CHALLENGE {server_nonce_hex}")
}

pub fn parse_auth_challenge_line(line: &str) -> Option<String> {
    line.strip_prefix("/AUTH_CHALLENGE ")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub fn build_auth_proof_line(proof_hex: &str) -> String {
    format!("/AUTH_PROOF {proof_hex}")
}

pub fn parse_auth_proof_line(line: &str) -> Option<String> {
    line.strip_prefix("/AUTH_PROOF ")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub fn build_invite_hello_line(token_id_hex: &str, client_nonce_hex: &str) -> String {
    format!("/INVITE_HELLO {token_id_hex} {client_nonce_hex}")
}

pub fn parse_invite_hello_line(line: &str) -> Option<(String, String)> {
    let mut parts = line.split_whitespace();
    if parts.next()? != "/INVITE_HELLO" {
        return None;
    }
    Some((parts.next()?.to_string(), parts.next()?.to_string()))
}

pub fn build_invite_challenge_line(server_nonce_hex: &str) -> String {
    format!("/INVITE_CHALLENGE {server_nonce_hex}")
}

pub fn parse_invite_challenge_line(line: &str) -> Option<String> {
    line.strip_prefix("/INVITE_CHALLENGE ")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub fn build_invite_proof_line(proof_hex: &str) -> String {
    format!("/INVITE_PROOF {proof_hex}")
}

pub fn parse_invite_proof_line(line: &str) -> Option<String> {
    line.strip_prefix("/INVITE_PROOF ")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub fn build_invite_ok_line(room_id: &str, blob_b64: &str) -> String {
    let room_b64 = URL_SAFE_NO_PAD.encode(room_id.as_bytes());
    format!("INVITE_OK {room_b64} {blob_b64}")
}

pub fn parse_invite_ok_line(line: &str) -> Option<(String, String)> {
    let mut parts = line.split_whitespace();
    if parts.next()? != "INVITE_OK" {
        return None;
    }
    let room_id = String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next()?).ok()?).ok()?;
    let blob_b64 = parts.next()?.to_string();
    Some((room_id, blob_b64))
}

pub fn build_invite_ready_line(nickname: &str) -> String {
    let nickname_b64 = URL_SAFE_NO_PAD.encode(nickname.as_bytes());
    format!("/INVITE_READY {nickname_b64}")
}

pub fn parse_invite_ready_line(line: &str) -> Option<String> {
    let encoded = line.strip_prefix("/INVITE_READY ")?;
    String::from_utf8(URL_SAFE_NO_PAD.decode(encoded.trim()).ok()?).ok()
}

pub fn parse_local_ui_event(line: &str) -> Option<LocalUiEvent> {
    if let Some(encoded) = line.strip_prefix("/LOCALNOTICE ") {
        let message = String::from_utf8(URL_SAFE_NO_PAD.decode(encoded.trim()).ok()?).ok()?;
        return Some(LocalUiEvent::Notice(message));
    }

    let mut parts = line.split_whitespace();
    if parts.next()? != "/LOCALTX" {
        return None;
    }

    match parts.next()? {
        "BEGIN" => {
            let transfer_id = parts.next()?.to_string();
            let file_name = String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next()?).ok()?).ok()?;
            let total_chunks = parts.next()?.parse().ok()?;
            let total_size = parts.next()?.parse().ok()?;
            Some(LocalUiEvent::TransferBegin {
                transfer_id,
                file_name,
                total_chunks,
                total_size,
            })
        }
        "PROGRESS" => {
            let transfer_id = parts.next()?.to_string();
            let acked_chunks = parts.next()?.parse().ok()?;
            let total_chunks = parts.next()?.parse().ok()?;
            Some(LocalUiEvent::TransferProgress {
                transfer_id,
                acked_chunks,
                total_chunks,
            })
        }
        "DONE" => Some(LocalUiEvent::TransferDone {
            transfer_id: parts.next()?.to_string(),
        }),
        "FAIL" => {
            let transfer_id = parts.next()?.to_string();
            let reason = String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next()?).ok()?).ok()?;
            Some(LocalUiEvent::TransferFailed { transfer_id, reason })
        }
        _ => None,
    }
}

pub fn sanitize_attachment_name(name: &str) -> String {
    let cleaned = Path::new(name)
        .file_name()
        .and_then(|raw| raw.to_str())
        .unwrap_or("attachment.bin")
        .trim()
        .chars()
        .map(|ch| match ch {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect::<String>();

    if cleaned.is_empty() {
        format!("attachment-{}.bin", Uuid::new_v4().simple())
    } else {
        cleaned
    }
}

pub fn format_file_size(size: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    match size {
        0..=1023 => format!("{size} B"),
        1024..=1_048_575 => format!("{:.1} KB", size as f64 / KB),
        1_048_576..=1_073_741_823 => format!("{:.1} MB", size as f64 / MB),
        _ => format!("{:.1} GB", size as f64 / GB),
    }
}

pub fn render_transfer_line(
    file_name: &str,
    total_size: u64,
    stage: TransferStage,
    acked_chunks: usize,
    total_chunks: usize,
    detail: Option<&str>,
) -> String {
    let status = match stage {
        TransferStage::Sending => {
            if total_chunks == 0 {
                "sending 0%".to_string()
            } else {
                let pct = (acked_chunks.saturating_mul(100)) / total_chunks.max(1);
                format!("sending {pct}%")
            }
        }
        TransferStage::Done => "done".to_string(),
        TransferStage::Failed => "failed".to_string(),
    };

    let mut line = format!("{status} | {file_name} | {}", format_file_size(total_size));
    if let Some(detail) = detail.filter(|s| !s.trim().is_empty()) {
        line.push_str(" | ");
        line.push_str(detail);
    }
    line
}

fn explicit_send_path(msg: &str) -> Result<Option<PathBuf>> {
    let Some(rest) = msg.strip_prefix("/send ") else {
        return Ok(None);
    };

    let raw = rest.trim();
    if raw.is_empty() {
        return Err(anyhow!("Usage: /send <path>"));
    }

    let normalized = strip_optional_quotes(raw);
    let path = PathBuf::from(normalized);
    if !path.is_file() {
        return Err(anyhow!("Attachment not found: {}", path.display()));
    }

    Ok(Some(path))
}

fn strip_optional_quotes(input: &str) -> &str {
    if input.len() >= 2 && input.starts_with('"') && input.ends_with('"') {
        &input[1..input.len() - 1]
    } else {
        input
    }
}

pub fn encode_rgba_as_png(rgba: &[u8], w: u32, h: u32) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();

    PngEncoder::new(&mut buf).write_image(rgba, w, h, ColorType::Rgba8.into())?;

    Ok(buf)
}

pub fn normalize_clipboard_rgba(bytes: &[u8], w: u32, h: u32) -> anyhow::Result<Vec<u8>> {
    let expected_len = (w as usize)
        .checked_mul(h as usize)
        .and_then(|px| px.checked_mul(4))
        .ok_or_else(|| anyhow!("Clipboard image dimensions are too large"))?;

    if bytes.len() != expected_len {
        return Err(anyhow!(
            "Clipboard image buffer size mismatch: expected {expected_len}, got {}",
            bytes.len()
        ));
    }

    let mut rgba = bytes.to_vec();
    let all_alpha_zero = rgba.chunks_exact(4).all(|px| px[3] == 0);

    if all_alpha_zero {
        for px in rgba.chunks_exact_mut(4) {
            px[3] = 255;
        }
    }

    Ok(rgba)
}

pub fn parse_clipboard_file_paths(text: &str) -> Option<Vec<PathBuf>> {
    let mut paths = Vec::new();

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        let normalized = strip_optional_quotes(line);
        let path = PathBuf::from(normalized);
        if !path.is_absolute() || !path.is_file() {
            return None;
        }
        paths.push(path);
    }

    if paths.is_empty() {
        None
    } else {
        Some(paths)
    }
}

#[derive(Serialize, Deserialize)]
struct InvitePayload {
    room_id: String,
    room_credential: String,
}

pub fn create_invite_blob(
    room_id: String,
    room_credential: String,
) -> Result<(String, String)> {
    let mut nonce = [0u8; 12];
    let mut blob_key = [0u8; 16];
    rand::rng().fill_bytes(&mut nonce);
    rand::rng().fill_bytes(&mut blob_key);

    let payload = InvitePayload {
        room_id,
        room_credential,
    };

    let key_bytes = Sha256::digest(blob_key);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), serde_json::to_vec(&payload)?.as_ref())
        .map_err(|_| anyhow!("Failed to encrypt invite blob"))?;

    let mut out = Vec::with_capacity(nonce.len() + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok((
        URL_SAFE_NO_PAD.encode(out),
        URL_SAFE_NO_PAD.encode(blob_key),
    ))
}

pub fn open_invite_blob(blob_b64: &str, blob_key_b64: &str) -> Option<(String, String)> {
    let bytes = URL_SAFE_NO_PAD.decode(blob_b64).ok()?;
    let blob_key = URL_SAFE_NO_PAD.decode(blob_key_b64).ok()?;

    if bytes.len() < 12 || blob_key.len() != 16 {
        return None;
    }

    let (nonce, cipher_bytes) = bytes.split_at(12);
    let key_bytes = Sha256::digest(&blob_key);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let plain = cipher.decrypt(Nonce::from_slice(nonce), cipher_bytes).ok()?;

    serde_json::from_slice::<InvitePayload>(&plain)
        .map(|payload| (payload.room_id, payload.room_credential))
        .ok()
}

pub fn create_invitation(
    server_addr: String,
    invite_token: String,
    blob_key_b64: String,
) -> Result<String> {
    let server_b64 = URL_SAFE_NO_PAD.encode(server_addr.as_bytes());
    Ok(format!("/INVITE:{server_b64}.{invite_token}.{blob_key_b64}"))
}

pub fn parse_invitation(inv: &str) -> Option<(String, String, String)> {
    let raw = inv.strip_prefix("/INVITE:")?;
    let mut parts = raw.splitn(3, '.');
    let server_addr = String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next()?).ok()?).ok()?;
    let invite_token = parts.next()?.to_string();
    let blob_key_b64 = parts.next()?.to_string();
    Some((server_addr, invite_token, blob_key_b64))
}

pub fn inviation_clear(inv: &str) -> String {
    if inv.starts_with("/INVITE:") {
        String::new()
    } else {
        inv.to_string()
    }
}

pub async fn read_file_bytes(path: &Path) -> Result<Vec<u8>> {
    Ok(fs::read(path).await?)
}
