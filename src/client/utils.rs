use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use base64::{
    engine::general_purpose,
    engine::general_purpose::URL_SAFE_NO_PAD,
    Engine as _,
};
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};
use chrono::Utc;
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

use super::crypto::{open, server_seal};
use super::receiver::{AttachmentKind, ChatMessage, TransferStage};

pub const HELP_TEXT: &str = r#"快捷键与命令说明：

• Ctrl+X       → 贴入剪贴板文本/图片
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

• Ctrl+X       → Paste clipboard text/image
• Ctrl+C       → Copy the currently selected message
• Ctrl+Z       → Undo in input box
• Ctrl+A       → Clear input box
• Ctrl+I       → Generate invite code
• /send <path> → Send any file as attachment
• ←/→          → Move cursor (Ctrl+← jump 3 characters, Ctrl+→ jump to end)
• ↑/↓          → Navigate list up/down (Ctrl+↑ jump 5 items, Ctrl+↓ jump to bottom)
• Tab          → Open the attachment in the selected row
• Esc          → Exit room"#;

pub const ATTACHMENT_CHUNK_SIZE: usize = 8 * 1024;
pub const PACKET_ACK_TIMEOUT_MS: u64 = 1500;
pub const PACKET_RETRY_LIMIT: usize = 3;

pub fn handshake_writeall_macro(line: String) -> Vec<u8> {
    let mut buf = server_seal(line).into_bytes();
    buf.push(b'\n');
    buf
}

pub fn parse_text_img(line: &str) -> (String, String) {
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
    let body_plain = open(body_slice).unwrap_or_else(|| body_slice.to_owned());

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

            let body_slice = after_time.trim_start();
            let body_plain = open(body_slice).unwrap_or_else(|| body_slice.to_owned());

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

#[derive(Serialize, Deserialize)]
struct Invite {
    server: String,
    enc_pwd: [u8; 32],
    room_id: String,
    room_key: String,
}

pub const PERIOD_SECS: i64 = 500;

fn derive_invite_key() -> [u8; 32] {
    let period_id = Utc::now().timestamp() / PERIOD_SECS;
    let bytes = period_id.to_be_bytes();
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = bytes[i % bytes.len()];
    }
    key
}

pub fn create_invitation(
    server_addr: String,
    server_pwd: String,
    room_id: String,
    pwd: String,
) -> Result<String, Box<dyn std::error::Error>> {
    let key = derive_invite_key();

    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    use super::crypto::pwd_hash;
    let auth = pwd_hash(&server_pwd);

    let inv = Invite {
        server: server_addr,
        enc_pwd: auth,
        room_id,
        room_key: pwd,
    };

    let mut buf = serde_json::to_vec(&inv)?;
    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    cipher.apply_keystream(&mut buf);

    let mut out = Vec::with_capacity(nonce.len() + buf.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    Ok(URL_SAFE_NO_PAD.encode(out))
}

pub fn parse_invitation(inv: &str) -> Option<(String, [u8; 32], String, String)> {
    let raw = inv.strip_prefix("/INVITE:")?;

    let bytes = match URL_SAFE_NO_PAD.decode(raw) {
        Ok(v) => v,
        Err(_) => {
            if raw.chars().all(|c| c.is_ascii_hexdigit()) {
                hex::decode(raw).ok()?
            } else {
                return None;
            }
        }
    };

    if bytes.len() < 12 {
        return None;
    }
    let (nonce, cipher) = bytes.split_at(12);

    let key = derive_invite_key();
    let mut buf = cipher.to_vec();
    let mut chacha = ChaCha20::new(&key.into(), nonce.into());
    chacha.apply_keystream(&mut buf);

    serde_json::from_slice::<Invite>(&buf)
        .map(|v| (v.server, v.enc_pwd, v.room_id, v.room_key))
        .ok()
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
