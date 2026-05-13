use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use uuid::Uuid;

use crate::protocol::attachment::AttachmentKind;

const EMPTY_FIELD_SENTINEL: &str = "~";

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
    EchoText {
        body: String,
    },
    EchoAttachment {
        attachment_id: String,
        file_name: String,
        total_size: u64,
        kind: AttachmentKind,
    },
    Notice(String),
}

#[derive(Debug, Clone)]
pub struct LocalInviteRequest {
    pub request_id: String,
    pub server_addr: String,
    pub room_id: String,
    pub room_credential: String,
    pub owner_capability: String,
}

#[derive(Debug, Clone)]
pub struct LocalAttachmentSend {
    pub file_name: String,
    pub kind: AttachmentKind,
    pub bytes: Vec<u8>,
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

pub fn build_local_echo_text_line(body: &str) -> String {
    let body_b64 = URL_SAFE_NO_PAD.encode(body.as_bytes());
    format!("/LOCALECHO TEXT {body_b64}")
}

pub fn build_local_echo_attachment_line(
    attachment_id: &str,
    file_name: &str,
    total_size: u64,
    kind: AttachmentKind,
) -> String {
    let attachment_b64 = URL_SAFE_NO_PAD.encode(attachment_id.as_bytes());
    let file_b64 = URL_SAFE_NO_PAD.encode(file_name.as_bytes());
    format!(
        "/LOCALECHO ATTACHMENT {attachment_b64} {file_b64} {total_size} {}",
        kind.as_protocol_tag()
    )
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

pub fn build_local_attachment_send_line(
    file_name: &str,
    kind: AttachmentKind,
    bytes: &[u8],
) -> String {
    let file_b64 = URL_SAFE_NO_PAD.encode(file_name.as_bytes());
    let bytes_b64 = URL_SAFE_NO_PAD.encode(bytes);
    format!(
        "/LOCALATTACH SEND {file_b64} {} {bytes_b64}",
        kind.as_protocol_tag()
    )
}

pub fn parse_local_attachment_send_line(line: &str) -> Option<LocalAttachmentSend> {
    let mut parts = line.split_whitespace();
    if parts.next()? != "/LOCALATTACH" || parts.next()? != "SEND" {
        return None;
    }

    let file_name = String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next()?).ok()?).ok()?;
    let kind = AttachmentKind::from_protocol_tag(parts.next()?)?;
    let bytes = URL_SAFE_NO_PAD.decode(parts.next()?).ok()?;
    Some(LocalAttachmentSend {
        file_name,
        kind,
        bytes,
    })
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

pub fn parse_local_ui_event(line: &str) -> Option<LocalUiEvent> {
    if let Some(encoded) = line.strip_prefix("/LOCALNOTICE ") {
        let message = String::from_utf8(URL_SAFE_NO_PAD.decode(encoded.trim()).ok()?).ok()?;
        return Some(LocalUiEvent::Notice(message));
    }

    if let Some(payload) = line.strip_prefix("/LOCALECHO ") {
        let mut parts = payload.split_whitespace();
        return match parts.next()? {
            "TEXT" => {
                let body = String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next()?).ok()?).ok()?;
                Some(LocalUiEvent::EchoText { body })
            }
            "ATTACHMENT" => {
                let attachment_id =
                    String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next()?).ok()?).ok()?;
                let file_name =
                    String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next()?).ok()?).ok()?;
                let total_size = parts.next()?.parse().ok()?;
                let kind = AttachmentKind::from_protocol_tag(parts.next()?)?;
                Some(LocalUiEvent::EchoAttachment {
                    attachment_id,
                    file_name,
                    total_size,
                    kind,
                })
            }
            _ => None,
        };
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
            Some(LocalUiEvent::TransferFailed {
                transfer_id,
                reason,
            })
        }
        _ => None,
    }
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
