use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{de::DeserializeOwned, Serialize};

pub fn line_bytes(line: impl AsRef<str>) -> Vec<u8> {
    let mut buf = line.as_ref().as_bytes().to_vec();
    buf.push(b'\n');
    buf
}

pub fn parse_display_body(line: &str) -> (String, String) {
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

    (name, after_name.trim_start().to_string())
}

pub fn build_transport_packet_line(packet_id: &str, payload: &str) -> String {
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
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

pub fn build_rmsg_line<T: Serialize>(message: &T) -> Result<String> {
    build_tagged_json_line("/RMSG", message)
}

pub fn parse_rmsg_line<T: DeserializeOwned>(line: &str) -> Option<T> {
    parse_tagged_json_line("/RMSG ", line)
}

pub fn build_key_announce_line<T: Serialize>(announce: &T) -> Result<String> {
    build_tagged_json_line("/KEY_ANNOUNCE", announce)
}

pub fn parse_key_announce_line<T: DeserializeOwned>(line: &str) -> Option<T> {
    parse_tagged_json_line("/KEY_ANNOUNCE ", line)
}

pub fn build_epoch_commit_line<T: Serialize>(commit: &T) -> Result<String> {
    build_tagged_json_line("/EPOCH_COMMIT", commit)
}

pub fn parse_epoch_commit_line<T: DeserializeOwned>(line: &str) -> Option<T> {
    parse_tagged_json_line("/EPOCH_COMMIT ", line)
}

pub fn is_epoch_control_line(line: &str) -> bool {
    line.starts_with("/KEY_ANNOUNCE ") || line.starts_with("/EPOCH_COMMIT ")
}

fn build_tagged_json_line<T: Serialize>(tag: &str, value: &T) -> Result<String> {
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(value)?);
    Ok(format!("{tag} {encoded}"))
}

fn parse_tagged_json_line<T: DeserializeOwned>(prefix: &str, line: &str) -> Option<T> {
    let payload = line.strip_prefix(prefix)?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload.trim()).ok()?).ok()
}
