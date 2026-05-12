use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

pub const INVITE_TTL_SECS: i64 = 600;

#[derive(Debug, Clone)]
pub struct ServerInviteRequest {
    pub request_id: String,
    pub room_id: String,
    pub owner_capability: String,
    pub blob_b64: String,
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

pub fn build_invite_token_line(
    request_id: &str,
    token_secret_b64: &str,
    expires_at: i64,
) -> String {
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

pub fn build_session_ok_line(member_id: &str, owner_capability: Option<&str>) -> String {
    let member_b64 = URL_SAFE_NO_PAD.encode(member_id.as_bytes());
    match owner_capability {
        Some(owner_capability) => format!("OK MEMBER {member_b64} OWNER {owner_capability}"),
        None => format!("OK MEMBER {member_b64}"),
    }
}

pub fn parse_session_ok_line(line: &str) -> Option<(String, Option<String>)> {
    let mut parts = line.split_whitespace();
    if parts.next()? != "OK" || parts.next()? != "MEMBER" {
        return None;
    }
    let member_id = String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next()?).ok()?).ok()?;
    let owner_capability = match parts.next() {
        Some("OWNER") => parts.next().map(|s| s.to_string()),
        None => None,
        _ => return None,
    };
    Some((member_id, owner_capability))
}
