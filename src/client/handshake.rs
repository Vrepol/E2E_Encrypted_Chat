use anyhow::{anyhow, Result};
use base64::Engine;
use rand::{distr::Alphanumeric, Rng, RngCore};
use std::{
    io::{self, IsTerminal},
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines},
    net::TcpStream,
};

use super::session::ConnectedSession;
use crate::crypto::invite::{open_invite_blob, parse_invitation};
use crate::crypto::{
    compute_invite_proof, compute_invite_token_id, compute_password_auth_proof,
    derive_invite_transport_key, derive_password_transport_key, pwd_hash,
    random_group_secret_epoch_0, GroupCryptoState, RoomCryptoState, TransportCrypto,
    TransportOpenResult, TransportSide,
};
use crate::protocol::{
    build_auth_hello_line, build_auth_proof_line, build_invite_hello_line, build_invite_proof_line,
    build_invite_ready_line, line_bytes, parse_auth_challenge_line, parse_invite_challenge_line,
    parse_invite_ok_line, parse_session_ok_line, MemberIdentity,
};
use crate::ui::banner;

pub async fn connect_and_login(
    server_addr_or_invite: &str,
    nickname: &str,
) -> Result<ConnectedSession> {
    if server_addr_or_invite.starts_with("/INVITE:") {
        return connect_with_invite(server_addr_or_invite, nickname).await;
    }

    connect_with_password(server_addr_or_invite, nickname).await
}

pub async fn connect_for_test(
    server_addr: &str,
    password: &str,
    nickname: &str,
    room_id: &str,
    room_credential: &str,
    action: &'static str,
) -> Result<ConnectedSession> {
    let start = start_password_session(server_addr, password).await?;
    finish_password_room_join(
        start,
        nickname,
        room_id.to_string(),
        room_credential.to_string(),
        action,
    )
    .await
}

async fn connect_with_invite(
    server_addr_or_invite: &str,
    nickname: &str,
) -> Result<ConnectedSession> {
    let (server_addr, token_secret_b64, blob_key_b64) =
        parse_invitation(server_addr_or_invite).ok_or_else(|| anyhow!("Invalid invitation"))?;
    let token_secret = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token_secret_b64.as_bytes())
        .map_err(|_| anyhow!("Invalid invitation token"))?;
    let token_id = compute_invite_token_id(&token_secret);
    let client_nonce = random_nonce32();

    let stream = TcpStream::connect(&server_addr).await?;
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    writer
        .write_all(
            line_bytes(build_invite_hello_line(
                &hex::encode(token_id),
                &hex::encode(client_nonce),
            ))
            .as_slice(),
        )
        .await?;

    let challenge = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow!("Server closed during invite challenge"))?;
    if challenge.starts_with("ERR ") {
        return Err(anyhow!("邀请码无效或已过期"));
    }
    let server_nonce_hex = parse_invite_challenge_line(&challenge)
        .ok_or_else(|| anyhow!("Invalid invite challenge"))?;
    let server_nonce = decode_hex_32(&server_nonce_hex)?;
    let transport_key =
        derive_invite_transport_key(&token_secret, &token_id, &client_nonce, &server_nonce);
    let proof = compute_invite_proof(&token_secret, &token_id, &client_nonce, &server_nonce);

    writer
        .write_all(line_bytes(build_invite_proof_line(&hex::encode(proof))).as_slice())
        .await?;

    let mut transport = TransportCrypto::new(transport_key, TransportSide::Client);
    let invite_ok_cipher = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow!("Server closed during invite auth"))?;
    let invite_ok = expect_fresh_transport_line(&mut transport, &invite_ok_cipher)
        .ok_or_else(|| anyhow!("Invalid encrypted invite response"))?;
    let (_room_id_from_server, blob_b64) =
        parse_invite_ok_line(&invite_ok).ok_or_else(|| anyhow!("Invalid INVITE_OK"))?;
    let (room_id, room_credential) = open_invite_blob(&blob_b64, &blob_key_b64)
        .ok_or_else(|| anyhow!("Invalid invitation blob"))?;
    let room_crypto = RoomCryptoState::from_room_credential(room_id, room_credential);

    let ready_line = build_invite_ready_line(nickname);
    let ready_cipher = transport.seal(&ready_line);
    writer
        .write_all(line_bytes(ready_cipher).as_slice())
        .await?;

    let ok_cipher = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow!("Server closed during invite finalize"))?;
    let ok_plain = expect_fresh_transport_line(&mut transport, &ok_cipher)
        .ok_or_else(|| anyhow!("Invalid encrypted invite finalize response"))?;
    let (member_id, owner_capability) = parse_session_ok_line(&ok_plain)
        .ok_or_else(|| anyhow!("Server refused invite: {ok_plain}"))?;
    if owner_capability.is_some() {
        return Err(anyhow!("Server refused invite: {ok_plain}"));
    }
    let group_crypto = GroupCryptoState::new_pending_epoch(
        room_crypto.room_id().to_string(),
        member_id.clone(),
        nickname.to_string(),
        0,
        room_crypto.room_auth_key(),
    )?;

    Ok(ConnectedSession {
        lines,
        writer,
        server_addr,
        room_crypto,
        group_crypto: Arc::new(Mutex::new(group_crypto)),
        transport: Arc::new(Mutex::new(transport)),
        local_member: MemberIdentity {
            member_id,
            nickname: nickname.to_string(),
        },
        owner_capability: None,
    })
}

async fn connect_with_password(
    server_addr_or_invite: &str,
    nickname: &str,
) -> Result<ConnectedSession> {
    let mut iter = server_addr_or_invite.splitn(2, '&');
    let server_addr = iter.next().unwrap_or("").to_string();
    let password = iter.next().unwrap_or("");
    let start = start_password_session(&server_addr, password).await?;
    let rooms = start.rooms.clone();

    let (room_id, room_credential, action) =
        prompt_session_selection(nickname, &start.server_addr, &rooms)?;
    finish_password_room_join(start, nickname, room_id, room_credential, action).await
}

struct PasswordLoginStart {
    lines: Lines<BufReader<tokio::net::tcp::OwnedReadHalf>>,
    writer: tokio::net::tcp::OwnedWriteHalf,
    server_addr: String,
    transport: TransportCrypto,
    rooms: Vec<String>,
}

async fn start_password_session(server_addr: &str, password: &str) -> Result<PasswordLoginStart> {
    let server_pwd_hash = pwd_hash(password);
    let client_nonce = random_nonce32();

    let stream = TcpStream::connect(server_addr).await?;
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    writer
        .write_all(line_bytes(build_auth_hello_line(&hex::encode(client_nonce))).as_slice())
        .await?;

    let challenge = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow!("Server closed during auth challenge"))?;
    if challenge.starts_with("ERR ") {
        return Err(anyhow!("Server declined: {challenge}"));
    }
    let server_nonce_hex =
        parse_auth_challenge_line(&challenge).ok_or_else(|| anyhow!("Invalid auth challenge"))?;
    let server_nonce = decode_hex_32(&server_nonce_hex)?;
    let transport_key =
        derive_password_transport_key(&server_pwd_hash, &client_nonce, &server_nonce);
    let proof = compute_password_auth_proof(&server_pwd_hash, &client_nonce, &server_nonce);

    writer
        .write_all(line_bytes(build_auth_proof_line(&hex::encode(proof))).as_slice())
        .await?;

    let mut transport = TransportCrypto::new(transport_key, TransportSide::Client);
    let ok_cipher = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow!("Server closed during auth"))?;
    let ok_plain = expect_fresh_transport_line(&mut transport, &ok_cipher)
        .ok_or_else(|| anyhow!("Invalid encrypted auth response"))?;
    if ok_plain.trim() != "OK" {
        return Err(anyhow!("Server declined: {ok_plain}"));
    }

    let rooms_cipher = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow!("Server closed during room banner"))?;
    let rooms_plain = expect_fresh_transport_line(&mut transport, &rooms_cipher)
        .ok_or_else(|| anyhow!("Invalid encrypted room banner"))?;
    if !rooms_plain.starts_with("ROOMS") {
        return Err(anyhow!("unexpected banner: {rooms_plain}"));
    }
    let rooms = rooms_plain
        .split_whitespace()
        .skip(1)
        .map(|s| s.to_owned())
        .collect();

    Ok(PasswordLoginStart {
        lines,
        writer,
        server_addr: server_addr.to_string(),
        transport,
        rooms,
    })
}

async fn finish_password_room_join(
    mut start: PasswordLoginStart,
    nickname: &str,
    room_id: String,
    room_credential: String,
    action: &'static str,
) -> Result<ConnectedSession> {
    let room_crypto = RoomCryptoState::from_room_credential(room_id, room_credential);
    let join_credential = room_crypto.join_credential();
    let join_plain = format!(
        "{action} {} {join_credential} {nickname}",
        room_crypto.room_id()
    );
    let join_cipher = start.transport.seal(&join_plain);
    start
        .writer
        .write_all(line_bytes(join_cipher).as_slice())
        .await?;

    let response_cipher = start
        .lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow!("Server closed during room join"))?;
    let response_plain = expect_fresh_transport_line(&mut start.transport, &response_cipher)
        .ok_or_else(|| anyhow!("Invalid encrypted room join response"))?;
    let (member_id, owner_capability) = parse_session_ok_line(&response_plain)
        .ok_or_else(|| anyhow!("server refused: {response_plain}"))?;
    let group_crypto = if action == "CREATE" {
        GroupCryptoState::new_single_epoch(
            room_crypto.room_id().to_string(),
            member_id.clone(),
            nickname.to_string(),
            0,
            random_group_secret_epoch_0(),
            room_crypto.room_auth_key(),
        )?
    } else {
        GroupCryptoState::new_pending_epoch(
            room_crypto.room_id().to_string(),
            member_id.clone(),
            nickname.to_string(),
            0,
            room_crypto.room_auth_key(),
        )?
    };

    Ok(ConnectedSession {
        lines: start.lines,
        writer: start.writer,
        server_addr: start.server_addr,
        room_crypto,
        group_crypto: Arc::new(Mutex::new(group_crypto)),
        transport: Arc::new(Mutex::new(start.transport)),
        local_member: MemberIdentity {
            member_id,
            nickname: nickname.to_string(),
        },
        owner_capability,
    })
}

fn prompt_session_selection(
    nickname: &str,
    server_addr: &str,
    rooms: &[String],
) -> Result<(String, String, &'static str)> {
    let mut notice: Option<String> = None;

    loop {
        render_session_selection(nickname, server_addr, rooms, notice.as_deref())?;
        let id = read_trimmed_line()?;

        if id.eq_ignore_ascii_case("/q") {
            return Err(anyhow!("断开服务器"));
        }

        let (session_id, session_key, action) = if id.eq_ignore_ascii_case("new") || id == "'" {
            (random_session_id(), random_session_key(), "CREATE")
        } else {
            let session_id = if id.is_empty() {
                "Public".to_string()
            } else if let Ok(idx) = id.parse::<usize>() {
                match rooms.get(idx.saturating_sub(1)) {
                    Some(room) => room.clone(),
                    None => {
                        notice = Some("Unknown session number.".to_string());
                        continue;
                    }
                }
            } else {
                id
            };
            if session_id.trim().is_empty() {
                notice = Some("Session ID cannot be empty.".to_string());
                continue;
            }

            if session_id == "Public" {
                let action = if rooms.iter().any(|room| room == &session_id) {
                    "JOIN"
                } else {
                    "CREATE"
                };
                (session_id, String::new(), action)
            } else {
                banner::prompt("Session key", "[hidden]")?;
                let session_key = read_secret_line()?;
                if session_key.trim().is_empty() {
                    notice = Some("Private sessions need a key.".to_string());
                    continue;
                }
                let action = if rooms.iter().any(|room| room == &session_id) {
                    "JOIN"
                } else {
                    "CREATE"
                };
                (session_id, session_key, action)
            }
        };

        return Ok((session_id, session_key, action));
    }
}

fn render_session_selection(
    nickname: &str,
    server_addr: &str,
    rooms: &[String],
    notice: Option<&str>,
) -> io::Result<()> {
    banner::clear_screen()?;
    banner::print_banner();
    banner::summary("Profile", nickname);
    banner::summary("Server", server_addr);
    if let Some(notice) = notice {
        banner::warning(notice);
    }
    banner::section(
        "Session",
        "Join an active session, create one, or press Enter for Public.",
    );
    if rooms.is_empty() {
        banner::note("No active sessions.");
    } else {
        for (idx, room) in rooms.iter().enumerate() {
            banner::option(idx + 1, room, "");
        }
    }
    banner::option("new", "Create private session", "random ID and key");
    banner::option("/q", "Disconnect", "");
    banner::prompt("Session ID", "[Public]")
}

fn read_trimmed_line() -> io::Result<String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn read_secret_line() -> io::Result<String> {
    if io::stdin().is_terminal() {
        rpassword::read_password()
    } else {
        read_trimmed_line()
    }
}

fn random_session_id() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(9)
        .map(char::from)
        .collect()
}

fn random_session_key() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_@#";
    (0..32)
        .map(|_| {
            let idx = rand::rng().random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

fn random_nonce32() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

fn decode_hex_32(value: &str) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(value, &mut out).map_err(|_| anyhow!("Invalid 32-byte hex field"))?;
    Ok(out)
}

fn expect_fresh_transport_line(
    transport: &mut TransportCrypto,
    cipher_line: &str,
) -> Option<String> {
    match transport.open(cipher_line)? {
        TransportOpenResult::Fresh(plain) => Some(plain),
        TransportOpenResult::Duplicate(_) => None,
    }
}
