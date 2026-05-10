use anyhow::{anyhow, Result};
use base64::Engine;
use colored::*;
use rand::{distr::Alphanumeric, Rng, RngCore};
use rpassword::read_password;
use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines},
    net::TcpStream,
};

use super::crypto::{
    compute_invite_proof, compute_invite_token_id, compute_password_auth_proof,
    derive_invite_transport_key, derive_password_transport_key, pwd_hash, RoomCryptoState,
    TransportCrypto,
};
use super::utils::{
    build_auth_hello_line, build_auth_proof_line, build_invite_hello_line,
    build_invite_ready_line, build_invite_proof_line, handshake_writeall_macro,
    open_invite_blob, parse_auth_challenge_line, parse_invitation, parse_invite_challenge_line,
    parse_invite_ok_line,
};

pub type SharedTransportCrypto = Arc<Mutex<TransportCrypto>>;

pub struct ConnectedSession {
    pub lines: Lines<BufReader<tokio::net::tcp::OwnedReadHalf>>,
    pub writer: tokio::net::tcp::OwnedWriteHalf,
    pub server_addr: String,
    pub room_crypto: RoomCryptoState,
    pub transport: SharedTransportCrypto,
    pub owner_capability: Option<String>,
}

pub async fn connect_and_login(server_addr_or_invite: &str, nickname: &str) -> Result<ConnectedSession> {
    if server_addr_or_invite.starts_with("/INVITE:") {
        return connect_with_invite(server_addr_or_invite, nickname).await;
    }

    connect_with_password(server_addr_or_invite, nickname).await
}

async fn connect_with_invite(server_addr_or_invite: &str, nickname: &str) -> Result<ConnectedSession> {
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
            handshake_writeall_macro(build_invite_hello_line(
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
    let server_nonce_hex =
        parse_invite_challenge_line(&challenge).ok_or_else(|| anyhow!("Invalid invite challenge"))?;
    let server_nonce = decode_hex_32(&server_nonce_hex)?;
    let transport_key =
        derive_invite_transport_key(&token_secret, &token_id, &client_nonce, &server_nonce);
    let proof = compute_invite_proof(&token_secret, &token_id, &client_nonce, &server_nonce);

    writer
        .write_all(handshake_writeall_macro(build_invite_proof_line(&hex::encode(proof))).as_slice())
        .await?;

    let mut transport = TransportCrypto::new(transport_key);
    let invite_ok_cipher = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow!("Server closed during invite auth"))?;
    let invite_ok = transport
        .open(&invite_ok_cipher)
        .ok_or_else(|| anyhow!("Invalid encrypted invite response"))?;
    let (_room_id_from_server, blob_b64) =
        parse_invite_ok_line(&invite_ok).ok_or_else(|| anyhow!("Invalid INVITE_OK"))?;
    let (room_id, room_credential) = open_invite_blob(&blob_b64, &blob_key_b64)
        .ok_or_else(|| anyhow!("Invalid invitation blob"))?;
    let room_crypto = RoomCryptoState::from_room_credential(room_id, room_credential);

    let ready_line = build_invite_ready_line(nickname);
    let ready_cipher = transport.seal(&ready_line);
    writer
        .write_all(handshake_writeall_macro(ready_cipher).as_slice())
        .await?;

    let ok_cipher = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow!("Server closed during invite finalize"))?;
    let ok_plain = transport
        .open(&ok_cipher)
        .ok_or_else(|| anyhow!("Invalid encrypted invite finalize response"))?;
    if !ok_plain.starts_with("OK") {
        return Err(anyhow!("Server refused invite: {ok_plain}"));
    }

    Ok(ConnectedSession {
        lines,
        writer,
        server_addr,
        room_crypto,
        transport: Arc::new(Mutex::new(transport)),
        owner_capability: None,
    })
}

async fn connect_with_password(server_addr_or_invite: &str, nickname: &str) -> Result<ConnectedSession> {
    let mut iter = server_addr_or_invite.splitn(2, '&');
    let server_addr = iter.next().unwrap_or("").to_string();
    let password = iter.next().unwrap_or("");
    let server_pwd_hash = pwd_hash(password);
    let client_nonce = random_nonce32();

    let stream = TcpStream::connect(&server_addr).await?;
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    writer
        .write_all(
            handshake_writeall_macro(build_auth_hello_line(&hex::encode(client_nonce))).as_slice(),
        )
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
    let transport_key = derive_password_transport_key(&server_pwd_hash, &client_nonce, &server_nonce);
    let proof = compute_password_auth_proof(&server_pwd_hash, &client_nonce, &server_nonce);

    writer
        .write_all(handshake_writeall_macro(build_auth_proof_line(&hex::encode(proof))).as_slice())
        .await?;

    let mut transport = TransportCrypto::new(transport_key);
    let ok_cipher = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow!("Server closed during auth"))?;
    let ok_plain = transport
        .open(&ok_cipher)
        .ok_or_else(|| anyhow!("Invalid encrypted auth response"))?;
    if ok_plain.trim() != "OK" {
        return Err(anyhow!("Server declined: {ok_plain}"));
    }

    let rooms_cipher = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow!("Server closed during room banner"))?;
    let rooms_plain = transport
        .open(&rooms_cipher)
        .ok_or_else(|| anyhow!("Invalid encrypted room banner"))?;
    if !rooms_plain.starts_with("ROOMS") {
        return Err(anyhow!("unexpected banner: {rooms_plain}"));
    }
    let rooms: Vec<String> = rooms_plain
        .split_whitespace()
        .skip(1)
        .map(|s| s.to_owned())
        .collect();
    if rooms.is_empty() {
        println!("\n{}", "— No Rooms Available —".green().bold());
    } else {
        println!("\n{} \n {}", "— Available Rooms —".green().bold(), rooms.join("; "));
    }

    let (room_id, room_credential, action) = prompt_room_selection(&rooms)?;
    let room_crypto = RoomCryptoState::from_room_credential(room_id, room_credential);
    let join_credential = room_crypto.join_credential();
    let join_plain = format!("{action} {} {join_credential} {nickname}", room_crypto.room_id());
    let join_cipher = transport.seal(&join_plain);
    writer
        .write_all(handshake_writeall_macro(join_cipher).as_slice())
        .await?;

    let response_cipher = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow!("Server closed during room join"))?;
    let response_plain = transport
        .open(&response_cipher)
        .ok_or_else(|| anyhow!("Invalid encrypted room join response"))?;
    if !response_plain.starts_with("OK") {
        return Err(anyhow!("server refused: {response_plain}"));
    }
    let owner_capability = parse_owner_capability(&response_plain);

    Ok(ConnectedSession {
        lines,
        writer,
        server_addr,
        room_crypto,
        transport: Arc::new(Mutex::new(transport)),
        owner_capability,
    })
}

fn prompt_room_selection(rooms: &[String]) -> Result<(String, String, &'static str)> {
    loop {
        print!(
            "{}",
            "Enter \"/q\" to disconnect, leave blank to join the Public Room,".yellow().bold()
        );
        print!("{}", "Room ID: ".blue());
        io::stdout().flush()?;
        let mut id = String::new();
        io::stdin().read_line(&mut id)?;

        if id.trim() == "/q" {
            return Err(anyhow!("Disconnected"));
        }
        if id.trim() == "'" {
            let room_id: String = rand::rng()
                .sample_iter(&Alphanumeric)
                .take(9)
                .map(char::from)
                .collect();
            const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_@#";
            let room_credential: String = (0..32)
                .map(|_| {
                    let idx = rand::rng().random_range(0..CHARSET.len());
                    CHARSET[idx] as char
                })
                .collect();
            return Ok((room_id, room_credential, "CREATE"));
        }

        let id = if id.trim().is_empty() { "Public" } else { id.trim() };
        if id != "Public" {
            print!("{}", "It wouldn't display while typing,".yellow().bold());
            print!("{}", "Password:".red());
            io::stdout().flush()?;
            let room_credential = read_password()?;
            let action = if rooms.contains(&id.to_string()) { "JOIN" } else { "CREATE" };
            return Ok((id.to_owned(), room_credential, action));
        }

        let action = if rooms.contains(&id.to_string()) { "JOIN" } else { "CREATE" };
        return Ok((id.to_owned(), String::new(), action));
    }
}

fn parse_owner_capability(resp: &str) -> Option<String> {
    let mut parts = resp.split_whitespace();
    if parts.next()? != "OK" {
        return None;
    }
    match parts.next() {
        Some("OWNER") => parts.next().map(|s| s.to_string()),
        _ => None,
    }
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
