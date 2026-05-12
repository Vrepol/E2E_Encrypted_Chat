use anyhow::Result;
use base64::Engine;
use rand::{distr::Alphanumeric, Rng, RngCore};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::broadcast,
};

use crate::crypto::{
    compute_invite_proof, compute_invite_token_id, compute_password_auth_proof,
    derive_invite_transport_key, derive_password_transport_key, TransportCrypto,
    TransportOpenResult, TransportSide,
};
use crate::protocol::{
    build_ack_line, build_auth_challenge_line, build_invite_challenge_line,
    build_invite_error_line, build_invite_ok_line, build_invite_token_line, build_session_ok_line,
    line_bytes, parse_auth_hello_line, parse_auth_proof_line, parse_invite_hello_line,
    parse_invite_proof_line, parse_invite_ready_line, parse_server_invite_request_line,
    parse_transport_packet_line, ServerInviteRequest, INVITE_TTL_SECS,
};

use super::{
    broadcast::{
        broadcast_room_event, packet_priority, BroadcastPriority, RoomBroadcast, ServerEvent,
    },
    invite::{
        begin_pending_invite, consume_invite_ready, insert_invite_token, reset_invite_to_unused,
        Invites,
    },
    room::{add_invited_member, broadcast_member_list, create_room, join_room, RoomGuard, Rooms},
};

pub(crate) async fn handle_client(
    socket: TcpStream,
    rooms: Rooms,
    invites: Invites,
    server_pwd_hash: [u8; 32],
) -> Result<()> {
    let (reader, mut writer) = socket.into_split();
    let mut lines = BufReader::new(reader).lines();

    let first_line = match lines.next_line().await? {
        Some(l) => l.trim_end().to_owned(),
        None => return Ok(()),
    };

    if let Some(client_nonce_hex) = parse_auth_hello_line(&first_line) {
        let client_nonce = decode_hex_32(&client_nonce_hex)?;
        return handle_password_client(
            lines,
            &mut writer,
            rooms,
            invites,
            client_nonce,
            server_pwd_hash,
        )
        .await;
    }

    if let Some((token_id_hex, client_nonce_hex)) = parse_invite_hello_line(&first_line) {
        let token_id = decode_hex_32(&token_id_hex)?;
        let client_nonce = decode_hex_32(&client_nonce_hex)?;
        return handle_invite_client(lines, &mut writer, rooms, invites, token_id, client_nonce)
            .await;
    }

    writer.write_all(b"ERR NeedHandshake\n").await?;
    Ok(())
}

async fn handle_password_client(
    mut lines: tokio::io::Lines<BufReader<tokio::net::tcp::OwnedReadHalf>>,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    rooms: Rooms,
    invites: Invites,
    client_nonce: [u8; 32],
    server_pwd_hash: [u8; 32],
) -> Result<()> {
    let server_nonce = random_nonce32();
    writer
        .write_all(line_bytes(build_auth_challenge_line(&hex::encode(server_nonce))).as_slice())
        .await?;

    let proof_line = match lines.next_line().await? {
        Some(line) => line.trim_end().to_owned(),
        None => return Ok(()),
    };
    let proof_hex = match parse_auth_proof_line(&proof_line) {
        Some(value) => value,
        None => {
            writer.write_all(b"ERR NeedAuthProof\n").await?;
            return Ok(());
        }
    };
    let proof = decode_hex_32(&proof_hex)?;
    let expected = compute_password_auth_proof(&server_pwd_hash, &client_nonce, &server_nonce);
    if proof != expected {
        writer.write_all(b"ERR BadAuth\n").await?;
        return Ok(());
    }

    let transport_key =
        derive_password_transport_key(&server_pwd_hash, &client_nonce, &server_nonce);
    let mut transport = TransportCrypto::new(transport_key, TransportSide::Server);
    write_transport_plain(writer, &mut transport, "OK").await?;

    let room_line = {
        let map = rooms.lock().unwrap();
        let mut line = String::from("ROOMS");
        for id in map.keys() {
            line.push(' ');
            line.push_str(id);
        }
        line
    };
    write_transport_plain(writer, &mut transport, &room_line).await?;

    let cmd_cipher = match lines.next_line().await? {
        Some(c) => c.trim_end().to_owned(),
        None => return Ok(()),
    };
    let cmd = match transport.open(&cmd_cipher) {
        Some(TransportOpenResult::Fresh(value)) => value,
        Some(TransportOpenResult::Duplicate(_)) | None => {
            write_transport_plain(writer, &mut transport, "ERR InvalidCmd").await?;
            return Ok(());
        }
    };

    let handshake = match parse_join_command(&rooms, &cmd) {
        Ok(Some(handshake)) => handshake,
        Ok(None) => {
            write_transport_plain(writer, &mut transport, "ERR InvalidCmd").await?;
            return Ok(());
        }
        Err(reason) => {
            write_transport_plain(writer, &mut transport, &format!("ERR {reason}")).await?;
            return Ok(());
        }
    };

    enter_room_loop(lines, writer, rooms, invites, transport, handshake).await
}

async fn handle_invite_client(
    mut lines: tokio::io::Lines<BufReader<tokio::net::tcp::OwnedReadHalf>>,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    rooms: Rooms,
    invites: Invites,
    token_id: [u8; 32],
    client_nonce: [u8; 32],
) -> Result<()> {
    let token_id_hex = hex::encode(token_id);
    let now = chrono::Utc::now().timestamp();
    let server_nonce = random_nonce32();
    let invite_prep =
        begin_pending_invite(&invites, &token_id_hex, client_nonce, server_nonce, now);
    let Some((token_secret, room_id, blob_b64)) = invite_prep else {
        writer.write_all(b"ERR InviteInvalid\n").await?;
        return Ok(());
    };

    writer
        .write_all(line_bytes(build_invite_challenge_line(&hex::encode(server_nonce))).as_slice())
        .await?;

    let proof_line = match lines.next_line().await? {
        Some(line) => line.trim_end().to_owned(),
        None => {
            reset_invite_to_unused(&invites, &token_id_hex, chrono::Utc::now().timestamp());
            return Ok(());
        }
    };
    let proof_hex = match parse_invite_proof_line(&proof_line) {
        Some(value) => value,
        None => {
            reset_invite_to_unused(&invites, &token_id_hex, chrono::Utc::now().timestamp());
            writer.write_all(b"ERR NeedInviteProof\n").await?;
            return Ok(());
        }
    };
    let proof = decode_hex_32(&proof_hex)?;
    let expected = compute_invite_proof(&token_secret, &token_id, &client_nonce, &server_nonce);
    if proof != expected {
        reset_invite_to_unused(&invites, &token_id_hex, chrono::Utc::now().timestamp());
        writer.write_all(b"ERR InviteInvalid\n").await?;
        return Ok(());
    }

    let transport_key =
        derive_invite_transport_key(&token_secret, &token_id, &client_nonce, &server_nonce);
    let mut transport = TransportCrypto::new(transport_key, TransportSide::Server);
    write_transport_plain(
        writer,
        &mut transport,
        &build_invite_ok_line(&room_id, &blob_b64),
    )
    .await?;

    let ready_cipher = match lines.next_line().await? {
        Some(line) => line.trim_end().to_owned(),
        None => {
            reset_invite_to_unused(&invites, &token_id_hex, chrono::Utc::now().timestamp());
            return Ok(());
        }
    };
    let ready_plain = match transport.open(&ready_cipher) {
        Some(TransportOpenResult::Fresh(value)) => value,
        Some(TransportOpenResult::Duplicate(_)) | None => {
            reset_invite_to_unused(&invites, &token_id_hex, chrono::Utc::now().timestamp());
            return Ok(());
        }
    };
    let nickname = match parse_invite_ready_line(&ready_plain) {
        Some(value) => value,
        None => {
            reset_invite_to_unused(&invites, &token_id_hex, chrono::Utc::now().timestamp());
            return Ok(());
        }
    };
    let member_id = random_member_id();

    let invite_ok = consume_invite_ready(
        &invites,
        &token_id_hex,
        &client_nonce,
        &server_nonce,
        chrono::Utc::now().timestamp(),
    );
    if !invite_ok {
        write_transport_plain(writer, &mut transport, "ERR InviteInvalid").await?;
        return Ok(());
    }

    let Some(broadcast) = add_invited_member(&rooms, &room_id, member_id.clone(), nickname.clone())
    else {
        write_transport_plain(writer, &mut transport, "ERR NoSuchRoom").await?;
        return Ok(());
    };

    let handshake = RoomHandshake {
        room_id,
        member_id,
        nickname,
        broadcast,
        owner_capability: None,
    };
    enter_room_loop(lines, writer, rooms, invites, transport, handshake).await
}

struct RoomHandshake {
    room_id: String,
    member_id: String,
    nickname: String,
    broadcast: RoomBroadcast,
    owner_capability: Option<String>,
}

fn parse_join_command(rooms: &Rooms, cmd: &str) -> Result<Option<RoomHandshake>, &'static str> {
    let mut parts = cmd.split_whitespace();
    let action = parts.next().unwrap_or_default();

    match action {
        "CREATE" => {
            let room_id = parts.next().unwrap_or_default().to_string();
            let cred = parts.next().unwrap_or_default().to_string();
            let nickname = parts.next().unwrap_or_default().to_string();
            if room_id.is_empty() || cred.is_empty() || nickname.is_empty() {
                Ok(None)
            } else {
                let member_id = random_member_id();
                let (broadcast, owner_capability) = create_room(
                    rooms,
                    room_id.clone(),
                    cred,
                    member_id.clone(),
                    nickname.clone(),
                )?;
                Ok(Some(RoomHandshake {
                    room_id,
                    member_id,
                    nickname,
                    broadcast,
                    owner_capability: Some(owner_capability),
                }))
            }
        }
        "JOIN" => {
            let room_id = parts.next().unwrap_or_default().to_string();
            let cred = parts.next().unwrap_or_default().to_string();
            let nickname = parts.next().unwrap_or_default().to_string();
            if room_id.is_empty() || cred.is_empty() || nickname.is_empty() {
                Ok(None)
            } else {
                let member_id = random_member_id();
                let broadcast =
                    join_room(rooms, &room_id, &cred, member_id.clone(), nickname.clone())?;
                Ok(Some(RoomHandshake {
                    room_id,
                    member_id,
                    nickname,
                    broadcast,
                    owner_capability: None,
                }))
            }
        }
        _ => Err("UnknownAction"),
    }
}

async fn enter_room_loop(
    mut lines: tokio::io::Lines<BufReader<tokio::net::tcp::OwnedReadHalf>>,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    rooms: Rooms,
    invites: Invites,
    mut transport: TransportCrypto,
    handshake: RoomHandshake,
) -> Result<()> {
    let RoomHandshake {
        room_id,
        member_id,
        nickname,
        broadcast: room_broadcast,
        owner_capability,
    } = handshake;

    write_transport_plain(
        writer,
        &mut transport,
        &build_session_ok_line(&member_id, owner_capability.as_deref()),
    )
    .await?;

    let _guard = RoomGuard {
        rooms: rooms.clone(),
        room_id: room_id.clone(),
        member_id: member_id.clone(),
        nickname: nickname.clone(),
        broadcast: room_broadcast.clone(),
    };

    let _ = room_broadcast.high_tx.send(ServerEvent::Plain {
        source_member_id: None,
        plain: format!("⚡ [{}] joined.", nickname),
    });
    let mut room_high_rx = room_broadcast.high_tx.subscribe();
    let mut room_low_rx = room_broadcast.low_tx.subscribe();
    {
        let map = rooms.lock().unwrap();
        if let Some(info) = map.get(&room_id) {
            broadcast_member_list(info);
        }
    }

    loop {
        tokio::select! {
            biased;

            result = lines.next_line() => {
                match result? {
                    Some(line) => {
                        let Some(open_result) = transport.open(line.trim_end()) else {
                            continue;
                        };
                        let (server_plain, is_duplicate) = match open_result {
                            TransportOpenResult::Fresh(plain) => (plain, false),
                            TransportOpenResult::Duplicate(plain) => (plain, true),
                        };

                        if server_plain == "/ping" {
                            let _ = write_transport_plain(writer, &mut transport, "/ping_ack").await;
                            continue;
                        }

                        let (broadcast_priority, broadcast_payload) = if let Some((packet_id, packet_payload)) = parse_transport_packet_line(&server_plain) {
                            let ack = build_ack_line(&packet_id);
                            let _ = write_transport_plain(writer, &mut transport, &ack).await;
                            if is_duplicate {
                                continue;
                            }
                            (packet_priority(&packet_id), packet_payload)
                        } else {
                            if is_duplicate {
                                continue;
                            }
                            (BroadcastPriority::High, server_plain)
                        };

                        if let Some(inv_req) = parse_server_invite_request_line(&broadcast_payload) {
                            let response = handle_invite_request(
                                &rooms,
                                &invites,
                                &room_id,
                                &member_id,
                                owner_capability.as_deref(),
                                inv_req,
                            );
                            let _ = write_transport_plain(writer, &mut transport, &response).await;
                            continue;
                        }

                        broadcast_room_event(
                            &room_broadcast,
                            broadcast_priority,
                            ServerEvent::Plain {
                                source_member_id: Some(member_id.clone()),
                                plain: format!("[{}] {}", nickname, broadcast_payload),
                            },
                        );
                    }
                    None => break,
                }
            }
            high_result = room_high_rx.recv() => {
                match high_result {
                    Ok(event) => {
                        let ServerEvent::Plain {
                            source_member_id,
                            plain,
                        } = event;
                        if source_member_id.as_deref() == Some(&member_id) {
                            continue;
                        }
                        if write_transport_plain(writer, &mut transport, &plain).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            low_result = room_low_rx.recv() => {
                match low_result {
                    Ok(event) => {
                        let ServerEvent::Plain {
                            source_member_id,
                            plain,
                        } = event;
                        if source_member_id.as_deref() == Some(&member_id) {
                            continue;
                        }
                        if write_transport_plain(writer, &mut transport, &plain).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }

    Ok(())
}

fn handle_invite_request(
    rooms: &Rooms,
    invites: &Invites,
    room_id: &str,
    member_id: &str,
    session_owner_capability: Option<&str>,
    request: ServerInviteRequest,
) -> String {
    if request.room_id != room_id {
        return build_invite_error_line(&request.request_id, "RoomMismatch");
    }

    let rooms_map = rooms.lock().unwrap();
    let Some(info) = rooms_map.get(room_id) else {
        return build_invite_error_line(&request.request_id, "NoSuchRoom");
    };

    let owner_capability = match (&info.owner_member_id, &info.owner_capability) {
        (Some(owner_member_id), Some(owner_capability)) if owner_member_id == member_id => {
            owner_capability
        }
        _ => return build_invite_error_line(&request.request_id, "OwnerOffline"),
    };

    if session_owner_capability != Some(owner_capability.as_str())
        || request.owner_capability != *owner_capability
    {
        return build_invite_error_line(&request.request_id, "InviteNotAllowed");
    }

    let mut token_secret = [0u8; 32];
    rand::rng().fill_bytes(&mut token_secret);
    let token_id = compute_invite_token_id(&token_secret);
    let token_id_hex = hex::encode(token_id);
    let token_secret_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_secret);
    let expires_at = chrono::Utc::now().timestamp() + INVITE_TTL_SECS;
    drop(rooms_map);

    insert_invite_token(
        invites,
        token_id_hex,
        room_id.to_string(),
        expires_at,
        request.blob_b64,
        token_secret,
    );

    build_invite_token_line(&request.request_id, &token_secret_b64, expires_at)
}

async fn write_transport_plain(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    transport: &mut TransportCrypto,
    plain: &str,
) -> Result<()> {
    let cipher_line = transport.seal(plain);
    writer.write_all(line_bytes(cipher_line).as_slice()).await?;
    Ok(())
}

fn random_nonce32() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

fn random_member_id() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect()
}

fn decode_hex_32(value: &str) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(value, &mut out)?;
    Ok(out)
}
