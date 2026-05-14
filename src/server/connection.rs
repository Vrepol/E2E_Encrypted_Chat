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
    line_bytes, parse_attachment_frame, parse_auth_hello_line, parse_auth_proof_line,
    parse_invite_hello_line, parse_invite_proof_line, parse_invite_ready_line,
    parse_server_invite_request_line, parse_transport_packet_line, AttachmentFrame,
    ServerInviteRequest, INVITE_TTL_SECS,
};

use super::{
    broadcast::{
        broadcast_room_event, packet_priority, BroadcastPriority, RoomBroadcast, ServerEvent,
    },
    invite::{
        begin_pending_invite, consume_invite_ready, insert_invite_token, reset_invite_to_unused,
        Invites,
    },
    logging::ServerLogger,
    room::{add_invited_member, broadcast_member_list, create_room, join_room, RoomGuard, Rooms},
};

pub(crate) async fn handle_client(
    socket: TcpStream,
    rooms: Rooms,
    invites: Invites,
    server_pwd_hash: [u8; 32],
    logger: ServerLogger,
    peer_addr: String,
) -> Result<()> {
    let (reader, mut writer) = socket.into_split();
    let mut lines = BufReader::new(reader).lines();

    let first_line = match lines.next_line().await? {
        Some(l) => l.trim_end().to_owned(),
        None => {
            logger.warn("conn", format!("peer={peer_addr} closed_before_handshake"));
            return Ok(());
        }
    };

    if let Some(client_nonce_hex) = parse_auth_hello_line(&first_line) {
        let client_nonce = decode_hex_32(&client_nonce_hex)?;
        logger.info("auth", format!("peer={peer_addr} method=password start"));
        return handle_password_client(
            lines,
            &mut writer,
            rooms,
            invites,
            client_nonce,
            server_pwd_hash,
            logger,
            peer_addr,
        )
        .await;
    }

    if let Some((token_id_hex, client_nonce_hex)) = parse_invite_hello_line(&first_line) {
        let token_id = decode_hex_32(&token_id_hex)?;
        let client_nonce = decode_hex_32(&client_nonce_hex)?;
        logger.info(
            "auth",
            format!("peer={peer_addr} method=invite token_id={token_id_hex} start"),
        );
        return handle_invite_client(
            lines,
            &mut writer,
            rooms,
            invites,
            token_id,
            client_nonce,
            logger,
            peer_addr,
        )
        .await;
    }

    logger.warn("auth", format!("peer={peer_addr} invalid_handshake"));
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
    logger: ServerLogger,
    peer_addr: String,
) -> Result<()> {
    let server_nonce = random_nonce32();
    writer
        .write_all(line_bytes(build_auth_challenge_line(&hex::encode(server_nonce))).as_slice())
        .await?;

    let proof_line = match lines.next_line().await? {
        Some(line) => line.trim_end().to_owned(),
        None => {
            logger.warn(
                "auth",
                format!("peer={peer_addr} disconnected_before_auth_proof"),
            );
            return Ok(());
        }
    };
    let proof_hex = match parse_auth_proof_line(&proof_line) {
        Some(value) => value,
        None => {
            logger.warn("auth", format!("peer={peer_addr} missing_auth_proof"));
            writer.write_all(b"ERR NeedAuthProof\n").await?;
            return Ok(());
        }
    };
    let proof = decode_hex_32(&proof_hex)?;
    let expected = compute_password_auth_proof(&server_pwd_hash, &client_nonce, &server_nonce);
    if proof != expected {
        logger.warn("auth", format!("peer={peer_addr} bad_password_proof"));
        writer.write_all(b"ERR BadAuth\n").await?;
        return Ok(());
    }

    let transport_key =
        derive_password_transport_key(&server_pwd_hash, &client_nonce, &server_nonce);
    let mut transport = TransportCrypto::new(transport_key, TransportSide::Server);
    logger.info("auth", format!("peer={peer_addr} method=password ok"));
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
        None => {
            logger.warn(
                "auth",
                format!("peer={peer_addr} disconnected_before_join_command"),
            );
            return Ok(());
        }
    };
    let cmd = match transport.open(&cmd_cipher) {
        Some(TransportOpenResult::Fresh(value)) => value,
        Some(TransportOpenResult::Duplicate(_)) | None => {
            logger.warn(
                "auth",
                format!("peer={peer_addr} invalid_join_command_cipher"),
            );
            write_transport_plain(writer, &mut transport, "ERR InvalidCmd").await?;
            return Ok(());
        }
    };

    let handshake = match parse_join_command(&rooms, &cmd) {
        Ok(Some(handshake)) => handshake,
        Ok(None) => {
            logger.warn(
                "room",
                format!("peer={peer_addr} malformed_join_command command={cmd}"),
            );
            write_transport_plain(writer, &mut transport, "ERR InvalidCmd").await?;
            return Ok(());
        }
        Err(reason) => {
            logger.warn(
                "room",
                format!("peer={peer_addr} join_rejected reason={reason} command={cmd}"),
            );
            write_transport_plain(writer, &mut transport, &format!("ERR {reason}")).await?;
            return Ok(());
        }
    };

    logger.info(
        "room",
        format!(
            "peer={peer_addr} action={} room={} member_id={} nickname={}",
            handshake.action, handshake.room_id, handshake.member_id, handshake.nickname
        ),
    );
    enter_room_loop(lines, writer, rooms, invites, transport, handshake, logger).await
}

async fn handle_invite_client(
    mut lines: tokio::io::Lines<BufReader<tokio::net::tcp::OwnedReadHalf>>,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    rooms: Rooms,
    invites: Invites,
    token_id: [u8; 32],
    client_nonce: [u8; 32],
    logger: ServerLogger,
    peer_addr: String,
) -> Result<()> {
    let token_id_hex = hex::encode(token_id);
    let now = chrono::Utc::now().timestamp();
    let server_nonce = random_nonce32();
    let invite_prep =
        begin_pending_invite(&invites, &token_id_hex, client_nonce, server_nonce, now);
    let Some((token_secret, room_id, blob_b64)) = invite_prep else {
        logger.warn(
            "invite",
            format!("peer={peer_addr} invalid_or_expired token_id={token_id_hex}"),
        );
        writer.write_all(b"ERR InviteInvalid\n").await?;
        return Ok(());
    };

    writer
        .write_all(line_bytes(build_invite_challenge_line(&hex::encode(server_nonce))).as_slice())
        .await?;

    let proof_line = match lines.next_line().await? {
        Some(line) => line.trim_end().to_owned(),
        None => {
            logger.warn(
                "invite",
                format!(
                    "peer={peer_addr} disconnected_before_invite_proof token_id={token_id_hex}"
                ),
            );
            reset_invite_to_unused(&invites, &token_id_hex, chrono::Utc::now().timestamp());
            return Ok(());
        }
    };
    let proof_hex = match parse_invite_proof_line(&proof_line) {
        Some(value) => value,
        None => {
            logger.warn(
                "invite",
                format!("peer={peer_addr} missing_invite_proof token_id={token_id_hex}"),
            );
            reset_invite_to_unused(&invites, &token_id_hex, chrono::Utc::now().timestamp());
            writer.write_all(b"ERR NeedInviteProof\n").await?;
            return Ok(());
        }
    };
    let proof = decode_hex_32(&proof_hex)?;
    let expected = compute_invite_proof(&token_secret, &token_id, &client_nonce, &server_nonce);
    if proof != expected {
        logger.warn(
            "invite",
            format!("peer={peer_addr} bad_invite_proof token_id={token_id_hex}"),
        );
        reset_invite_to_unused(&invites, &token_id_hex, chrono::Utc::now().timestamp());
        writer.write_all(b"ERR InviteInvalid\n").await?;
        return Ok(());
    }

    let transport_key =
        derive_invite_transport_key(&token_secret, &token_id, &client_nonce, &server_nonce);
    let mut transport = TransportCrypto::new(transport_key, TransportSide::Server);
    logger.info(
        "invite",
        format!("peer={peer_addr} token_id={token_id_hex} room={room_id} invite_ok"),
    );
    write_transport_plain(
        writer,
        &mut transport,
        &build_invite_ok_line(&room_id, &blob_b64),
    )
    .await?;

    let ready_cipher = match lines.next_line().await? {
        Some(line) => line.trim_end().to_owned(),
        None => {
            logger.warn(
                "invite",
                format!(
                    "peer={peer_addr} disconnected_before_invite_ready token_id={token_id_hex}"
                ),
            );
            reset_invite_to_unused(&invites, &token_id_hex, chrono::Utc::now().timestamp());
            return Ok(());
        }
    };
    let ready_plain = match transport.open(&ready_cipher) {
        Some(TransportOpenResult::Fresh(value)) => value,
        Some(TransportOpenResult::Duplicate(_)) | None => {
            logger.warn(
                "invite",
                format!("peer={peer_addr} invalid_invite_ready token_id={token_id_hex}"),
            );
            reset_invite_to_unused(&invites, &token_id_hex, chrono::Utc::now().timestamp());
            return Ok(());
        }
    };
    let nickname = match parse_invite_ready_line(&ready_plain) {
        Some(value) => value,
        None => {
            logger.warn(
                "invite",
                format!("peer={peer_addr} malformed_invite_ready token_id={token_id_hex}"),
            );
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
        logger.warn(
            "invite",
            format!("peer={peer_addr} invite_consumption_failed token_id={token_id_hex}"),
        );
        write_transport_plain(writer, &mut transport, "ERR InviteInvalid").await?;
        return Ok(());
    }

    let Some(broadcast) = add_invited_member(&rooms, &room_id, member_id.clone(), nickname.clone())
    else {
        logger.warn(
            "invite",
            format!("peer={peer_addr} room_missing_after_invite room={room_id}"),
        );
        write_transport_plain(writer, &mut transport, "ERR NoSuchRoom").await?;
        return Ok(());
    };

    let handshake = RoomHandshake {
        action: "INVITE_JOIN",
        room_id,
        member_id,
        nickname,
        broadcast,
        owner_capability: None,
    };
    logger.info(
        "room",
        format!(
            "peer={peer_addr} action={} room={} member_id={} nickname={}",
            handshake.action, handshake.room_id, handshake.member_id, handshake.nickname
        ),
    );
    enter_room_loop(lines, writer, rooms, invites, transport, handshake, logger).await
}

struct RoomHandshake {
    action: &'static str,
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
                    action: "CREATE",
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
                    action: "JOIN",
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
    logger: ServerLogger,
) -> Result<()> {
    let RoomHandshake {
        action,
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
        logger: logger.clone(),
    };

    logger.info(
        "room",
        format!(
            "session_ready room={} action={} member_id={} nickname={}",
            room_id, action, member_id, nickname
        ),
    );
    let _ = room_broadcast.high_tx.send(ServerEvent::Plain {
        source_member_id: None,
        plain: format!("⚡ [{}] joined.", nickname),
    });
    let mut room_high_rx = room_broadcast.high_tx.subscribe();
    let mut room_low_rx = room_broadcast.low_tx.subscribe();
    {
        let map = rooms.lock().unwrap();
        if let Some(info) = map.get(&room_id) {
            broadcast_member_list(&room_id, info, &logger);
        }
    }

    loop {
        tokio::select! {
            biased;

            result = lines.next_line() => {
                match result? {
                    Some(line) => {
                        let Some(open_result) = transport.open(line.trim_end()) else {
                            logger.warn(
                                "flow",
                                format!("room={} member_id={} invalid_transport_cipher", room_id, member_id),
                            );
                            continue;
                        };
                        let (server_plain, is_duplicate) = match open_result {
                            TransportOpenResult::Fresh(plain) => (plain, false),
                            TransportOpenResult::Duplicate(plain) => (plain, true),
                        };

                        if server_plain == "/ping" {
                            logger.info(
                                "flow",
                                format!("room={} from={} control=ping", room_id, nickname),
                            );
                            let _ = write_transport_plain(writer, &mut transport, "/ping_ack").await;
                            continue;
                        }

                        let (broadcast_priority, broadcast_payload) = if let Some((packet_id, packet_payload)) = parse_transport_packet_line(&server_plain) {
                            let ack = build_ack_line(&packet_id);
                            let _ = write_transport_plain(writer, &mut transport, &ack).await;
                            logger.info(
                                "flow",
                                format!(
                                    "room={} from={} packet_id={} duplicate={} {}",
                                    room_id,
                                    nickname,
                                    packet_id,
                                    is_duplicate,
                                    summarize_payload(&packet_payload),
                                ),
                            );
                            if is_duplicate {
                                continue;
                            }
                            (packet_priority(&packet_id), packet_payload)
                        } else {
                            logger.info(
                                "flow",
                                format!(
                                    "room={} from={} duplicate={} {}",
                                    room_id,
                                    nickname,
                                    is_duplicate,
                                    summarize_payload(&server_plain),
                                ),
                            );
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
                                &logger,
                            );
                            let _ = write_transport_plain(writer, &mut transport, &response).await;
                            continue;
                        }

                        logger.info(
                            "flow",
                            format!(
                                "room={} broadcast from={} priority={:?} {}",
                                room_id,
                                nickname,
                                broadcast_priority,
                                summarize_payload(&broadcast_payload),
                            ),
                        );
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
                        logger.info(
                            "flow",
                            format!(
                                "room={} deliver to={} {}",
                                room_id,
                                nickname,
                                summarize_outbound_plain(&plain),
                            ),
                        );
                        if write_transport_plain(writer, &mut transport, &plain).await.is_err() {
                            logger.warn(
                                "flow",
                                format!("room={} deliver_failed to={} channel=high", room_id, nickname),
                            );
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
                        logger.info(
                            "flow",
                            format!(
                                "room={} deliver to={} {}",
                                room_id,
                                nickname,
                                summarize_outbound_plain(&plain),
                            ),
                        );
                        if write_transport_plain(writer, &mut transport, &plain).await.is_err() {
                            logger.warn(
                                "flow",
                                format!("room={} deliver_failed to={} channel=low", room_id, nickname),
                            );
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
    logger: &ServerLogger,
) -> String {
    if request.room_id != room_id {
        logger.warn(
            "invite",
            format!(
                "request_id={} member_id={} room={} reason=room_mismatch target_room={}",
                request.request_id, member_id, room_id, request.room_id
            ),
        );
        return build_invite_error_line(&request.request_id, "RoomMismatch");
    }

    let rooms_map = rooms.lock().unwrap();
    let Some(info) = rooms_map.get(room_id) else {
        logger.warn(
            "invite",
            format!(
                "request_id={} member_id={} room={} reason=no_such_room",
                request.request_id, member_id, room_id
            ),
        );
        return build_invite_error_line(&request.request_id, "NoSuchRoom");
    };

    let owner_capability = match (&info.owner_member_id, &info.owner_capability) {
        (Some(owner_member_id), Some(owner_capability)) if owner_member_id == member_id => {
            owner_capability
        }
        _ => {
            logger.warn(
                "invite",
                format!(
                    "request_id={} member_id={} room={} reason=owner_offline",
                    request.request_id, member_id, room_id
                ),
            );
            return build_invite_error_line(&request.request_id, "OwnerOffline");
        }
    };

    if session_owner_capability != Some(owner_capability.as_str())
        || request.owner_capability != *owner_capability
    {
        logger.warn(
            "invite",
            format!(
                "request_id={} member_id={} room={} reason=invite_not_allowed",
                request.request_id, member_id, room_id
            ),
        );
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

    logger.info(
        "invite",
        format!(
            "request_id={} member_id={} room={} expires_at={}",
            request.request_id, member_id, room_id, expires_at
        ),
    );
    build_invite_token_line(&request.request_id, &token_secret_b64, expires_at)
}

fn summarize_payload(payload: &str) -> String {
    if payload.starts_with("/RMSG ") {
        return format!("secure_text_frame bytes={}", payload.len());
    }
    if payload.starts_with("/KEY_ANNOUNCE ") {
        return format!("key_announce bytes={}", payload.len());
    }
    if payload.starts_with("/EPOCH_COMMIT ") {
        return format!("epoch_commit bytes={}", payload.len());
    }
    if let Some(frame) = parse_attachment_frame(payload) {
        return match frame {
            AttachmentFrame::Meta(meta) => format!(
                "file_manifest transfer_id={} file={} size={} chunks={}",
                meta.transfer_id, meta.file_name, meta.total_size, meta.total_chunks
            ),
            AttachmentFrame::EncryptedChunk(chunk) => format!(
                "file_chunk transfer_id={} index={} cipher_bytes={}",
                chunk.transfer_id,
                chunk.index,
                chunk.ciphertext.len()
            ),
        };
    }
    if let Some(invite) = parse_server_invite_request_line(payload) {
        return format!(
            "invite_request request_id={} room={}",
            invite.request_id, invite.room_id
        );
    }
    format!("text={}", truncate_for_log(payload, 120))
}

fn summarize_outbound_plain(plain: &str) -> String {
    if let Some(rest) = plain.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let sender = &rest[..end];
            let payload = rest[end + 1..].trim_start();
            return format!("from={} {}", sender, summarize_payload(payload));
        }
    }
    format!("event={}", truncate_for_log(plain, 120))
}

fn truncate_for_log(text: &str, max_chars: usize) -> String {
    let total = text.chars().count();
    if total <= max_chars {
        return text.to_string();
    }
    let shortened = text.chars().take(max_chars).collect::<String>();
    format!("{shortened}…(+{} chars)", total - max_chars)
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
