use anyhow::Result;
use base64::Engine;
use clap::Parser;
use futures_util::FutureExt;
use once_cell::sync::OnceCell;
use rand::{distr::Alphanumeric, Rng, RngCore};
use rust_chat::app_config::{DEFAULT_SERVER_PASSWORD, DEFAULT_SERVER_PORT};
use rust_chat::client::{
    crypto::{
        compute_invite_proof, compute_invite_token_id, compute_password_auth_proof,
        derive_invite_transport_key, derive_password_transport_key, pwd_hash, TransportCrypto,
        TransportOpenResult, TransportSide,
    },
    utils::{
        build_ack_line, build_auth_challenge_line, build_invite_challenge_line,
        build_invite_error_line, build_invite_ok_line, build_invite_token_line,
        build_member_list_line, build_session_ok_line, handshake_writeall_macro,
        parse_auth_hello_line, parse_auth_proof_line, parse_invite_hello_line,
        parse_invite_proof_line, parse_invite_ready_line, parse_server_invite_request_line,
        parse_transport_packet_line, MemberIdentity, INVITE_TTL_SECS,
    },
};
use std::{
    collections::HashMap,
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::broadcast,
};

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value_t = DEFAULT_SERVER_PORT)]
    port: u16,
    #[arg(short = 'k', default_value_t = String::from(DEFAULT_SERVER_PASSWORD))]
    password: String,
}

static SERVER_PWD_HASH: OnceCell<[u8; 32]> = OnceCell::new();
const INVITE_PENDING_TTL_SECS: i64 = 30;

#[derive(Clone, Debug)]
enum ServerEvent {
    Plain {
        source_member_id: Option<String>,
        plain: String,
    },
}

#[derive(Clone)]
struct RoomBroadcast {
    high_tx: broadcast::Sender<ServerEvent>,
    low_tx: broadcast::Sender<ServerEvent>,
}

struct RoomInfo {
    broadcast: RoomBroadcast,
    join_credential: String,
    members: HashMap<String, String>,
    owner_member_id: Option<String>,
    owner_capability: Option<String>,
}

enum InviteUseState {
    Unused,
    Pending {
        client_nonce: [u8; 32],
        server_nonce: [u8; 32],
        pending_until: i64,
    },
    Used,
}

struct InviteTokenInfo {
    room_id: String,
    expires_at: i64,
    blob_b64: String,
    token_secret: [u8; 32],
    state: InviteUseState,
}

type Rooms = Arc<Mutex<HashMap<String, RoomInfo>>>;
type Invites = Arc<Mutex<HashMap<String, InviteTokenInfo>>>;

struct RoomGuard {
    rooms: Rooms,
    room_id: String,
    member_id: String,
    nickname: String,
    broadcast: RoomBroadcast,
}

impl Drop for RoomGuard {
    fn drop(&mut self) {
        let _ = self.broadcast.high_tx.send(ServerEvent::Plain {
            source_member_id: None,
            plain: format!("⚡ [{}] left.", self.nickname),
        });

        let mut map = self.rooms.lock().unwrap();
        if let Some(info) = map.get_mut(&self.room_id) {
            info.members.remove(&self.member_id);
            if info.owner_member_id.as_deref() == Some(&self.member_id) {
                info.owner_member_id = None;
                info.owner_capability = None;
            }
            broadcast_member_list(info);
            if info.members.is_empty() {
                map.remove(&self.room_id);
            }
        }
    }
}

fn broadcast_member_list(info: &RoomInfo) {
    let mut members = info
        .members
        .iter()
        .map(|(member_id, nickname)| MemberIdentity {
            member_id: member_id.clone(),
            nickname: nickname.clone(),
        })
        .collect::<Vec<_>>();
    members.sort_by(|a, b| {
        a.nickname
            .cmp(&b.nickname)
            .then_with(|| a.member_id.cmp(&b.member_id))
    });
    let _ = info.broadcast.high_tx.send(ServerEvent::Plain {
        source_member_id: None,
        plain: build_member_list_line(&members),
    });
}

#[derive(Clone, Copy)]
enum BroadcastPriority {
    High,
    Low,
}

fn packet_priority(packet_id: &str) -> BroadcastPriority {
    if packet_id.starts_with("att-") {
        BroadcastPriority::Low
    } else {
        BroadcastPriority::High
    }
}

fn broadcast_room_event(
    broadcast: &RoomBroadcast,
    priority: BroadcastPriority,
    event: ServerEvent,
) {
    let sender = match priority {
        BroadcastPriority::High => &broadcast.high_tx,
        BroadcastPriority::Low => &broadcast.low_tx,
    };
    let _ = sender.send(event);
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    SERVER_PWD_HASH.set(pwd_hash(&args.password)).unwrap();

    let bind_addr = format!("0.0.0.0:{}", args.port);
    let listener = TcpListener::bind(&bind_addr).await?;
    println!("🛰️  Chat-Server listening on {}", bind_addr);

    let rooms: Rooms = Arc::new(Mutex::new(HashMap::new()));
    let invites: Invites = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (socket, addr) = listener.accept().await?;
        let rooms_clone = rooms.clone();
        let invites_clone = invites.clone();

        tokio::spawn(
            AssertUnwindSafe(async move {
                if let Err(e) = handle_client(socket, rooms_clone, invites_clone).await {
                    eprintln!("客户端 {} 出错：{:#}", addr, e);
                }
            })
            .catch_unwind()
            .map(move |res| {
                if let Err(panic) = res {
                    eprintln!("子任务 for {} panic 已捕获：{:?}", addr, panic);
                }
            }),
        );
    }
}

async fn handle_client(socket: TcpStream, rooms: Rooms, invites: Invites) -> Result<()> {
    let (reader, mut writer) = socket.into_split();
    let mut lines = BufReader::new(reader).lines();

    let first_line = match lines.next_line().await? {
        Some(l) => l.trim_end().to_owned(),
        None => return Ok(()),
    };

    if let Some(client_nonce_hex) = parse_auth_hello_line(&first_line) {
        let client_nonce = decode_hex_32(&client_nonce_hex)?;
        return handle_password_client(lines, &mut writer, rooms, invites, client_nonce).await;
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
) -> Result<()> {
    let server_nonce = random_nonce32();
    writer
        .write_all(
            handshake_writeall_macro(build_auth_challenge_line(&hex::encode(server_nonce)))
                .as_slice(),
        )
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
    let expected =
        compute_password_auth_proof(SERVER_PWD_HASH.get().unwrap(), &client_nonce, &server_nonce);
    if proof != expected {
        writer.write_all(b"ERR BadAuth\n").await?;
        return Ok(());
    }

    let transport_key =
        derive_password_transport_key(SERVER_PWD_HASH.get().unwrap(), &client_nonce, &server_nonce);
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
    let invite_prep = {
        let mut invites_map = invites.lock().unwrap();
        normalize_invites(&mut invites_map, now);
        match invites_map.get_mut(&token_id_hex) {
            Some(info) => match info.state {
                InviteUseState::Unused => {
                    let server_nonce = random_nonce32();
                    let token_secret = info.token_secret;
                    let room_id = info.room_id.clone();
                    let blob_b64 = info.blob_b64.clone();
                    info.state = InviteUseState::Pending {
                        client_nonce,
                        server_nonce,
                        pending_until: now + INVITE_PENDING_TTL_SECS,
                    };
                    Some((server_nonce, token_secret, room_id, blob_b64))
                }
                _ => None,
            },
            None => None,
        }
    };
    let Some((server_nonce, token_secret, room_id, blob_b64)) = invite_prep else {
        writer.write_all(b"ERR InviteInvalid\n").await?;
        return Ok(());
    };

    writer
        .write_all(
            handshake_writeall_macro(build_invite_challenge_line(&hex::encode(server_nonce)))
                .as_slice(),
        )
        .await?;

    let proof_line = match lines.next_line().await? {
        Some(line) => line.trim_end().to_owned(),
        None => {
            reset_invite_to_unused(&invites, &token_id_hex);
            return Ok(());
        }
    };
    let proof_hex = match parse_invite_proof_line(&proof_line) {
        Some(value) => value,
        None => {
            reset_invite_to_unused(&invites, &token_id_hex);
            writer.write_all(b"ERR NeedInviteProof\n").await?;
            return Ok(());
        }
    };
    let proof = decode_hex_32(&proof_hex)?;
    let expected = compute_invite_proof(&token_secret, &token_id, &client_nonce, &server_nonce);
    if proof != expected {
        reset_invite_to_unused(&invites, &token_id_hex);
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
            reset_invite_to_unused(&invites, &token_id_hex);
            return Ok(());
        }
    };
    let ready_plain = match transport.open(&ready_cipher) {
        Some(TransportOpenResult::Fresh(value)) => value,
        Some(TransportOpenResult::Duplicate(_)) | None => {
            reset_invite_to_unused(&invites, &token_id_hex);
            return Ok(());
        }
    };
    let nickname = match parse_invite_ready_line(&ready_plain) {
        Some(value) => value,
        None => {
            reset_invite_to_unused(&invites, &token_id_hex);
            return Ok(());
        }
    };
    let member_id = random_member_id();

    let invite_ok = consume_invite_ready(&invites, &token_id_hex, &client_nonce, &server_nonce);
    if !invite_ok {
        write_transport_plain(writer, &mut transport, "ERR InviteInvalid").await?;
        return Ok(());
    }

    let broadcast = match {
        let mut map = rooms.lock().unwrap();
        if let Some(info) = map.get_mut(&room_id) {
            info.members.insert(member_id.clone(), nickname.clone());
            Some(info.broadcast.clone())
        } else {
            None
        }
    } {
        Some(broadcast) => broadcast,
        None => {
            write_transport_plain(writer, &mut transport, "ERR NoSuchRoom").await?;
            return Ok(());
        }
    };

    let handshake = RoomHandshake::Join {
        room_id,
        member_id,
        nickname,
        broadcast,
        owner_capability: None,
    };
    enter_room_loop(lines, writer, rooms, invites, transport, handshake).await
}

enum RoomHandshake {
    Create {
        room_id: String,
        member_id: String,
        nickname: String,
        broadcast: RoomBroadcast,
        owner_capability: Option<String>,
    },
    Join {
        room_id: String,
        member_id: String,
        nickname: String,
        broadcast: RoomBroadcast,
        owner_capability: Option<String>,
    },
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
                let mut map = rooms.lock().unwrap();
                if map.contains_key(&room_id) {
                    Err("RoomExists")
                } else {
                    let owner_capability: String = rand::rng()
                        .sample_iter(&Alphanumeric)
                        .take(32)
                        .map(char::from)
                        .collect();
                    let (high_tx, _) = broadcast::channel::<ServerEvent>(500);
                    let (low_tx, _) = broadcast::channel::<ServerEvent>(500);
                    let broadcast = RoomBroadcast { high_tx, low_tx };
                    let mut members = HashMap::new();
                    members.insert(member_id.clone(), nickname.clone());
                    map.insert(
                        room_id.clone(),
                        RoomInfo {
                            broadcast: broadcast.clone(),
                            join_credential: cred,
                            members,
                            owner_member_id: Some(member_id.clone()),
                            owner_capability: Some(owner_capability.clone()),
                        },
                    );

                    Ok(Some(RoomHandshake::Create {
                        room_id,
                        member_id,
                        nickname,
                        broadcast,
                        owner_capability: Some(owner_capability),
                    }))
                }
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
                match {
                    let mut map = rooms.lock().unwrap();
                    if let Some(info) = map.get_mut(&room_id) {
                        if info.join_credential != cred {
                            Err("BadCredential")
                        } else {
                            info.members.insert(member_id.clone(), nickname.clone());
                            Ok(info.broadcast.clone())
                        }
                    } else {
                        Err("NoSuchRoom")
                    }
                } {
                    Ok(broadcast) => Ok(Some(RoomHandshake::Join {
                        room_id,
                        member_id,
                        nickname,
                        broadcast,
                        owner_capability: None,
                    })),
                    Err(reason) => Err(reason),
                }
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
    let (room_id, member_id, nickname, room_broadcast, owner_capability) = match handshake {
        RoomHandshake::Create {
            room_id,
            member_id,
            nickname,
            broadcast,
            owner_capability,
        } => {
            write_transport_plain(
                writer,
                &mut transport,
                &build_session_ok_line(&member_id, owner_capability.as_deref()),
            )
            .await?;
            (room_id, member_id, nickname, broadcast, owner_capability)
        }
        RoomHandshake::Join {
            room_id,
            member_id,
            nickname,
            broadcast,
            owner_capability,
        } => {
            write_transport_plain(
                writer,
                &mut transport,
                &build_session_ok_line(&member_id, owner_capability.as_deref()),
            )
            .await?;
            (room_id, member_id, nickname, broadcast, owner_capability)
        }
    };
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

                        let (broadcast_priority, broadcast_payload) = if let Some((packet_id, room_cipher)) = parse_transport_packet_line(&server_plain) {
                            let ack = build_ack_line(&packet_id);
                            let _ = write_transport_plain(writer, &mut transport, &ack).await;
                            if is_duplicate {
                                continue;
                            }
                            (packet_priority(&packet_id), room_cipher)
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
    request: rust_chat::client::utils::ServerInviteRequest,
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

    let mut invites_map = invites.lock().unwrap();
    invites_map.insert(
        token_id_hex,
        InviteTokenInfo {
            room_id: room_id.to_string(),
            expires_at,
            blob_b64: request.blob_b64,
            token_secret,
            state: InviteUseState::Unused,
        },
    );

    build_invite_token_line(&request.request_id, &token_secret_b64, expires_at)
}

async fn write_transport_plain(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    transport: &mut TransportCrypto,
    plain: &str,
) -> Result<()> {
    let cipher_line = transport.seal(plain);
    writer
        .write_all(handshake_writeall_macro(cipher_line).as_slice())
        .await?;
    Ok(())
}

fn normalize_invites(invites_map: &mut HashMap<String, InviteTokenInfo>, now: i64) {
    invites_map
        .retain(|_, info| info.expires_at >= now && !matches!(info.state, InviteUseState::Used));
    for info in invites_map.values_mut() {
        if let InviteUseState::Pending { pending_until, .. } = info.state {
            if pending_until < now {
                info.state = InviteUseState::Unused;
            }
        }
    }
}

fn reset_invite_to_unused(invites: &Invites, token_id_hex: &str) {
    let now = chrono::Utc::now().timestamp();
    let mut invites_map = invites.lock().unwrap();
    normalize_invites(&mut invites_map, now);
    if let Some(info) = invites_map.get_mut(token_id_hex) {
        info.state = InviteUseState::Unused;
    }
}

fn consume_invite_ready(
    invites: &Invites,
    token_id_hex: &str,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
) -> bool {
    let now = chrono::Utc::now().timestamp();
    let mut invites_map = invites.lock().unwrap();
    normalize_invites(&mut invites_map, now);
    let Some(info) = invites_map.get_mut(token_id_hex) else {
        return false;
    };
    match info.state {
        InviteUseState::Pending {
            client_nonce: pending_client_nonce,
            server_nonce: pending_server_nonce,
            ..
        } if &pending_client_nonce == client_nonce && &pending_server_nonce == server_nonce => {
            info.state = InviteUseState::Used;
            true
        }
        _ => false,
    }
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
