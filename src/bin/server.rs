use anyhow::Result;
use clap::Parser;
use futures_util::FutureExt;
use once_cell::sync::OnceCell;
use rand::{distr::Alphanumeric, Rng};
use rust_chat::client::{
    crypto::{dec_auth, pwd_hash, server_open, server_seal},
    utils::{
        build_ack_line, build_invite_error_line, build_invite_token_line,
        handshake_writeall_macro, parse_server_invite_request_line, parse_transport_packet_line,
        INVITE_TTL_SECS,
    },
};
use std::{
    collections::{HashMap, HashSet},
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
    #[arg(short, long, default_value_t = 6655)]
    port: u16,
    #[arg(short = 'k', default_value = "Vrepol")]
    password: String,
}

static SERVER_PWD_HASH: OnceCell<[u8; 32]> = OnceCell::new();

struct RoomInfo {
    tx: broadcast::Sender<String>,
    credential: String,
    members: HashSet<String>,
    owner_nickname: Option<String>,
    owner_capability: Option<String>,
}

struct InviteTokenInfo {
    room_id: String,
    credential: String,
    expires_at: i64,
    used: bool,
}

type Rooms = Arc<Mutex<HashMap<String, RoomInfo>>>;
type Invites = Arc<Mutex<HashMap<String, InviteTokenInfo>>>;

struct RoomGuard {
    rooms: Rooms,
    room_id: String,
    nickname: String,
    tx: broadcast::Sender<String>,
}

impl Drop for RoomGuard {
    fn drop(&mut self) {
        let server_enc = server_seal(format!("⚡ [{}] left.", self.nickname));
        let _ = self.tx.send(format!("{}\n", server_enc));

        let mut map = self.rooms.lock().unwrap();
        if let Some(info) = map.get_mut(&self.room_id) {
            info.members.remove(&self.nickname);
            if info.owner_nickname.as_deref() == Some(&self.nickname) {
                info.owner_nickname = None;
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
    let names: Vec<_> = info.members.iter().cloned().collect();
    let cipher = server_seal(format!("/member_list {}", names.join(",")));
    let _ = info.tx.send(format!("{}\n", cipher));
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    SERVER_PWD_HASH.set(pwd_hash(&args.password)).unwrap();
    rust_chat::client::crypto::set_server_key(pwd_hash(&args.password));

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

    let enc_line = match lines.next_line().await? {
        Some(l) => l.trim_end().to_owned(),
        None => return Ok(()),
    };

    let auth_line = server_open(&enc_line).unwrap();
    if !auth_line.starts_with("AUTH ") {
        writer.write_all(b"ERR NeedAUTH\n").await?;
        return Ok(());
    }
    let auth_ok = dec_auth(&auth_line[5..], SERVER_PWD_HASH.get().unwrap());
    if !auth_ok {
        writer.write_all(b"ERR BadAuth\n").await?;
        return Ok(());
    }
    writer.write_all(&handshake_writeall_macro("OK".to_string())).await?;

    let room_line = {
        let map = rooms.lock().unwrap();
        let mut line = String::from("ROOMS");
        for id in map.keys() {
            line.push(' ');
            line.push_str(id);
        }
        line.push('\n');
        line
    };
    writer.write_all(server_seal(room_line).as_bytes()).await?;
    writer.write_all(b"\n").await?;

    let cmd = match lines.next_line().await? {
        Some(c) => c.trim_end().to_owned(),
        None => return Ok(()),
    };
    let cmd = server_open(&cmd).unwrap_or(cmd);
    let mut parts = cmd.split_whitespace();
    let action = parts.next().unwrap_or_default();

    enum Handshake {
        Create {
            room_id: String,
            nickname: String,
            tx: broadcast::Sender<String>,
            owner_capability: String,
        },
        Join {
            room_id: String,
            nickname: String,
            tx: broadcast::Sender<String>,
        },
    }

    let handshake: Result<Option<Handshake>, &'static str> = match action {
        "CREATE" => {
            let room_id = parts.next().unwrap_or_default().to_string();
            let cred = parts.next().unwrap_or_default().to_string();
            let nickname = parts.next().unwrap_or_default().to_string();
            if room_id.is_empty() || cred.is_empty() || nickname.is_empty() {
                Ok(None)
            } else {
                let mut map = rooms.lock().unwrap();
                if map.contains_key(&room_id) {
                    Err("RoomExists")
                } else {
                    let owner_capability: String = rand::rng()
                        .sample_iter(&Alphanumeric)
                        .take(32)
                        .map(char::from)
                        .collect();
                    let (tx, _) = broadcast::channel::<String>(500);
                    let mut set = HashSet::new();
                    set.insert(nickname.clone());
                    map.insert(
                        room_id.clone(),
                        RoomInfo {
                            tx: tx.clone(),
                            credential: cred,
                            members: set,
                            owner_nickname: Some(nickname.clone()),
                            owner_capability: Some(owner_capability.clone()),
                        },
                    );

                    Ok(Some(Handshake::Create {
                        room_id,
                        nickname,
                        tx,
                        owner_capability,
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
                match {
                    let mut map = rooms.lock().unwrap();
                    if let Some(info) = map.get_mut(&room_id) {
                        if info.credential != cred {
                            Err("BadCredential")
                        } else {
                            info.members.insert(nickname.clone());
                            Ok(info.tx.clone())
                        }
                    } else {
                        Err("NoSuchRoom")
                    }
                } {
                    Ok(tx) => Ok(Some(Handshake::Join {
                        room_id,
                        nickname,
                        tx,
                    })),
                    Err(reason) => Err(reason),
                }
            }
        }
        "JOIN_INVITE" => {
            let room_id = parts.next().unwrap_or_default().to_string();
            let token = parts.next().unwrap_or_default().to_string();
            let credential = parts.next().unwrap_or_default().to_string();
            let nickname = parts.next().unwrap_or_default().to_string();
            if room_id.is_empty() || token.is_empty() || credential.is_empty() || nickname.is_empty() {
                Ok(None)
            } else {
                let now = chrono::Utc::now().timestamp();
                let invite_ok = {
                    let mut invites_map = invites.lock().unwrap();
                    invites_map.retain(|_, info| !info.used && info.expires_at >= now);
                    match invites_map.get_mut(&token) {
                        Some(info)
                            if !info.used
                                && info.expires_at >= now
                                && info.room_id == room_id
                                && info.credential == credential =>
                        {
                            info.used = true;
                            true
                        }
                        _ => false,
                    }
                };

                if !invite_ok {
                    Err("InviteInvalid")
                } else {
                    match {
                        let mut map = rooms.lock().unwrap();
                        if let Some(info) = map.get_mut(&room_id) {
                            info.members.insert(nickname.clone());
                            Ok(info.tx.clone())
                        } else {
                            Err("NoSuchRoom")
                        }
                    } {
                        Ok(tx) => Ok(Some(Handshake::Join {
                            room_id,
                            nickname,
                            tx,
                        })),
                        Err(reason) => Err(reason),
                    }
                }
            }
        }
        _ => {
            Err("UnknownAction")
        }
    };

    let handshake = match handshake {
        Ok(Some(handshake)) => handshake,
        Ok(None) => {
            writer.write_all(b"ERR InvalidCmd\n").await?;
            return Ok(());
        }
        Err(reason) => {
            return write_error_and_return(&mut writer, reason).await;
        }
    };

    let (room_id, nickname, room_tx, owner_capability) = match handshake {
        Handshake::Create {
            room_id,
            nickname,
            tx,
            owner_capability,
        } => {
            let reply = handshake_writeall_macro(format!("OK OWNER {owner_capability}"));
            writer.write_all(&reply).await?;
            (room_id, nickname, tx, Some(owner_capability))
        }
        Handshake::Join { room_id, nickname, tx } => {
            writer.write_all(&handshake_writeall_macro("OK".to_string())).await?;
            (room_id, nickname, tx, None)
        }
    };

    let _guard = RoomGuard {
        rooms: rooms.clone(),
        room_id: room_id.clone(),
        nickname: nickname.clone(),
        tx: room_tx.clone(),
    };

    let server_enc = server_seal(format!("⚡ [{}] joined.", nickname));
    let _ = room_tx.send(format!("{}\n", server_enc));
    let mut room_rx = room_tx.subscribe();
    {
        let map = rooms.lock().unwrap();
        if let Some(info) = map.get(&room_id) {
            broadcast_member_list(info);
        }
    }

    loop {
        tokio::select! {
            result = lines.next_line() => {
                match result? {
                    Some(line) => {
                        if line == "$$ping$$" {
                            let _ = writer.write_all(b"/ping_ack\n").await;
                            continue;
                        }

                        let server_plain = server_open(&line).unwrap_or(line);
                        let broadcast_payload = if let Some((packet_id, room_cipher)) = parse_transport_packet_line(&server_plain) {
                            let ack = handshake_writeall_macro(build_ack_line(&packet_id));
                            let _ = writer.write_all(&ack).await;
                            room_cipher
                        } else {
                            server_plain
                        };

                        if let Some(inv_req) = parse_server_invite_request_line(&broadcast_payload) {
                            let response = handle_invite_request(
                                &rooms,
                                &invites,
                                &room_id,
                                &nickname,
                                owner_capability.as_deref(),
                                inv_req,
                            );
                            let _ = writer.write_all(&handshake_writeall_macro(response)).await;
                            continue;
                        }

                        let server_enc = server_seal(format!("[{}] {}", nickname, broadcast_payload));
                        let _ = room_tx.send(format!("{}\n", server_enc));
                    }
                    None => break,
                }
            }
            Ok(msg) = room_rx.recv() => {
                if writer.write_all(msg.as_bytes()).await.is_err() {
                    break;
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
    nickname: &str,
    session_owner_capability: Option<&str>,
    request: rust_chat::client::utils::ServerInviteRequest,
) -> String {
    if request.room_id != room_id {
        return build_invite_error_line(&request.request_id, "RoomMismatch");
    }

    let mut rooms_map = rooms.lock().unwrap();
    let Some(info) = rooms_map.get_mut(room_id) else {
        return build_invite_error_line(&request.request_id, "NoSuchRoom");
    };

    let owner_capability = match (&info.owner_nickname, &info.owner_capability) {
        (Some(owner_name), Some(owner_capability)) if owner_name == nickname => owner_capability,
        _ => return build_invite_error_line(&request.request_id, "OwnerOffline"),
    };

    if session_owner_capability != Some(owner_capability.as_str())
        || request.owner_capability != *owner_capability
    {
        return build_invite_error_line(&request.request_id, "InviteNotAllowed");
    }

    let token: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(40)
        .map(char::from)
        .collect();
    let expires_at = chrono::Utc::now().timestamp() + INVITE_TTL_SECS;

    drop(rooms_map);

    let mut invites_map = invites.lock().unwrap();
    invites_map.insert(
        token.clone(),
        InviteTokenInfo {
            room_id: room_id.to_string(),
            credential: info_credential(rooms, room_id),
            expires_at,
            used: false,
        },
    );

    build_invite_token_line(&request.request_id, &token, expires_at)
}

fn info_credential(rooms: &Rooms, room_id: &str) -> String {
    let rooms_map = rooms.lock().unwrap();
    rooms_map
        .get(room_id)
        .map(|info| info.credential.clone())
        .unwrap_or_default()
}

async fn write_error_and_return(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    reason: &str,
) -> Result<()> {
    writer
        .write_all(format!("ERR {reason}\n").as_bytes())
        .await?;
    Ok(())
}
