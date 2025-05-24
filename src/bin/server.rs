use anyhow::Result;
use futures_util::FutureExt;
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
fn broadcast_member_list(info: &RoomInfo) {
        let names: Vec<_> = info.members.iter().cloned().collect();
        let _ = info.tx.send(format!("/member_list {}\n", names.join(",")));
}
struct RoomInfo {
    tx: broadcast::Sender<String>,
    credential: String,
    members: HashSet<String>,
}
type Rooms = Arc<Mutex<HashMap<String, RoomInfo>>>;

/// 离开清理 guard：Drop 时发送离开消息并回收空房间
struct RoomGuard {
    rooms: Rooms,
    room_id: String,
    nickname: String,
    tx: broadcast::Sender<String>,
}

impl Drop for RoomGuard {
    fn drop(&mut self) {
        // 发送离开广播
        let _ = self.tx.send(format!("⚡ [{}] left.\n", self.nickname));
        // 回收空房间
        let mut map = self.rooms.lock().unwrap();
        if let Some(info) = map.get_mut(&self.room_id) {
            // 只有自己一个订阅者时，移除房间
            info.members.remove(&self.nickname);
                        broadcast_member_list(info);              // ← 推送最新名单
                        if info.members.is_empty() {
                            map.remove(&self.room_id);
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let listener = TcpListener::bind("0.0.0.0:6655").await?;
    println!("🛰️  Chat-Server listening on 6655");

    let rooms: Rooms = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (socket, addr) = listener.accept().await?;
        let rooms_clone = rooms.clone();

        tokio::spawn(
            AssertUnwindSafe(async move {
                if let Err(e) = handle_client(socket, rooms_clone).await {
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

async fn handle_client(socket: TcpStream, rooms: Rooms) -> Result<()> {
    let (reader, mut writer) = socket.into_split();
    let mut lines = BufReader::new(reader).lines();

    /* ---------- ① 发送房间列表 ---------- */
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
    writer.write_all(room_line.as_bytes()).await?;

    /* ---------- ② 读取客户端指令 ---------- */
    let cmd = match lines.next_line().await? {
        Some(c) => c,
        None => return Ok(()),
    };
    let mut parts = cmd.split_whitespace();
    let action   = parts.next().unwrap_or_default();
    let room_id  = parts.next().unwrap_or_default().to_string();
    let cred     = parts.next().unwrap_or_default().to_string();
    let nickname = parts.next().unwrap_or_default().to_string();

    if room_id.is_empty() || cred.is_empty() || nickname.is_empty() {
        writer.write_all(b"ERR InvalidCmd\n").await?;
        return Ok(());
    }

    /* ---------- ③ 同步处理房间表（无 await） ---------- */
    enum Handshake {
        Ok(broadcast::Sender<String>),
        Err(&'static str),
    }
    let handshake = {
        let mut map = rooms.lock().unwrap();
        match action {
            "CREATE" => {
                if map.contains_key(&room_id) {
                    Handshake::Err("RoomExists")
                } else {
                    let (tx, _) = broadcast::channel::<String>(500);
                    let mut set = HashSet::new();
                    set.insert(nickname.clone());
                    let info = RoomInfo { tx: tx.clone(), credential: cred.clone(), members: set };
                    map.insert(room_id.clone(), info);
                    Handshake::Ok(tx)
                }
            }
            "JOIN" => {
                if let Some(info) = map.get_mut(&room_id) {
                    if info.credential == cred {
                        info.members.insert(nickname.clone());
                        Handshake::Ok(info.tx.clone())
                    } else {
                        Handshake::Err("BadCredential")
                    }
                } else {
                    Handshake::Err("NoSuchRoom")
                }
            }
            _ => Handshake::Err("UnknownAction"),
        }
    };

    /* ---------- ④ 发送握手结果 & 创建清理 guard ---------- */
    let room_tx = match handshake {
        Handshake::Ok(tx) => {
            writer.write_all(b"OK\n").await?;
            tx
        }
        Handshake::Err(why) => {
            writer.write_all(format!("ERR {why}\n").as_bytes()).await?;
            return Ok(());
        }
    };

    // 把 guard 放在这里，确保后续任何退出都会调用它的 Drop
    let _guard = RoomGuard {
        rooms: rooms.clone(),
        room_id: room_id.clone(),
        nickname: nickname.clone(),
        tx: room_tx.clone(),
    };

    // 发送加入通知
    let _ = room_tx.send(format!("⚡ [{}] joined.\n", nickname));
    let mut room_rx = room_tx.subscribe();
    {
        let map = rooms.lock().unwrap();
        if let Some(info) = map.get(&room_id) {
            broadcast_member_list(info);   // <-- 现在新客户端已经订阅，一定能收到
        }
    }
    /* ---------- ⑤ 正式聊天循环 ---------- */
    loop {
        tokio::select! {
            result = lines.next_line() => {
                match result? {
                    Some(line) => {
                        if line == "$$ping$$" {
                            let _ = writer.write_all(b"/ping_ack\n").await;
                            continue;
                        }
                        let _ = room_tx.send(format!("[{}] {}\n", nickname, line));
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

    // 注意：不需要手动发送离开或回收房间，_guard 会在此作用域结束时自动执行
    Ok(())
}
