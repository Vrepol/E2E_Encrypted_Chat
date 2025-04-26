// ==============================
// src/bin/server.rs
// ==============================
use anyhow::Result;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::broadcast,
};

#[tokio::main]
async fn main() -> Result<()> {
    // 1. 监听端口
    let listener = TcpListener::bind("0.0.0.0:6655").await?;
    println!("🛰️  Chat-Server listening on 6655");
    // 2. 广播通道：所有客户端共享
    let (tx, _rx) = broadcast::channel::<String>(500);

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("⇄ 新连接：{addr}");
        let tx = tx.clone();
        let mut rx = tx.subscribe();

        // 3. 为每个客户端开一个任务
        tokio::spawn(async move {
            if let Err(e) = handle_client(socket, tx, &mut rx).await {
                eprintln!("客户端 {addr} 出错：{e:#}");
            }
        });
    }
}

async fn handle_client(
    socket: TcpStream,
    tx: broadcast::Sender<String>,
    rx: &mut broadcast::Receiver<String>,
) -> Result<()> {
    let (reader, mut writer) = socket.into_split();
    let mut lines = BufReader::new(reader).lines();

    // ——握手阶段：读取第一行作为昵称——
    let nickname = match lines.next_line().await? {
        Some(n) if !n.trim().is_empty() => n.trim().to_owned(),
        _ => return Ok(()), // 没有昵称，直接结束
    };
    tx.send(format!("⚡ [{nickname}] joined\n"))?;

    // ——正式消息循环——
    loop {
        tokio::select! {
            // ① 客户端发来新消息
            result = lines.next_line() => {
                match result? {
                    Some(line) => {
                        let msg = format!("[{nickname}] {line}\n");
                        let _ = tx.send(msg);          // 广播
                    }
                    None => break,                    // EOF
                }
            }
            // ② 其它客户端的广播消息
            Ok(msg) = rx.recv() => {
                if writer.write_all(msg.as_bytes()).await.is_err() {
                    break;
                }
            }
        }
    }

    // ——离开——
    let _ = tx.send(format!("⚡ [{nickname}] left\n"));
    Ok(())
}
