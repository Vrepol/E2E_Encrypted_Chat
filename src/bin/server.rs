use anyhow::Result;
use std::panic::AssertUnwindSafe;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::broadcast,
};
use futures_util::FutureExt; // 为 catch_unwind 引入扩展方法

#[tokio::main]
async fn main() -> Result<()> {
    // 1. 监听端口
    let listener = TcpListener::bind("0.0.0.0:6655").await?;
    println!("🛰️  Chat-Server listening on 6655");

    // 2. 广播通道：所有客户端共享
    let (tx, _rx) = broadcast::channel::<String>(500);

    loop {
        // 接受新连接
        let (socket, addr) = listener.accept().await?;
        println!("⇄ 新连接：{}", addr);

        let tx = tx.clone();
        let mut rx = tx.subscribe();

        // 3. 在 spawn 中使用 catch_unwind，避免子任务 panic 影响整个运行时
        tokio::spawn(
            AssertUnwindSafe(async move {
                if let Err(e) = handle_client(socket, tx, &mut rx).await {
                    eprintln!("客户端 {} 出错：{:#}", addr, e);
                }
            })
            .catch_unwind() // 捕获 panic
            .map(move |res| {
                if let Err(panic) = res {
                    eprintln!("子任务 for {} panic 已捕获：{:?}", addr, panic);
                }
            }),
        );
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
        Some(n) if !n.trim().is_empty() => n.trim().to_string(),
        _ => return Ok(()),
    };
    tx.send(format!("⚡ [{}] joined.\n", nickname))?;

    // ——正式消息循环——
    loop {
        tokio::select! {
            // ① 本客户端发来新消息
            result = lines.next_line() => {
                match result? {
                    Some(line) => {
                        let msg = format!("[{}] {}\n", nickname, line);
                        let _ = tx.send(msg);
                    }
                    None => break, // EOF
                }
            }
            // ② 接收其它客户端的广播
            Ok(msg) = rx.recv() => {
                if writer.write_all(msg.as_bytes()).await.is_err() {
                    break;
                }
            }
        }
    }

    // ——离开——
    let _ = tx.send(format!("⚡ [{}] left.\n", nickname));
    Ok(())
}
