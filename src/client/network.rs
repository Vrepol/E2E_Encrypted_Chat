// src/network.rs
use anyhow::Result;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    time::{interval, sleep, Duration},
};

/// 启动网络任务：负责连接、心跳、读写和自动重连
///
/// `server_addr` 服务器地址；  
/// `username`   用户昵称；  
/// `net_tx`     把收到的「非心跳」消息发给 UI；  
/// `out_rx`     从 UI 那边接收要发给服务器的消息（包括用户输入）  
pub async fn run(
    server_addr: &str,
    username: &str,
    net_tx: UnboundedSender<String>,
    mut out_rx: UnboundedReceiver<String>,
) -> Result<()> {
    loop {
        match TcpStream::connect(server_addr).await {
            Ok(stream) => {
                let (reader, mut writer) = stream.into_split();
                let mut lines = BufReader::new(reader).lines();

                // —— 握手：先发昵称 —— 
                writer.write_all(username.as_bytes()).await?;
                writer.write_all(b"\n").await?;

                // —— 心跳定时器：每 30s 发一次 "/ping" —— 
                let mut hb = interval(Duration::from_secs(30));

                loop {
                    tokio::select! {
                        // 1) 读服务器发过来的消息
                        res = lines.next_line() => {
                            match res {
                                Ok(Some(line)) if line != "/ping_ack" => {
                                    let _ = net_tx.send(line);
                                }
                                _ => {
                                    eprintln!("⚠️ 连接断开，准备重连…");
                                    break;
                                }
                            }
                        }

                        // 2) 写从 UI 发过来的消息
                        Some(msg) = out_rx.recv() => {
                            if writer.write_all(msg.as_bytes()).await.is_err() {
                                eprintln!("⚠️ 写入失败，连接中断");
                                break;
                            }
                            let _ = writer.write_all(b"\n").await;
                        }

                        // 3) 定时发心跳
                        _ = hb.tick() => {
                            if writer.write_all(b"$$ping$$\n").await.is_err() {
                                eprintln!("⚠️ 心跳发送失败");
                                break;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("❌ 无法连接 {}: {}", server_addr, e);
            }
        }

        // 等待 5 秒再重试
        sleep(Duration::from_secs(5)).await;
        eprintln!("⏳ 重试连接 {} …", server_addr);
    }
}
