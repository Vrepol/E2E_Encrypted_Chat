// src/network.rs

use anyhow::Result;
use tokio::{
    io::{AsyncWriteExt, BufReader, Lines},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    time::{interval, Duration},
};
use super::crypto::seal;
use super::utils::get_plaintext;
pub async fn chat_loop(
    mut lines: Lines<BufReader<OwnedReadHalf>>,  // ← 和 connect_and_login 返回的一致
    mut writer: OwnedWriteHalf,                  // ← stream.into_split() 给的就是这个
    net_tx: UnboundedSender<String>,
    mut out_rx: UnboundedReceiver<String>,
) -> Result<()> {
    let mut hb = interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            // 1) 读
            res = lines.next_line() => {
                match res {
                    Ok(Some(line)) => {
                        if line == "/ping_ack" || line == "$$ping$$" {
                            // 只是心跳确认，忽略它
                            continue;
                        }
                        // 真正的业务消息
                        let _ = net_tx.send(line);
                    }
                    Ok(None) => {
                        eprintln!("⚠️ Server closed the connection.");
                        break;
                    }
                    Err(e) => {
                        eprintln!("⚠️ Failed to receive message: {}", e);
                        break;
                    }
                }
            }
            // 2) 写
            msg = out_rx.recv() => {
                match msg {
                    Some(text) if text == "//~``~//" => {
                        // 然后再 shutdown 写端，发 FIN
                        writer.shutdown().await?;
                        break;  // 结束 chat_loop
                    }
                    Some(text) => {
                        let plain = get_plaintext(&text).await?;
                        // 正常聊天消息
                        let cipher_line = seal(&plain);
                        if writer.write_all(cipher_line.as_bytes()).await.is_err() {
                            eprintln!("⚠️ Failed to send");
                            break;
                        }
                        let _ = writer.write_all(b"\n").await;
                    }
                    None => {
                        // 通道关闭了，也退出
                        writer.shutdown().await?;
                        break;
                    }
                }
            }
            

            // 3) 心跳
            _ = hb.tick() => {
                if writer.write_all(b"$$ping$$\n").await.is_err() {
                    break;
                }
            }
        }
    }
    Ok(())
}
