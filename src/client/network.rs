// src/network.rs

use anyhow::Result;
use tokio::{
    io::{AsyncWriteExt, BufReader, Lines},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    time::{interval, Duration},
};
use super::crypto::seal;

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
                        if line == "/ping_ack" {
                            // 只是心跳确认，忽略它
                            continue;
                        }
                        // 真正的业务消息
                        let _ = net_tx.send(line);
                    }
                    Ok(None) => {
                        eprintln!("⚠️ 服务器关闭了连接");
                        break;
                    }
                    Err(e) => {
                        eprintln!("⚠️ 读取出错: {}", e);
                        break;
                    }
                }
            }

            // 2) 写
            Some(msg) = out_rx.recv() => {
                let cipher_line = seal(&msg);
                if writer.write_all(cipher_line.as_bytes()).await.is_err() {
                    eprintln!("⚠️ 写入失败");
                    break;
                }
                let _ = writer.write_all(b"\n").await;
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
