use super::crypto::{server_open, server_seal, seal};   // open = 房间密钥的解密
use super::utils::get_plaintext;
use tokio::{io::{AsyncWriteExt, BufReader, Lines}, net::tcp::OwnedReadHalf,
            sync::mpsc::{UnboundedReceiver, UnboundedSender},
            time::{interval, Duration}};
use anyhow::Result;
use tokio::net::tcp::OwnedWriteHalf;
pub async fn chat_loop(
    mut lines: Lines<BufReader<OwnedReadHalf>>,
    mut writer: OwnedWriteHalf,
    net_tx:      UnboundedSender<String>,
    mut out_rx:  UnboundedReceiver<String>,
) -> Result<()> {
    let mut hb = interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            /* ---------------- 1) 读 ---------------- */
            res = lines.next_line() => {
                match res {
                    Ok(Some(line)) => {
                        if line == "/ping_ack" || line == "$$ping$$" { continue; }

                        // ① 尝试用 SERVER_KEY 解密控制消息
                        if let Some(plain) = server_open(&line) {
                            net_tx.send(plain).ok();
                            continue;
                        }
                    }
                    Ok(None) => { eprintln!("⚠️ Server closed the connection."); break; }
                    Err(e)   => { eprintln!("⚠️ Failed to receive message: {e}"); break; }
                }
            }

            /* ---------------- 2) 写 ---------------- */
            msg = out_rx.recv() => {
                match msg {
                    Some(text) if text == "//~``~//" => {
                        writer.shutdown().await?;
                        break;
                    }
                    Some(text) => {
                        let plain = get_plaintext(&text).await?;
                        let cipher_line = server_seal(seal(&plain));

                        if writer.write_all(cipher_line.as_bytes()).await.is_err() {
                            eprintln!("⚠️ Failed to send");
                            break;
                        }
                        let _ = writer.write_all(b"\n").await;
                    }
                    None => {
                        writer.shutdown().await?;
                        break;
                    }
                }
            }

            /* ---------------- 3) 心跳 ---------------- */
            _ = hb.tick() => {
                if writer.write_all(b"$$ping$$\n").await.is_err() {
                    break;
                }
            }
        }
    }
    Ok(())
}
