// src/client/receiver.rs
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::PathBuf;

use chrono::Local;
use tokio::sync::mpsc::UnboundedReceiver;
use tui::widgets::ListState;
use uuid::Uuid;
use base64::{engine::general_purpose, Engine as _};
use crate::client::utils::parse_text_img;
use super::notifier;

/// 区分文本消息和图片消息
#[derive(Debug, Clone)]
pub enum ChatMessage {
    Text(String),
    Image {
        path:    PathBuf,
        sender:  String,
        ts:      String,   // 这里存储 Local::now().format("%H:%M:%S").to_string()
    },
}

/// 将消息从网络通道里“抽干”到本地消息列表中
pub fn drain_messages(
    net_rx: &mut UnboundedReceiver<String>,
    messages: &mut Vec<ChatMessage>,
    list_state: &mut ListState,
    my_name: &str,
) {
    while let Ok(line) = net_rx.try_recv() {
        if line.contains("$$ping$$") {
            continue;
        }

        // 拆分发送者、原始时间戳（这里不再用）和 body
        let (sender, _orig_ts, body) = parse_text_img(&line);

        // ★ 只有别人发的才提醒
        if sender != my_name {
            notifier::notify();
        }

        // 判断是否滚动到底部
        let at_bottom = list_state
            .selected()
            .map(|i| i + 1 == messages.len())
            .unwrap_or(true);

        // 本地时间戳
        let now = Local::now();
        let hms = now.format("%H:%M:%S").to_string();

        if body.starts_with("/IMGDATA") {
            // 图片分支：去掉前缀，解 base64，写文件
            let b64_data = &body["/IMGDATA".len()..];
            match general_purpose::STANDARD.decode(b64_data) {
                Ok(bytes) => {
                    // 临时目录 ./rust_chat_images
                    let mut dir = std::env::temp_dir();
                    dir.push("rust_chat_images");
                    let _ = create_dir_all(&dir);

                    // 文件名：img_<timestamp>_<uuid>.png
                    let file_name = format!("img_{}.png", Uuid::new_v4());
                    dir.push(file_name);

                    if let Ok(mut file) = File::create(&dir) {
                        let _ = file.write_all(&bytes);
                        messages.push(
                            ChatMessage::Image { 
                                path: dir.clone() ,
                                sender:sender.clone(),
                                ts: hms.clone()}
                        );
                    } else {
                        // 写文件失败，退回为文本显示
                        let fallback = format!("[{}] <图片保存失败>", hms);
                        messages.push(ChatMessage::Text(fallback));
                    }
                }
                Err(_) => {
                    // 解码失败，退回为文本
                    let fallback = format!("[{}] <无效的图片数据>", hms);
                    messages.push(ChatMessage::Text(fallback));
                }
            }
        } else {
            // 文本分支：按旧逻辑加时间戳
            let formatted = if let Some(pos) = line.find(']') {
                // 保留原来中括号后的内容
                let (left, right) = line.split_at(pos + 1);
                format!("{} [{}]{}", left, hms, right)
            } else {
                format!("[{}] {}", hms, line)
            };
            messages.push(ChatMessage::Text(formatted));
        }

        // 维持选中最后一条
        if at_bottom {
            list_state.select(Some(messages.len().saturating_sub(1)));
        }
        // 超过 500 条就删除前 100 条
        if messages.len() > 500 {
            messages.drain(..100);
        }
    }
}
