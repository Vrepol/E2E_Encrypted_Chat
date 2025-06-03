// src/client/receiver.rs
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use chrono::Local;
use tokio::sync::mpsc::UnboundedReceiver;
use tui::widgets::ListState;
use uuid::Uuid;
use base64::{engine::general_purpose, Engine as _};
use crate::client::utils::parse_text_img;
use super::notifier;
use std::path::Path;

/// 区分文本消息和图片消息
#[derive(Debug, Clone)]
pub enum ChatMessage {
    Text(String),
    Image {
        path:    PathBuf,
        sender:  String,
        ts:      String,
    },
}

/// 将消息从网络通道里“抽干”到本地消息列表中
pub fn drain_messages(
    net_rx: &mut UnboundedReceiver<String>,
    messages: &mut Vec<ChatMessage>,
    list_state: &mut ListState,
    my_name: &str,
    img_dir: &Path,
    members:    &mut Vec<String>, 
) {
    while let Ok(line) = net_rx.try_recv() {
        if line.starts_with("/member_list ") {
                members.clear();
                members.extend(
                    line["/member_list ".len()..]
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string()),
                );
                continue;
        }

        // 拆分发送者、原始时间戳（这里不再用）和 body
        let (sender, body) = parse_text_img(&line);

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
                    let file_path = img_dir.join(format!("img_{}.png", Uuid::new_v4()));
                    if let Ok(mut file) = File::create(&file_path) {
                        let _ = file.write_all(&bytes);
                        messages.push(ChatMessage::Image {
                            path:   file_path,
                            sender: sender.clone(),
                            ts:     hms.clone(),
                        });
                    } else {
                        // 写文件失败，退回为文本显示
                        let fallback = format!("[{}] <Failed to save image>", hms);
                        messages.push(ChatMessage::Text(fallback));
                    }
                }
                Err(_) => {
                    // 解码失败，退回为文本
                    let fallback = format!("[{}] <Invalid image data>", hms);
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
