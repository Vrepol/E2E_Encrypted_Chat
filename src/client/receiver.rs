// src/client/receiver.rs
use tokio::sync::mpsc::UnboundedReceiver;
use tui::widgets::ListState;
use crate::client::utils::parse_name_body;
use super::notifier;
use chrono::Local;
pub fn drain_messages(
    net_rx: &mut UnboundedReceiver<String>,
    messages: &mut Vec<String>,
    list_state: &mut ListState,
    my_name: &str,
) {
    while let Ok(line) = net_rx.try_recv() {
        if line.contains("$$ping$$") {
            continue;
        }

        // ★ 提醒：别人发的才提醒
        let (sender, _ ,_) = parse_name_body(&line);
        if sender != my_name {
            notifier::notify();
        }

        // —— 以下与旧逻辑相同 ——
        let at_bottom = list_state
            .selected()
            .map(|i| i + 1 == messages.len())
            .unwrap_or(true);

        let now = Local::now();
        let hms = now.format("%H:%M:%S").to_string();
        let formatted = if let Some(pos) = line.find(']') {
            // split_at(pos+1) 保证 left 包含 ']'，right 以空格开头
            let (left, right) = line.split_at(pos + 1);
            format!("{} [{}]{}", left, hms, right)
        } else {
            // 如果没有找到 ']'，就简单地在最前面加
            format!("[{}] {}", hms, line)
        };

        // 3. 推入带时间戳的新行
        messages.push(formatted);

        if at_bottom {
            list_state.select(Some(messages.len().saturating_sub(1)));
        }

        if messages.len() > 500 {
            messages.drain(..100);
        }
    }
}
