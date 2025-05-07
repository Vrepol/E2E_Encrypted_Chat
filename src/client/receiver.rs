// src/client/receiver.rs
use tokio::sync::mpsc::UnboundedReceiver;
use tui::widgets::ListState;
use crate::client::utils::parse_name_body;
use super::notifier;

pub fn drain_messages(
    net_rx: &mut UnboundedReceiver<String>,
    messages: &mut Vec<String>,
    list_state: &mut ListState,
    my_name: &str,                   // ← 新参数
) {
    while let Ok(line) = net_rx.try_recv() {
        if line.contains("$$ping$$") {
            continue;
        }

        // ★ 提醒：别人发的才提醒
        let (sender, _) = parse_name_body(&line);   // 解析一次就够
        if sender != my_name {
            notifier::notify();
        }

        // —— 以下与旧逻辑相同 ——
        let at_bottom = list_state
            .selected()
            .map(|i| i + 1 == messages.len())
            .unwrap_or(true);

        messages.push(line);

        if at_bottom {
            list_state.select(Some(messages.len().saturating_sub(1)));
        }

        if messages.len() > 500 {
            messages.drain(..100);
        }
    }
}
