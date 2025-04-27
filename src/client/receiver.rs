// src/client/receiver.rs
use tokio::sync::mpsc::UnboundedReceiver;
use tui::widgets::ListState;

/// 从 `net_rx` 拉取所有可用消息，丢弃心跳包 `$$ping$$`，
/// 并把剩余消息追加到 `messages` 并维护 `list_state`。
pub fn drain_messages(
    net_rx: &mut UnboundedReceiver<String>,
    messages: &mut Vec<String>,
    list_state: &mut ListState,
) {
    while let Ok(line) = net_rx.try_recv() {
        // 丢弃心跳
        if line.contains("$$ping$$") {
            continue;
        }
        // 是否在底部
        let at_bottom = list_state
            .selected()
            .map(|i| i + 1 == messages.len())
            .unwrap_or(true);

        // 添加消息
        messages.push(line);

        // 如果之前在底部，则滚到底
        if at_bottom {
            list_state.select(Some(messages.len().saturating_sub(1)));
        }

        // 限长保留最近 500 条
        if messages.len() > 500 {
            messages.drain(..100);
        }
    }
}