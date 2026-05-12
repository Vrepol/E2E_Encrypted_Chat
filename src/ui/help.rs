use crate::client::receiver::{TransferDirection, TransferStage};

pub const HELP_TEXT: &str = r#"快捷键与命令说明：

• Ctrl+X       → 智能贴入剪贴板文本/图片/文件
• Ctrl+C       → 复制当前选中消息
• Ctrl+Z       → 撤销输入框
• Ctrl+A       → 清空输入框
• Ctrl+I       → 生成邀请码
• /send <path> → 发送任意文件
• ←/→          → 移动光标（Ctrl+← 跳3字符，Ctrl+→ 跳至末尾）
• ↑/↓          → 列表选上下（Ctrl+↑ 跳 5 条，Ctrl+↓ 跳到底部）
• Tab          → 打开选中行的附件
• Esc          → 退出房间"#;

pub const HELP_TEXT_EN: &str = r#"Keyboard Shortcuts and Command Descriptions:

• Ctrl+X       → Smart paste clipboard text/image/files
• Ctrl+C       → Copy the currently selected message
• Ctrl+Z       → Undo in input box
• Ctrl+A       → Clear input box
• Ctrl+I       → Generate invite code
• /send <path> → Send any file as attachment
• ←/→          → Move cursor (Ctrl+← jump 3 characters, Ctrl+→ jump to end)
• ↑/↓          → Navigate list up/down (Ctrl+↑ jump 5 items, Ctrl+↓ jump to bottom)
• Tab          → Open the attachment in the selected row
• Esc          → Exit room"#;

pub fn format_file_size(size: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    match size {
        0..=1023 => format!("{size} B"),
        1024..=1_048_575 => format!("{:.1} KB", size as f64 / KB),
        1_048_576..=1_073_741_823 => format!("{:.1} MB", size as f64 / MB),
        _ => format!("{:.1} GB", size as f64 / GB),
    }
}

pub fn render_transfer_line(
    file_name: &str,
    total_size: u64,
    direction: TransferDirection,
    stage: TransferStage,
    acked_chunks: usize,
    total_chunks: usize,
    detail: Option<&str>,
) -> String {
    let status = match (direction, stage) {
        (_, TransferStage::Done) => "done".to_string(),
        (_, TransferStage::Failed) => "failed".to_string(),
        (TransferDirection::Sending, TransferStage::Active) => {
            if total_chunks == 0 {
                "sending 0%".to_string()
            } else {
                let pct = (acked_chunks.saturating_mul(100)) / total_chunks.max(1);
                format!("sending {pct}%")
            }
        }
        (TransferDirection::Receiving, TransferStage::Active) => {
            if total_chunks == 0 {
                "receiving 0%".to_string()
            } else {
                let pct = (acked_chunks.saturating_mul(100)) / total_chunks.max(1);
                format!("receiving {pct}%")
            }
        }
    };

    let mut line = format!("{status} | {file_name} | {}", format_file_size(total_size));
    if let Some(detail) = detail.filter(|s| !s.trim().is_empty()) {
        line.push_str(" | ");
        line.push_str(detail);
    }
    line
}
