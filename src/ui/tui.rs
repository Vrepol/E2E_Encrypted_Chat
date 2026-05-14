use crate::client::receiver::ChatMessage;
use crate::protocol::MemberIdentity;
use crate::ui::help::format_file_size;
use tui::{
    backend::Backend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Span, Spans},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

#[derive(Debug, Clone)]
pub struct RenderedChatRow {
    pub message_index: usize,
    pub text: String,
    pub color: Color,
}

const LIST_HIGHLIGHT_SYMBOL: &str = "▌ ";

pub fn parse_name_body(msg: &ChatMessage) -> (String, String, String) {
    match msg {
        ChatMessage::Text(line) => {
            let (name, after_name) = if let Some(start) = line.find('[') {
                if let Some(end_rel) = line[start + 1..].find(']') {
                    let end = start + 1 + end_rel;
                    let name = line[start + 1..end].to_owned();
                    let rest = &line[end + 1..];
                    (name, rest)
                } else {
                    ("???".into(), line.as_str())
                }
            } else {
                ("???".into(), line.as_str())
            };

            let (time, after_time) = if let Some(start) = after_name.find('[') {
                if let Some(end_rel) = after_name[start + 1..].find(']') {
                    let end = start + 1 + end_rel;
                    let time = after_name[start + 1..end].to_owned();
                    let rest = &after_name[end + 1..];
                    (time, rest)
                } else {
                    ("??:??:??".into(), after_name)
                }
            } else {
                ("??:??:??".into(), after_name)
            };

            let body_plain = after_time.trim_start().to_owned();
            (name, time, body_plain)
        }
        ChatMessage::Attachment {
            sender,
            ts,
            name,
            size,
            kind,
            ..
        } => {
            let label = match kind {
                crate::protocol::AttachmentKind::Image => "图片",
                crate::protocol::AttachmentKind::File => "文件",
            };
            let body = format!("[{}] {} ({})", label, name, format_file_size(*size));
            (sender.to_string(), ts.to_string(), body)
        }
    }
}

fn nth_grapheme_byte_idx(s: &str, n: usize) -> usize {
    s.grapheme_indices(true)
        .nth(n)
        .map(|(idx, _)| idx)
        .unwrap_or_else(|| s.len())
}

fn wrap_graphemes(text: &str, max_width: u16) -> Vec<String> {
    if max_width == 0 {
        return vec![String::new()];
    }

    let mut lines = Vec::new();
    let mut current_line = String::new();
    let mut current_width = 0u16;

    for symbol in text.graphemes(true) {
        if symbol == "\n" {
            lines.push(std::mem::take(&mut current_line));
            current_width = 0;
            continue;
        }

        let symbol_width = symbol.width() as u16;
        if symbol_width > max_width {
            continue;
        }

        if current_width + symbol_width > max_width {
            lines.push(std::mem::take(&mut current_line));
            current_width = 0;
        }

        current_line.push_str(symbol);
        current_width += symbol_width;
    }

    lines.push(current_line);

    if lines.is_empty() {
        lines.push(String::new());
    }

    lines
}

fn input_cursor_position(input: &str, cursor: usize, max_width: u16) -> (u16, u16) {
    let byte_idx = nth_grapheme_byte_idx(input, cursor);
    let prefix = &input[..byte_idx];
    let wrapped = wrap_graphemes(prefix, max_width);
    let cursor_y = wrapped.len().saturating_sub(1) as u16;
    let cursor_x = wrapped
        .last()
        .map(|line| line.as_str().width() as u16)
        .unwrap_or(0);
    (cursor_x, cursor_y)
}

pub fn chat_inner_width(size: Rect) -> usize {
    size.width
        .saturating_sub(4)
        .saturating_sub(LIST_HIGHLIGHT_SYMBOL.width() as u16) as usize
}

pub fn build_chat_rows(
    messages: &[ChatMessage],
    chat_inner_width: usize,
    username: &str,
) -> Vec<RenderedChatRow> {
    let bubble_width = if chat_inner_width < 24 {
        chat_inner_width.max(1)
    } else {
        (chat_inner_width.saturating_mul(3) / 4).clamp(24, chat_inner_width)
    };
    let wrap_width = bubble_width.saturating_sub(2).max(1) as u16;
    let mut rows = Vec::new();

    for (message_index, raw) in messages.iter().enumerate() {
        let (name, time, display_body) = parse_name_body(raw);
        let is_me = name == username;
        let is_system = name == "System";
        let color = if is_system {
            Color::DarkGray
        } else if is_me {
            Color::Cyan
        } else {
            Color::LightMagenta
        };

        if is_system {
            let system_line = format!("• {time}  {display_body}");
            for line in wrap_graphemes(&system_line, chat_inner_width.max(1) as u16) {
                rows.push(RenderedChatRow {
                    message_index,
                    text: line,
                    color,
                });
            }
            continue;
        }

        let display_name = if is_me { "You" } else { name.as_str() };
        let title = if is_me {
            format!("{display_name} · {time} ─╮")
        } else {
            format!("╭─ {display_name} · {time}")
        };
        rows.push(RenderedChatRow {
            message_index,
            text: align_chat_row(&title, chat_inner_width, is_me),
            color,
        });

        let lines = wrap_graphemes(&display_body, wrap_width);
        let last = lines.len().saturating_sub(1);
        for (i, line) in lines.iter().enumerate() {
            let text = format_chat_body_line(line, i == last, is_me);
            rows.push(RenderedChatRow {
                message_index,
                text: align_chat_row(&text, chat_inner_width, is_me),
                color,
            });
        }
    }

    rows
}

fn format_chat_body_line(line: &str, is_last: bool, align_right: bool) -> String {
    match (align_right, is_last) {
        (true, true) => format!("{line} ─╯"),
        (true, false) => format!("{line} │"),
        (false, true) => format!("╰─ {line}"),
        (false, false) => format!("│ {line}"),
    }
}

fn align_chat_row(text: &str, max_width: usize, align_right: bool) -> String {
    if !align_right {
        return text.to_string();
    }

    let text_width = text.width();
    let pad = max_width.saturating_sub(text_width);
    format!("{}{}", " ".repeat(pad), text)
}

pub fn selected_message_index(
    rows: &[RenderedChatRow],
    selected_row: Option<usize>,
) -> Option<usize> {
    let row = selected_row?;
    rows.get(row).map(|item| item.message_index)
}

fn flash_notice_area(chat_area: Rect, notice: &str) -> Option<Rect> {
    if chat_area.width <= 2 || chat_area.height <= 2 || notice.trim().is_empty() {
        return None;
    }

    let inner_width = chat_area.width.saturating_sub(2);
    let width = (notice.width() as u16)
        .saturating_add(4)
        .min(inner_width)
        .max(1);
    let x = chat_area.x + 1 + inner_width.saturating_sub(width) / 2;
    let y = chat_area.y + chat_area.height.saturating_sub(2);

    Some(Rect {
        x,
        y,
        width,
        height: 1,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn draw_chat<B: Backend>(
    f: &mut Frame<B>,
    chat_rows: &[RenderedChatRow],
    list_state: &mut ListState,
    member_list: &[MemberIdentity],
    transfer_lines: &[String],
    input: &str,
    cursor: usize,
    username: &str,
    room_id: &str,
    safety_code: Option<&str>,
    flash_notice: Option<&str>,
) {
    let size = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Min(1),
            Constraint::Length(3), // 成员栏
            Constraint::Length(4), // 传输状态
            Constraint::Length(5), // 输入框
        ])
        .split(size);

    let items: Vec<ListItem> = chat_rows
        .iter()
        .map(|row| {
            let marker = row.text.trim_start();
            let style = if marker.starts_with("╭─") || marker.ends_with("─╮") {
                Style::default().fg(row.color).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(row.color)
            };
            ListItem::new(Spans::from(Span::styled(row.text.clone(), style)))
        })
        .collect();

    f.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" Session {room_id} "))
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .highlight_symbol(LIST_HIGHLIGHT_SYMBOL)
            .highlight_style(Style::default().bg(Color::Rgb(28, 35, 38))),
        chunks[0],
        list_state,
    );

    if let Some(notice) = flash_notice {
        if let Some(area) = flash_notice_area(chunks[0], notice) {
            f.render_widget(
                Paragraph::new(format!(" {notice} "))
                    .alignment(Alignment::Center)
                    .style(
                        Style::default()
                            .fg(Color::Magenta)
                            .add_modifier(Modifier::BOLD),
                    ),
                area,
            );
        }
    }

    // —— Members —— //
    let members_text = if member_list.is_empty() {
        "Waiting for members".to_string()
    } else {
        member_list
            .iter()
            .map(|member| member.nickname.clone())
            .collect::<Vec<_>>()
            .join(", ")
    };
    f.render_widget(
        Paragraph::new(members_text).block(
            Block::default()
                .borders(Borders::ALL)
                .title(members_title(safety_code))
                .border_style(Style::default().fg(Color::Cyan)),
        ),
        chunks[1],
    );

    // —— Transfers —— //
    let transfers_text = if transfer_lines.is_empty() {
        "Idle".to_string()
    } else {
        transfer_lines.join("\n")
    };
    f.render_widget(
        Paragraph::new(transfers_text).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Transfers ")
                .border_style(Style::default().fg(Color::Cyan)),
        ),
        chunks[2],
    );

    // —— Input —— //
    let inner_width = (chunks[3].width - 2).max(1);
    let wrapped_input = wrap_graphemes(input, inner_width);
    f.render_widget(
        Paragraph::new(wrapped_input.join("\n")).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {username} · Enter to send · Esc to leave "))
                .border_style(Style::default().fg(Color::Cyan)),
        ),
        chunks[3],
    );

    // —— 光标定位 —— //
    let (cursor_x, cursor_y) = input_cursor_position(input, cursor, inner_width);
    f.set_cursor(chunks[3].x + 1 + cursor_x, chunks[3].y + 1 + cursor_y);
}

pub fn members_title(safety_code: Option<&str>) -> String {
    match safety_code {
        Some(code) => format!(" Members · Verify {code} "),
        None => " Members · Verify ... ".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_chat_rows, flash_notice_area, input_cursor_position, members_title,
        selected_message_index, wrap_graphemes, RenderedChatRow,
    };
    use crate::client::receiver::ChatMessage;
    use tui::layout::Rect;
    use tui::style::Color;
    use unicode_width::UnicodeWidthStr;

    #[test]
    fn cursor_advances_for_trailing_space() {
        assert_eq!(input_cursor_position("a ", 2, 10), (2, 0));
    }

    #[test]
    fn cursor_wraps_graphemewise_after_space_boundary() {
        assert_eq!(input_cursor_position("foo bar", 7, 4), (3, 1));
    }

    #[test]
    fn cursor_counts_cjk_width_correctly() {
        assert_eq!(input_cursor_position("中a文", 3, 10), (5, 0));
    }

    #[test]
    fn grapheme_wrap_does_not_move_whole_word_after_space() {
        assert_eq!(
            wrap_graphemes("很多都是 咔哒蚀刻换手机", 10),
            vec!["很多都是 ", "咔哒蚀刻换", "手机"]
        );
    }

    #[test]
    fn members_title_shows_verify_code() {
        assert_eq!(
            members_title(Some("🦊 🌙 🧊 🍀")),
            " Members · Verify 🦊 🌙 🧊 🍀 "
        );
    }

    #[test]
    fn selected_message_index_maps_rows_back_to_source_message() {
        let rows = vec![
            RenderedChatRow {
                message_index: 3,
                text: "header".to_string(),
                color: Color::Blue,
            },
            RenderedChatRow {
                message_index: 3,
                text: "body".to_string(),
                color: Color::Blue,
            },
            RenderedChatRow {
                message_index: 4,
                text: "other".to_string(),
                color: Color::Red,
            },
        ];

        assert_eq!(selected_message_index(&rows, Some(1)), Some(3));
        assert_eq!(selected_message_index(&rows, Some(2)), Some(4));
        assert_eq!(selected_message_index(&rows, Some(9)), None);
    }

    #[test]
    fn flash_notice_area_centers_near_bottom_of_chat_panel() {
        let area = flash_notice_area(
            Rect {
                x: 0,
                y: 0,
                width: 40,
                height: 12,
            },
            "Copied",
        )
        .expect("toast area should exist");

        assert_eq!(area.y, 10);
        assert!(area.x > 0);
        assert!(area.width >= 10);
    }

    #[test]
    fn own_message_uses_right_edge_corners_without_extra_tail_row() {
        let rows = build_chat_rows(&[ChatMessage::Text("[me][12:00] hi".to_string())], 24, "me");

        assert_eq!(rows.len(), 2);
        assert!(rows[0].text.ends_with("You · 12:00 ─╮"));
        assert!(rows[1].text.ends_with("hi ─╯"));
        assert!(rows.iter().all(|row| row.text.width() <= 24));
    }

    #[test]
    fn other_message_uses_left_edge_corners_on_last_body_line() {
        let rows = build_chat_rows(
            &[ChatMessage::Text("[bob][12:00] hi".to_string())],
            24,
            "me",
        );

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].text, "╭─ bob · 12:00");
        assert_eq!(rows[1].text, "╰─ hi");
    }
}
