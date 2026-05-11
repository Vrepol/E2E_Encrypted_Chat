// src/client/utils/ui.rs
use super::receiver::ChatMessage;
use super::safety::SafetyCode;
use super::utils::parse_name_body;
use super::utils::MemberIdentity;
use tui::{
    backend::Backend,
    layout::{Constraint, Direction, Layout, Rect},
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
    size.width.saturating_sub(4) as usize
}

pub fn build_chat_rows(
    messages: &[ChatMessage],
    chat_inner_width: usize,
    username: &str,
) -> Vec<RenderedChatRow> {
    const PREFIX_WIDTH: usize = 5;
    let wrap_width = chat_inner_width.saturating_sub(PREFIX_WIDTH).max(1) as u16;
    let mut rows = Vec::new();

    for (message_index, raw) in messages.iter().enumerate() {
        let (name, time, display_body) = parse_name_body(raw);
        let color = if name == "System" {
            Color::DarkGray
        } else if name == username {
            Color::Blue
        } else {
            Color::Red
        };

        rows.push(RenderedChatRow {
            message_index,
            text: format!("┌-[{}]-#{}", name, time),
            color,
        });

        let lines = wrap_graphemes(&display_body, wrap_width);
        let last = lines.len().saturating_sub(1);
        for (i, line) in lines.iter().enumerate() {
            let prefix = if i == last { "└--$" } else { "|   " };
            rows.push(RenderedChatRow {
                message_index,
                text: format!("{} {}", prefix, line),
                color,
            });
        }
    }

    rows
}

pub fn selected_message_index(
    rows: &[RenderedChatRow],
    selected_row: Option<usize>,
) -> Option<usize> {
    let row = selected_row?;
    rows.get(row).map(|item| item.message_index)
}

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
    safety_code: Option<&SafetyCode>,
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
            let style = if row.text.starts_with("┌-") {
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
                    .title(format!("<Room: {}>", room_id))
                    .style(Style::default().fg(Color::Rgb(0, 135, 0))),
            )
            .highlight_symbol(">"),
        chunks[0],
        list_state,
    );

    // —— Members —— //
    let members_text = if member_list.is_empty() {
        "<空>".to_string()
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
                .style(Style::default().fg(Color::Rgb(0, 135, 0))),
        ),
        chunks[1],
    );

    // —— Transfers —— //
    let transfers_text = if transfer_lines.is_empty() {
        "No active transfers".to_string()
    } else {
        transfer_lines.join("\n")
    };
    f.render_widget(
        Paragraph::new(transfers_text).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Transfers")
                .style(Style::default().fg(Color::Rgb(0, 135, 0))),
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
                .title(format!("{} >", username))
                .style(Style::default().fg(Color::Rgb(0, 135, 0))),
        ),
        chunks[3],
    );

    // —— 光标定位 —— //
    let (cursor_x, cursor_y) = input_cursor_position(input, cursor, inner_width);
    f.set_cursor(chunks[3].x + 1 + cursor_x, chunks[3].y + 1 + cursor_y);
}

pub fn members_title(safety_code: Option<&SafetyCode>) -> String {
    match safety_code {
        Some(code) => format!("Members | Verify Code: {}", code.emoji()),
        None => "Members | Verify Code: ...".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{input_cursor_position, members_title, wrap_graphemes};
    use crate::client::safety::SafetyCode;

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
        let code = SafetyCode {
            hash: [
                0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        };

        assert_eq!(
            members_title(Some(&code)),
            "Members | Verify Code: 🦊 🌙 🧊 🍀"
        );
    }
}
