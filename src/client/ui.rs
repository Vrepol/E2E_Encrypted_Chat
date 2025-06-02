// src/client/utils/ui.rs
use tui::{
    backend::Backend,
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Span, Spans},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};
use unicode_width::UnicodeWidthStr;
use textwrap::wrap;
use super::utils::parse_name_body;
use super::receiver::ChatMessage;
use unicode_segmentation::UnicodeSegmentation;
fn nth_grapheme_byte_idx(s: &str, n: usize) -> usize {
    s.grapheme_indices(true)
     .nth(n)
     .map(|(idx, _)| idx)
     .unwrap_or_else(|| s.len())
}
pub fn draw_chat<B: Backend>(
    f: &mut Frame<B>,
    messages: &[ChatMessage],
    list_state: &mut ListState,
    member_list: &[String],
    input: &str,
    cursor: usize,
    username: &str,
    room_id: &str,
) {
    let size = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Min(1),
            Constraint::Length(3),   // 成员栏
            Constraint::Length(5),   // 输入框
        ])
        .split(size);

    let chat_inner_width = (chunks[0].width - 2) as usize;
    const PREFIX_WIDTH: usize = 5;

    let items: Vec<ListItem> = messages.iter().map(|raw| {
        let (name, time, display_body) = parse_name_body(raw);
        let color  = if name == username { Color::Blue } else { Color::Red };

        // ① 头行
        let mut spans = vec![Spans::from(
            Span::styled(format!("┌-[{}]-#{}", name, time),
                         Style::default().fg(color).add_modifier(Modifier::BOLD))
        )];

        // ② body 行（动态折行）
        let wrap_width = chat_inner_width.saturating_sub(PREFIX_WIDTH);
        let lines = wrap(&display_body, wrap_width);
        let last = lines.len().saturating_sub(1);
        for (i, line) in lines.iter().enumerate() {
            let prefix = if i == last { "└--$" } else { "|   " };
            spans.push(Spans::from(
                Span::styled(format!("{} {}", prefix, line),
                             Style::default().fg(color))
            ));
        }
        ListItem::new(spans)
    }).collect();

    f.render_stateful_widget(
        List::new(items)
            .block(Block::default()
                .borders(Borders::ALL)
                .title(format!("<Room: {}>", room_id))
                .style(Style::default().fg(Color::Rgb(0, 135, 0))))
            .highlight_symbol(">"),
        chunks[0],
        list_state,
    );

    // —— Members —— //
    let members_text = if member_list.is_empty() {
        "<空>".to_string()
    } else {
        member_list.join(", ")
    };
    f.render_widget(
        Paragraph::new(members_text)
            .block(Block::default().borders(Borders::ALL).title("Members")
            .style(Style::default().fg(Color::Rgb(0, 135, 0)))),
        chunks[1],
    );

    // —— Input —— //
    use tui::widgets::Wrap;
    f.render_widget(
        Paragraph::new(input)
            .wrap(Wrap { trim: false })
            .block(Block::default()
                .borders(Borders::ALL)
                .title(format!("{} >", username))
                .style(Style::default().fg(Color::Rgb(0, 135, 0)))),
        chunks[2],
    );

    // —— 光标定位 —— //
    let inner_width = (chunks[2].width - 2) as usize;
    let byte_idx = nth_grapheme_byte_idx(input, cursor);
    let prefix   = &input[..byte_idx];
    let wrapped  = wrap(prefix, inner_width);
    let cursor_y = wrapped.len() as u16 - 1;
    let cursor_x = wrapped.last().unwrap().as_ref().width() as u16;
    f.set_cursor(chunks[2].x + 1 + cursor_x, chunks[2].y + 1 + cursor_y);
}