// src/bin/client.rs
use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event as CEvent, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::{
    io::{self, Write},
    sync::{mpsc, Arc},
    thread,
    time::{Duration, Instant},
};
use tokio::sync::mpsc as tokio_mpsc;
use tui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Span, Spans},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Terminal,
};
use unicode_width::UnicodeWidthStr;
use rust_chat::client::utils::parse_name_body;
use rust_chat::client::network; // ← 记得在 lib.rs/mod.rs 中 `pub mod network;`
use rust_chat::client::receiver::drain_messages;
use textwrap::wrap;
// ================== UI 事件枚举 ==================
#[derive(Debug)]
enum Event<I> {
    Input(I),
    Tick,
}

#[tokio::main]
async fn main() -> Result<()> {
    /* ---------- 1. 询问昵称、选择服务器 ---------- */
    print!("Your Nickname: ");
    io::stdout().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim().to_owned();
    if username.is_empty() {
        eprintln!("Nickname cannot be empty.");
        return Ok(());
    }

    let servers = vec![
        "100.97.92.19:6655",
        "192.168.1.8:6655",
        "8.153.67.166:6655",
    ];
    println!("Available Server:");
    for (i, s) in servers.iter().enumerate() {
        println!("  {}. {}", i + 1, s);
    }
    print!("Choose from (1-{}): ", servers.len());
    io::stdout().flush()?;

    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;
    let idx = choice.trim().parse::<usize>().unwrap_or(1).saturating_sub(1);
    let server_addr = servers[idx.min(servers.len() - 1)];
    println!("Connecting {} …", server_addr);

    /* ---------- 2. 网络 <-> UI 的通道 ---------- */
    let (net_tx, mut net_rx) = tokio_mpsc::unbounded_channel::<String>(); // 网络 → UI
    let (out_tx, out_rx) = tokio_mpsc::unbounded_channel::<String>();     // UI → 网络

    /* ---------- 3. 启动网络任务（自动重连 + 心跳） ---------- */
    let net_username = username.clone(); // 给网络任务一份拷贝
    tokio::spawn(async move {
        if let Err(e) = network::run(server_addr, &net_username, net_tx, out_rx).await {
            eprintln!("network::run error: {e}");
        }
    });

    /* ---------- 4. 终端 UI 初始化 ---------- */
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    /* ---------- 5. 键盘 + Tick 线程 ---------- */
    let (ev_tx, ev_rx) = mpsc::channel();
    let running = Arc::new(());
    let flag = Arc::downgrade(&running);
    thread::spawn(move || {
        let tick_rate = Duration::from_millis(200);
        let mut last_tick = Instant::now();
        loop {
            if flag.upgrade().is_none() {
                return;
            }
            let timeout = tick_rate.saturating_sub(last_tick.elapsed());
            if event::poll(timeout).unwrap_or(false) {
                if let Ok(CEvent::Key(key)) = event::read() {
                    let _ = ev_tx.send(Event::Input(key));
                }
            }
            if last_tick.elapsed() >= tick_rate {
                let _ = ev_tx.send(Event::Tick);
                last_tick = Instant::now();
            }
        }
    });

    /* ---------- 6. 应用状态 ---------- */
    let mut messages: Vec<String> = Vec::new();
    let mut input = String::new();
    let mut list_state = ListState::default();
    const MAX_WIDTH: usize = 34;
    /* ---------- 7. 主循环 ---------- */
    'ui: loop {
        // ——— 绘制 ———
        terminal.draw(|f| {
            let size = f.size();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([Constraint::Min(1), Constraint::Length(3)].as_ref())
                .split(size);

            // 聊天记录
            let items: Vec<ListItem> = messages
                .iter()
                .map(|raw| {
                    let (name, body) = parse_name_body(raw);
                    let color = if name == username { Color::Blue } else { Color::Red };
                    let indent = if name == username { "───" } else { "" };
                    let symbol = if name == username { "⁂" } else { "※" };

                    // 1) 首行：┌──[name]
                    let mut spans = vec![
                        Spans::from( Span::styled(
                            format!("┌──{}[{}]", indent, name),
                            Style::default().fg(color).add_modifier(Modifier::BOLD),
                        ))
                    ];

                    // 2) body 多行
                    let wrapped_lines = wrap(&body, MAX_WIDTH);
                    for (i, line) in wrapped_lines.iter().enumerate() {
                        // 首 body 行 用 └─，后续用空格对齐
                        let prefix = if i==wrapped_lines.len()-1 { "└─" } else { "│ " };
                        spans.push( Spans::from( Span::styled(
                            format!("{}{} {}", prefix, symbol, line),
                            Style::default().fg(color).add_modifier(Modifier::BOLD),
                        )));
                    }

                    ListItem::new(spans)
                })
                .collect();

            let chat = List::new(items)
                .block(
                    Block::default()
                .borders(Borders::ALL)
                .title("Chat")
                .style(Style::default().fg(Color::Rgb(0, 135, 0))))
                .highlight_symbol("☠️ ");
            f.render_stateful_widget(chat, chunks[0], &mut list_state);

            // 输入框
            let input_box = Paragraph::new(input.as_ref()).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!("{} >", username))
                    .style(Style::default().fg(Color::Rgb(0, 135, 0))),
            );
            f.render_widget(input_box, chunks[1]);
            let display_width = UnicodeWidthStr::width(input.as_str()) as u16;
            f.set_cursor(chunks[1].x + display_width + 1, chunks[1].y + 1);
        })?;

        // ——— 处理键盘事件 ———
        match ev_rx.recv() {
            Ok(Event::Input(key)) => match key.code {
                KeyCode::Char(c) => input.push(c),
                KeyCode::Backspace => {
                    input.pop();
                }
                KeyCode::Enter => {
                    let msg = input.trim();
                    if !msg.is_empty() {
                        // 把输入通过 out_tx 发给网络任务
                        let _ = out_tx.send(msg.to_string());
                        input.clear();
                    }
                }
                KeyCode::Up => {
                    let step = 10;
                    // 按 ↑，选中上一条
                    if let Some(i) = list_state.selected() {
                        list_state.select(Some(i.saturating_sub(step)));
                    }
                }
                KeyCode::Down => {
                    let step = 10;
                    // 按 ↓，选中下一条
                    if let Some(i) = list_state.selected() {
                        let next = (i + step).min(messages.len().saturating_sub(1));
                        list_state.select(Some(next));
                    }
                }
                KeyCode::Esc => break 'ui,
                _ => {}
            },
            _ => {}
        }

        // ——— 收网络消息 ———
        drain_messages(&mut net_rx, &mut messages, &mut list_state);
    }

    /* ---------- 8. 清理退出 ---------- */
    drop(running);
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}
