// src/bin/client.rs
use anyhow::Result;
use crossterm::{
    event::{self, EnableMouseCapture, Event as CEvent, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::{
    io::{self},
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
use colored::*;
use unicode_width::UnicodeWidthStr;
use rust_chat::client::utils::parse_name_body;
use rust_chat::client::network; // ← 记得在 lib.rs/mod.rs 中 `pub mod network;`
use rust_chat::client::receiver::drain_messages;
use textwrap::wrap;
use unicode_segmentation::UnicodeSegmentation;
use rust_chat::client::initialization::initial;
use rust_chat::client::handshake;
use base64::Engine as _;
use rust_chat::client::clipboard::{self, ClipData};
use crossterm::event::KeyModifiers;
/// 第 n 个字形单元（grapheme）在字符串中的字节偏移
fn nth_grapheme_byte_idx(s: &str, n: usize) -> usize {
    s.grapheme_indices(true)
     .nth(n)
     .map(|(idx, _)| idx)
     .unwrap_or_else(|| s.len())
}
// ================== UI 事件枚举 ==================
#[derive(Debug)]
enum Event<I> {
    Input(I),
    Tick,
}

#[tokio::main]
async fn main() -> Result<()> {
    
    /* ---------- 1. 在这里初始化用户名和服务器 ---------- */
    let (username,server_addr) =initial()?;
    loop {
    /* ---------- 2. 网络 <-> UI 的通道 ---------- */
    let (net_tx, mut net_rx) = tokio_mpsc::unbounded_channel::<String>(); // 网络 → UI
    let (out_tx, out_rx) = tokio_mpsc::unbounded_channel::<String>();     // UI → 网络

    
    //非异步函数，返还的是服务器当前的房间列表
    //在这个函数中需要在这里插入房间选择与验证，让服务端分配客户至某个房间
    let (lines, writer, _room_id) = loop {
        match handshake::connect_and_login(server_addr, &username).await {
            Ok((lines, writer, room_id)) => {
                break (lines, writer, room_id);
            }
            Err(e) if e.to_string().contains("BadCredential") => {
                // 这里捕获到服务器返回 ERR BadCredential
                println!("{}","===================================".green().bold());
                eprintln!("❌ 密码错误，请重新输入房间号和密码。\n");
                continue;
            }
            Err(other) => {
                // 其它错误直接向上抛
                return Err(other);
            }
        }
    };
    /* ---------- 3. 启动网络任务（自动重连 + 心跳） ---------- */
    tokio::spawn(async move {
        if let Err(e) = network::chat_loop(lines, writer, net_tx, out_rx).await {
            eprintln!("chat_loop error: {e}");
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
    let mut cursor = 0usize;
    let mut list_state = ListState::default();
    const MAX_WIDTH: usize = 40;
    /* ---------- 7. 主循环 ---------- */
    'ui: loop {
        // ——— 绘制 ———
        terminal.draw(|f| {
            let size = f.size();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Min(1),
                    Constraint::Length(3),  // 新增的状态栏
                    Constraint::Length(3),  // 输入框
                ].as_ref())
                .split(size);
            // 聊天记录
            let items: Vec<ListItem> = messages
                .iter()
                .map(|raw| {
                    let (name,time, body) = parse_name_body(raw);
                    let color = if name == username { Color::Blue } else { Color::Red };
                    let indent = if name == username { "" } else { "" };
                    let symbol = if name == username { "$" } else { "$" };

                    // 1) 首行：┌──[name]
                    let mut spans = vec![
                        Spans::from( Span::styled(
                            format!("┌-[{}]-{}#{}",name,indent, time),
                            Style::default().fg(color).add_modifier(Modifier::BOLD),
                        ))
                    ];

                    // 2) body 多行
                    let wrapped_lines = wrap(&body, MAX_WIDTH);
                    for (i, line) in wrapped_lines.iter().enumerate() {
                        // 首 body 行 用 └─，后续用空格对齐
                        let prefix = if i==wrapped_lines.len()-1 { "└--" } else { "|  " };
                        spans.push( Spans::from( Span::styled(
                            format!("{}{} {}", prefix, symbol, line),
                            Style::default().fg(color).add_modifier(Modifier::BOLD),
                        )));
                    }

                    ListItem::new(spans)
                })
                .collect();
            let title = format!("<Room: {}>", _room_id.clone());
            let chat = List::new(items)
                .block(
                    Block::default()
                .borders(Borders::ALL)
                .title(title)
                .style(Style::default().fg(Color::Rgb(0, 135, 0))))
                .highlight_symbol(">");
            f.render_stateful_widget(chat, chunks[0], &mut list_state);
            

            let status_chunk = chunks[1];
            let status = Paragraph::new("这里要接受服务端发来的/member_list 信息")
                .block(
                    Block::default().borders(Borders::ALL).title("Members")
                    .style(Style::default().fg(Color::Rgb(0, 135, 0))),
                );
            f.render_widget(status, status_chunk);
                    
            // 输入框
            let input_box = Paragraph::new(input.as_ref()).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!("{} >", username))
                    .style(Style::default().fg(Color::Rgb(0, 135, 0))),
            );
            f.render_widget(input_box, chunks[2]);
            //let display_width = UnicodeWidthStr::width(input.as_str()) as u16;
            let byte_idx = nth_grapheme_byte_idx(&input, cursor);
            let prefix = &input[..byte_idx];                       // 光标左侧内容
            let display_width = UnicodeWidthStr::width(prefix) as u16;
            f.set_cursor(chunks[2].x + display_width + 1, chunks[2].y + 1);  
        })?;

        // ——— 处理键盘事件 ———
        match ev_rx.recv() {
            Ok(Event::Input(key)) => match key.code {
                // 1) Ctrl + V 贴入
                KeyCode::Char('v') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    match clipboard::get() {
                        Ok(ClipData::Text(txt)) => {
                            // 插到光标处
                            let byte_idx = nth_grapheme_byte_idx(&input, cursor);
                            input.insert_str(byte_idx, &txt);
                            cursor += txt.graphemes(true).count();
                        }
                        Ok(ClipData::Image(img)) => {
                            // TODO: 把 img.bytes 转 base64，构造占位符发送
                            let b64 = base64::engine::general_purpose::STANDARD.encode(img.bytes);
                            let placeholder = format!("/img:{}:{}", img.width, img.height);
                            // 这里直接发送占位符，后续可改成真正的图片协议
                            let _ = out_tx.send(format!("{}{}", placeholder, b64));
                        }
                        Err(e) => eprintln!("⚠️ 粘贴失败: {e}"),
                    }
                },
                
                // 2) Ctrl + C 复制选中行
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    if let Some(sel) = list_state.selected() {
                        let (_, _, body) = parse_name_body(&messages[sel]);  // 去掉前缀
                        if let Err(e) = clipboard::set_text(&body) {
                            eprintln!("⚠️ 复制失败: {e}");
                        }
                    }
                },
                KeyCode::Char(ch) if !key.modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) 
                    =>{
                        // 1 个 Unicode grapheme 当做一个 char 插入
                        let s = ch.to_string();
                        let byte_idx = nth_grapheme_byte_idx(&input, cursor);
                        input.insert_str(byte_idx, &s);
                        cursor += 1;
                    },
                // ←  向左
                KeyCode::Left => {
                    if cursor > 0 {
                        cursor -= 1;
                    }
                }
            
                // →  向右
                KeyCode::Right => {
                    let total = input.graphemes(true).count();
                    if cursor < total {
                        cursor += 1;
                    }
                }
            
                // Backspace：删掉光标左侧 1 个字符
                KeyCode::Backspace => {
                    if cursor > 0 {
                        let start = nth_grapheme_byte_idx(&input, cursor - 1);
                        let end   = nth_grapheme_byte_idx(&input, cursor);
                        input.replace_range(start..end, "");
                        cursor -= 1;
                    }
                }
                KeyCode::Enter => {
                    let msg = input.trim();
                    if !msg.is_empty() {
                        // 把输入通过 out_tx 发给网络任务
                        let _ = out_tx.send(msg.to_string());
                        input.clear();
                        cursor = 0;
                    }
                }
                KeyCode::Up => {
                    let step = 1;
                    // 按 ↑，选中上一条
                    if let Some(i) = list_state.selected() {
                        list_state.select(Some(i.saturating_sub(step)));
                    }
                }
                KeyCode::Down => {
                    let step = 1;
                    // 按 ↓，选中下一条
                    if let Some(i) = list_state.selected() {
                        let next = (i + step).min(messages.len().saturating_sub(1));
                        list_state.select(Some(next));
                    }
                }
                KeyCode::Esc => {
                    let _ = out_tx.send("/leave".to_string());
                    drop(out_tx);
                    break 'ui;
                    
                }
                _ => {}
                
            },
            _ => {}
        }

        // ——— 收网络消息 ———
        drain_messages(&mut net_rx, &mut messages, &mut list_state, &username);
    }

    /* ---------- 8. 清理退出 ---------- */
    drop(running);
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        //DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    println!("{} [{}]","❌ 退出房间",_room_id);
    println!("{}","========Press Crtl + C to quit========".red().bold());
    continue;
    }
    Ok(())
}
