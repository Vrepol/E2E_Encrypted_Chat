// ==============================
// src/bin/client.rs  (Cyber-UI + Unicode‑safe parsing)
// ==============================
use std::{
    io::{self, Write},
    sync::{mpsc, Arc},
    thread,
    time::{Duration, Instant},
};

use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event as CEvent, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::mpsc as tokio_mpsc,
};
use tui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Span, Spans},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};

#[derive(Debug)]
enum Event<I> {
    Input(I),
    Tick,
}

#[tokio::main]
async fn main() -> Result<()> {
    // ——询问昵称——
    print!("请输入用户名: ");
    io::stdout().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim().to_owned();
    if username.is_empty() {
        eprintln!("用户名不能为空！按回车退出 …");
        io::stdin().read_line(&mut String::new())?;
        return Ok(());
    }

    // ——连接服务器——
    let stream = match TcpStream::connect("100.89.77.120:6655").await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("连接服务器失败: {e}. 按回车退出 …");
            io::stdin().read_line(&mut String::new())?;
            return Ok(());
        }
    };
    let (reader, mut writer) = stream.into_split();

    // ——发送用户名——
    writer.write_all(username.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    // ——异步读取服务器消息——
    let (net_tx, mut net_rx) = tokio_mpsc::unbounded_channel::<String>();
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let _ = net_tx.send(line);
        }
    });

    // ——终端 UI 设置——
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // ——键盘 & 定时器线程——
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
            let timeout = tick_rate.checked_sub(last_tick.elapsed()).unwrap_or_default();
            match event::poll(timeout) {
                Ok(true) => {
                    if let Ok(CEvent::Key(key)) = event::read() {
                        let _ = ev_tx.send(Event::Input(key));
                    }
                }
                Ok(false) => {}
                Err(_) => continue,
            }
            if last_tick.elapsed() >= tick_rate {
                let _ = ev_tx.send(Event::Tick);
                last_tick = Instant::now();
            }
        }
    });

    // ——应用状态——
    let mut messages: Vec<String> = Vec::new();
    let mut input = String::new();

    // ========== 主循环 ==========
    'ui: loop {
        // ——绘制——
        terminal.draw(|f| {
            let size = f.size();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([Constraint::Min(1), Constraint::Length(3)].as_ref())
                .split(size);

            // ——聊天记录——
            let items: Vec<ListItem> = messages
                .iter()
                .map(|raw| {
                    // 尝试提取 "[name] ..."
                    let (name, body) = parse_name_body(raw);
                    let name_color = if name == username { Color::Blue } else { Color::Red };

                    ListItem::new(vec![
                        Spans::from(Span::styled(name, Style::default().fg(name_color).add_modifier(Modifier::BOLD))),
                        Spans::from(Span::raw(body)),
                    ])
                })
                .collect();

            let chat = List::new(items).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Chat")
                    .style(Style::default().fg(Color::Rgb(0, 135, 0))),
            );
            f.render_widget(chat, chunks[0]);

            // ——输入框——
            let input_box = Paragraph::new(input.as_ref()).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!("{} >", username))
                    .style(Style::default().fg(Color::Rgb(0, 135, 0))),
            );
            f.render_widget(input_box, chunks[1]);
            f.set_cursor(chunks[1].x + input.len() as u16 + 2, chunks[1].y + 1);
        })?;

        // ——事件处理——
        match ev_rx.recv() {
            Ok(Event::Input(key)) => match key.code {
                KeyCode::Char(c) => input.push(c),
                KeyCode::Backspace => {
                    input.pop();
                }
                KeyCode::Enter => {
                    let body = input.trim();
                    if !body.is_empty() {
                        writer.write_all(body.as_bytes()).await?;
                        writer.write_all(b"\n").await?;
                        input.clear();
                    }
                }
                KeyCode::Esc => break 'ui,
                _ => {}
            },
            Ok(Event::Tick) => {}
            Err(_) => break 'ui,
        }

        // ——服务器消息——
        while let Ok(line) = net_rx.try_recv() {
            messages.push(line);
            if messages.len() > 500 {
                messages.drain(..100);
            }
        }
    }

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

/// 从一行文本中解析用户名和消息内容，容忍前缀表情/标记。
fn parse_name_body(line: &str) -> (String, String) {
    // 查找第一对 []
    if let Some(start) = line.find('[') {
        if let Some(end) = line[start..].find(']') {
            let end = start + end;
            let name = line[start + 1..end].trim().to_owned();
            let body = line[end + 1..].trim().to_owned();
            return (name, body);
        }
    }
    ("???".into(), line.trim().to_owned())
}
