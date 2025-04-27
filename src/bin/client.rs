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
use tui::widgets::ListState;
use rust_chat::client::utils::parse_name_body;
#[derive(Debug)]
enum Event<I> {
    Input(I),
    Tick,
}
#[tokio::main]
async fn main() -> Result<()> {
    // ——询问昵称——
    print!("Your Nickname: ");
    io::stdout().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim().to_owned();
    if username.is_empty() {
        eprintln!("Nickname was empty, press Enter to continue …");
        io::stdin().read_line(&mut String::new())?;
        return Ok(());
    }
        // ——可选的服务器地址列表——
    let servers = vec![
        "100.97.92.19:6655",
        "192.168.1.8:6655",
        "8.153.67.166:6655",
    ];

    // ——让用户选择服务器——
    println!("Available Server: ");
    for (i, srv) in servers.iter().enumerate() {
        println!("  {}. {}", i + 1, srv);
    }
    print!("Choose from(1-{}): ", servers.len());
    io::stdout().flush()?;

    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;
    let idx = choice.trim().parse::<usize>()
        .ok()
        .and_then(|n| if n >= 1 && n <= servers.len() { Some(n - 1) } else { None })
        .unwrap_or(0);  // 默认选第一个
    let server_addr = servers[idx];
    println!("Connecting: {}\n", server_addr);

    // ——连接服务器——
    let stream = match TcpStream::connect(server_addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Fail to connect server: {e}. Press Enter to continue …");
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
    let mut list_state = ListState::default();
    list_state.select(Some(messages.len().saturating_sub(1)));
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
                    // 提取用户名和消息体
                    let (name, body) = parse_name_body(raw);
                    // 根据是不是自己决定颜色
                    let name_color = if name == username { Color::Blue } else { Color::Red };
                    let self_indent =if name ==username {"───"} else {""};
                    let self_symbol =if name ==username {"⁂"} else {"※"};
                    // 第一行：┌──[name]
                    let name_line = Span::styled(
                        format!("┌──{}[{}]",self_indent, name),
                        Style::default()
                            .fg(name_color)
                            .add_modifier(Modifier::BOLD),
                    );

                    // 第二行：└─⁂ body
                    let msg_line = Span::styled(format!("└─{}{} {}",self_indent,self_symbol, body)
                        , Style::default()
                            .fg(name_color)
                            .add_modifier(Modifier::BOLD));

                    // 用两个 Spans 构造一个 ListItem（即两行）
                    ListItem::new(vec![
                        Spans::from(name_line),
                        Spans::from(msg_line),
                    ])
                })
                .collect();

                let chat = List::new(items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Chat")
                        .style(Style::default().fg(Color::Rgb(0, 135, 0))),
                )
                .highlight_symbol("» ");
            f.render_stateful_widget(chat, chunks[0], &mut list_state);

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
            Ok(Event::Tick) => {}
            Err(_) => break 'ui,
        }
        // ——服务器消息——
        while let Ok(line) = net_rx.try_recv() {
            // “翻到最底”标志：选中索引 == 最后一条的索引
            let at_bottom = list_state.selected() == Some(messages.len().saturating_sub(1));
        
            messages.push(line);
        
            // 如果之前在底部，才滚到底
            if at_bottom {
                list_state.select(Some(messages.len().saturating_sub(1)));
            }
        
            if messages.len() > 500 {
                // 删除最旧 100 条前先记录一下当前选中，再做偏移
                messages.drain(..100);
                if let Some(sel) = list_state.selected() {
                    // 把 sel 往前挪 100
                    list_state.select(Some(sel.saturating_sub(100)));
                }
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

// 从一行文本中解析用户名和消息内容，容忍前缀表情/标记。

