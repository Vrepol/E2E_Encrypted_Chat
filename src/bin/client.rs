// src/bin/client.rs
/* ---------- 标准库 ---------- */
use std::{
    io,
    sync::{mpsc, Arc},
    thread,
    time::{Duration, Instant},
};

/* ---------- 外部依赖 ---------- */
use anyhow::Result;
use colored::*;
use crossterm::{
    execute,
    event::{self, Event as CEvent, EnableMouseCapture, DisableMouseCapture},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use tempfile;
use tokio::sync::mpsc as tokio_mpsc;
use tui::{
    backend::CrosstermBackend,
    widgets::ListState,
    Terminal,
};

/* ---------- 本地 crate ---------- */
use rust_chat::client::{
    utils::inviation_clear,
    network,
    receiver::{drain_messages, ChatMessage},
    initialization::{initial_serveraddr, initial_name,init_color},
    handshake,
    keyboard::{handle_key, UndoMgr, KeyCtx, ControlFlow},
};
/// 第 n 个字形单元（grapheme）在字符串中的字节偏移
// ================== UI 事件枚举 ==================
#[derive(Debug)]
enum Event<I> {
    Input(I),
    Tick,
}
#[derive(Clone)]
enum UiMode {
    Chat,                             // 默认聊天界面
    _ImagePreview(std::path::PathBuf), // 正在预览的图片路径
}

#[tokio::main]
async fn main() -> Result<()> {
    init_color();
    let username = initial_name()?;
    let mut server_addr =initial_serveraddr()?;
    /* ---------- 1. 在这里初始化用户名和服务器 ---------- */
    loop {
    //如果用户是通过邀请码进入的房间退出房间后会回到选择服务器界面
    //TODO：用户在选择房间界面，能否按下Esc回到服务器选择界面
    //因为用户一旦连接上了某个服务器后就无法使用邀请码进入房间了
    
    /* ---------- 2. 网络 <-> UI 的通道 ---------- */
    let (net_tx, mut net_rx) = tokio_mpsc::unbounded_channel::<String>(); // 网络 → UI
    let (out_tx, out_rx) = tokio_mpsc::unbounded_channel::<String>();     // UI → 网络

    //得到服务器地址后开始握手
    let (lines, writer, room_id,pwd) = loop {
        if server_addr.is_empty() {
            let new_addr = initial_serveraddr()?;
            server_addr = new_addr;
        }
        match handshake::connect_and_login(&server_addr, &username).await {
            Ok((lines, writer, room_id,pwd)) => {
                break (lines, writer, room_id,pwd);
            }
            Err(e) if e.to_string().contains("邀请码无效") => {
                eprintln!("❌ 邀请码无效或已过期，请重新选择服务器或输入新的邀请码。\n");
                server_addr.clear();
            }
            Err(e) if e.to_string().contains("断开服务器") => {
                eprintln!("断开服务器... \n");
                server_addr.clear();
            }
            // 其它网络 / IO 错误，也让用户重选
            Err(e) => {
                eprintln!("HandShake Error: {}", e);
                server_addr.clear();
            }
            
        }
        
    };
    //特性：受邀请者退出房间后回到服务器选择界面，而且在房间中无法生成正确的邀请码
    server_addr=inviation_clear(&server_addr);

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
    let ui_mode = UiMode::Chat;
    let mut messages: Vec<ChatMessage> = Vec::new();
    let mut member_list: Vec<String>   = Vec::new();
    let mut input = String::new();
    let mut cursor = 0usize;
    let mut list_state = ListState::default();
    let img_tempdir = tempfile::Builder::new()
        .prefix("")
        .tempdir()?;
    let mut undo_mgr = UndoMgr::new();
    use rust_chat::client::ui::{draw_chat};
    /* ---------- 7. 主循环 ---------- */
    'ui: loop {
        terminal.draw(|f| {
            match ui_mode {
                UiMode::Chat => draw_chat(
                    f,
                    &messages,
                    &mut list_state,
                    &member_list,
                    &input,
                    cursor,
                    &username,
                    &room_id,
                ),
                UiMode::_ImagePreview(_) => { /* 这里什么也不画，draw_image 会接管 */ }
            }
        })?;
        // ——— 处理键盘事件 ———
        match ev_rx.recv() {
            Ok(Event::Input(key)) => {
                let mut ctx = KeyCtx {
                    input:       &mut input,
                    cursor:      &mut cursor,
                    list_state:  &mut list_state,
                    messages:    &mut messages,
                    member_list: &mut member_list,
                    undo_mgr:    &mut undo_mgr,
                    out_tx:      &out_tx,
                    server_addr: &mut server_addr,
                    room_id:     &room_id,
                    pwd:         &pwd,
                    username:    &username,
                };
                if let ControlFlow::Quit = handle_key(key, &mut ctx) {
                    break 'ui;
                }
            }
            _ => {}
        }

        // ——— 收网络消息 ———
        drain_messages(&mut net_rx, &mut messages, &mut list_state, &username,img_tempdir.path(),&mut member_list,);
    }
    
    /* ---------- 8. 清理退出 ---------- */
    drop(running);
    execute!(terminal.backend_mut(), DisableMouseCapture)?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        
    )?;
    disable_raw_mode()?;
    terminal.show_cursor()?;
    println!("{} [{}]","❌ 退出房间",room_id);
    println!("{}","========Press Crtl + C to quit========\n".red().bold());
    continue;
    }
}
