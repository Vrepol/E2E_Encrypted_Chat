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
    widgets::ListState,
    Terminal,
};
use colored::*;
use rust_chat::client::utils::{parse_name_body,encode_rgba_as_png,create_invitation,
    inviation_clear,HELP_TEXT};
use rust_chat::client::network; // ← 记得在 lib.rs/mod.rs 中 `pub mod network;`
use rust_chat::client::receiver::{drain_messages,ChatMessage};
use unicode_segmentation::UnicodeSegmentation;
use rust_chat::client::initialization::{initial_serveraddr,initial_name};
use rust_chat::client::handshake;
use base64::Engine as _;
use rust_chat::client::clipboard::{self, ClipData};
use crossterm::event::KeyModifiers;
use tempfile;
use rust_chat::client::keyboard::{OpKind,UndoMgr};
/// 第 n 个字形单元（grapheme）在字符串中的字节偏移
fn nth_grapheme_byte_idx(s: &str, n: usize) -> usize {
    s.grapheme_indices(true)
     .nth(n)
     .map(|(idx, _)| idx)
     .unwrap_or_else(|| s.len())
}
fn open_image(path: &std::path::Path) -> anyhow::Result<()> {
    open::that(path)?;
    Ok(())
}
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
            Ok(Event::Input(key)) => match key.code {
                KeyCode::Char('x') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    match clipboard::get() {
                        Ok(ClipData::Text(txt)) => {
                            // 插到光标处
                            undo_mgr.maybe_push(&input, cursor, OpKind::Insert);
                            let byte_idx = nth_grapheme_byte_idx(&input, cursor);
                            input.insert_str(byte_idx, &txt);
                            cursor += txt.graphemes(true).count();
                        }
                        Ok(ClipData::Image(img)) => {
                            let png_buf = encode_rgba_as_png(&img.bytes,
                                img.width.try_into().unwrap(),
                                img.height.try_into().unwrap(),)?;
                            // TODO: 把 img.bytes 转 base64，构造占位符发送
                            let b64 = base64::engine::general_purpose::STANDARD.encode(&png_buf);
                            let placeholder = format!("/IMGDATA");
                            // 这里直接发送占位符，后续可改成真正的图片协议
                            let _ = out_tx.send(format!("{}{}", placeholder, b64));
                        }
                        Err(e) => {
                            // 如果既不是文本也不是图片，也把错误发到聊天框
                            let tip = format!("⚠️ 读取剪贴板失败: {}", e);
                            let _ = out_tx.send(tip);
                        },
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

                KeyCode::Char('h') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    let _ = out_tx.send(format!("{}", HELP_TEXT));
                },
                KeyCode::Char(ch) if !key.modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) 
                    =>{
                        undo_mgr.maybe_push(&input, cursor, OpKind::Insert);
                        let s = ch.to_string();
                        let byte_idx = nth_grapheme_byte_idx(&input, cursor);
                        input.insert_str(byte_idx, &s);
                        cursor += 1;
                    },
                    KeyCode::Char('i') if key.modifiers.contains(KeyModifiers::CONTROL)
                =>{
                    let mut iter = server_addr.splitn(2, '&');
                    let server = iter.next().unwrap_or("");
                    let server_pwd = iter.next().unwrap_or("");
                    let result = create_invitation(server.to_string().clone(),server_pwd.to_string().clone()
                                ,room_id.clone(),pwd.clone());
                    match result {
                        Ok(code) => {
                            let _ = out_tx.send(format!("/INVITE:{}", code));
                        }
                        Err(err) => {
                            let _ = out_tx.send("生成邀请码失败".to_string());
                            eprintln!("生成邀请码失败：{}", err);
                            },
                        }
                    }
                // ←  向左
                KeyCode::Left if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    cursor = cursor.saturating_sub(3);
                }
                KeyCode::Left => {
                    if cursor > 0 {
                        cursor -= 1;
                    }
                }
                
                // →  向右
                KeyCode::Right if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    let total = input.graphemes(true).count();
                    if cursor < total {
                        cursor = total;
                    }
                }
                KeyCode::Right => {
                    let total = input.graphemes(true).count();
                    if cursor < total {
                        cursor += 1;
                    }
                }
            
                // Backspace：删掉光标左侧 1 个字符
                KeyCode::Backspace => {
                    if cursor > 0 {
                        undo_mgr.maybe_push(&input, cursor, OpKind::Insert);
                        let start = nth_grapheme_byte_idx(&input, cursor - 1);
                        let end   = nth_grapheme_byte_idx(&input, cursor);
                        input.replace_range(start..end, "");
                        cursor -= 1;
                    }
                }
                KeyCode::Enter => {
                    undo_mgr.maybe_push(&input, cursor, OpKind::Insert);
                    let msg = input.trim();
                    if !msg.is_empty() {
                    
                        // 把输入通过 out_tx 发给网络任务
                        let _ = out_tx.send(msg.to_string());
                        input.clear();
                        cursor = 0;
                    }
                }
                //清空输入框
                KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL)
                =>{
                    undo_mgr.maybe_push(&input, cursor, OpKind::Insert);
                    input.clear();
                    cursor = 0;
                    }
                KeyCode::Up if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    let step = 5;
                    // 按 ↑，选中上一条
                    if let Some(i) = list_state.selected() {
                        list_state.select(Some(i.saturating_sub(step)));
                    }
                }
                KeyCode::Char('z') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    undo_mgr.undo(&mut input, &mut cursor);
                }
                KeyCode::Up => {
                    let step = 1;
                    // 按 ↑，选中上一条
                    if let Some(i) = list_state.selected() {
                        list_state.select(Some(i.saturating_sub(step)));
                    }
                }

                KeyCode::Down if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    list_state.select(Some(messages.len()-1));
                }

                KeyCode::Down => {
                    let step = 1;
                    // 按 ↓，选中下一条
                    if let Some(i) = list_state.selected() {
                        let next = (i + step).min(messages.len().saturating_sub(1));
                        list_state.select(Some(next));
                    }
                }
                KeyCode::Tab => {
                    if let Some(selected) = list_state.selected() {
                        // 假设 images 是 Vec<Option<PathBuf>>
                        if let ChatMessage::Image { path, .. } = &messages[selected] {
                            if let Err(e) = open_image(path) {
                                eprintln!("无法打开图片: {e}");
                            }
                        }
                    }
                }
                KeyCode::Esc => {
                    let _ = out_tx.send("//~``~//".to_string());
                    drop(out_tx);
                    break 'ui;
                    
                }
                _ => {}
                
            },
            _ => {}
        }

        // ——— 收网络消息 ———
        drain_messages(&mut net_rx, &mut messages, &mut list_state, &username,img_tempdir.path(),&mut member_list,);
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
    println!("{} [{}]","❌ 退出房间",room_id);
    println!("{}","========Press Crtl + C to quit========\n".red().bold());
    continue;
    }
    Ok(())
}
