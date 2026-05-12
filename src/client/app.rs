use std::{
    io,
    sync::{mpsc, Arc},
    thread,
    time::{Duration, Instant},
};

use anyhow::Result;
use colored::*;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event as CEvent},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use tokio::sync::mpsc as tokio_mpsc;
use tui::{backend::CrosstermBackend, widgets::ListState, Terminal};

use crate::{
    attachments::store::AttachmentStore,
    client::{
        handshake,
        initialization::{init_color, initial_name, initial_serveraddr},
        network,
        receiver::{drain_messages, ChatMessage, ReceiverState, TransferUiState},
        session::SharedGroupCrypto,
    },
    crypto::{compute_room_safety_state, RoomSafetyState, SafetyTranscript},
    protocol::{build_epoch_commit_line, build_key_announce_line, MemberIdentity},
    ui::keyboard::{handle_key, ControlFlow, KeyCtx, UndoMgr},
    ui::tui::{build_chat_rows, chat_inner_width, draw_chat, RenderedChatRow},
};

#[derive(Debug)]
enum Event<I> {
    Input(I),
    Tick,
}

#[derive(Clone)]
enum UiMode {
    Chat,
    _ImagePreview(std::path::PathBuf),
}

pub async fn run() -> Result<()> {
    init_color();
    let username = initial_name()?;
    let mut server_addr = initial_serveraddr()?;

    loop {
        let (net_tx, mut net_rx) = tokio_mpsc::unbounded_channel::<String>();
        let (out_tx, out_rx) = tokio_mpsc::unbounded_channel::<String>();

        let session = loop {
            if server_addr.is_empty() {
                server_addr = initial_serveraddr()?;
            }
            match handshake::connect_and_login(&server_addr, &username).await {
                Ok(session) => break session,
                Err(e) if e.to_string().contains("邀请码无效") => {
                    eprintln!("❌ 邀请码无效或已过期，请重新选择服务器或输入新的邀请码。\n");
                    server_addr.clear();
                }
                Err(e) if e.to_string().contains("断开服务器") => {
                    eprintln!("断开服务器... \n");
                    server_addr.clear();
                }
                Err(e) => {
                    eprintln!("HandShake Error: {}", e);
                    server_addr.clear();
                }
            }
        };

        let room_id = session.room_crypto.room_id().to_string();
        let room_credential = session.room_crypto.room_credential().to_string();
        let owner_capability = session.owner_capability.clone();
        let mut active_server_addr = session.server_addr.clone();
        server_addr = clear_invitation(&server_addr);

        let group_crypto = session.group_crypto.clone();
        let ui_group_crypto = session.group_crypto.clone();
        let transport = session.transport.clone();
        let lines = session.lines;
        let writer = session.writer;
        let room_tempdir = tempfile::Builder::new().prefix("").tempdir()?;
        let attachment_store =
            Arc::new(AttachmentStore::new_in(room_tempdir.path().to_path_buf())?);
        let net_attachment_store = attachment_store.clone();
        tokio::spawn(async move {
            if let Err(e) = network::chat_loop(
                lines,
                writer,
                net_tx,
                out_rx,
                group_crypto,
                transport,
                net_attachment_store,
            )
            .await
            {
                eprintln!("chat_loop error: {e}");
            }
        });

        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

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

        let ui_mode = UiMode::Chat;
        let mut messages: Vec<ChatMessage> = Vec::new();
        let mut member_list: Vec<MemberIdentity> = Vec::new();
        let mut room_safety_state: Option<RoomSafetyState> = None;
        let mut receiver_state = ReceiverState::default();
        let mut transfer_ui_state = TransferUiState::default();
        let mut input = String::new();
        let mut cursor = 0usize;
        let mut list_state = ListState::default();
        let mut undo_mgr = UndoMgr::new();
        let mut chat_rows: Vec<RenderedChatRow>;
        trigger_phase2_actions(&out_tx, &ui_group_crypto);

        'ui: loop {
            let size = terminal.size()?;
            chat_rows = build_chat_rows(&messages, chat_inner_width(size), &username);
            if let Some(selected) = list_state.selected() {
                if selected >= chat_rows.len() && !chat_rows.is_empty() {
                    list_state.select(Some(chat_rows.len() - 1));
                }
            } else if !chat_rows.is_empty() {
                list_state.select(Some(chat_rows.len() - 1));
            }

            terminal.draw(|f| {
                let transfer_lines = transfer_ui_state.lines(2);
                let safety_code = room_safety_state.as_ref().map(|state| state.code.emoji());
                match &ui_mode {
                    UiMode::Chat => draw_chat(
                        f,
                        &chat_rows,
                        &mut list_state,
                        &member_list,
                        &transfer_lines,
                        &input,
                        cursor,
                        &username,
                        &room_id,
                        safety_code.as_deref(),
                    ),
                    UiMode::_ImagePreview(_) => {}
                }
            })?;

            if let Ok(Event::Input(key)) = ev_rx.recv() {
                let mut ctx = KeyCtx {
                    input: &mut input,
                    cursor: &mut cursor,
                    list_state: &mut list_state,
                    chat_rows: &chat_rows,
                    messages: &mut messages,
                    member_list: &mut member_list,
                    undo_mgr: &mut undo_mgr,
                    out_tx: &out_tx,
                    server_addr: &mut active_server_addr,
                    room_id: &room_id,
                    pwd: &room_credential,
                    username: &username,
                    attachment_dir: room_tempdir.path(),
                    attachment_store: attachment_store.as_ref(),
                    owner_capability: &owner_capability,
                };
                if let ControlFlow::Quit = handle_key(key, &mut ctx) {
                    break 'ui;
                }
            }

            let was_at_bottom = list_state
                .selected()
                .map(|i| i + 1 >= chat_rows.len())
                .unwrap_or(true);
            let drain_outcome = drain_messages(
                &mut net_rx,
                &mut messages,
                &username,
                &ui_group_crypto,
                attachment_store.as_ref(),
                &mut member_list,
                &mut receiver_state,
                &mut transfer_ui_state,
            );
            if drain_outcome.member_list_changed {
                let transcript = SafetyTranscript::room_v0(&room_id, &member_list);
                room_safety_state = Some(compute_room_safety_state(transcript));
            }
            if drain_outcome.phase2_action_needed {
                trigger_phase2_actions(&out_tx, &ui_group_crypto);
            }
            let size = terminal.size()?;
            chat_rows = build_chat_rows(&messages, chat_inner_width(size), &username);
            if was_at_bottom && !chat_rows.is_empty() {
                list_state.select(Some(chat_rows.len() - 1));
            } else if let Some(selected) = list_state.selected() {
                if selected >= chat_rows.len() && !chat_rows.is_empty() {
                    list_state.select(Some(chat_rows.len() - 1));
                }
            }
        }

        drop(running);
        execute!(terminal.backend_mut(), DisableMouseCapture)?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        disable_raw_mode()?;
        terminal.show_cursor()?;
        println!("❌ 退出房间 [{}]", room_id);
        println!(
            "{}",
            "========Press Crtl + C to quit========\n".red().bold()
        );
    }
}

fn clear_invitation(inv: &str) -> String {
    if inv.starts_with("/INVITE:") {
        String::new()
    } else {
        inv.to_string()
    }
}

fn trigger_phase2_actions(
    out_tx: &tokio_mpsc::UnboundedSender<String>,
    group_crypto: &SharedGroupCrypto,
) {
    let (announce_line, commit_line, local_commit) = {
        let Ok(mut guard) = group_crypto.lock() else {
            return;
        };
        let announce_line = build_key_announce_line(&guard.local_key_announce()).ok();
        let local_commit = guard.build_pending_epoch_commit().ok().flatten();
        let commit_line = local_commit
            .as_ref()
            .and_then(|commit| build_epoch_commit_line(commit).ok());
        (announce_line, commit_line, local_commit)
    };

    if let Some(line) = announce_line {
        out_tx.send(line).ok();
    }

    if let Some(line) = commit_line {
        out_tx.send(line).ok();
    }

    if let Some(commit) = local_commit {
        if let Ok(mut guard) = group_crypto.lock() {
            if guard.apply_epoch_commit(&commit).ok() == Some(true) {
                if let Ok(line) = build_key_announce_line(&guard.local_key_announce()) {
                    out_tx.send(line).ok();
                }
            }
        }
    }
}
