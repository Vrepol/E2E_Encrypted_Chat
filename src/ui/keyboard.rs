use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::sync::mpsc::UnboundedSender;
use tui::widgets::ListState;
use unicode_segmentation::UnicodeSegmentation;
use uuid::Uuid;

use super::clipboard::{self, ClipData};
use super::help::{HELP_TEXT, HELP_TEXT_EN};
use super::tui::{parse_name_body, selected_message_index, RenderedChatRow};
use crate::attachments::store::AttachmentStore;
use crate::client::receiver::ChatMessage;
use crate::protocol::{
    build_local_attachment_send_line, build_local_invite_request_line, build_local_notice_line,
    AttachmentKind, MemberIdentity,
};
use crate::ui::clipboard::{
    encode_rgba_as_png, normalize_clipboard_rgba, parse_clipboard_file_paths,
};

pub enum ControlFlow {
    Continue,
    Quit,
}

fn queue_attachment_paths(out_tx: &UnboundedSender<String>, paths: &[PathBuf]) {
    for path in paths {
        let _ = out_tx.send(path.to_string_lossy().to_string());
    }
}
pub struct KeyCtx<'a> {
    pub input: &'a mut String,
    pub cursor: &'a mut usize,
    pub list_state: &'a mut ListState,
    pub chat_rows: &'a [RenderedChatRow],
    pub messages: &'a mut Vec<ChatMessage>,
    pub member_list: &'a mut Vec<MemberIdentity>,
    pub undo_mgr: &'a mut UndoMgr,
    pub out_tx: &'a UnboundedSender<String>,
    pub server_addr: &'a mut String,
    pub room_id: &'a String,
    pub pwd: &'a String,
    pub username: &'a String,
    pub attachment_dir: &'a Path,
    pub attachment_store: &'a AttachmentStore,
    pub owner_capability: &'a Option<String>,
    pub copied_until: &'a mut Option<Instant>,
}

pub fn handle_key(key: KeyEvent, ctx: &mut KeyCtx) -> ControlFlow {
    match key.code {
        KeyCode::Char('x') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            match clipboard::get() {
                Ok(ClipData::Text(txt)) => {
                    if let Some(paths) = parse_clipboard_file_paths(&txt) {
                        queue_attachment_paths(ctx.out_tx, &paths);
                    } else {
                        ctx.undo_mgr
                            .maybe_push(ctx.input, *ctx.cursor, OpKind::Insert);
                        let byte_idx = nth_grapheme_byte_idx(ctx.input, *ctx.cursor);
                        ctx.input.insert_str(byte_idx, &txt);
                        *ctx.cursor += txt.graphemes(true).count();
                    }
                }
                Ok(ClipData::Image(img)) => {
                    let width: u32 = img.width.try_into().unwrap();
                    let height: u32 = img.height.try_into().unwrap();
                    let rgba = match normalize_clipboard_rgba(&img.bytes, width, height) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            let _ = ctx
                                .out_tx
                                .send(build_local_notice_line(&format!("剪贴板图片格式异常: {e}")));
                            return ControlFlow::Continue;
                        }
                    };
                    let png_buf = match encode_rgba_as_png(&rgba, width, height) {
                        Ok(b) => b,
                        Err(e) => {
                            eprintln!("⚠️ Failed to encode image: {e}");
                            return ControlFlow::Continue;
                        }
                    };
                    let file_name = format!("clipboard_{}.png", Uuid::new_v4().simple());
                    let _ = ctx.out_tx.send(build_local_attachment_send_line(
                        &file_name,
                        AttachmentKind::Image,
                        &png_buf,
                    ));
                }
                Ok(ClipData::Files(paths)) => {
                    queue_attachment_paths(ctx.out_tx, &paths);
                }
                Err(e) => {
                    let _ = ctx
                        .out_tx
                        .send(build_local_notice_line(&format!("读取剪贴板失败: {e}")));
                }
            }
        }

        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let Some(sel) = selected_message_index(ctx.chat_rows, ctx.list_state.selected()) {
                let (_, _, body) = parse_name_body(&ctx.messages[sel]);
                if let Err(e) = clipboard::set_text(&body) {
                    eprintln!("⚠️ Failed to paste: {e}");
                } else {
                    *ctx.copied_until = Some(Instant::now() + Duration::from_millis(1200));
                }
            }
        }

        KeyCode::Char('h') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            let _ = ctx.out_tx.send(build_local_notice_line(HELP_TEXT));
        }
        KeyCode::Char('j') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            let _ = ctx.out_tx.send(build_local_notice_line(HELP_TEXT_EN));
        }

        KeyCode::Char('i') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            let Some(owner_capability) = ctx.owner_capability.as_deref() else {
                let _ = ctx.out_tx.send(build_local_notice_line(
                    "只有当前房主连接可以申请一次性邀请码",
                ));
                return ControlFlow::Continue;
            };
            if ctx.server_addr.trim().is_empty() {
                let _ = ctx.out_tx.send(build_local_notice_line(
                    "当前连接没有可用的服务器地址，无法申请邀请码",
                ));
                return ControlFlow::Continue;
            }
            let request = build_local_invite_request_line(
                ctx.server_addr,
                ctx.room_id,
                ctx.pwd,
                owner_capability,
            );
            let _ = ctx.out_tx.send(request);
        }

        KeyCode::Char(ch)
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            ctx.undo_mgr
                .maybe_push(ctx.input, *ctx.cursor, OpKind::Insert);
            let s = ch.to_string();
            let byte_idx = nth_grapheme_byte_idx(ctx.input, *ctx.cursor);
            ctx.input.insert_str(byte_idx, &s);
            *ctx.cursor += 1;
        }

        KeyCode::Left if key.modifiers.contains(KeyModifiers::CONTROL) => {
            *ctx.cursor = (*ctx.cursor).saturating_sub(3);
        }
        KeyCode::Left if *ctx.cursor > 0 => {
            *ctx.cursor -= 1;
        }
        KeyCode::Left => {}
        KeyCode::Right if key.modifiers.contains(KeyModifiers::CONTROL) => {
            let total = ctx.input.graphemes(true).count();
            if *ctx.cursor < total {
                *ctx.cursor = total;
            }
        }
        KeyCode::Right => {
            let total = ctx.input.graphemes(true).count();
            if *ctx.cursor < total {
                *ctx.cursor += 1;
            }
        }

        KeyCode::Backspace if *ctx.cursor > 0 => {
            ctx.undo_mgr
                .maybe_push(ctx.input, *ctx.cursor, OpKind::Insert);
            let start = nth_grapheme_byte_idx(ctx.input, *ctx.cursor - 1);
            let end = nth_grapheme_byte_idx(ctx.input, *ctx.cursor);
            ctx.input.replace_range(start..end, "");
            *ctx.cursor -= 1;
        }
        KeyCode::Backspace => {}
        KeyCode::Enter => {
            ctx.undo_mgr
                .maybe_push(ctx.input, *ctx.cursor, OpKind::Insert);
            let msg = ctx.input.trim();
            if !msg.is_empty() {
                let _ = ctx.out_tx.send(msg.to_string());
                ctx.input.clear();
                *ctx.cursor = 0;
            }
        }
        KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            ctx.undo_mgr
                .maybe_push(ctx.input, *ctx.cursor, OpKind::Insert);
            ctx.input.clear();
            *ctx.cursor = 0;
        }
        KeyCode::Char('z') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            ctx.undo_mgr.undo(ctx.input, ctx.cursor);
        }

        KeyCode::Up if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let Some(i) = ctx.list_state.selected() {
                ctx.list_state.select(Some(i.saturating_sub(5)));
            }
        }
        KeyCode::Up => {
            if let Some(i) = ctx.list_state.selected() {
                ctx.list_state.select(Some(i.saturating_sub(1)));
            }
        }
        KeyCode::Down if key.modifiers.contains(KeyModifiers::CONTROL) => {
            ctx.list_state
                .select(Some(ctx.chat_rows.len().saturating_sub(1)));
        }
        KeyCode::Down => {
            if let Some(i) = ctx.list_state.selected() {
                let next = (i + 1).min(ctx.chat_rows.len().saturating_sub(1));
                ctx.list_state.select(Some(next));
            }
        }
        KeyCode::Tab => {
            if let Some(sel) = selected_message_index(ctx.chat_rows, ctx.list_state.selected()) {
                if let ChatMessage::Attachment { attachment_id, .. } = &ctx.messages[sel] {
                    if let Err(e) = ctx
                        .attachment_store
                        .open_temp_and_cleanup_after_delay(attachment_id)
                    {
                        let _ = ctx
                            .out_tx
                            .send(build_local_notice_line(&format!("打开附件失败: {e}")));
                    }
                }
            }
        }

        KeyCode::Esc => {
            let _ = ctx.out_tx.send("//~``~//".to_string());
            return ControlFlow::Quit;
        }

        _ => {}
    }
    ControlFlow::Continue
}

fn nth_grapheme_byte_idx(s: &str, n: usize) -> usize {
    s.grapheme_indices(true)
        .nth(n)
        .map(|(idx, _)| idx)
        .unwrap_or_else(|| s.len())
}
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum OpKind {
    Insert,
    Other,
}

pub struct UndoMgr {
    stack: Vec<(String, usize)>,
    last_save: Instant,
    last_kind: OpKind,
    max_depth: usize,
}

impl UndoMgr {
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            last_save: Instant::now(),
            last_kind: OpKind::Other,
            max_depth: 200,
        }
    }

    pub fn maybe_push(&mut self, input: &str, cursor: usize, kind: OpKind) {
        let elapsed = self.last_save.elapsed();
        if elapsed > Duration::from_millis(500) || kind != self.last_kind {
            self.stack.push((input.to_owned(), cursor));
            if self.stack.len() > self.max_depth {
                self.stack.remove(0);
            }
            self.last_save = Instant::now();
            self.last_kind = kind;
        }
    }

    pub fn undo(&mut self, input: &mut String, cursor: &mut usize) {
        if let Some((prev, pos)) = self.stack.pop() {
            *input = prev;
            *cursor = pos.min(input.graphemes(true).count());
        }
    }
}

impl Default for UndoMgr {
    fn default() -> Self {
        Self::new()
    }
}
