// client/keyboard.rs
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::{fs, path::{Path, PathBuf}};
use tokio::sync::mpsc::UnboundedSender;
use tui::widgets::ListState;
use unicode_segmentation::UnicodeSegmentation;
use uuid::Uuid;

use super::attachment_store::AttachmentStore;
use super::receiver::ChatMessage;
use super::ui::{selected_message_index, RenderedChatRow};
use super::clipboard::{self, ClipData};
use super::utils::{
    build_local_invite_request_line, build_local_notice_line, encode_rgba_as_png,
    normalize_clipboard_rgba, MemberIdentity,
    parse_clipboard_file_paths, parse_name_body, HELP_TEXT, HELP_TEXT_EN,
};
pub enum ControlFlow { Continue, Quit }

fn queue_attachment_paths(out_tx: &UnboundedSender<String>, paths: &[PathBuf]) {
    for path in paths {
        let _ = out_tx.send(path.to_string_lossy().to_string());
    }
}
/// 让 client 把所有可变状态打包进来，便于在这里直接修改。

pub struct KeyCtx<'a> {
    pub input:       &'a mut String,
    pub cursor:      &'a mut usize,
    pub list_state:  &'a mut ListState,
    pub chat_rows:   &'a [RenderedChatRow],
    pub messages:    &'a mut Vec<ChatMessage>,
    pub member_list: &'a mut Vec<MemberIdentity>, // 目前未用到，但保留以备扩展
    pub undo_mgr:    &'a mut UndoMgr,
    pub out_tx:      &'a UnboundedSender<String>,
    pub server_addr: &'a mut String,
    pub room_id:     &'a String,
    pub pwd:         &'a String,
    pub username:    &'a String,
    pub attachment_dir: &'a Path,
    pub attachment_store: &'a AttachmentStore,
    pub owner_capability: &'a Option<String>,
}

/// 处理一次 KeyEvent：改动都通过 ctx 传回；Esc 返回 Quit
pub fn handle_key(key: KeyEvent, ctx: &mut KeyCtx) -> ControlFlow {
    match key.code {
        // =============== 剪贴板粘贴 ===============
        KeyCode::Char('x') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            match clipboard::get() {
                Ok(ClipData::Text(txt)) => {
                    if let Some(paths) = parse_clipboard_file_paths(&txt) {
                        queue_attachment_paths(ctx.out_tx, &paths);
                    } else {
                        ctx.undo_mgr.maybe_push(ctx.input, *ctx.cursor, OpKind::Insert);
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
                            let _ = ctx.out_tx.send(build_local_notice_line(&format!("剪贴板图片格式异常: {e}")));
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
                    let file_path = ctx.attachment_dir.join(format!(
                        "clipboard_{}.png",
                        Uuid::new_v4().simple()
                    ));
                    match fs::write(&file_path, png_buf) {
                        Ok(_) => {
                            let _ = ctx.out_tx.send(file_path.to_string_lossy().to_string());
                        }
                        Err(e) => {
                            let _ = ctx.out_tx.send(build_local_notice_line(&format!("写入临时图片失败: {e}")));
                        }
                    }
                }
                Ok(ClipData::Files(paths)) => {
                    queue_attachment_paths(ctx.out_tx, &paths);
                }
                Err(e) => {
                    let _ = ctx.out_tx.send(build_local_notice_line(&format!("读取剪贴板失败: {e}")));
                }
            }
        }

        // =============== 复制选中行 ===============
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let Some(sel) = selected_message_index(ctx.chat_rows, ctx.list_state.selected()) {
                let (_, _, body) = parse_name_body(&ctx.messages[sel]);
                if let Err(e) = clipboard::set_text(&body) {
                    eprintln!("⚠️ Failed to paste: {e}");
                }
            }
        }

        // =============== 帮助文本 ===============
        KeyCode::Char('h') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            let _ = ctx.out_tx.send(HELP_TEXT.to_string());
        }
        KeyCode::Char('j') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            let _ = ctx.out_tx.send(HELP_TEXT_EN.to_string());
        }

        // =============== 生成邀请码 ===============
        KeyCode::Char('i') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            let Some(owner_capability) = ctx.owner_capability.as_deref() else {
                let _ = ctx.out_tx.send(build_local_notice_line("只有当前房主连接可以申请一次性邀请码"));
                return ControlFlow::Continue;
            };
            if ctx.server_addr.trim().is_empty() {
                let _ = ctx.out_tx.send(build_local_notice_line("当前连接没有可用的服务器地址，无法申请邀请码"));
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

        // =============== 普通字符插入 ===============
        KeyCode::Char(ch) if !key.modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) => {
            ctx.undo_mgr.maybe_push(ctx.input, *ctx.cursor, OpKind::Insert);
            let s = ch.to_string();
            let byte_idx = nth_grapheme_byte_idx(ctx.input, *ctx.cursor);
            ctx.input.insert_str(byte_idx, &s);
            *ctx.cursor += 1;
        }

        // =============== 光标移动 ===============
        KeyCode::Left  if key.modifiers.contains(KeyModifiers::CONTROL) => {
            *ctx.cursor = (*ctx.cursor).saturating_sub(3);
        }
        KeyCode::Left  => { if *ctx.cursor > 0 { *ctx.cursor -= 1; } }
        KeyCode::Right if key.modifiers.contains(KeyModifiers::CONTROL) => {
            let total = ctx.input.graphemes(true).count();
            if *ctx.cursor < total { *ctx.cursor = total; }
        }
        KeyCode::Right => {
            let total = ctx.input.graphemes(true).count();
            if *ctx.cursor < total { *ctx.cursor += 1; }
        }

        // =============== Backspace / Enter / 清空 / 撤销 ===============
        KeyCode::Backspace => {
            if *ctx.cursor > 0 {
                ctx.undo_mgr.maybe_push(ctx.input, *ctx.cursor, OpKind::Insert);
                let start = nth_grapheme_byte_idx(ctx.input, *ctx.cursor - 1);
                let end   = nth_grapheme_byte_idx(ctx.input, *ctx.cursor);
                ctx.input.replace_range(start..end, "");
                *ctx.cursor -= 1;
            }
        }
        KeyCode::Enter => {
            ctx.undo_mgr.maybe_push(ctx.input, *ctx.cursor, OpKind::Insert);
            let msg = ctx.input.trim();
            if !msg.is_empty() {
                let _ = ctx.out_tx.send(msg.to_string());
                ctx.input.clear();
                *ctx.cursor = 0;
            }
        }
        KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            ctx.undo_mgr.maybe_push(ctx.input, *ctx.cursor, OpKind::Insert);
            ctx.input.clear();
            *ctx.cursor = 0;
        }
        KeyCode::Char('z') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            ctx.undo_mgr.undo(ctx.input, ctx.cursor);
        }

        // =============== 列表上下 & Tab 预览 ===============
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
                    if let Err(e) = ctx.attachment_store.open_temp_and_cleanup_after_delay(attachment_id) {
                        let _ = ctx.out_tx.send(build_local_notice_line(&format!("打开附件失败: {e}")));
                    }
                }
            }
        }

        // =============== Esc 退出 ===============
        KeyCode::Esc => {
            let _ = ctx.out_tx.send("//~``~//".to_string());
            return ControlFlow::Quit;
        }

        _ => {}
    }
    ControlFlow::Continue
}

// 第 n 个字形单元在字符串中的字节偏移（从原 client.rs 搬过来）
fn nth_grapheme_byte_idx(s: &str, n: usize) -> usize {
    s.grapheme_indices(true)
     .nth(n)
     .map(|(idx, _)| idx)
     .unwrap_or_else(|| s.len())
}


use std::time::{Duration, Instant};
/// 一次编辑动作的类别（按你需要再细分）
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum OpKind { Insert, Other }

pub struct UndoMgr {
    stack:       Vec<(String, usize)>, // (内容快照, 光标)
    last_save:   Instant,              // 上一次压栈时间
    last_kind:   OpKind,               // 上一次操作类型
    max_depth:   usize,                // 可选：栈深上限
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

    /// 条件压栈：>500 ms 或操作类型变了
    pub fn maybe_push(&mut self,
                  input: &String,
                  cursor: usize,
                  kind: OpKind)
    {
        let elapsed = self.last_save.elapsed();
        if elapsed > Duration::from_millis(500) || kind != self.last_kind {
            self.stack.push((input.clone(), cursor));
            if self.stack.len() > self.max_depth {
                self.stack.remove(0);            // 裁掉最早的
            }
            self.last_save = Instant::now();
            self.last_kind = kind;
        }
    }

    /// 撤销一步
    pub fn undo(&mut self, input: &mut String, cursor: &mut usize) {
        if let Some((prev, pos)) = self.stack.pop() {
            *input  = prev;
            *cursor = pos.min(input.graphemes(true).count());
        }
    }
}
