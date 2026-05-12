use chrono::Local;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::{
    attachments::{
        receiver::{
            append_encrypted_chunk, register_attachment, AttachmentReceiveEvent,
            AttachmentReceiveState, CompletedAttachment,
        },
        store::AttachmentStore,
    },
    crypto::{decrypt_message, EncryptedMessage, EpochCommit, GroupCryptoState, MemberKeyAnnounce},
    protocol::{
        parse_attachment_frame, parse_display_body, parse_epoch_commit_line,
        parse_key_announce_line, parse_local_ui_event, parse_member_list_line, parse_rmsg_line,
        AttachmentFrame, AttachmentKind, LocalUiEvent, MemberIdentity,
    },
    ui::{help::render_transfer_line, notifier},
};

use super::session::SharedGroupCrypto;

const DRAIN_BATCH_LIMIT: usize = 128;
const PENDING_EPOCH_COMMIT_LIMIT: usize = 8;

#[derive(Debug, Clone)]
pub enum ChatMessage {
    Text(String),
    Attachment {
        attachment_id: String,
        sender: String,
        ts: String,
        name: String,
        size: u64,
        kind: AttachmentKind,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStage {
    Active,
    Done,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Sending,
    Receiving,
}

#[derive(Debug, Clone)]
pub struct TransferStatus {
    pub transfer_id: String,
    pub file_name: String,
    pub total_chunks: usize,
    pub acked_chunks: usize,
    pub total_size: u64,
    pub direction: TransferDirection,
    pub stage: TransferStage,
    pub detail: Option<String>,
}

#[derive(Default)]
pub struct TransferUiState {
    order: Vec<String>,
    transfers: std::collections::HashMap<String, TransferStatus>,
}

impl TransferUiState {
    pub fn apply(&mut self, event: LocalUiEvent) -> Option<String> {
        match event {
            LocalUiEvent::TransferBegin {
                transfer_id,
                file_name,
                total_chunks,
                total_size,
            } => {
                if !self.order.contains(&transfer_id) {
                    self.order.push(transfer_id.clone());
                }
                self.transfers.insert(
                    transfer_id.clone(),
                    TransferStatus {
                        transfer_id,
                        file_name,
                        total_chunks,
                        acked_chunks: 0,
                        total_size,
                        direction: TransferDirection::Sending,
                        stage: TransferStage::Active,
                        detail: None,
                    },
                );
                None
            }
            LocalUiEvent::TransferProgress {
                transfer_id,
                acked_chunks,
                total_chunks,
            } => {
                if let Some(status) = self.transfers.get_mut(&transfer_id) {
                    status.acked_chunks = acked_chunks;
                    status.total_chunks = total_chunks;
                    status.stage = TransferStage::Active;
                    status.detail = None;
                }
                None
            }
            LocalUiEvent::TransferDone { transfer_id } => {
                if let Some(status) = self.transfers.get_mut(&transfer_id) {
                    status.acked_chunks = status.total_chunks;
                    status.stage = TransferStage::Done;
                    status.detail = Some("server acked".to_string());
                }
                None
            }
            LocalUiEvent::TransferFailed {
                transfer_id,
                reason,
            } => {
                let file_name = if let Some(status) = self.transfers.get_mut(&transfer_id) {
                    status.stage = TransferStage::Failed;
                    status.detail = Some(reason.clone());
                    status.file_name.clone()
                } else {
                    transfer_id.clone()
                };
                Some(format!("传输失败: {file_name} - {reason}"))
            }
            LocalUiEvent::EchoText { .. } | LocalUiEvent::EchoAttachment { .. } => None,
            LocalUiEvent::Notice(message) => Some(message),
        }
    }

    pub fn begin_incoming(
        &mut self,
        transfer_id: String,
        file_name: String,
        total_chunks: usize,
        total_size: u64,
    ) {
        if !self.order.contains(&transfer_id) {
            self.order.push(transfer_id.clone());
        }
        self.transfers.insert(
            transfer_id.clone(),
            TransferStatus {
                transfer_id,
                file_name,
                total_chunks,
                acked_chunks: 0,
                total_size,
                direction: TransferDirection::Receiving,
                stage: TransferStage::Active,
                detail: None,
            },
        );
    }

    pub fn progress_incoming(
        &mut self,
        transfer_id: &str,
        received_chunks: usize,
        total_chunks: usize,
    ) {
        if let Some(status) = self.transfers.get_mut(transfer_id) {
            status.acked_chunks = received_chunks;
            status.total_chunks = total_chunks;
            status.stage = TransferStage::Active;
            status.detail = None;
        }
    }

    pub fn finish_incoming(&mut self, transfer_id: &str) {
        if let Some(status) = self.transfers.get_mut(transfer_id) {
            status.acked_chunks = status.total_chunks;
            status.stage = TransferStage::Done;
            status.detail = Some("received".to_string());
        }
    }

    pub fn fail_incoming(&mut self, transfer_id: &str, reason: &str) {
        if let Some(status) = self.transfers.get_mut(transfer_id) {
            status.stage = TransferStage::Failed;
            status.detail = Some(reason.to_string());
        }
    }

    pub fn lines(&self, limit: usize) -> Vec<String> {
        let mut lines = Vec::new();

        for transfer_id in self.order.iter().rev().take(limit) {
            if let Some(status) = self.transfers.get(transfer_id) {
                lines.push(render_transfer_line(
                    &status.file_name,
                    status.total_size,
                    status.direction,
                    status.stage,
                    status.acked_chunks,
                    status.total_chunks,
                    status.detail.as_deref(),
                ));
            }
        }

        lines
    }
}

#[derive(Default)]
pub struct ReceiverState {
    attachments: AttachmentReceiveState,
    pending_epoch_commits: Vec<EpochCommit>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DrainOutcome {
    pub member_list_changed: bool,
    pub phase2_action_needed: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn drain_messages(
    net_rx: &mut UnboundedReceiver<String>,
    messages: &mut Vec<ChatMessage>,
    my_name: &str,
    group_crypto: &SharedGroupCrypto,
    attachment_store: &AttachmentStore,
    members: &mut Vec<MemberIdentity>,
    receiver_state: &mut ReceiverState,
    transfer_ui_state: &mut TransferUiState,
) -> DrainOutcome {
    let mut outcome = DrainOutcome::default();
    let mut processed = 0usize;

    while let Ok(line) = net_rx.try_recv() {
        processed += 1;

        if should_drop_unframed_control_line(&line) {
            if processed >= DRAIN_BATCH_LIMIT {
                break;
            }
            continue;
        }

        if let Some(parsed_members) = parse_member_list_line(&line) {
            members.clear();
            members.extend(parsed_members.clone());
            if let Ok(mut guard) = group_crypto.lock() {
                let _ = guard.replace_members(
                    parsed_members
                        .iter()
                        .map(|member| (member.member_id.clone(), member.nickname.clone())),
                );
                if retry_pending_epoch_commits(receiver_state, &mut guard) {
                    outcome.phase2_action_needed = true;
                }
            }
            outcome.member_list_changed = true;
            outcome.phase2_action_needed = true;
            if processed >= DRAIN_BATCH_LIMIT {
                break;
            }
            continue;
        }

        if let Some(event) = parse_local_ui_event(&line) {
            let hms = Local::now().format("%H:%M:%S").to_string();
            if let Some(message) = handle_local_ui_event(event, my_name, transfer_ui_state, &hms) {
                push_message(messages, message);
            }
            continue;
        }

        let hms = Local::now().format("%H:%M:%S").to_string();
        let (outer_sender, raw_body) = parse_display_body(&line);
        if let Some(announce) = parse_key_announce_line::<MemberKeyAnnounce>(&raw_body) {
            if let Ok(mut guard) = group_crypto.lock() {
                if guard.apply_key_announce(&announce).unwrap_or(false) {
                    outcome.phase2_action_needed = true;
                }
                if retry_pending_epoch_commits(receiver_state, &mut guard) {
                    outcome.phase2_action_needed = true;
                }
            }
            if processed >= DRAIN_BATCH_LIMIT {
                break;
            }
            continue;
        }
        if let Some(commit) = parse_epoch_commit_line::<EpochCommit>(&raw_body) {
            if let Ok(mut guard) = group_crypto.lock() {
                match guard.apply_epoch_commit(&commit) {
                    Ok(true) => outcome.phase2_action_needed = true,
                    Ok(false) => {}
                    Err(_) => {
                        queue_pending_epoch_commit(receiver_state, commit);
                    }
                }
            }
            if processed >= DRAIN_BATCH_LIMIT {
                break;
            }
            continue;
        }
        if let Some(AttachmentFrame::EncryptedChunk(chunk)) = parse_attachment_frame(&raw_body) {
            let result =
                append_encrypted_chunk(&mut receiver_state.attachments, chunk, attachment_store);
            if let Some(message) = attachment_result_to_message(result, transfer_ui_state, &hms) {
                if outer_sender != my_name {
                    notifier::notify();
                }
                push_message(messages, message);
            }
            if processed >= DRAIN_BATCH_LIMIT {
                break;
            }
            continue;
        }
        let decrypted = parse_rmsg_line::<EncryptedMessage>(&raw_body).and_then(|encrypted| {
            let mut guard = group_crypto.lock().ok()?;
            decrypt_message(&mut guard, &encrypted)
                .ok()
                .and_then(|message| {
                    let body = String::from_utf8(message.plaintext).ok()?;
                    let sender = guard
                        .member_display_name(&message.header.sender_id)
                        .unwrap_or_else(|| outer_sender.clone());
                    Some((sender, body))
                })
        });

        let (sender, body) = match decrypted {
            Some((sender, body)) => (sender, body),
            None if raw_body.starts_with("/RMSG ") => {
                if processed >= DRAIN_BATCH_LIMIT {
                    break;
                }
                continue;
            }
            None if line.starts_with("⚡ ") => ("System".to_string(), line),
            None => {
                if processed >= DRAIN_BATCH_LIMIT {
                    break;
                }
                continue;
            }
        };

        let result = match parse_attachment_frame(&body) {
            Some(AttachmentFrame::Meta(meta)) => register_attachment(
                &mut receiver_state.attachments,
                sender.clone(),
                meta,
                attachment_store,
            ),
            Some(AttachmentFrame::EncryptedChunk(chunk)) => {
                append_encrypted_chunk(&mut receiver_state.attachments, chunk, attachment_store)
            }
            None => Ok(Vec::new()),
        };

        if let Some(message) = attachment_result_to_message(result, transfer_ui_state, &hms) {
            if sender != my_name {
                notifier::notify();
            }
            push_message(messages, message);
            if processed >= DRAIN_BATCH_LIMIT {
                break;
            }
            continue;
        }

        if parse_attachment_frame(&body).is_none() {
            if sender != my_name {
                notifier::notify();
            }
            push_message(
                messages,
                ChatMessage::Text(format_text_message(&sender, &body, &hms)),
            );
        }

        if processed >= DRAIN_BATCH_LIMIT {
            break;
        }
    }

    outcome
}

fn attachment_result_to_message(
    result: Result<Vec<AttachmentReceiveEvent>, String>,
    transfer_ui_state: &mut TransferUiState,
    hms: &str,
) -> Option<ChatMessage> {
    match result {
        Ok(events) => apply_attachment_events(events, transfer_ui_state, hms),
        Err(err) => Some(ChatMessage::Text(format!("[System] [{hms}] {err}"))),
    }
}

fn apply_attachment_events(
    events: Vec<AttachmentReceiveEvent>,
    transfer_ui_state: &mut TransferUiState,
    hms: &str,
) -> Option<ChatMessage> {
    let mut message = None;

    for event in events {
        match event {
            AttachmentReceiveEvent::Begin {
                transfer_id,
                file_name,
                total_chunks,
                total_size,
            } => transfer_ui_state.begin_incoming(transfer_id, file_name, total_chunks, total_size),
            AttachmentReceiveEvent::Progress {
                transfer_id,
                received_chunks,
                total_chunks,
            } => transfer_ui_state.progress_incoming(&transfer_id, received_chunks, total_chunks),
            AttachmentReceiveEvent::Complete(CompletedAttachment {
                transfer_id,
                attachment_id,
                sender,
                file_name,
                total_size,
                kind,
            }) => {
                transfer_ui_state.finish_incoming(&transfer_id);
                message = Some(ChatMessage::Attachment {
                    attachment_id,
                    sender,
                    ts: hms.to_string(),
                    name: file_name,
                    size: total_size,
                    kind,
                });
            }
        }
    }

    message
}

fn queue_pending_epoch_commit(receiver_state: &mut ReceiverState, commit: EpochCommit) {
    if receiver_state
        .pending_epoch_commits
        .iter()
        .any(|pending| pending == &commit)
    {
        return;
    }
    receiver_state.pending_epoch_commits.push(commit);
    if receiver_state.pending_epoch_commits.len() > PENDING_EPOCH_COMMIT_LIMIT {
        receiver_state.pending_epoch_commits.remove(0);
    }
}

fn retry_pending_epoch_commits(
    receiver_state: &mut ReceiverState,
    group_crypto: &mut GroupCryptoState,
) -> bool {
    let mut applied = false;
    let mut idx = 0;
    while idx < receiver_state.pending_epoch_commits.len() {
        let commit = receiver_state.pending_epoch_commits[idx].clone();
        match group_crypto.apply_epoch_commit(&commit) {
            Ok(true) => {
                applied = true;
                receiver_state.pending_epoch_commits.remove(idx);
            }
            Ok(false) => {
                receiver_state.pending_epoch_commits.remove(idx);
            }
            Err(_) => {
                idx += 1;
            }
        }
    }
    applied
}

fn format_text_message(sender: &str, body: &str, hms: &str) -> String {
    format!("[{sender}] [{hms}] {body}")
}

fn handle_local_ui_event(
    event: LocalUiEvent,
    my_name: &str,
    transfer_ui_state: &mut TransferUiState,
    hms: &str,
) -> Option<ChatMessage> {
    match event {
        LocalUiEvent::EchoText { body } => {
            Some(ChatMessage::Text(format_text_message(my_name, &body, hms)))
        }
        LocalUiEvent::EchoAttachment {
            attachment_id,
            file_name,
            total_size,
            kind,
        } => Some(ChatMessage::Attachment {
            attachment_id,
            sender: my_name.to_string(),
            ts: hms.to_string(),
            name: file_name,
            size: total_size,
            kind,
        }),
        other => transfer_ui_state
            .apply(other)
            .map(|notice| ChatMessage::Text(format!("[System] [{hms}] {notice}"))),
    }
}

fn push_message(messages: &mut Vec<ChatMessage>, message: ChatMessage) {
    messages.push(message);

    if messages.len() > 500 {
        messages.drain(..100);
    }
}

fn should_drop_unframed_control_line(line: &str) -> bool {
    !line.starts_with('[')
        && (line == "/ping_ack"
            || line == "/ping"
            || line == "OK"
            || line.starts_with("OK ")
            || line.starts_with("/ACK ")
            || line.starts_with("INVITE_OK "))
}
