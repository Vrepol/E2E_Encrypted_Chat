use std::{net::TcpListener as StdTcpListener, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Result;
use rust_chat::{
    attachments::store::AttachmentStore,
    client::{
        handshake, network,
        receiver::{drain_messages, ChatMessage, ReceiverState, TransferUiState},
        session::SharedGroupCrypto,
    },
    protocol::{
        build_epoch_commit_line, build_key_announce_line, build_local_invite_request_line,
        MemberIdentity,
    },
};
use tempfile::TempDir;
use tokio::{sync::mpsc, task::JoinHandle, time::sleep};

struct TestClient {
    out_tx: mpsc::UnboundedSender<String>,
    net_rx: mpsc::UnboundedReceiver<String>,
    group_crypto: SharedGroupCrypto,
    attachment_store: Arc<AttachmentStore>,
    _room_dir: TempDir,
    _network_task: JoinHandle<()>,
    messages: Vec<ChatMessage>,
    members: Vec<MemberIdentity>,
    receiver_state: ReceiverState,
    transfer_ui_state: TransferUiState,
    username: String,
    room_id: String,
    owner_capability: Option<String>,
}

impl TestClient {
    async fn connect(
        server_addr: &str,
        password: &str,
        nickname: &str,
        room_id: &str,
        room_credential: &str,
        action: &'static str,
    ) -> Result<Self> {
        let session = if server_addr.starts_with("/INVITE:") {
            handshake::connect_and_login(server_addr, nickname).await?
        } else {
            handshake::connect_for_test(
                server_addr,
                password,
                nickname,
                room_id,
                room_credential,
                action,
            )
            .await?
        };
        let (net_tx, net_rx) = mpsc::unbounded_channel();
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let attachment_dir = tempfile::tempdir()?;
        let attachment_store = Arc::new(AttachmentStore::new_in(
            attachment_dir.path().to_path_buf(),
        )?);
        let group_crypto = session.group_crypto.clone();
        let transport = session.transport.clone();
        let network_store = attachment_store.clone();
        let owner_capability = session.owner_capability.clone();
        let task = tokio::spawn(async move {
            let _ = network::chat_loop(
                session.lines,
                session.writer,
                net_tx,
                out_rx,
                group_crypto.clone(),
                transport,
                network_store,
            )
            .await;
        });

        Ok(Self {
            out_tx,
            net_rx,
            group_crypto: session.group_crypto,
            attachment_store,
            _room_dir: attachment_dir,
            _network_task: task,
            messages: Vec::new(),
            members: Vec::new(),
            receiver_state: ReceiverState::default(),
            transfer_ui_state: TransferUiState::default(),
            username: nickname.to_string(),
            room_id: room_id.to_string(),
            owner_capability,
        })
    }

    fn trigger_phase2_actions(&self) {
        let (announce_line, commit_line, local_commit) = {
            let Ok(mut guard) = self.group_crypto.lock() else {
                return;
            };
            let announce_line = build_key_announce_line(&guard.local_key_announce()).ok();
            let local_commit = guard.build_join_epoch_commit().ok().flatten();
            let commit_line = local_commit
                .as_ref()
                .and_then(|commit| build_epoch_commit_line(commit).ok());
            (announce_line, commit_line, local_commit)
        };

        if let Some(line) = announce_line {
            self.out_tx.send(line).ok();
        }

        if let Some(line) = commit_line {
            self.out_tx.send(line).ok();
        }

        if let Some(commit) = local_commit {
            if let Ok(mut guard) = self.group_crypto.lock() {
                let _ = guard.apply_epoch_commit(&commit);
            }
        }
    }

    fn drain_once(&mut self) {
        let outcome = drain_messages(
            &mut self.net_rx,
            &mut self.messages,
            &self.username,
            &self.group_crypto,
            self.attachment_store.as_ref(),
            &mut self.members,
            &mut self.receiver_state,
            &mut self.transfer_ui_state,
        );
        if outcome.phase2_action_needed {
            self.trigger_phase2_actions();
        }
    }

    fn has_text(&self, needle: &str) -> bool {
        self.messages.iter().any(|message| match message {
            ChatMessage::Text(body) => body.contains(needle),
            ChatMessage::Attachment { .. } => false,
        })
    }

    fn latest_attachment_id(&self) -> Option<String> {
        self.messages
            .iter()
            .rev()
            .find_map(|message| match message {
                ChatMessage::Attachment { attachment_id, .. } => Some(attachment_id.clone()),
                ChatMessage::Text(_) => None,
            })
    }

    fn latest_invite_code(&self) -> Option<String> {
        self.messages
            .iter()
            .rev()
            .find_map(|message| match message {
                ChatMessage::Text(body) => body
                    .find("/INVITE:")
                    .map(|idx| body[idx..].trim().to_string()),
                ChatMessage::Attachment { .. } => None,
            })
    }

    fn request_invite(&self, server_addr: &str, room_credential: &str) {
        let owner_capability = self
            .owner_capability
            .as_deref()
            .expect("owner capability should exist for inviter");
        let request = build_local_invite_request_line(
            server_addr,
            &self.room_id,
            room_credential,
            owner_capability,
        );
        self.out_tx.send(request).expect("request should enqueue");
    }
}

fn free_port() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("ephemeral port should bind");
    listener
        .local_addr()
        .expect("local addr should exist")
        .port()
}

async fn spawn_server(password: &str) -> (u16, JoinHandle<()>) {
    let port = free_port();
    let password = password.to_string();
    let task = tokio::spawn(async move {
        let _ = rust_chat::server::app::run(port, password).await;
    });

    for _ in 0..40 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }

    (port, task)
}

async fn settle_clients(clients: &mut [&mut TestClient], rounds: usize) {
    for _ in 0..rounds {
        for client in &mut *clients {
            client.drain_once();
        }
        sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn clients_can_exchange_text_messages() -> Result<()> {
    let password = "integration-pass";
    let (port, server_task) = spawn_server(password).await;
    let server_addr = format!("127.0.0.1:{port}");

    let mut alice = TestClient::connect(
        &server_addr,
        password,
        "alice",
        "room-a",
        "room-key",
        "CREATE",
    )
    .await?;
    let mut bob =
        TestClient::connect(&server_addr, password, "bob", "room-a", "room-key", "JOIN").await?;

    alice.trigger_phase2_actions();
    bob.trigger_phase2_actions();
    settle_clients(&mut [&mut alice, &mut bob], 12).await;

    alice.out_tx.send("hello bob".to_string())?;
    settle_clients(&mut [&mut alice, &mut bob], 20).await;

    assert!(bob.has_text("hello bob"));

    alice.out_tx.send("//~``~//".to_string()).ok();
    bob.out_tx.send("//~``~//".to_string()).ok();
    server_task.abort();
    Ok(())
}

#[tokio::test]
async fn clients_can_exchange_small_attachments() -> Result<()> {
    let password = "integration-attachment-pass";
    let (port, server_task) = spawn_server(password).await;
    let server_addr = format!("127.0.0.1:{port}");

    let mut alice = TestClient::connect(
        &server_addr,
        password,
        "alice",
        "room-b",
        "room-key",
        "CREATE",
    )
    .await?;
    let mut bob =
        TestClient::connect(&server_addr, password, "bob", "room-b", "room-key", "JOIN").await?;

    alice.trigger_phase2_actions();
    bob.trigger_phase2_actions();
    settle_clients(&mut [&mut alice, &mut bob], 12).await;

    let payload = b"small attachment payload".to_vec();
    let temp_dir = tempfile::tempdir()?;
    let path: PathBuf = temp_dir.path().join("demo.txt");
    tokio::fs::write(&path, &payload).await?;
    alice.out_tx.send(path.to_string_lossy().to_string())?;
    settle_clients(&mut [&mut alice, &mut bob], 60).await;

    let attachment_id = bob
        .latest_attachment_id()
        .expect("receiver should have an attachment");
    let opened = bob.attachment_store.decrypt_attachment(&attachment_id)?;
    assert_eq!(opened, payload);

    alice.out_tx.send("//~``~//".to_string()).ok();
    bob.out_tx.send("//~``~//".to_string()).ok();
    server_task.abort();
    Ok(())
}

#[tokio::test]
async fn wrong_server_password_is_rejected() -> Result<()> {
    let password = "integration-right-pass";
    let (port, server_task) = spawn_server(password).await;
    let server_addr = format!("127.0.0.1:{port}");

    let result = TestClient::connect(
        &server_addr,
        "integration-wrong-pass",
        "alice",
        "room-c",
        "",
        "JOIN",
    )
    .await;
    assert!(result.is_err());

    server_task.abort();
    Ok(())
}

#[tokio::test]
async fn invite_code_can_be_used_once() -> Result<()> {
    let password = "integration-invite-pass";
    let room_credential = "invite-room-key";
    let (port, server_task) = spawn_server(password).await;
    let server_addr = format!("127.0.0.1:{port}");

    let mut alice = TestClient::connect(
        &server_addr,
        password,
        "alice",
        "room-invite",
        room_credential,
        "CREATE",
    )
    .await?;

    alice.trigger_phase2_actions();
    settle_clients(&mut [&mut alice], 10).await;

    alice.request_invite(&server_addr, room_credential);
    settle_clients(&mut [&mut alice], 20).await;

    let invite = alice
        .latest_invite_code()
        .expect("invite should be emitted to owner");

    let mut bob = TestClient::connect(&invite, "", "bob", "ignored", "", "JOIN").await?;
    bob.trigger_phase2_actions();
    settle_clients(&mut [&mut alice, &mut bob], 20).await;
    assert!(bob.members.iter().any(|member| member.nickname == "alice"));

    let second_use = handshake::connect_and_login(&invite, "carol").await;
    assert!(second_use.is_err());

    alice.out_tx.send("//~``~//".to_string()).ok();
    bob.out_tx.send("//~``~//".to_string()).ok();
    server_task.abort();
    Ok(())
}
