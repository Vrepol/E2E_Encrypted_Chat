use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use mistv::{
    attachments::store::AttachmentStore,
    client::{
        handshake, network,
        receiver::{drain_messages, ChatMessage, ReceiverState, TransferUiState},
        session::{ConnectedSession, SharedGroupCrypto},
    },
    protocol::{
        build_epoch_commit_line, build_key_announce_line, build_local_invite_request_line,
        MemberIdentity,
    },
    transport::packet::send_transport_payload_now,
};
use tempfile::TempDir;
use tokio::{
    io::{BufReader, Lines},
    net::tcp::OwnedReadHalf,
};
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

struct LogOnlyClient {
    writer: tokio::net::tcp::OwnedWriteHalf,
    transport: std::sync::Arc<std::sync::Mutex<mistv::crypto::TransportCrypto>>,
    _lines: Lines<BufReader<OwnedReadHalf>>,
}

impl LogOnlyClient {
    async fn connect(
        server_addr: &str,
        password: &str,
        nickname: &str,
        room_id: &str,
        room_credential: &str,
        action: &'static str,
    ) -> Result<Self> {
        let ConnectedSession {
            lines,
            writer,
            transport,
            ..
        } = handshake::connect_for_test(
            server_addr,
            password,
            nickname,
            room_id,
            room_credential,
            action,
        )
        .await?;

        Ok(Self {
            writer,
            transport,
            _lines: lines,
        })
    }

    async fn send_secure_log_line(&mut self, packet_id: &str, note: &str) -> Result<()> {
        let payload = format!("/RMSG synthetic::{note}");
        send_transport_payload_now(&mut self.writer, packet_id, &payload, &self.transport).await
    }

    async fn shutdown(&mut self) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        self.writer.shutdown().await?;
        Ok(())
    }
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
            let local_commit = guard.build_pending_epoch_commit().ok().flatten();
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
                if guard.apply_epoch_commit(&commit).ok() == Some(true) {
                    if let Ok(line) = build_key_announce_line(&guard.local_key_announce()) {
                        self.out_tx.send(line).ok();
                    }
                }
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

async fn spawn_server(password: &str) -> (u16, JoinHandle<()>) {
    spawn_server_with_log(password, None).await
}

async fn spawn_server_with_log(password: &str, log_path: Option<PathBuf>) -> (u16, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral listener should bind");
    let port = listener
        .local_addr()
        .expect("local addr should exist")
        .port();
    let password = password.to_string();
    let task = tokio::spawn(async move {
        let result = match log_path {
            Some(path) => {
                mistv::server::app::run_with_listener_and_log_file(listener, password, path).await
            }
            None => mistv::server::app::run_with_listener(listener, password).await,
        };
        let _ = result;
    });

    let mut ready = false;
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            ready = true;
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "server on port {port} did not become ready");

    (port, task)
}

fn test_log_path(name: &str) -> PathBuf {
    Path::new("target").join("test-logs").join(name)
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

#[tokio::test]
async fn three_clients_chat_saves_server_log() -> Result<()> {
    let password = "integration-three-pass";
    let log_path = test_log_path("three-person-chat-server.log");
    let (port, server_task) = spawn_server_with_log(password, Some(log_path.clone())).await;
    let server_addr = format!("127.0.0.1:{port}");

    let mut alice = LogOnlyClient::connect(
        &server_addr,
        password,
        "alice",
        "room-trio",
        "room-trio-key",
        "CREATE",
    )
    .await?;
    let mut bob = LogOnlyClient::connect(
        &server_addr,
        password,
        "bob",
        "room-trio",
        "room-trio-key",
        "JOIN",
    )
    .await?;
    let mut carol = LogOnlyClient::connect(
        &server_addr,
        password,
        "carol",
        "room-trio",
        "room-trio-key",
        "JOIN",
    )
    .await?;

    sleep(Duration::from_millis(300)).await;

    alice
        .send_secure_log_line("msg-alice-1", "alice:早上好，今天先测一下三人群聊链路。")
        .await?;
    sleep(Duration::from_millis(150)).await;
    bob.send_secure_log_line(
        "msg-bob-1",
        "bob:收到，我这边回一条短消息，确认广播顺序正常。",
    )
    .await?;
    sleep(Duration::from_millis(150)).await;
    carol
        .send_secure_log_line(
            "msg-carol-1",
            "carol:我会重点看服务器日志里的 join、relay 和 member_list。",
        )
        .await?;
    sleep(Duration::from_millis(150)).await;
    alice
        .send_secure_log_line(
            "msg-alice-2",
            "alice:第二轮我再发一句，方便后面按时间线排查。",
        )
        .await?;

    alice.shutdown().await.ok();
    bob.shutdown().await.ok();
    carol.shutdown().await.ok();
    sleep(Duration::from_millis(300)).await;
    server_task.abort();

    let log = tokio::fs::read_to_string(&log_path).await?;
    assert!(log.contains("listening addr=127.0.0.1:"));
    assert!(log.contains("room=room-trio"));
    assert!(log.contains("nickname=alice"));
    assert!(log.contains("nickname=bob"));
    assert!(log.contains("nickname=carol"));
    assert!(log.contains("broadcast member_list room=room-trio members=alice, bob, carol"));
    assert!(log.contains("broadcast from=alice priority=High secure_text_frame"));
    assert!(log.contains("broadcast from=bob priority=High secure_text_frame"));
    assert!(log.contains("broadcast from=carol priority=High secure_text_frame"));

    Ok(())
}
