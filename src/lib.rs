// lib.rs

pub mod app_config;
pub mod client;

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use crate::client::attachment_store::AttachmentStore;
    use crate::client::crypto::{
        decrypt_message, encrypt_message, proposer_order, GroupCryptoState, RoomCryptoState,
        SecureMessageType,
    };
    use crate::client::notifier;
    use crate::client::receiver::AttachmentKind;
    use crate::client::receiver::{drain_messages, ChatMessage, ReceiverState, TransferUiState};
    use crate::client::utils::{
        build_ack_line, build_epoch_commit_line, build_file_chunk2_line,
        build_file_manifest2_line, build_local_echo_attachment_line, build_local_echo_text_line,
        build_local_invite_request_line, build_member_list_line, build_rmsg_line,
        build_transport_packet_line, create_invitation, create_invite_blob, normalize_clipboard_rgba,
        open_invite_blob, parse_ack_line, parse_clipboard_file_paths, parse_invitation,
        parse_local_invite_request_line, parse_local_ui_event, parse_rmsg_line,
        parse_transport_packet_line, LocalUiEvent, MemberIdentity,
    };

    #[test]
    fn test_notify() {
        notifier::notify();
    }

    #[test]
    fn test_transport_packet_round_trip() {
        let line = build_transport_packet_line("packet-1", "/RMSG payload");
        let (packet_id, payload) =
            parse_transport_packet_line(&line).expect("transport packet should parse");
        assert_eq!(packet_id, "packet-1");
        assert_eq!(payload, "/RMSG payload");
    }

    #[test]
    fn test_ack_line_round_trip() {
        let line = build_ack_line("packet-2");
        assert_eq!(parse_ack_line(&line), Some("packet-2"));
    }

    #[test]
    fn test_rmsg_line_round_trip() {
        let room_crypto = RoomCryptoState::from_room_credential("room-a", "room-password");
        let mut alice = GroupCryptoState::new_single_epoch(
            "room-a",
            "alice-id",
            "alice",
            0,
            room_crypto.placeholder_epoch_secret(),
            room_crypto.room_auth_key(),
        )
        .expect("group crypto should initialize");
        alice
            .replace_members([
                ("alice-id".to_string(), "alice".to_string()),
                ("bob-id".to_string(), "bob".to_string()),
            ])
            .expect("member roster should update");

        let encrypted = encrypt_message(&mut alice, SecureMessageType::Text, b"hello secure room")
            .expect("sender encryption should succeed");
        let line = build_rmsg_line(&encrypted).expect("rmsg line should build");
        let parsed = parse_rmsg_line(&line).expect("rmsg line should parse");
        assert_eq!(parsed, encrypted);
    }

    #[test]
    fn test_secure_message_round_trip() {
        let room_crypto = RoomCryptoState::from_room_credential("room-a", "room-password");
        let mut alice = GroupCryptoState::new_single_epoch(
            "room-a",
            "alice-id",
            "alice",
            0,
            room_crypto.placeholder_epoch_secret(),
            room_crypto.room_auth_key(),
        )
        .expect("alice group crypto should initialize");
        let mut bob = GroupCryptoState::new_single_epoch(
            "room-a",
            "bob-id",
            "bob",
            0,
            room_crypto.placeholder_epoch_secret(),
            room_crypto.room_auth_key(),
        )
        .expect("bob group crypto should initialize");
        let roster = [
            ("alice-id".to_string(), "alice".to_string()),
            ("bob-id".to_string(), "bob".to_string()),
        ];
        alice
            .replace_members(roster.clone())
            .expect("alice roster should update");
        bob.replace_members(roster)
            .expect("bob roster should update");

        let encrypted = encrypt_message(&mut alice, SecureMessageType::Text, b"phase1 hello")
            .expect("encrypt should succeed");
        let decrypted = decrypt_message(&mut bob, &encrypted).expect("decrypt should succeed");
        assert_eq!(decrypted.plaintext, b"phase1 hello");
        assert_eq!(alice.my_sender_chain.msg_no, 1);
        assert_eq!(
            bob.recv_chains
                .get("alice-id")
                .map(|chain| chain.next_msg_no),
            Some(1)
        );
    }

    #[test]
    fn test_filechunk2_is_processed_outside_rmsg() {
        let room_crypto = RoomCryptoState::from_room_credential("room-a", "room-password");
        let mut alice = GroupCryptoState::new_single_epoch(
            "room-a",
            "alice-id",
            "alice",
            0,
            room_crypto.placeholder_epoch_secret(),
            room_crypto.room_auth_key(),
        )
        .expect("alice should initialize");
        let mut bob = GroupCryptoState::new_single_epoch(
            "room-a",
            "bob-id",
            "bob",
            0,
            room_crypto.placeholder_epoch_secret(),
            room_crypto.room_auth_key(),
        )
        .expect("bob should initialize");
        let roster = [
            ("alice-id".to_string(), "alice".to_string()),
            ("bob-id".to_string(), "bob".to_string()),
        ];
        alice
            .replace_members(roster.clone())
            .expect("alice roster should update");
        bob.replace_members(roster)
            .expect("bob roster should update");

        let payload = b"phase4 attachment chunk";
        let transfer_id = "transfer-v2";
        let file_key = [7u8; 32];
        let nonce_base = [9u8; 8];
        let sha256_hex = hex::encode(sha2::Sha256::digest(payload));
        let manifest = build_file_manifest2_line(
            transfer_id,
            AttachmentKind::File,
            "demo.txt",
            payload.len() as u64,
            1,
            &sha256_hex,
            &file_key,
            &nonce_base,
        )
        .expect("manifest should build");
        let encrypted_manifest = encrypt_message(
            &mut alice,
            SecureMessageType::FileManifest,
            manifest.as_bytes(),
        )
        .expect("manifest should encrypt");
        let manifest_line = build_rmsg_line(&encrypted_manifest).expect("rmsg should build");
        let chunk_line = build_file_chunk2_line(transfer_id, 0, payload, &file_key, &nonce_base)
            .expect("chunk should build");

        let group_crypto = Arc::new(Mutex::new(bob));
        let (net_tx, mut net_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        net_tx
            .send(format!("[alice] {manifest_line}"))
            .expect("manifest should enqueue");
        net_tx
            .send(format!("[alice] {chunk_line}"))
            .expect("chunk should enqueue");

        let temp_dir = tempfile::Builder::new()
            .prefix("rust-chat-filechunk2")
            .tempdir()
            .expect("tempdir should build");
        let attachment_store = AttachmentStore::new_in(temp_dir.path().to_path_buf())
            .expect("attachment store should initialize");
        let mut messages = Vec::<ChatMessage>::new();
        let mut members = Vec::<MemberIdentity>::new();
        let mut receiver_state = ReceiverState::default();
        let mut transfer_ui_state = TransferUiState::default();

        let _ = drain_messages(
            &mut net_rx,
            &mut messages,
            "bob",
            &group_crypto,
            &attachment_store,
            &mut members,
            &mut receiver_state,
            &mut transfer_ui_state,
        );

        assert!(matches!(
            messages.last(),
            Some(ChatMessage::Attachment { name, size, .. })
                if name == "demo.txt" && *size == payload.len() as u64
        ));
        assert!(transfer_ui_state
            .lines(1)
            .first()
            .is_some_and(|line| line.contains("done")));
    }

    #[test]
    fn test_tampered_secure_message_does_not_advance_recv_chain() {
        let room_crypto = RoomCryptoState::from_room_credential("room-a", "room-password");
        let mut alice = GroupCryptoState::new_single_epoch(
            "room-a",
            "alice-id",
            "alice",
            0,
            room_crypto.placeholder_epoch_secret(),
            room_crypto.room_auth_key(),
        )
        .expect("alice group crypto should initialize");
        let mut bob = GroupCryptoState::new_single_epoch(
            "room-a",
            "bob-id",
            "bob",
            0,
            room_crypto.placeholder_epoch_secret(),
            room_crypto.room_auth_key(),
        )
        .expect("bob group crypto should initialize");
        let roster = [
            ("alice-id".to_string(), "alice".to_string()),
            ("bob-id".to_string(), "bob".to_string()),
        ];
        alice
            .replace_members(roster.clone())
            .expect("alice roster should update");
        bob.replace_members(roster)
            .expect("bob roster should update");

        let mut encrypted = encrypt_message(&mut alice, SecureMessageType::Text, b"phase1 hello")
            .expect("encrypt should succeed");
        encrypted.ciphertext[0] ^= 0x01;

        assert!(decrypt_message(&mut bob, &encrypted).is_err());
        assert_eq!(
            bob.recv_chains
                .get("alice-id")
                .map(|chain| chain.next_msg_no),
            Some(0)
        );
    }

    #[test]
    fn test_key_announce_updates_member_public_key() {
        let room_crypto = RoomCryptoState::from_room_credential("room-a", "room-password");
        let mut alice = GroupCryptoState::new_single_epoch(
            "room-a",
            "alice-id",
            "alice",
            0,
            room_crypto.placeholder_epoch_secret(),
            room_crypto.room_auth_key(),
        )
        .expect("alice should initialize");
        let mut bob = GroupCryptoState::new_single_epoch(
            "room-a",
            "bob-id",
            "bob",
            0,
            room_crypto.placeholder_epoch_secret(),
            room_crypto.room_auth_key(),
        )
        .expect("bob should initialize");
        alice
            .replace_members([
                ("alice-id".to_string(), "alice".to_string()),
                ("bob-id".to_string(), "bob".to_string()),
            ])
            .expect("alice roster should update");
        bob.replace_members([
            ("alice-id".to_string(), "alice".to_string()),
            ("bob-id".to_string(), "bob".to_string()),
        ])
        .expect("bob roster should update");

        let announce = alice.local_key_announce();
        assert!(bob
            .apply_key_announce(&announce)
            .expect("announce should apply"));
        assert_eq!(
            bob.members
                .get("alice-id")
                .and_then(|member| member.x25519_public.clone()),
            Some(alice.current_x25519_public().to_vec())
        );
    }

    #[test]
    fn test_join_rekey_commit_rotates_epoch_and_unblocks_new_member() {
        let room_crypto = RoomCryptoState::from_room_credential("room-a", "room-password");
        let mut alice = GroupCryptoState::new_single_epoch(
            "room-a",
            "alice-id",
            "alice",
            0,
            room_crypto.placeholder_epoch_secret(),
            room_crypto.room_auth_key(),
        )
        .expect("alice should initialize");
        let mut bob = GroupCryptoState::new_single_epoch(
            "room-a",
            "bob-id",
            "bob",
            0,
            room_crypto.placeholder_epoch_secret(),
            room_crypto.room_auth_key(),
        )
        .expect("bob should initialize");
        let mut charlie = GroupCryptoState::new_single_epoch(
            "room-a",
            "charlie-id",
            "charlie",
            0,
            room_crypto.placeholder_epoch_secret(),
            room_crypto.room_auth_key(),
        )
        .expect("charlie should initialize");

        let initial_roster = [
            ("alice-id".to_string(), "alice".to_string()),
            ("bob-id".to_string(), "bob".to_string()),
        ];
        alice
            .replace_members(initial_roster.clone())
            .expect("alice roster should update");
        bob.replace_members(initial_roster)
            .expect("bob roster should update");
        alice.pending_transition = None;
        bob.pending_transition = None;

        let alice_announce = alice.local_key_announce();
        let bob_announce = bob.local_key_announce();
        bob.apply_key_announce(&alice_announce)
            .expect("bob should learn alice key");
        alice
            .apply_key_announce(&bob_announce)
            .expect("alice should learn bob key");

        let joined_roster = [
            ("alice-id".to_string(), "alice".to_string()),
            ("bob-id".to_string(), "bob".to_string()),
            ("charlie-id".to_string(), "charlie".to_string()),
        ];
        alice
            .replace_members(joined_roster.clone())
            .expect("alice joined roster should update");
        bob.replace_members(joined_roster.clone())
            .expect("bob joined roster should update");
        charlie
            .replace_members(joined_roster)
            .expect("charlie joined roster should update");

        let charlie_announce = charlie.local_key_announce();
        let alice_announce = alice.local_key_announce();
        let bob_announce = bob.local_key_announce();

        alice
            .apply_key_announce(&bob_announce)
            .expect("alice should refresh bob key");
        alice
            .apply_key_announce(&charlie_announce)
            .expect("alice should learn charlie key");
        bob.apply_key_announce(&alice_announce)
            .expect("bob should refresh alice key");
        bob.apply_key_announce(&charlie_announce)
            .expect("bob should learn charlie key");
        charlie
            .apply_key_announce(&alice_announce)
            .expect("charlie should learn alice key");
        charlie
            .apply_key_announce(&bob_announce)
            .expect("charlie should learn bob key");

        let proposer = proposer_order(
            "room-a",
            0,
            crate::client::crypto::EpochEventType::Join,
            "charlie-id",
            &["alice-id".to_string(), "bob-id".to_string()],
        )[0]
        .clone();
        let commit = if proposer == "alice-id" {
            alice
                .build_join_epoch_commit()
                .expect("alice build should succeed")
                .expect("alice should be proposer")
        } else {
            bob.build_join_epoch_commit()
                .expect("bob build should succeed")
                .expect("bob should be proposer")
        };

        if proposer == "alice-id" {
            assert!(alice
                .apply_epoch_commit(&commit)
                .expect("alice apply should succeed"));
        } else {
            assert!(bob
                .apply_epoch_commit(&commit)
                .expect("bob apply should succeed"));
        }
        if proposer == "alice-id" {
            assert!(bob
                .apply_epoch_commit(&commit)
                .expect("bob apply should succeed"));
        } else {
            assert!(alice
                .apply_epoch_commit(&commit)
                .expect("alice apply should succeed"));
        }
        assert!(charlie
            .apply_epoch_commit(&commit)
            .expect("charlie apply should succeed"));

        assert_eq!(alice.epoch, 1);
        assert_eq!(bob.epoch, 1);
        assert_eq!(charlie.epoch, 1);

        let encrypted = encrypt_message(&mut alice, SecureMessageType::Text, b"epoch one hello")
            .expect("epoch one encrypt should succeed");
        let decrypted_bob =
            decrypt_message(&mut bob, &encrypted).expect("bob should decrypt epoch one");
        let decrypted_charlie =
            decrypt_message(&mut charlie, &encrypted).expect("charlie should decrypt epoch one");
        assert_eq!(decrypted_bob.plaintext, b"epoch one hello");
        assert_eq!(decrypted_charlie.plaintext, b"epoch one hello");
    }

    #[test]
    fn test_third_joiner_can_accept_commit_from_existing_later_epoch() {
        let room_crypto = RoomCryptoState::from_room_credential("room-a", "room-password");
        let mut alice = GroupCryptoState::new_single_epoch(
            "room-a",
            "alice-id",
            "alice",
            0,
            room_crypto.placeholder_epoch_secret(),
            room_crypto.room_auth_key(),
        )
        .expect("alice should initialize");
        let mut bob = GroupCryptoState::new_single_epoch(
            "room-a",
            "bob-id",
            "bob",
            0,
            room_crypto.placeholder_epoch_secret(),
            room_crypto.room_auth_key(),
        )
        .expect("bob should initialize");

        alice
            .replace_members([("alice-id".to_string(), "alice".to_string())])
            .expect("alice initial roster should update");

        let first_join_roster = [
            ("alice-id".to_string(), "alice".to_string()),
            ("bob-id".to_string(), "bob".to_string()),
        ];
        alice
            .replace_members(first_join_roster.clone())
            .expect("alice should see bob join");
        bob.replace_members(first_join_roster)
            .expect("bob should see joined roster");

        let bob_announce = bob.local_key_announce();
        alice
            .apply_key_announce(&bob_announce)
            .expect("alice should learn bob key");
        let first_commit = alice
            .build_join_epoch_commit()
            .expect("alice should build bob join commit")
            .expect("alice is the only old member proposer");
        assert!(alice
            .apply_epoch_commit(&first_commit)
            .expect("alice should apply bob join commit"));
        assert!(bob
            .apply_epoch_commit(&first_commit)
            .expect("bob should apply first join commit"));
        assert_eq!(alice.epoch, 1);
        assert_eq!(bob.epoch, 1);

        let mut charlie = GroupCryptoState::new_single_epoch(
            "room-a",
            "charlie-id",
            "charlie",
            0,
            room_crypto.placeholder_epoch_secret(),
            room_crypto.room_auth_key(),
        )
        .expect("charlie should initialize");

        let third_join_roster = [
            ("alice-id".to_string(), "alice".to_string()),
            ("bob-id".to_string(), "bob".to_string()),
            ("charlie-id".to_string(), "charlie".to_string()),
        ];
        alice
            .replace_members(third_join_roster.clone())
            .expect("alice should see charlie join");
        bob.replace_members(third_join_roster.clone())
            .expect("bob should see charlie join");
        charlie
            .replace_members(third_join_roster)
            .expect("charlie should see joined roster");

        let alice_announce = alice.local_key_announce();
        let bob_announce = bob.local_key_announce();
        let charlie_announce = charlie.local_key_announce();
        alice
            .apply_key_announce(&bob_announce)
            .expect("alice should know bob key");
        alice
            .apply_key_announce(&charlie_announce)
            .expect("alice should learn charlie key");
        bob.apply_key_announce(&alice_announce)
            .expect("bob should know alice key");
        bob.apply_key_announce(&charlie_announce)
            .expect("bob should learn charlie key");
        charlie
            .apply_key_announce(&alice_announce)
            .expect("charlie should learn alice key");
        charlie
            .apply_key_announce(&bob_announce)
            .expect("charlie should learn bob key");

        let proposer = proposer_order(
            "room-a",
            1,
            crate::client::crypto::EpochEventType::Join,
            "charlie-id",
            &["alice-id".to_string(), "bob-id".to_string()],
        )[0]
        .clone();
        let third_commit = if proposer == "alice-id" {
            alice
                .build_join_epoch_commit()
                .expect("alice build should succeed")
                .expect("alice should be proposer")
        } else {
            bob.build_join_epoch_commit()
                .expect("bob build should succeed")
                .expect("bob should be proposer")
        };

        if proposer == "alice-id" {
            assert!(alice
                .apply_epoch_commit(&third_commit)
                .expect("alice should apply charlie join commit"));
            assert!(bob
                .apply_epoch_commit(&third_commit)
                .expect("bob should apply charlie join commit"));
        } else {
            assert!(bob
                .apply_epoch_commit(&third_commit)
                .expect("bob should apply charlie join commit"));
            assert!(alice
                .apply_epoch_commit(&third_commit)
                .expect("alice should apply charlie join commit"));
        }
        assert!(charlie
            .apply_epoch_commit(&third_commit)
            .expect("charlie should accept commit from existing epoch 1"));

        assert_eq!(alice.epoch, 2);
        assert_eq!(bob.epoch, 2);
        assert_eq!(charlie.epoch, 2);

        let encrypted = encrypt_message(&mut alice, SecureMessageType::Text, b"epoch two hello")
            .expect("alice should encrypt at epoch two");
        let decrypted =
            decrypt_message(&mut charlie, &encrypted).expect("charlie should decrypt epoch two");
        assert_eq!(decrypted.plaintext, b"epoch two hello");
    }

    #[test]
    fn test_late_old_epoch_message_after_join_rekey_is_still_accepted() {
        let room_crypto = RoomCryptoState::from_room_credential("room-a", "room-password");
        let mut alice = GroupCryptoState::new_single_epoch(
            "room-a",
            "alice-id",
            "alice",
            0,
            room_crypto.placeholder_epoch_secret(),
            room_crypto.room_auth_key(),
        )
        .expect("alice should initialize");
        let mut bob = GroupCryptoState::new_single_epoch(
            "room-a",
            "bob-id",
            "bob",
            0,
            room_crypto.placeholder_epoch_secret(),
            room_crypto.room_auth_key(),
        )
        .expect("bob should initialize");
        let mut charlie = GroupCryptoState::new_single_epoch(
            "room-a",
            "charlie-id",
            "charlie",
            0,
            room_crypto.placeholder_epoch_secret(),
            room_crypto.room_auth_key(),
        )
        .expect("charlie should initialize");

        let initial_roster = [
            ("alice-id".to_string(), "alice".to_string()),
            ("bob-id".to_string(), "bob".to_string()),
        ];
        alice
            .replace_members(initial_roster.clone())
            .expect("alice roster should update");
        bob.replace_members(initial_roster)
            .expect("bob roster should update");
        alice.pending_transition = None;
        bob.pending_transition = None;

        let alice_announce = alice.local_key_announce();
        let bob_announce = bob.local_key_announce();
        bob.apply_key_announce(&alice_announce)
            .expect("bob should learn alice key");
        alice
            .apply_key_announce(&bob_announce)
            .expect("alice should learn bob key");

        let joined_roster = [
            ("alice-id".to_string(), "alice".to_string()),
            ("bob-id".to_string(), "bob".to_string()),
            ("charlie-id".to_string(), "charlie".to_string()),
        ];
        alice
            .replace_members(joined_roster.clone())
            .expect("alice joined roster should update");
        bob.replace_members(joined_roster.clone())
            .expect("bob joined roster should update");
        charlie
            .replace_members(joined_roster)
            .expect("charlie joined roster should update");

        let charlie_announce = charlie.local_key_announce();
        let alice_announce = alice.local_key_announce();
        let bob_announce = bob.local_key_announce();
        alice
            .apply_key_announce(&bob_announce)
            .expect("alice should refresh bob key");
        alice
            .apply_key_announce(&charlie_announce)
            .expect("alice should learn charlie key");
        bob.apply_key_announce(&alice_announce)
            .expect("bob should refresh alice key");
        bob.apply_key_announce(&charlie_announce)
            .expect("bob should learn charlie key");
        charlie
            .apply_key_announce(&alice_announce)
            .expect("charlie should learn alice key");
        charlie
            .apply_key_announce(&bob_announce)
            .expect("charlie should learn bob key");

        let proposer = proposer_order(
            "room-a",
            0,
            crate::client::crypto::EpochEventType::Join,
            "charlie-id",
            &["alice-id".to_string(), "bob-id".to_string()],
        )[0]
        .clone();
        let commit = if proposer == "alice-id" {
            alice
                .build_join_epoch_commit()
                .expect("alice build should succeed")
                .expect("alice should be proposer")
        } else {
            bob.build_join_epoch_commit()
                .expect("bob build should succeed")
                .expect("bob should be proposer")
        };

        if proposer == "alice-id" {
            assert!(alice
                .apply_epoch_commit(&commit)
                .expect("alice apply should succeed"));
            assert!(bob
                .apply_epoch_commit(&commit)
                .expect("bob apply should succeed"));
        } else {
            assert!(bob
                .apply_epoch_commit(&commit)
                .expect("bob apply should succeed"));
            assert!(alice
                .apply_epoch_commit(&commit)
                .expect("alice apply should succeed"));
        }

        let late_old_epoch = encrypt_message(
            &mut charlie,
            SecureMessageType::Text,
            b"late old epoch from charlie",
        )
        .expect("charlie should still encrypt under epoch zero");
        let decrypted_alice = decrypt_message(&mut alice, &late_old_epoch)
            .expect("alice should accept late old epoch");
        let decrypted_bob =
            decrypt_message(&mut bob, &late_old_epoch).expect("bob should accept late old epoch");
        assert_eq!(decrypted_alice.plaintext, b"late old epoch from charlie");
        assert_eq!(decrypted_bob.plaintext, b"late old epoch from charlie");

        assert!(charlie
            .apply_epoch_commit(&commit)
            .expect("charlie apply should succeed"));
        assert_eq!(charlie.epoch, 1);
    }

    #[test]
    fn test_joiner_retries_epoch_commit_that_arrives_before_member_list() {
        let room_crypto = RoomCryptoState::from_room_credential("room-a", "room-password");
        let mut alice = GroupCryptoState::new_single_epoch(
            "room-a",
            "alice-id",
            "alice",
            0,
            room_crypto.placeholder_epoch_secret(),
            room_crypto.room_auth_key(),
        )
        .expect("alice should initialize");
        let mut bob = GroupCryptoState::new_single_epoch(
            "room-a",
            "bob-id",
            "bob",
            0,
            room_crypto.placeholder_epoch_secret(),
            room_crypto.room_auth_key(),
        )
        .expect("bob should initialize");
        let charlie = GroupCryptoState::new_single_epoch(
            "room-a",
            "charlie-id",
            "charlie",
            0,
            room_crypto.placeholder_epoch_secret(),
            room_crypto.room_auth_key(),
        )
        .expect("charlie should initialize");

        let initial_roster = [
            ("alice-id".to_string(), "alice".to_string()),
            ("bob-id".to_string(), "bob".to_string()),
        ];
        alice
            .replace_members(initial_roster.clone())
            .expect("alice roster should update");
        bob.replace_members(initial_roster)
            .expect("bob roster should update");
        alice.pending_transition = None;
        bob.pending_transition = None;

        let joined_roster = [
            ("alice-id".to_string(), "alice".to_string()),
            ("bob-id".to_string(), "bob".to_string()),
            ("charlie-id".to_string(), "charlie".to_string()),
        ];
        alice
            .replace_members(joined_roster.clone())
            .expect("alice joined roster should update");
        bob.replace_members(joined_roster)
            .expect("bob joined roster should update");

        let alice_announce = alice.local_key_announce();
        let bob_announce = bob.local_key_announce();
        let charlie_announce = charlie.local_key_announce();
        alice
            .apply_key_announce(&bob_announce)
            .expect("alice should know bob key");
        alice
            .apply_key_announce(&charlie_announce)
            .expect("alice should know charlie key");
        bob.apply_key_announce(&alice_announce)
            .expect("bob should know alice key");
        bob.apply_key_announce(&charlie_announce)
            .expect("bob should know charlie key");

        let proposer = proposer_order(
            "room-a",
            0,
            crate::client::crypto::EpochEventType::Join,
            "charlie-id",
            &["alice-id".to_string(), "bob-id".to_string()],
        )[0]
        .clone();
        let commit = if proposer == "alice-id" {
            alice
                .build_join_epoch_commit()
                .expect("alice build should succeed")
                .expect("alice should be proposer")
        } else {
            bob.build_join_epoch_commit()
                .expect("bob build should succeed")
                .expect("bob should be proposer")
        };
        let commit_line = build_epoch_commit_line(&commit).expect("commit line should build");
        let member_list_line = build_member_list_line(&[
            MemberIdentity {
                member_id: "alice-id".to_string(),
                nickname: "alice".to_string(),
            },
            MemberIdentity {
                member_id: "bob-id".to_string(),
                nickname: "bob".to_string(),
            },
            MemberIdentity {
                member_id: "charlie-id".to_string(),
                nickname: "charlie".to_string(),
            },
        ]);

        let group_crypto = Arc::new(Mutex::new(charlie));
        let (net_tx, mut net_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        net_tx
            .send(format!("[alice] {commit_line}"))
            .expect("commit should enqueue");

        let temp_dir = tempfile::Builder::new()
            .prefix("rust-chat-commit-order")
            .tempdir()
            .expect("tempdir should build");
        let attachment_store = AttachmentStore::new_in(temp_dir.path().to_path_buf())
            .expect("attachment store should initialize");
        let mut messages = Vec::<ChatMessage>::new();
        let mut members = Vec::<MemberIdentity>::new();
        let mut receiver_state = ReceiverState::default();
        let mut transfer_ui_state = TransferUiState::default();

        let first = drain_messages(
            &mut net_rx,
            &mut messages,
            "charlie",
            &group_crypto,
            &attachment_store,
            &mut members,
            &mut receiver_state,
            &mut transfer_ui_state,
        );
        assert!(!first.member_list_changed);
        assert_eq!(group_crypto.lock().expect("lock should succeed").epoch, 0);

        net_tx
            .send(member_list_line)
            .expect("member list should enqueue");
        let second = drain_messages(
            &mut net_rx,
            &mut messages,
            "charlie",
            &group_crypto,
            &attachment_store,
            &mut members,
            &mut receiver_state,
            &mut transfer_ui_state,
        );
        assert!(second.member_list_changed);
        assert_eq!(group_crypto.lock().expect("lock should succeed").epoch, 1);
    }

    #[test]
    fn test_invite_round_trip() {
        let (blob_b64, blob_key_b64) =
            create_invite_blob("room-a".to_string(), "room-password".to_string())
                .expect("invite blob should build");
        let invite = create_invitation(
            "127.0.0.1:6655".to_string(),
            "invite-token-123".to_string(),
            blob_key_b64.clone(),
        )
        .expect("invite should build");

        let (server, token, parsed_blob_key) =
            parse_invitation(&invite).expect("invite should parse");
        let (room_id, room_credential) =
            open_invite_blob(&blob_b64, &parsed_blob_key).expect("invite blob should open");
        assert_eq!(server, "127.0.0.1:6655");
        assert_eq!(room_id, "room-a");
        assert_eq!(room_credential, "room-password");
        assert_eq!(token, "invite-token-123");
        assert_eq!(parsed_blob_key, blob_key_b64);
    }

    #[test]
    fn test_local_invite_request_round_trip_with_empty_room_key() {
        let line = build_local_invite_request_line("127.0.0.1:6655", "Public", "", "owner-cap-1");
        let parsed = parse_local_invite_request_line(&line).expect("request should parse");
        assert_eq!(parsed.server_addr, "127.0.0.1:6655");
        assert_eq!(parsed.room_id, "Public");
        assert_eq!(parsed.room_credential, "");
        assert_eq!(parsed.owner_capability, "owner-cap-1");
    }

    #[test]
    fn test_normalize_clipboard_rgba_fills_missing_alpha() {
        let raw = vec![10, 20, 30, 0, 40, 50, 60, 0];

        let normalized =
            normalize_clipboard_rgba(&raw, 2, 1).expect("clipboard rgba should normalize");
        assert_eq!(normalized, vec![10, 20, 30, 255, 40, 50, 60, 255,]);
    }

    #[test]
    fn test_parse_clipboard_file_paths_rejects_mixed_lines() {
        let temp_path = std::env::temp_dir().join("rust_chat_clipboard_test.txt");
        std::fs::write(&temp_path, b"ok").expect("temp file should be created");

        let mixed = format!("{}\nnot-a-real-path", temp_path.display());
        assert!(parse_clipboard_file_paths(&mixed).is_none());

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_parse_clipboard_file_paths_accepts_all_valid_absolute_paths() {
        let path_a = std::env::temp_dir().join("rust_chat_clipboard_test_a.txt");
        let path_b = std::env::temp_dir().join("rust_chat_clipboard_test_b.txt");
        std::fs::write(&path_a, b"a").expect("temp file A should be created");
        std::fs::write(&path_b, b"b").expect("temp file B should be created");

        let joined = format!("\"{}\"\n{}", path_a.display(), path_b.display());
        let parsed = parse_clipboard_file_paths(&joined).expect("all valid paths should parse");
        assert_eq!(parsed, vec![path_a.clone(), path_b.clone()]);

        let _ = std::fs::remove_file(path_a);
        let _ = std::fs::remove_file(path_b);
    }

    #[test]
    fn test_local_echo_text_round_trip() {
        let line = build_local_echo_text_line("hello local echo");
        assert!(matches!(
            parse_local_ui_event(&line),
            Some(LocalUiEvent::EchoText { body }) if body == "hello local echo"
        ));
    }

    #[test]
    fn test_local_echo_attachment_round_trip() {
        let line =
            build_local_echo_attachment_line("attachment-1", "demo.txt", 42, AttachmentKind::File);
        assert!(matches!(
            parse_local_ui_event(&line),
            Some(LocalUiEvent::EchoAttachment {
                attachment_id,
                file_name,
                total_size,
                kind: AttachmentKind::File,
            }) if attachment_id == "attachment-1" && file_name == "demo.txt" && total_size == 42
        ));
    }
}
