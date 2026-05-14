pub mod attachment;
pub mod invite;
pub mod line;
pub mod local_event;
pub mod member;

pub use attachment::{
    build_file_chunk2_line, build_file_manifest2_line, decrypt_file_chunk2,
    is_attachment_protocol_line, parse_attachment_frame, AttachmentFrame, AttachmentKind,
    AttachmentMeta, EncryptedAttachmentChunk,
};
pub use invite::{
    build_auth_challenge_line, build_auth_hello_line, build_auth_proof_line,
    build_invite_challenge_line, build_invite_error_line, build_invite_hello_line,
    build_invite_ok_line, build_invite_proof_line, build_invite_ready_line,
    build_invite_token_line, build_server_invite_request_line, build_session_ok_line,
    parse_auth_challenge_line, parse_auth_hello_line, parse_auth_proof_line,
    parse_invite_challenge_line, parse_invite_error_line, parse_invite_hello_line,
    parse_invite_ok_line, parse_invite_proof_line, parse_invite_ready_line,
    parse_invite_token_line, parse_server_invite_request_line, parse_session_ok_line,
    ServerInviteRequest, INVITE_TTL_SECS,
};
pub use line::{
    build_ack_line, build_epoch_commit_line, build_key_announce_line, build_rmsg_line,
    build_transport_packet_line, is_epoch_control_line, line_bytes, parse_ack_line,
    parse_display_body, parse_epoch_commit_line, parse_key_announce_line, parse_rmsg_line,
    parse_transport_packet_line,
};
pub use local_event::{
    build_local_attachment_send_line, build_local_echo_attachment_line, build_local_echo_text_line,
    build_local_invite_request_line, build_local_notice_line, build_local_transfer_begin_line,
    build_local_transfer_done_line, build_local_transfer_failed_line,
    build_local_transfer_progress_line, parse_local_attachment_send_line,
    parse_local_invite_request_line, parse_local_ui_event, LocalAttachmentSend, LocalInviteRequest,
    LocalUiEvent,
};
pub use member::{
    build_member_list_line, member_display_name, parse_member_list_line, MemberIdentity,
};

#[cfg(test)]
mod tests {
    use sha2::{Digest as ShaDigest, Sha256};

    use super::{
        build_ack_line, build_epoch_commit_line, build_file_chunk2_line, build_file_manifest2_line,
        build_invite_error_line, build_invite_token_line, build_key_announce_line,
        build_local_attachment_send_line, build_local_echo_attachment_line,
        build_local_echo_text_line, build_local_invite_request_line, build_member_list_line,
        build_rmsg_line, build_server_invite_request_line, build_transport_packet_line,
        parse_ack_line, parse_attachment_frame, parse_epoch_commit_line, parse_invite_error_line,
        parse_invite_token_line, parse_key_announce_line, parse_local_attachment_send_line,
        parse_local_invite_request_line, parse_local_ui_event, parse_member_list_line,
        parse_rmsg_line, parse_server_invite_request_line, parse_transport_packet_line,
        AttachmentFrame, AttachmentKind, LocalUiEvent, MemberIdentity,
    };
    use crate::crypto::{
        EncryptedMessage, EpochCommit, EpochEventType, MemberKeyAnnounce, SecureMessageHeader,
        SecureMessageType, WrappedEpochSecret,
    };

    #[test]
    fn transport_packet_round_trip() {
        let line = build_transport_packet_line("packet-1", "/RMSG payload");
        let (packet_id, payload) =
            parse_transport_packet_line(&line).expect("transport packet should parse");
        assert_eq!(packet_id, "packet-1");
        assert_eq!(payload, "/RMSG payload");
    }

    #[test]
    fn ack_round_trip() {
        let line = build_ack_line("packet-2");
        assert_eq!(parse_ack_line(&line), Some("packet-2"));
    }

    #[test]
    fn rmsg_round_trip() {
        let message = EncryptedMessage {
            header: SecureMessageHeader {
                version: 1,
                group_id: "room-a".to_string(),
                epoch: 7,
                sender_id: "alice".to_string(),
                msg_no: 3,
                msg_type: SecureMessageType::Text,
            },
            ciphertext: vec![1, 2, 3, 4],
        };

        let line = build_rmsg_line(&message).expect("rmsg line should build");
        let parsed = parse_rmsg_line::<EncryptedMessage>(&line).expect("rmsg line should parse");
        assert_eq!(parsed, message);
    }

    #[test]
    fn key_announce_round_trip() {
        let announce = MemberKeyAnnounce {
            group_id: "room-a".to_string(),
            epoch: 5,
            member_id: "alice".to_string(),
            x25519_public: vec![7; 32],
            nonce: vec![1; 16],
            mac: vec![2; 32],
        };

        let line = build_key_announce_line(&announce).expect("announce line should build");
        let parsed = parse_key_announce_line::<MemberKeyAnnounce>(&line)
            .expect("announce line should parse");
        assert_eq!(parsed, announce);
    }

    #[test]
    fn epoch_commit_round_trip() {
        let commit = EpochCommit {
            group_id: "room-a".to_string(),
            old_epoch: 1,
            new_epoch: 2,
            event_type: EpochEventType::Join,
            affected_member_id: "bob".to_string(),
            old_roster_hash: "old".to_string(),
            new_roster_hash: "new".to_string(),
            proposer_id: "alice".to_string(),
            proposer_attempt: 0,
            wrapped_secrets: vec![WrappedEpochSecret {
                recipient_id: "alice".to_string(),
                proposer_x25519_pub: vec![9; 32],
                nonce: vec![3; 12],
                ciphertext: vec![1, 2, 3],
            }],
        };

        let line = build_epoch_commit_line(&commit).expect("commit line should build");
        let parsed =
            parse_epoch_commit_line::<EpochCommit>(&line).expect("commit line should parse");
        assert_eq!(parsed, commit);
    }

    #[test]
    fn member_list_round_trip_supports_unicode() {
        let members = vec![
            MemberIdentity {
                member_id: "alice-id".to_string(),
                nickname: "Alice Smith".to_string(),
            },
            MemberIdentity {
                member_id: "bob-id".to_string(),
                nickname: "小明🙂".to_string(),
            },
        ];

        let line = build_member_list_line(&members);
        let parsed = parse_member_list_line(&line).expect("member list should parse");
        assert_eq!(parsed, members);
    }

    #[test]
    fn invite_request_token_error_round_trip() {
        let request_line = build_server_invite_request_line("req-1", "Public", "owner-cap", "blob");
        let request =
            parse_server_invite_request_line(&request_line).expect("invite request should parse");
        assert_eq!(request.request_id, "req-1");
        assert_eq!(request.room_id, "Public");
        assert_eq!(request.owner_capability, "owner-cap");
        assert_eq!(request.blob_b64, "blob");

        let token_line = build_invite_token_line("req-1", "token-b64", 123);
        let token = parse_invite_token_line(&token_line).expect("invite token should parse");
        assert_eq!(token, ("req-1".to_string(), "token-b64".to_string(), 123));

        let error_line = build_invite_error_line("req-1", "InviteNotAllowed");
        let error = parse_invite_error_line(&error_line).expect("invite error should parse");
        assert_eq!(error, ("req-1".to_string(), "InviteNotAllowed".to_string()));
    }

    #[test]
    fn local_ui_event_round_trip() {
        let echo_text = build_local_echo_text_line("hello local");
        assert!(matches!(
            parse_local_ui_event(&echo_text),
            Some(LocalUiEvent::EchoText { body }) if body == "hello local"
        ));

        let echo_attachment =
            build_local_echo_attachment_line("att-1", "demo.txt", 42, AttachmentKind::File);
        assert!(matches!(
            parse_local_ui_event(&echo_attachment),
            Some(LocalUiEvent::EchoAttachment {
                attachment_id,
                file_name,
                total_size,
                kind: AttachmentKind::File,
            }) if attachment_id == "att-1" && file_name == "demo.txt" && total_size == 42
        ));

        let invite_request =
            build_local_invite_request_line("127.0.0.1:6655", "Public", "", "owner-cap-1");
        let parsed = parse_local_invite_request_line(&invite_request)
            .expect("local invite request should parse");
        assert_eq!(parsed.server_addr, "127.0.0.1:6655");
        assert_eq!(parsed.room_id, "Public");
        assert_eq!(parsed.room_credential, "");
        assert_eq!(parsed.owner_capability, "owner-cap-1");

        let local_attachment =
            build_local_attachment_send_line("clipboard.png", AttachmentKind::Image, b"png-bytes");
        let parsed_attachment = parse_local_attachment_send_line(&local_attachment)
            .expect("local attachment should parse");
        assert_eq!(parsed_attachment.file_name, "clipboard.png");
        assert_eq!(parsed_attachment.kind, AttachmentKind::Image);
        assert_eq!(parsed_attachment.bytes, b"png-bytes");
    }

    #[test]
    fn attachment_manifest_and_chunk_round_trip() {
        let payload = b"phase4 attachment chunk";
        let transfer_id = "transfer-v2";
        let file_key = [7u8; 32];
        let nonce_base = [9u8; 8];
        let sha256_hex = hex::encode(Sha256::digest(payload));

        let manifest = build_file_manifest2_line(
            "room-a",
            7,
            "alice-id",
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
        let chunk = build_file_chunk2_line(
            "room-a",
            7,
            "alice-id",
            transfer_id,
            0,
            1,
            payload,
            &file_key,
            &nonce_base,
        )
        .expect("chunk should build");

        let parsed_manifest = parse_attachment_frame(&manifest).expect("manifest should parse");
        let parsed_chunk = parse_attachment_frame(&chunk).expect("chunk should parse");

        match parsed_manifest {
            AttachmentFrame::Meta(meta) => {
                assert_eq!(meta.group_id, "room-a");
                assert_eq!(meta.epoch, 7);
                assert_eq!(meta.sender_id, "alice-id");
                assert_eq!(meta.transfer_id, transfer_id);
                assert_eq!(meta.file_name, "demo.txt");
                assert_eq!(meta.total_size, payload.len() as u64);
            }
            AttachmentFrame::EncryptedChunk(_) => panic!("expected manifest frame"),
        }

        match parsed_chunk {
            AttachmentFrame::EncryptedChunk(chunk) => {
                assert_eq!(chunk.transfer_id, transfer_id);
                assert_eq!(chunk.index, 0);
            }
            AttachmentFrame::Meta(_) => panic!("expected chunk frame"),
        }
    }

    #[test]
    fn malformed_lines_return_none() {
        assert!(parse_transport_packet_line("/PKT only-id").is_none());
        assert!(parse_rmsg_line::<EncryptedMessage>("/RMSG not-base64").is_none());
        assert!(parse_key_announce_line::<MemberKeyAnnounce>("/KEY_ANNOUNCE no").is_none());
        assert!(parse_epoch_commit_line::<EpochCommit>("/EPOCH_COMMIT no").is_none());
        assert!(parse_member_list_line("/member_list broken").is_none());
        assert!(parse_server_invite_request_line("/INVITE_REQUEST only").is_none());
        assert!(parse_local_ui_event("/LOCALTX PROGRESS broken").is_none());
        assert!(parse_attachment_frame("/FILECHUNK2 broken").is_none());
    }
}
