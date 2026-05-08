// lib.rs

pub mod client;
pub mod app_config;

#[cfg(test)]
mod tests {
    use crate::client::crypto::{open, seal, set_room_key};
    use crate::client::notifier;
    use crate::client::receiver::AttachmentKind;
    use crate::client::utils::{
        build_ack_line, build_attachment_frames_from_bytes, build_local_invite_request_line,
        create_invite_blob, normalize_clipboard_rgba, open_invite_blob,
        parse_clipboard_file_paths,
        build_transport_packet_line, create_invitation, parse_ack_line, parse_attachment_frame,
        parse_invitation, parse_local_invite_request_line, parse_transport_packet_line,
        AttachmentFrame,
    };

    #[test]
    fn test_notify() {
        notifier::notify();
    }

    #[test]
    fn test_attachment_frames_round_trip() {
        let payload = b"chunked attachment payload for rust chat";
        let frames = build_attachment_frames_from_bytes("demo.txt", payload, AttachmentKind::File)
            .expect("attachment frames should build");

        assert!(matches!(
            parse_attachment_frame(&frames[0]),
            Some(AttachmentFrame::Meta(_))
        ));

        let mut rebuilt = Vec::new();
        for frame in frames.iter().skip(1) {
            match parse_attachment_frame(frame) {
                Some(AttachmentFrame::Chunk(chunk)) => rebuilt.extend_from_slice(&chunk.data),
                other => panic!("unexpected frame: {other:?}"),
            }
        }

        assert_eq!(rebuilt, payload);
    }

    #[test]
    fn test_transport_packet_round_trip() {
        let line = build_transport_packet_line("packet-1", "ENC:payload");
        let (packet_id, payload) =
            parse_transport_packet_line(&line).expect("transport packet should parse");
        assert_eq!(packet_id, "packet-1");
        assert_eq!(payload, "ENC:payload");
    }

    #[test]
    fn test_ack_line_round_trip() {
        let line = build_ack_line("packet-2");
        assert_eq!(parse_ack_line(&line), Some("packet-2"));
    }

    #[test]
    fn test_room_cipher_round_trip() {
        set_room_key("00112233445566778899aabbccddeeff");
        let cipher = seal("hello room");
        assert!(cipher.starts_with("ENC:"));
        assert_eq!(open(&cipher).as_deref(), Some("hello room"));
    }

    #[test]
    fn test_invite_round_trip() {
        let server_hash = [7u8; 32];
        let (blob_b64, blob_key_b64) = create_invite_blob(
            server_hash,
            "room-a".to_string(),
            "room-password".to_string(),
        )
        .expect("invite blob should build");
        let invite = create_invitation(
            "127.0.0.1:6655".to_string(),
            "invite-token-123".to_string(),
            blob_key_b64.clone(),
        )
        .expect("invite should build");

        let (server, token, parsed_blob_key) =
            parse_invitation(&invite).expect("invite should parse");
        let (parsed_hash, room_id, room_key) =
            open_invite_blob(&blob_b64, &parsed_blob_key).expect("invite blob should open");
        assert_eq!(server, "127.0.0.1:6655");
        assert_eq!(parsed_hash, server_hash);
        assert_eq!(room_id, "room-a");
        assert_eq!(room_key, "room-password");
        assert_eq!(token, "invite-token-123");
        assert_eq!(parsed_blob_key, blob_key_b64);
    }

    #[test]
    fn test_local_invite_request_round_trip_with_empty_room_key() {
        let line = build_local_invite_request_line(
            "127.0.0.1:6655",
            [9u8; 32],
            "Public",
            "",
            "owner-cap-1",
        );
        let parsed = parse_local_invite_request_line(&line).expect("request should parse");
        assert_eq!(parsed.server_addr, "127.0.0.1:6655");
        assert_eq!(parsed.server_pwd_hash, [9u8; 32]);
        assert_eq!(parsed.room_id, "Public");
        assert_eq!(parsed.room_key, "");
        assert_eq!(parsed.owner_capability, "owner-cap-1");
    }

    #[test]
    fn test_normalize_clipboard_rgba_fills_missing_alpha() {
        let raw = vec![
            10, 20, 30, 0,
            40, 50, 60, 0,
        ];

        let normalized = normalize_clipboard_rgba(&raw, 2, 1).expect("clipboard rgba should normalize");
        assert_eq!(
            normalized,
            vec![
                10, 20, 30, 255,
                40, 50, 60, 255,
            ]
        );
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
}
