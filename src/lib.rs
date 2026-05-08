// lib.rs

pub mod client;

#[cfg(test)]
mod tests {
    use crate::client::notifier;
    use crate::client::receiver::AttachmentKind;
    use crate::client::utils::{
        build_ack_line, build_attachment_frames_from_bytes, build_transport_packet_line,
        parse_ack_line, parse_attachment_frame, parse_transport_packet_line, AttachmentFrame,
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
}
