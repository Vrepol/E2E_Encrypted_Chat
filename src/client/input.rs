use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};

use crate::protocol::{
    is_attachment_protocol_line, parse_local_attachment_send_line, AttachmentKind,
};

#[derive(Debug, Clone)]
pub enum OutgoingPayload {
    Text(String),
    AttachmentPath(PathBuf),
    AttachmentMemory {
        file_name: String,
        bytes: Vec<u8>,
        kind: AttachmentKind,
    },
}

pub fn classify_outgoing_input(msg: &str) -> Result<OutgoingPayload> {
    if let Some(local_attachment) = parse_local_attachment_send_line(msg) {
        return Ok(OutgoingPayload::AttachmentMemory {
            file_name: local_attachment.file_name,
            bytes: local_attachment.bytes,
            kind: local_attachment.kind,
        });
    }

    if is_attachment_protocol_line(msg) {
        return Ok(OutgoingPayload::Text(msg.to_string()));
    }

    if let Some(path) = explicit_send_path(msg)? {
        return Ok(OutgoingPayload::AttachmentPath(path));
    }

    let trimmed = msg.trim();
    let path = Path::new(trimmed);
    if path.is_file() {
        return Ok(OutgoingPayload::AttachmentPath(path.to_path_buf()));
    }

    Ok(OutgoingPayload::Text(msg.to_string()))
}

fn explicit_send_path(msg: &str) -> Result<Option<PathBuf>> {
    let Some(rest) = msg.strip_prefix("/send ") else {
        return Ok(None);
    };

    let raw = rest.trim();
    if raw.is_empty() {
        return Err(anyhow!("Usage: /send <path>"));
    }

    let normalized = strip_optional_quotes(raw);
    let path = PathBuf::from(normalized);
    if !path.is_file() {
        return Err(anyhow!("Attachment not found: {}", path.display()));
    }

    Ok(Some(path))
}

pub(crate) fn strip_optional_quotes(input: &str) -> &str {
    if input.len() >= 2 && input.starts_with('"') && input.ends_with('"') {
        &input[1..input.len() - 1]
    } else {
        input
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_outgoing_input, OutgoingPayload};
    use crate::protocol::{build_local_attachment_send_line, AttachmentKind};
    #[test]
    fn plain_text_stays_text() {
        assert!(matches!(
            classify_outgoing_input("hello").expect("classification should succeed"),
            OutgoingPayload::Text(body) if body == "hello"
        ));
    }

    #[test]
    fn missing_path_in_send_command_is_rejected() {
        assert!(classify_outgoing_input("/send ").is_err());
    }

    #[test]
    fn explicit_send_path_becomes_attachment() {
        let dir = tempfile::tempdir().expect("tempdir should build");
        let path = dir.path().join("demo.txt");
        std::fs::write(&path, b"demo").expect("file should be created");
        let command = format!("/send {}", path.display());

        assert!(matches!(
            classify_outgoing_input(&command).expect("classification should succeed"),
            OutgoingPayload::AttachmentPath(parsed) if parsed == path
        ));
    }

    #[test]
    fn direct_existing_path_becomes_attachment() {
        let dir = tempfile::tempdir().expect("tempdir should build");
        let path = dir.path().join("direct.bin");
        std::fs::write(&path, b"demo").expect("file should be created");

        assert!(matches!(
            classify_outgoing_input(&path.to_string_lossy()).expect("classification should succeed"),
            OutgoingPayload::AttachmentPath(parsed) if parsed == path
        ));
    }

    #[test]
    fn missing_path_falls_back_to_text() {
        let missing = std::env::temp_dir().join("mistv_missing_path_for_test.txt");
        let text = missing.to_string_lossy().to_string();

        assert!(matches!(
            classify_outgoing_input(&text).expect("classification should succeed"),
            OutgoingPayload::Text(body) if body == text
        ));
    }

    #[test]
    fn local_memory_attachment_becomes_attachment_payload() {
        let line =
            build_local_attachment_send_line("clipboard.png", AttachmentKind::Image, b"png-bytes");

        assert!(matches!(
            classify_outgoing_input(&line).expect("classification should succeed"),
            OutgoingPayload::AttachmentMemory {
                file_name,
                bytes,
                kind: AttachmentKind::Image,
            } if file_name == "clipboard.png" && bytes == b"png-bytes"
        ));
    }
}
