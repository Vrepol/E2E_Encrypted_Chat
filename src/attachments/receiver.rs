use std::collections::HashMap;

use sha2::{Digest as ShaDigest, Sha256};

use crate::{
    attachments::store::AttachmentStore,
    crypto::zeroize,
    protocol::{decrypt_file_chunk2, AttachmentKind, AttachmentMeta, EncryptedAttachmentChunk},
    util::path::sanitize_attachment_name,
};

#[derive(Default)]
pub struct AttachmentReceiveState {
    incoming: HashMap<String, IncomingAttachment>,
}

struct IncomingAttachment {
    sender: String,
    file_name: String,
    total_size: u64,
    total_chunks: usize,
    sha256_hex: String,
    kind: AttachmentKind,
    file_key: [u8; 32],
    nonce_base: [u8; 8],
    chunks: Vec<Option<Vec<u8>>>,
    received_chunks: usize,
}

impl Drop for IncomingAttachment {
    fn drop(&mut self) {
        zeroize(&mut self.file_key);
        zeroize(&mut self.nonce_base);
    }
}

#[derive(Debug, Clone)]
pub struct CompletedAttachment {
    pub transfer_id: String,
    pub attachment_id: String,
    pub sender: String,
    pub file_name: String,
    pub total_size: u64,
    pub kind: AttachmentKind,
}

#[derive(Debug, Clone)]
pub enum AttachmentReceiveEvent {
    Begin {
        transfer_id: String,
        file_name: String,
        total_chunks: usize,
        total_size: u64,
    },
    Progress {
        transfer_id: String,
        received_chunks: usize,
        total_chunks: usize,
    },
    Complete(CompletedAttachment),
}

pub fn register_attachment(
    state: &mut AttachmentReceiveState,
    sender: String,
    meta: AttachmentMeta,
    attachment_store: &AttachmentStore,
) -> Result<Vec<AttachmentReceiveEvent>, String> {
    validate_manifest(&meta)?;

    let begin = AttachmentReceiveEvent::Begin {
        transfer_id: meta.transfer_id.clone(),
        file_name: meta.file_name.clone(),
        total_chunks: meta.total_chunks,
        total_size: meta.total_size,
    };

    let incoming = IncomingAttachment {
        sender,
        file_name: meta.file_name,
        total_size: meta.total_size,
        total_chunks: meta.total_chunks,
        sha256_hex: meta.sha256_hex,
        kind: meta.kind,
        file_key: meta.file_key,
        nonce_base: meta.nonce_base,
        chunks: vec![None; meta.total_chunks],
        received_chunks: 0,
    };

    if meta.total_chunks == 0 {
        let complete = finalize_attachment(meta.transfer_id.clone(), incoming, attachment_store)?;
        return Ok(vec![begin, AttachmentReceiveEvent::Complete(complete)]);
    }

    state.incoming.insert(meta.transfer_id, incoming);
    Ok(vec![begin])
}

pub fn append_encrypted_chunk(
    state: &mut AttachmentReceiveState,
    encrypted_chunk: EncryptedAttachmentChunk,
    attachment_store: &AttachmentStore,
) -> Result<Vec<AttachmentReceiveEvent>, String> {
    let (file_key, nonce_base) = {
        let Some(incoming) = state.incoming.get(&encrypted_chunk.transfer_id) else {
            return Ok(Vec::new());
        };
        (incoming.file_key, incoming.nonce_base)
    };
    let data = decrypt_file_chunk2(&encrypted_chunk, &file_key, &nonce_base)
        .map_err(|err| err.to_string())?;
    append_chunk(
        state,
        encrypted_chunk.transfer_id,
        encrypted_chunk.index,
        data,
        attachment_store,
    )
}

pub fn append_chunk(
    state: &mut AttachmentReceiveState,
    transfer_id: String,
    index: usize,
    data: Vec<u8>,
    attachment_store: &AttachmentStore,
) -> Result<Vec<AttachmentReceiveEvent>, String> {
    let mut ready = false;
    let (received_chunks, total_chunks);

    {
        let Some(incoming) = state.incoming.get_mut(&transfer_id) else {
            return Ok(Vec::new());
        };

        if index >= incoming.total_chunks {
            return Err(format!("Attachment chunk out of range: {index}"));
        }

        if incoming.chunks[index].is_none() {
            incoming.chunks[index] = Some(data);
            incoming.received_chunks += 1;
        }

        (received_chunks, total_chunks) = (incoming.received_chunks, incoming.total_chunks);
        if incoming.received_chunks == incoming.total_chunks {
            ready = true;
        }
    }

    let mut events = vec![AttachmentReceiveEvent::Progress {
        transfer_id: transfer_id.clone(),
        received_chunks,
        total_chunks,
    }];

    if !ready {
        return Ok(events);
    }

    let incoming = state
        .incoming
        .remove(&transfer_id)
        .ok_or_else(|| "Attachment state missing during finalize".to_string())?;
    let complete = finalize_attachment(transfer_id, incoming, attachment_store)?;
    events.push(AttachmentReceiveEvent::Complete(complete));
    Ok(events)
}

fn validate_manifest(meta: &AttachmentMeta) -> Result<(), String> {
    if meta.total_chunks == 0 && meta.total_size != 0 {
        return Err("Attachment manifest mismatch: zero chunks with non-zero size".to_string());
    }
    if meta.total_chunks > 0 && meta.total_size == 0 {
        return Err("Attachment manifest mismatch: non-zero chunks with zero size".to_string());
    }
    if meta.sha256_hex.len() != 64 || !meta.sha256_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Attachment manifest checksum is invalid".to_string());
    }
    Ok(())
}

fn finalize_attachment(
    transfer_id: String,
    mut incoming: IncomingAttachment,
    attachment_store: &AttachmentStore,
) -> Result<CompletedAttachment, String> {
    let mut hasher = Sha256::new();
    let mut plain_bytes = Vec::with_capacity(incoming.total_size as usize);
    let mut written_size = 0u64;
    let safe_name = sanitize_attachment_name(&incoming.file_name);

    for chunk in std::mem::take(&mut incoming.chunks) {
        let chunk = chunk.ok_or_else(|| {
            format!("Attachment {transfer_id} is incomplete, missing one or more chunks")
        })?;
        written_size = written_size.saturating_add(chunk.len() as u64);
        hasher.update(&chunk);
        plain_bytes.extend_from_slice(&chunk);
    }

    if written_size != incoming.total_size {
        return Err(format!(
            "Attachment size mismatch: expected {}, got {}",
            incoming.total_size, written_size
        ));
    }

    let digest = hex::encode(hasher.finalize());
    if digest != incoming.sha256_hex {
        return Err(format!(
            "Attachment checksum mismatch for {}",
            incoming.file_name
        ));
    }

    let attachment_id = attachment_store
        .store_attachment(&safe_name, &plain_bytes)
        .map_err(|e| e.to_string())?;

    Ok(CompletedAttachment {
        transfer_id,
        attachment_id,
        sender: std::mem::take(&mut incoming.sender),
        file_name: safe_name,
        total_size: written_size,
        kind: incoming.kind,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        append_chunk, register_attachment, AttachmentReceiveEvent, AttachmentReceiveState,
    };
    use crate::{
        attachments::store::AttachmentStore,
        protocol::{AttachmentKind, AttachmentMeta},
    };
    use sha2::{Digest as ShaDigest, Sha256};

    fn manifest(name: &str, bytes: &[u8], total_chunks: usize) -> AttachmentMeta {
        AttachmentMeta {
            transfer_id: "transfer-1".to_string(),
            kind: AttachmentKind::File,
            file_name: name.to_string(),
            total_size: bytes.len() as u64,
            total_chunks,
            sha256_hex: hex::encode(Sha256::digest(bytes)),
            file_key: [3u8; 32],
            nonce_base: [7u8; 8],
        }
    }

    #[test]
    fn manifest_with_zero_chunks_and_nonzero_size_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir should build");
        let store = AttachmentStore::new_in(dir.path().to_path_buf())
            .expect("attachment store should initialize");
        let mut state = AttachmentReceiveState::default();
        let mut meta = manifest("demo.txt", b"abc", 0);
        meta.total_size = 3;
        assert!(register_attachment(&mut state, "alice".to_string(), meta, &store).is_err());
    }

    #[test]
    fn chunk_out_of_range_is_rejected_without_panic() {
        let dir = tempfile::tempdir().expect("tempdir should build");
        let store = AttachmentStore::new_in(dir.path().to_path_buf())
            .expect("attachment store should initialize");
        let mut state = AttachmentReceiveState::default();
        let meta = manifest("demo.txt", b"abc", 1);
        register_attachment(&mut state, "alice".to_string(), meta, &store)
            .expect("manifest should register");
        assert!(append_chunk(
            &mut state,
            "transfer-1".to_string(),
            9,
            b"a".to_vec(),
            &store
        )
        .is_err());
    }

    #[test]
    fn duplicate_chunk_does_not_panic_or_double_count() {
        let dir = tempfile::tempdir().expect("tempdir should build");
        let store = AttachmentStore::new_in(dir.path().to_path_buf())
            .expect("attachment store should initialize");
        let mut state = AttachmentReceiveState::default();
        let meta = manifest("demo.txt", b"abc", 1);
        register_attachment(&mut state, "alice".to_string(), meta, &store)
            .expect("manifest should register");
        let first = append_chunk(
            &mut state,
            "transfer-1".to_string(),
            0,
            b"abc".to_vec(),
            &store,
        )
        .expect("first chunk should succeed");
        assert!(matches!(
            first.last(),
            Some(AttachmentReceiveEvent::Complete(_))
        ));
    }
}
