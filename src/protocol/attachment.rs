use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use serde::{Deserialize, Serialize};

const FILE_CHUNK2_AAD_LABEL: &[u8] = b"rust-chat filechunk2 v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachmentKind {
    Image,
    File,
}

impl AttachmentKind {
    pub fn as_protocol_tag(self) -> &'static str {
        match self {
            Self::Image => "img",
            Self::File => "file",
        }
    }

    pub fn from_protocol_tag(tag: &str) -> Option<Self> {
        match tag {
            "img" => Some(Self::Image),
            "file" => Some(Self::File),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AttachmentMeta {
    pub group_id: String,
    pub epoch: u64,
    pub sender_id: String,
    pub transfer_id: String,
    pub kind: AttachmentKind,
    pub file_name: String,
    pub total_size: u64,
    pub total_chunks: usize,
    pub sha256_hex: String,
    pub file_key: [u8; 32],
    pub nonce_base: [u8; 8],
}

#[derive(Debug, Clone)]
pub struct EncryptedAttachmentChunk {
    pub transfer_id: String,
    pub index: usize,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum AttachmentFrame {
    Meta(AttachmentMeta),
    EncryptedChunk(EncryptedAttachmentChunk),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileManifestV2 {
    group_id: String,
    epoch: u64,
    sender_id: String,
    transfer_id: String,
    kind: String,
    file_name: String,
    total_size: u64,
    total_chunks: usize,
    sha256_hex: String,
    file_key: Vec<u8>,
    nonce_base: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileChunk2Wire {
    transfer_id: String,
    index: usize,
    ciphertext: Vec<u8>,
}

pub fn is_attachment_protocol_line(line: &str) -> bool {
    line.starts_with("/FILEMANIFEST2 ") || line.starts_with("/FILECHUNK2 ")
}

pub fn parse_attachment_frame(body: &str) -> Option<AttachmentFrame> {
    let mut parts = body.split_whitespace();
    match parts.next()? {
        "/FILEMANIFEST2" => parse_file_manifest2_payload(parts.next()?).map(AttachmentFrame::Meta),
        "/FILECHUNK2" => {
            parse_file_chunk2_payload(parts.next()?).map(AttachmentFrame::EncryptedChunk)
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_file_manifest2_line(
    group_id: &str,
    epoch: u64,
    sender_id: &str,
    transfer_id: &str,
    kind: AttachmentKind,
    file_name: &str,
    total_size: u64,
    total_chunks: usize,
    sha256_hex: &str,
    file_key: &[u8; 32],
    nonce_base: &[u8; 8],
) -> Result<String> {
    let manifest = FileManifestV2 {
        group_id: group_id.to_string(),
        epoch,
        sender_id: sender_id.to_string(),
        transfer_id: transfer_id.to_string(),
        kind: kind.as_protocol_tag().to_string(),
        file_name: file_name.to_string(),
        total_size,
        total_chunks,
        sha256_hex: sha256_hex.to_string(),
        file_key: file_key.to_vec(),
        nonce_base: nonce_base.to_vec(),
    };
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&manifest)?);
    Ok(format!("/FILEMANIFEST2 {encoded}"))
}

pub fn build_file_chunk2_line(
    group_id: &str,
    epoch: u64,
    sender_id: &str,
    transfer_id: &str,
    index: usize,
    total_chunks: usize,
    chunk: &[u8],
    file_key: &[u8; 32],
    nonce_base: &[u8; 8],
) -> Result<String> {
    let nonce = file_chunk2_nonce(nonce_base, index)?;
    let aad = file_chunk2_aad(group_id, epoch, sender_id, transfer_id, index, total_chunks);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(file_key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: chunk,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("Attachment chunk encryption failed"))?;
    let wire = FileChunk2Wire {
        transfer_id: transfer_id.to_string(),
        index,
        ciphertext,
    };
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&wire)?);
    Ok(format!("/FILECHUNK2 {encoded}"))
}

pub fn decrypt_file_chunk2(
    chunk: &EncryptedAttachmentChunk,
    meta: &AttachmentMeta,
) -> Result<Vec<u8>> {
    let nonce = file_chunk2_nonce(&meta.nonce_base, chunk.index)?;
    let aad = file_chunk2_aad(
        &meta.group_id,
        meta.epoch,
        &meta.sender_id,
        &chunk.transfer_id,
        chunk.index,
        meta.total_chunks,
    );
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&meta.file_key));
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: chunk.ciphertext.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("Attachment chunk authentication failed"))
}

fn parse_file_manifest2_payload(payload: &str) -> Option<AttachmentMeta> {
    let manifest: FileManifestV2 =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload.trim()).ok()?).ok()?;
    let file_key: [u8; 32] = manifest.file_key.try_into().ok()?;
    let nonce_base: [u8; 8] = manifest.nonce_base.try_into().ok()?;
    Some(AttachmentMeta {
        group_id: manifest.group_id,
        epoch: manifest.epoch,
        sender_id: manifest.sender_id,
        transfer_id: manifest.transfer_id,
        kind: AttachmentKind::from_protocol_tag(&manifest.kind)?,
        file_name: manifest.file_name,
        total_size: manifest.total_size,
        total_chunks: manifest.total_chunks,
        sha256_hex: manifest.sha256_hex,
        file_key,
        nonce_base,
    })
}

fn parse_file_chunk2_payload(payload: &str) -> Option<EncryptedAttachmentChunk> {
    let wire: FileChunk2Wire =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload.trim()).ok()?).ok()?;
    Some(EncryptedAttachmentChunk {
        transfer_id: wire.transfer_id,
        index: wire.index,
        ciphertext: wire.ciphertext,
    })
}

fn file_chunk2_nonce(nonce_base: &[u8; 8], index: usize) -> Result<[u8; 12]> {
    let index = u32::try_from(index).map_err(|_| anyhow!("Attachment chunk index too large"))?;
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(nonce_base);
    nonce[8..].copy_from_slice(&index.to_be_bytes());
    Ok(nonce)
}

fn file_chunk2_aad(
    group_id: &str,
    epoch: u64,
    sender_id: &str,
    transfer_id: &str,
    index: usize,
    total_chunks: usize,
) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(FILE_CHUNK2_AAD_LABEL);
    aad.extend_from_slice(&(group_id.len() as u64).to_be_bytes());
    aad.extend_from_slice(group_id.as_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(&(sender_id.len() as u64).to_be_bytes());
    aad.extend_from_slice(sender_id.as_bytes());
    aad.extend_from_slice(&(transfer_id.len() as u64).to_be_bytes());
    aad.extend_from_slice(transfer_id.as_bytes());
    aad.extend_from_slice(&(index as u64).to_be_bytes());
    aad.extend_from_slice(&(total_chunks as u64).to_be_bytes());
    aad
}
