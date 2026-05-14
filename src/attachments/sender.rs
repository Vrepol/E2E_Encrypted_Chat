use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex},
};

use anyhow::{anyhow, Result};
use rand::RngCore;
use sha2::{Digest as ShaDigest, Sha256};
use tokio::{
    fs::File,
    io::AsyncReadExt,
    net::tcp::OwnedWriteHalf,
    sync::mpsc::UnboundedSender,
    task::JoinHandle,
    time::{Duration, Instant},
};

use crate::{
    attachments::{kind::infer_attachment_kind, store::AttachmentStore},
    crypto::{encrypt_message, zeroize, GroupCryptoState, SecureMessageType, TransportCrypto},
    protocol::{
        build_file_chunk2_line, build_file_manifest2_line, build_local_echo_attachment_line,
        build_local_notice_line, build_local_transfer_begin_line, build_local_transfer_done_line,
        build_local_transfer_failed_line, build_local_transfer_progress_line, build_rmsg_line,
        AttachmentKind,
    },
    transport::packet::{
        send_transport_payload_now, AckRegistry, PACKET_ACK_TIMEOUT_MS, PACKET_RETRY_LIMIT,
    },
    util::path::file_name_or_default,
};

pub const ATTACHMENT_CHUNK_SIZE: usize = 32 * 1024;
pub const ATTACHMENT_WINDOW_SIZE: usize = 3;

#[derive(Clone)]
struct AttachmentContext {
    group_id: String,
    epoch: u64,
    sender_id: String,
}

pub struct AttachmentJob {
    pub source: AttachmentSource,
    pub source_label: String,
    pub transfer_id: String,
    pub file_name: String,
    pub kind: AttachmentKind,
    pub total_size: u64,
    pub total_chunks: usize,
    pub sha256_hex: String,
    pub next_chunk_index: usize,
    pub acked_chunks: usize,
    pub meta_sent: bool,
    pub meta_packet_id: String,
    pub manifest_plain_line: Option<String>,
    pub manifest_secure_line: Option<String>,
    manifest_context: Option<AttachmentContext>,
    pub meta_attempts: usize,
    pub meta_last_sent_at: Option<Instant>,
    pub file_key: [u8; 32],
    pub nonce_base: [u8; 8],
    pub in_flight: Vec<InFlightChunk>,
}

impl Drop for AttachmentJob {
    fn drop(&mut self) {
        zeroize(&mut self.file_key);
        zeroize(&mut self.nonce_base);
    }
}

pub struct InFlightChunk {
    pub packet_id: String,
    pub chunk_line: String,
    pub chunk_index: usize,
    pub attempts: usize,
    pub last_sent_at: Instant,
}

pub enum AttachmentSource {
    File { path: PathBuf, file: File },
    Memory { bytes: Vec<u8>, offset: usize },
}

impl AttachmentSource {
    async fn read_chunk(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            Self::File { file, .. } => Ok(file.read(buf).await?),
            Self::Memory { bytes, offset } => {
                let remaining = bytes.len().saturating_sub(*offset);
                let read = remaining.min(buf.len());
                buf[..read].copy_from_slice(&bytes[*offset..*offset + read]);
                *offset += read;
                Ok(read)
            }
        }
    }

    async fn bytes_for_echo(&self) -> Result<Vec<u8>> {
        match self {
            Self::File { path, .. } => Ok(tokio::fs::read(path).await?),
            Self::Memory { bytes, .. } => Ok(bytes.clone()),
        }
    }
}

pub enum QueuedAttachment {
    Path(PathBuf),
    Memory {
        file_name: String,
        bytes: Vec<u8>,
        kind: AttachmentKind,
    },
}

impl QueuedAttachment {
    fn label(&self) -> String {
        match self {
            Self::Path(path) => path.display().to_string(),
            Self::Memory { file_name, .. } => file_name.clone(),
        }
    }
}

pub struct PreparingUpload {
    pub label: String,
    pub task: JoinHandle<Result<AttachmentJob>>,
}

#[allow(clippy::too_many_arguments)]
pub async fn pump_attachment_upload(
    writer: &mut OwnedWriteHalf,
    net_tx: &UnboundedSender<String>,
    group_crypto: &Arc<StdMutex<GroupCryptoState>>,
    transport: &Arc<StdMutex<TransportCrypto>>,
    ack_registry: Arc<AckRegistry>,
    pending_uploads: &mut VecDeque<QueuedAttachment>,
    preparing_upload: &mut Option<PreparingUpload>,
    active_upload: &mut Option<AttachmentJob>,
    attachment_store: Arc<AttachmentStore>,
) {
    if active_upload.is_none() {
        if let Some(preparing) = preparing_upload.as_ref() {
            if !preparing.task.is_finished() {
                return;
            }
        }

        if let Some(preparing) = preparing_upload.take() {
            match preparing.task.await {
                Ok(Ok(job)) => {
                    net_tx
                        .send(build_local_transfer_begin_line(
                            &job.transfer_id,
                            &job.file_name,
                            job.total_chunks,
                            job.total_size,
                        ))
                        .ok();
                    *active_upload = Some(job);
                }
                Ok(Err(err)) => {
                    net_tx
                        .send(build_local_notice_line(&format!(
                            "附件初始化失败 {}: {err}",
                            preparing.label
                        )))
                        .ok();
                }
                Err(err) => {
                    net_tx
                        .send(build_local_notice_line(&format!(
                            "附件初始化任务失败 {}: {err}",
                            preparing.label
                        )))
                        .ok();
                }
            }
            if active_upload.is_none() {
                return;
            }
        }

        let Some(item) = pending_uploads.pop_front() else {
            return;
        };
        let label = item.label();
        *preparing_upload = Some(PreparingUpload {
            label,
            task: tokio::spawn(async move { initialize_attachment_job(item).await }),
        });
        return;
    }

    let Some(job) = active_upload.as_mut() else {
        return;
    };

    if !job.meta_sent {
        match process_attachment_meta(writer, group_crypto, transport, ack_registry.clone(), job)
            .await
        {
            Ok(true) => {
                if job.total_chunks == 0 {
                    if let Err(err) =
                        emit_local_attachment_echo(net_tx, attachment_store.as_ref(), job).await
                    {
                        net_tx
                            .send(build_local_notice_line(&format!("附件本地回显失败: {err}")))
                            .ok();
                    }
                    net_tx
                        .send(build_local_transfer_done_line(&job.transfer_id))
                        .ok();
                    *active_upload = None;
                }
            }
            Ok(false) => {}
            Err(err) => {
                ack_registry.finish(&job.meta_packet_id).await;
                net_tx
                    .send(build_local_transfer_failed_line(
                        &job.transfer_id,
                        &err.to_string(),
                    ))
                    .ok();
                *active_upload = None;
            }
        }
        return;
    }

    if let Err(err) =
        process_attachment_window(writer, net_tx, transport, ack_registry.clone(), job).await
    {
        cleanup_attachment_window(ack_registry.clone(), job).await;
        net_tx
            .send(build_local_transfer_failed_line(
                &job.transfer_id,
                &err.to_string(),
            ))
            .ok();
        *active_upload = None;
        return;
    }

    if job.acked_chunks >= job.total_chunks
        && job.next_chunk_index >= job.total_chunks
        && job.in_flight.is_empty()
    {
        if let Err(err) = emit_local_attachment_echo(net_tx, attachment_store.as_ref(), job).await {
            net_tx
                .send(build_local_notice_line(&format!("附件本地回显失败: {err}")))
                .ok();
        }
        net_tx
            .send(build_local_transfer_done_line(&job.transfer_id))
            .ok();
        *active_upload = None;
    }
}

pub async fn initialize_attachment_job(item: QueuedAttachment) -> Result<AttachmentJob> {
    match item {
        QueuedAttachment::Path(path) => initialize_attachment_job_owned(path).await,
        QueuedAttachment::Memory {
            file_name,
            bytes,
            kind,
        } => initialize_memory_attachment_job(file_name, bytes, kind).await,
    }
}

pub async fn initialize_attachment_job_owned(path: PathBuf) -> Result<AttachmentJob> {
    let metadata = tokio::fs::metadata(&path).await?;
    if !metadata.is_file() {
        return Err(anyhow!("Path is not a file: {}", path.display()));
    }

    let total_size = metadata.len();
    let total_chunks = if total_size == 0 {
        0
    } else {
        usize::try_from(total_size)?.div_ceil(ATTACHMENT_CHUNK_SIZE)
    };
    let file_name = file_name_or_default(&path);
    let sha256_hex = hash_file(&path).await?;
    let file = File::open(&path).await?;
    let transfer_id = uuid::Uuid::new_v4().simple().to_string();
    let mut file_key = [0u8; 32];
    let mut nonce_base = [0u8; 8];
    rand::rng().fill_bytes(&mut file_key);
    rand::rng().fill_bytes(&mut nonce_base);

    Ok(AttachmentJob {
        source_label: path.display().to_string(),
        source: AttachmentSource::File {
            path: path.clone(),
            file,
        },
        meta_packet_id: packet_id_for_attachment_meta(&transfer_id),
        manifest_plain_line: None,
        manifest_secure_line: None,
        manifest_context: None,
        transfer_id,
        file_name,
        kind: infer_attachment_kind(&path),
        total_size,
        total_chunks,
        sha256_hex,
        next_chunk_index: 0,
        acked_chunks: 0,
        meta_sent: false,
        meta_attempts: 0,
        meta_last_sent_at: None,
        file_key,
        nonce_base,
        in_flight: Vec::new(),
    })
}

pub async fn initialize_memory_attachment_job(
    file_name: String,
    bytes: Vec<u8>,
    kind: AttachmentKind,
) -> Result<AttachmentJob> {
    let total_size = u64::try_from(bytes.len())?;
    let total_chunks = if bytes.is_empty() {
        0
    } else {
        bytes.len().div_ceil(ATTACHMENT_CHUNK_SIZE)
    };
    let sha256_hex = hash_bytes(&bytes);
    let transfer_id = uuid::Uuid::new_v4().simple().to_string();
    let mut file_key = [0u8; 32];
    let mut nonce_base = [0u8; 8];
    rand::rng().fill_bytes(&mut file_key);
    rand::rng().fill_bytes(&mut nonce_base);

    Ok(AttachmentJob {
        source_label: file_name.clone(),
        source: AttachmentSource::Memory { bytes, offset: 0 },
        meta_packet_id: packet_id_for_attachment_meta(&transfer_id),
        manifest_plain_line: None,
        manifest_secure_line: None,
        manifest_context: None,
        transfer_id,
        file_name,
        kind,
        total_size,
        total_chunks,
        sha256_hex,
        next_chunk_index: 0,
        acked_chunks: 0,
        meta_sent: false,
        meta_attempts: 0,
        meta_last_sent_at: None,
        file_key,
        nonce_base,
        in_flight: Vec::new(),
    })
}

fn packet_id_for_attachment_meta(transfer_id: &str) -> String {
    format!("att-{transfer_id}-meta")
}

fn packet_id_for_attachment_chunk(transfer_id: &str, index: usize) -> String {
    format!("att-{transfer_id}-chunk-{index}")
}

async fn process_attachment_meta(
    writer: &mut OwnedWriteHalf,
    group_crypto: &Arc<StdMutex<GroupCryptoState>>,
    transport: &Arc<StdMutex<TransportCrypto>>,
    ack_registry: Arc<AckRegistry>,
    job: &mut AttachmentJob,
) -> Result<bool> {
    let max_attempts = PACKET_RETRY_LIMIT + 1;

    if ack_registry.is_acked(&job.meta_packet_id).await {
        ack_registry.finish(&job.meta_packet_id).await;
        job.meta_sent = true;
        return Ok(true);
    }

    let should_send = match job.meta_last_sent_at {
        None => true,
        Some(last_sent_at)
            if last_sent_at.elapsed() >= Duration::from_millis(PACKET_ACK_TIMEOUT_MS) =>
        {
            if job.meta_attempts >= max_attempts {
                ack_registry.finish(&job.meta_packet_id).await;
                return Err(anyhow!("ACK timeout for attachment metadata"));
            }
            true
        }
        Some(_) => false,
    };

    if should_send {
        ack_registry.subscribe(&job.meta_packet_id).await;
        if job.manifest_secure_line.is_none() || job.manifest_plain_line.is_none() {
            let secure_line = {
                let mut guard = group_crypto
                    .lock()
                    .map_err(|_| anyhow!("Group crypto state unavailable"))?;
                if guard.my_sender_chain.is_none() {
                    return Err(anyhow!("Current epoch secret unavailable"));
                }
                let context = AttachmentContext {
                    group_id: guard.group_id.clone(),
                    epoch: guard.epoch,
                    sender_id: guard.my_member_id.clone(),
                };
                let manifest_plain_line = build_file_manifest2_line(
                    &context.group_id,
                    context.epoch,
                    &context.sender_id,
                    &job.transfer_id,
                    job.kind,
                    &job.file_name,
                    job.total_size,
                    job.total_chunks,
                    &job.sha256_hex,
                    &job.file_key,
                    &job.nonce_base,
                )?;
                let encrypted = encrypt_message(
                    &mut guard,
                    SecureMessageType::FileManifest,
                    manifest_plain_line.as_bytes(),
                )?;
                job.manifest_context = Some(context);
                job.manifest_plain_line = Some(manifest_plain_line);
                build_rmsg_line(&encrypted)?
            };
            job.manifest_secure_line = Some(secure_line);
        }
        let secure_line = job
            .manifest_secure_line
            .as_ref()
            .ok_or_else(|| anyhow!("Attachment manifest is unavailable"))?;
        send_transport_payload_now(writer, &job.meta_packet_id, secure_line, transport).await?;
        job.meta_attempts += 1;
        job.meta_last_sent_at = Some(Instant::now());
    }

    Ok(false)
}

async fn process_attachment_window(
    writer: &mut OwnedWriteHalf,
    net_tx: &UnboundedSender<String>,
    transport: &Arc<StdMutex<TransportCrypto>>,
    ack_registry: Arc<AckRegistry>,
    job: &mut AttachmentJob,
) -> Result<()> {
    let max_attempts = PACKET_RETRY_LIMIT + 1;
    let mut idx = 0;

    while idx < job.in_flight.len() {
        let packet_id = job.in_flight[idx].packet_id.clone();
        if ack_registry.is_acked(&packet_id).await {
            ack_registry.finish(&packet_id).await;
            job.acked_chunks += 1;
            job.in_flight.remove(idx);
            net_tx
                .send(build_local_transfer_progress_line(
                    &job.transfer_id,
                    job.acked_chunks,
                    job.total_chunks,
                ))
                .ok();
            continue;
        }

        if job.in_flight[idx].last_sent_at.elapsed() >= Duration::from_millis(PACKET_ACK_TIMEOUT_MS)
        {
            if job.in_flight[idx].attempts >= max_attempts {
                let failed_chunk = job.in_flight[idx].chunk_index;
                return Err(anyhow!(
                    "ACK timeout for chunk {} of {}",
                    failed_chunk + 1,
                    job.total_chunks
                ));
            }

            send_transport_payload_now(
                writer,
                &job.in_flight[idx].packet_id,
                &job.in_flight[idx].chunk_line,
                transport,
            )
            .await?;
            job.in_flight[idx].attempts += 1;
            job.in_flight[idx].last_sent_at = Instant::now();
        }

        idx += 1;
    }

    while job.in_flight.len() < ATTACHMENT_WINDOW_SIZE && job.next_chunk_index < job.total_chunks {
        let context = job
            .manifest_context
            .as_ref()
            .ok_or_else(|| anyhow!("Attachment manifest context is unavailable"))?;
        let chunk_index = job.next_chunk_index;
        let mut buf = vec![0u8; ATTACHMENT_CHUNK_SIZE];
        let read = job.source.read_chunk(&mut buf).await?;
        if read == 0 {
            return Err(anyhow!(
                "Unexpected EOF while reading attachment {}",
                job.source_label
            ));
        }

        let chunk_line = build_file_chunk2_line(
            &context.group_id,
            context.epoch,
            &context.sender_id,
            &job.transfer_id,
            chunk_index,
            job.total_chunks,
            &buf[..read],
            &job.file_key,
            &job.nonce_base,
        )?;
        let packet_id = packet_id_for_attachment_chunk(&job.transfer_id, chunk_index);
        send_transport_payload_now(writer, &packet_id, &chunk_line, transport).await?;
        job.in_flight.push(InFlightChunk {
            packet_id,
            chunk_line,
            chunk_index,
            attempts: 1,
            last_sent_at: Instant::now(),
        });
        job.next_chunk_index += 1;
    }

    Ok(())
}

async fn cleanup_attachment_window(ack_registry: Arc<AckRegistry>, job: &AttachmentJob) {
    for chunk in &job.in_flight {
        ack_registry.finish(&chunk.packet_id).await;
    }
}

async fn emit_local_attachment_echo(
    net_tx: &UnboundedSender<String>,
    attachment_store: &AttachmentStore,
    job: &AttachmentJob,
) -> Result<()> {
    let bytes = job.source.bytes_for_echo().await?;
    let attachment_id = attachment_store.store_attachment(&job.file_name, &bytes)?;
    net_tx
        .send(build_local_echo_attachment_line(
            &attachment_id,
            &job.file_name,
            job.total_size,
            job.kind,
        ))
        .ok();
    Ok(())
}

async fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).await?;
    let mut buf = vec![0u8; ATTACHMENT_CHUNK_SIZE];
    let mut hasher = Sha256::new();

    loop {
        let read = file.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::{initialize_memory_attachment_job, ATTACHMENT_CHUNK_SIZE};
    use crate::protocol::AttachmentKind;
    use sha2::Digest as _;

    #[tokio::test]
    async fn memory_attachment_job_reads_from_memory_without_path() {
        let payload = vec![7u8; ATTACHMENT_CHUNK_SIZE + 3];
        let expected_hash = hex::encode(sha2::Sha256::digest(&payload));
        let mut job = initialize_memory_attachment_job(
            "clipboard.png".to_string(),
            payload.clone(),
            AttachmentKind::Image,
        )
        .await
        .expect("memory attachment should initialize");

        assert_eq!(job.file_name, "clipboard.png");
        assert_eq!(job.kind, AttachmentKind::Image);
        assert_eq!(job.total_size, payload.len() as u64);
        assert_eq!(job.total_chunks, 2);
        assert_eq!(job.sha256_hex, expected_hash);

        let mut first = vec![0u8; ATTACHMENT_CHUNK_SIZE];
        let read = job
            .source
            .read_chunk(&mut first)
            .await
            .expect("first chunk should read");
        assert_eq!(read, ATTACHMENT_CHUNK_SIZE);
        assert_eq!(&first, &payload[..ATTACHMENT_CHUNK_SIZE]);

        let mut second = vec![0u8; ATTACHMENT_CHUNK_SIZE];
        let read = job
            .source
            .read_chunk(&mut second)
            .await
            .expect("second chunk should read");
        assert_eq!(read, 3);
        assert_eq!(&second[..3], &payload[ATTACHMENT_CHUNK_SIZE..]);
    }
}
