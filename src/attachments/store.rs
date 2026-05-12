use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use uuid::Uuid;

const HEADER_MAGIC: [u8; 4] = [0x9d, 0x41, 0x7a, 0x26];
const HEADER_VERSION: u8 = 1;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

type OpenFn = Arc<dyn Fn(&Path) -> Result<()> + Send + Sync>;

#[derive(Clone)]
struct AttachmentRecord {
    cipher_path: PathBuf,
    display_name: String,
}

pub struct AttachmentStore {
    root: PathBuf,
    local_storage_key: [u8; KEY_LEN],
    records: Mutex<HashMap<String, AttachmentRecord>>,
    opener: OpenFn,
    cleanup_delay: Duration,
}

impl AttachmentStore {
    pub fn new_in(root: PathBuf) -> Result<Self> {
        let mut local_storage_key = [0u8; KEY_LEN];
        rand::rng().fill_bytes(&mut local_storage_key);
        fs::create_dir_all(&root).with_context(|| {
            format!("failed to create attachment store root {}", root.display())
        })?;

        Ok(Self {
            root,
            local_storage_key,
            records: Mutex::new(HashMap::new()),
            opener: Arc::new(|path| {
                open::that(path).map_err(|err| anyhow!("failed to open {}: {err}", path.display()))
            }),
            cleanup_delay: Duration::from_secs(10),
        })
    }

    pub fn store_attachment(&self, display_name: &str, bytes: &[u8]) -> Result<String> {
        let attachment_id = Uuid::new_v4().simple().to_string();
        let cipher_path = self.unique_random_path(None)?;
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut salt);
        rand::rng().fill_bytes(&mut nonce);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(
            &self.derive_attachment_key(&salt, &attachment_id)?,
        ));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), bytes)
            .map_err(|_| anyhow!("failed to encrypt attachment bytes"))?;

        let mut encoded =
            Vec::with_capacity(HEADER_MAGIC.len() + 1 + SALT_LEN + NONCE_LEN + ciphertext.len());
        encoded.extend_from_slice(&HEADER_MAGIC);
        encoded.push(HEADER_VERSION);
        encoded.extend_from_slice(&salt);
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(&ciphertext);

        fs::write(&cipher_path, encoded).with_context(|| {
            format!(
                "failed to write encrypted attachment {}",
                cipher_path.display()
            )
        })?;

        self.records
            .lock()
            .map_err(|_| anyhow!("attachment store lock poisoned"))?
            .insert(
                attachment_id.clone(),
                AttachmentRecord {
                    cipher_path,
                    display_name: display_name.to_string(),
                },
            );

        Ok(attachment_id)
    }

    pub fn open_temp_and_cleanup_after_delay(&self, attachment_id: &str) -> Result<PathBuf> {
        let record = self.record_for(attachment_id)?;
        let bytes = self.decrypt_attachment(attachment_id)?;
        let temp_plain_path =
            self.unique_random_path(extension_for(&record.display_name).as_deref())?;
        fs::write(&temp_plain_path, bytes).with_context(|| {
            format!(
                "failed to write temp attachment {}",
                temp_plain_path.display()
            )
        })?;
        set_readonly(&temp_plain_path)?;

        if let Err(err) = (self.opener)(&temp_plain_path) {
            let _ = fs::remove_file(&temp_plain_path);
            return Err(err);
        }

        let cleanup_path = temp_plain_path.clone();
        let delay = self.cleanup_delay;
        thread::spawn(move || {
            thread::sleep(delay);
            let _ = fs::remove_file(&cleanup_path);
        });

        Ok(temp_plain_path)
    }

    pub fn decrypt_attachment(&self, attachment_id: &str) -> Result<Vec<u8>> {
        let record = self.record_for(attachment_id)?;
        let encoded = fs::read(&record.cipher_path).with_context(|| {
            format!(
                "failed to read encrypted attachment {}",
                record.cipher_path.display()
            )
        })?;

        Self::decrypt_encoded_bytes(&self.local_storage_key, attachment_id, &encoded)
    }

    fn record_for(&self, attachment_id: &str) -> Result<AttachmentRecord> {
        self.records
            .lock()
            .map_err(|_| anyhow!("attachment store lock poisoned"))?
            .get(attachment_id)
            .cloned()
            .ok_or_else(|| anyhow!("attachment not found: {attachment_id}"))
    }

    fn derive_attachment_key(
        &self,
        salt: &[u8; SALT_LEN],
        attachment_id: &str,
    ) -> Result<[u8; KEY_LEN]> {
        Self::derive_attachment_key_from_master(&self.local_storage_key, salt, attachment_id)
    }

    fn derive_attachment_key_from_master(
        master_key: &[u8; KEY_LEN],
        salt: &[u8; SALT_LEN],
        attachment_id: &str,
    ) -> Result<[u8; KEY_LEN]> {
        let hk = Hkdf::<Sha256>::new(Some(salt), master_key);
        let mut derived = [0u8; KEY_LEN];
        hk.expand(attachment_id.as_bytes(), &mut derived)
            .map_err(|_| anyhow!("failed to derive attachment key"))?;
        Ok(derived)
    }

    fn decrypt_encoded_bytes(
        master_key: &[u8; KEY_LEN],
        attachment_id: &str,
        encoded: &[u8],
    ) -> Result<Vec<u8>> {
        let min_len = HEADER_MAGIC.len() + 1 + SALT_LEN + NONCE_LEN;
        if encoded.len() < min_len {
            return Err(anyhow!("encrypted attachment is truncated"));
        }

        if encoded[..HEADER_MAGIC.len()] != HEADER_MAGIC {
            return Err(anyhow!("encrypted attachment magic mismatch"));
        }

        if encoded[HEADER_MAGIC.len()] != HEADER_VERSION {
            return Err(anyhow!("encrypted attachment version mismatch"));
        }

        let salt_start = HEADER_MAGIC.len() + 1;
        let nonce_start = salt_start + SALT_LEN;
        let ciphertext_start = nonce_start + NONCE_LEN;

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&encoded[salt_start..nonce_start]);
        let nonce = &encoded[nonce_start..ciphertext_start];
        let ciphertext = &encoded[ciphertext_start..];
        let key = Self::derive_attachment_key_from_master(master_key, &salt, attachment_id)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow!("failed to decrypt attachment payload"))
    }

    fn unique_random_path(&self, extension: Option<&str>) -> Result<PathBuf> {
        for _ in 0..16 {
            let mut name_bytes = [0u8; 16];
            rand::rng().fill_bytes(&mut name_bytes);
            let mut file_name = hex::encode(name_bytes);
            if let Some(ext) = extension.filter(|ext| !ext.is_empty()) {
                file_name.push('.');
                file_name.push_str(ext);
            }

            let candidate = self.root.join(file_name);
            if !candidate.exists() {
                return Ok(candidate);
            }
        }

        Err(anyhow!("failed to allocate unique temp file path"))
    }

    #[cfg(test)]
    fn encrypted_path_for_test(&self, attachment_id: &str) -> PathBuf {
        self.record_for(attachment_id).unwrap().cipher_path
    }

    #[cfg(test)]
    fn local_storage_key_for_test(&self) -> [u8; KEY_LEN] {
        self.local_storage_key
    }

    #[cfg(test)]
    fn with_options_for_test(
        root: PathBuf,
        local_storage_key: [u8; KEY_LEN],
        opener: OpenFn,
        cleanup_delay: Duration,
    ) -> Self {
        Self {
            root,
            local_storage_key,
            records: Mutex::new(HashMap::new()),
            opener,
            cleanup_delay,
        }
    }
}

fn extension_for(display_name: &str) -> Option<String> {
    Path::new(display_name)
        .extension()
        .and_then(|ext| ext.to_str())
        .filter(|ext| !ext.trim().is_empty())
        .map(|ext| ext.to_string())
}

fn set_readonly(path: &Path) -> Result<()> {
    let mut permissions = fs::metadata(path)
        .with_context(|| format!("failed to read metadata for {}", path.display()))?
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)
        .with_context(|| format!("failed to mark {} as read-only", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{extension_for, AttachmentStore, OpenFn};
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
        thread,
        time::Duration,
    };
    use tempfile::tempdir;

    fn test_store(
        root: PathBuf,
        key: [u8; 32],
        opener: OpenFn,
        cleanup_delay: Duration,
    ) -> AttachmentStore {
        AttachmentStore::with_options_for_test(root, key, opener, cleanup_delay)
    }

    #[test]
    fn encrypted_filename_hides_original_name_and_extension() {
        let dir = tempdir().unwrap();
        let store = test_store(
            dir.path().to_path_buf(),
            [7u8; 32],
            Arc::new(|_| Ok(())),
            Duration::from_millis(50),
        );
        let attachment_id = store
            .store_attachment("secret-plan.pdf", b"payload")
            .unwrap();
        let cipher_path = store.encrypted_path_for_test(&attachment_id);
        let file_name = cipher_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_lowercase();

        assert!(!file_name.contains("secret"));
        assert!(!file_name.contains("plan"));
        assert!(!file_name.contains("pdf"));
        assert_eq!(cipher_path.parent().unwrap(), dir.path());
    }

    #[test]
    fn encrypted_payload_does_not_contain_plaintext() {
        let dir = tempdir().unwrap();
        let store = test_store(
            dir.path().to_path_buf(),
            [9u8; 32],
            Arc::new(|_| Ok(())),
            Duration::from_millis(50),
        );
        let payload = b"top-secret-plaintext-payload";
        let attachment_id = store.store_attachment("evidence.bin", payload).unwrap();
        let cipher_bytes = fs::read(store.encrypted_path_for_test(&attachment_id)).unwrap();

        assert!(!cipher_bytes
            .windows(payload.len())
            .any(|window| window == payload));
    }

    #[test]
    fn decrypt_with_wrong_local_storage_key_fails() {
        let dir = tempdir().unwrap();
        let store = test_store(
            dir.path().to_path_buf(),
            [3u8; 32],
            Arc::new(|_| Ok(())),
            Duration::from_millis(50),
        );
        let attachment_id = store.store_attachment("proof.txt", b"hello world").unwrap();
        let cipher_bytes = fs::read(store.encrypted_path_for_test(&attachment_id)).unwrap();
        let err = AttachmentStore::decrypt_encoded_bytes(&[4u8; 32], &attachment_id, &cipher_bytes)
            .unwrap_err()
            .to_string();

        assert!(err.contains("decrypt"));
    }

    #[test]
    fn room_or_server_key_material_cannot_decrypt_local_attachment() {
        let dir = tempdir().unwrap();
        let store = test_store(
            dir.path().to_path_buf(),
            [1u8; 32],
            Arc::new(|_| Ok(())),
            Duration::from_millis(50),
        );
        let attachment_id = store
            .store_attachment("slides.pptx", b"office bytes")
            .unwrap();
        let cipher_bytes = fs::read(store.encrypted_path_for_test(&attachment_id)).unwrap();

        let mut fake_room_server_key = [0u8; 32];
        fake_room_server_key[..16].copy_from_slice(b"room-key-1234567");
        fake_room_server_key[16..].copy_from_slice(b"server-key-12345");

        assert!(AttachmentStore::decrypt_encoded_bytes(
            &fake_room_server_key,
            &attachment_id,
            &cipher_bytes
        )
        .is_err());
    }

    #[test]
    fn open_temp_preserves_extension_and_uses_opener() {
        let dir = tempdir().unwrap();
        let opened_path: Arc<Mutex<Option<PathBuf>>> = Arc::new(Mutex::new(None));
        let opened_path_clone = opened_path.clone();
        let store = test_store(
            dir.path().to_path_buf(),
            [6u8; 32],
            Arc::new(move |path: &Path| {
                *opened_path_clone.lock().unwrap() = Some(path.to_path_buf());
                Ok(())
            }),
            Duration::from_millis(200),
        );
        let attachment_id = store.store_attachment("photo.jpeg", b"img-bytes").unwrap();
        let temp_plain_path = store
            .open_temp_and_cleanup_after_delay(&attachment_id)
            .unwrap();

        assert_eq!(
            temp_plain_path.extension().and_then(|ext| ext.to_str()),
            Some("jpeg")
        );
        assert_eq!(opened_path.lock().unwrap().as_ref(), Some(&temp_plain_path));
        assert!(fs::metadata(&temp_plain_path)
            .unwrap()
            .permissions()
            .readonly());
        assert_eq!(fs::read(&temp_plain_path).unwrap(), b"img-bytes");
    }

    #[test]
    fn temp_plaintext_is_deleted_after_cleanup_delay() {
        let dir = tempdir().unwrap();
        let store = test_store(
            dir.path().to_path_buf(),
            [8u8; 32],
            Arc::new(|_| Ok(())),
            Duration::from_millis(75),
        );
        let attachment_id = store.store_attachment("report.pdf", b"pdf-bytes").unwrap();
        let temp_plain_path = store
            .open_temp_and_cleanup_after_delay(&attachment_id)
            .unwrap();
        assert!(temp_plain_path.exists());

        thread::sleep(Duration::from_millis(250));
        assert!(!temp_plain_path.exists());
    }

    #[test]
    fn no_pending_delete_or_product_markers_are_created() {
        let dir = tempdir().unwrap();
        let store = test_store(
            dir.path().to_path_buf(),
            [5u8; 32],
            Arc::new(|_| Ok(())),
            Duration::from_millis(30),
        );
        let attachment_id = store
            .store_attachment("archive.tar.gz", b"archive")
            .unwrap();
        let temp_plain_path = store
            .open_temp_and_cleanup_after_delay(&attachment_id)
            .unwrap();
        thread::sleep(Duration::from_millis(120));

        let entries: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_lowercase())
            .collect();

        assert!(!entries.iter().any(|name| name.contains("pending_delete")));
        assert!(!entries.iter().any(|name| name.contains("rust-chat")));
        assert!(!entries.iter().any(|name| name.contains("attachment")));
        assert!(!entries.iter().any(|name| name.contains("room")));
        assert_eq!(extension_for("archive.tar.gz").as_deref(), Some("gz"));
        assert!(!temp_plain_path.exists());
    }

    #[test]
    fn local_storage_key_is_independent_from_test_fixture_name() {
        let dir = tempdir().unwrap();
        let store = test_store(
            dir.path().to_path_buf(),
            [11u8; 32],
            Arc::new(|_| Ok(())),
            Duration::from_millis(50),
        );

        assert_eq!(store.local_storage_key_for_test(), [11u8; 32]);
    }
}
