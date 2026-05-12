use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

pub use super::core::{
    compute_invite_proof, compute_invite_token_id, compute_password_auth_proof,
    derive_invite_transport_key, derive_password_transport_key, pwd_hash,
};

#[derive(Serialize, Deserialize)]
struct InvitePayload {
    room_id: String,
    room_credential: String,
}

pub fn create_invite_blob(room_id: String, room_credential: String) -> Result<(String, String)> {
    let mut nonce = [0u8; 12];
    let mut blob_key = [0u8; 16];
    rand::rng().fill_bytes(&mut nonce);
    rand::rng().fill_bytes(&mut blob_key);

    let payload = InvitePayload {
        room_id,
        room_credential,
    };

    let key_bytes = Sha256::digest(blob_key);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            serde_json::to_vec(&payload)?.as_ref(),
        )
        .map_err(|_| anyhow!("Failed to encrypt invite blob"))?;

    let mut out = Vec::with_capacity(nonce.len() + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok((
        URL_SAFE_NO_PAD.encode(out),
        URL_SAFE_NO_PAD.encode(blob_key),
    ))
}

pub fn open_invite_blob(blob_b64: &str, blob_key_b64: &str) -> Option<(String, String)> {
    let bytes = URL_SAFE_NO_PAD.decode(blob_b64).ok()?;
    let blob_key = URL_SAFE_NO_PAD.decode(blob_key_b64).ok()?;

    if bytes.len() < 12 || blob_key.len() != 16 {
        return None;
    }

    let (nonce, cipher_bytes) = bytes.split_at(12);
    let key_bytes = Sha256::digest(&blob_key);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), cipher_bytes)
        .ok()?;

    serde_json::from_slice::<InvitePayload>(&plain)
        .map(|payload| (payload.room_id, payload.room_credential))
        .ok()
}

pub fn create_invitation(
    server_addr: String,
    invite_token: String,
    blob_key_b64: String,
) -> Result<String> {
    let server_b64 = URL_SAFE_NO_PAD.encode(server_addr.as_bytes());
    Ok(format!(
        "/INVITE:{server_b64}.{invite_token}.{blob_key_b64}"
    ))
}

pub fn parse_invitation(inv: &str) -> Option<(String, String, String)> {
    let raw = inv.strip_prefix("/INVITE:")?;
    let mut parts = raw.splitn(3, '.');
    let server_addr = String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next()?).ok()?).ok()?;
    let invite_token = parts.next()?.to_string();
    let blob_key_b64 = parts.next()?.to_string();
    Some((server_addr, invite_token, blob_key_b64))
}
