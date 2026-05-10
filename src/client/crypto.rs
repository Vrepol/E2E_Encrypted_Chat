use base64::{engine::general_purpose as b64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::{HashSet, VecDeque};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const ROOM_INFO: &[u8] = b"room-enc";
const ROOM_STATE_LABEL: &[u8] = b"rust-chat room-state v1";
const ROOM_JOIN_LABEL: &[u8] = b"rust-chat room-join-credential v1";
const TRANSPORT_C2S_INFO: &[u8] = b"rust-chat transport c2s key v1";
const TRANSPORT_S2C_INFO: &[u8] = b"rust-chat transport s2c key v1";
const AUTH_PROOF_LABEL: &[u8] = b"rust-chat auth proof v1";
const INVITE_PROOF_LABEL: &[u8] = b"rust-chat invite proof v1";
const INVITE_TOKEN_ID_LABEL: &[u8] = b"rust-chat token id v1";
const TRANSPORT_REPLAY_WINDOW: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomCryptoState {
    room_id: String,
    room_credential: String,
    room_key: [u8; 32],
}

impl RoomCryptoState {
    pub fn from_room_credential(room_id: impl Into<String>, room_credential: impl Into<String>) -> Self {
        let room_id = room_id.into();
        let room_credential = room_credential.into();
        let digest = md5::Md5::digest(format!("{room_id}{room_credential}").as_bytes());
        let mut room_key = [0u8; 32];
        room_key[..16].copy_from_slice(&digest);
        room_key[16..].copy_from_slice(&digest);
        Self {
            room_id,
            room_credential,
            room_key,
        }
    }

    pub fn room_id(&self) -> &str {
        &self.room_id
    }

    pub fn room_credential(&self) -> &str {
        &self.room_credential
    }

    pub fn join_credential(&self) -> String {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(&self.room_key[..16]).expect("room join credential");
        mac.update(ROOM_JOIN_LABEL);
        hex::encode(mac.finalize().into_bytes())
    }

    pub fn seal(&self, plain: &str) -> String {
        let encoded = aead_seal_randomized(&self.room_key, ROOM_INFO, plain.as_bytes());
        format!("ENC:{encoded}")
    }

    pub fn open(&self, line: &str) -> Option<String> {
        let encoded = line.strip_prefix("ENC:")?;
        let plain = aead_open_randomized(&self.room_key, ROOM_INFO, encoded)?;
        String::from_utf8(plain).ok()
    }

    pub fn placeholder_epoch_secret(&self) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(ROOM_STATE_LABEL), &self.room_key);
        let mut out = [0u8; 32];
        hk.expand(b"epoch-placeholder", &mut out)
            .expect("room placeholder epoch");
        out
    }
}

#[derive(Debug, Clone)]
pub struct TransportCrypto {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_seq: u64,
    next_recv_seq: u64,
    recent_recv_seqs: VecDeque<u64>,
    seen_recv_seqs: HashSet<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportSide {
    Client,
    Server,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportOpenResult {
    Fresh(String),
    Duplicate(String),
}

impl TransportCrypto {
    pub fn new(shared_secret: [u8; 32], side: TransportSide) -> Self {
        let (send_info, recv_info) = match side {
            TransportSide::Client => (TRANSPORT_C2S_INFO, TRANSPORT_S2C_INFO),
            TransportSide::Server => (TRANSPORT_S2C_INFO, TRANSPORT_C2S_INFO),
        };
        Self {
            send_key: transport_direction_key(&shared_secret, send_info),
            recv_key: transport_direction_key(&shared_secret, recv_info),
            send_seq: 0,
            next_recv_seq: 0,
            recent_recv_seqs: VecDeque::new(),
            seen_recv_seqs: HashSet::new(),
        }
    }

    pub fn send_key(&self) -> &[u8; 32] {
        &self.send_key
    }

    pub fn recv_key(&self) -> &[u8; 32] {
        &self.recv_key
    }

    pub fn seal(&mut self, plain: &str) -> String {
        let cipher = aead_seal_sequenced(&self.send_key, self.send_seq, plain.as_bytes());
        self.send_seq = self.send_seq.wrapping_add(1);
        cipher
    }

    pub fn open(&mut self, cipher_line: &str) -> Option<TransportOpenResult> {
        let (seq, plain) = aead_open_sequenced(&self.recv_key, cipher_line)?;
        let plain = String::from_utf8(plain).ok()?;

        if seq == self.next_recv_seq {
            self.mark_seq_seen(seq);
            self.next_recv_seq = self.next_recv_seq.wrapping_add(1);
            return Some(TransportOpenResult::Fresh(plain));
        }

        if seq < self.next_recv_seq && self.seen_recv_seqs.contains(&seq) {
            return Some(TransportOpenResult::Duplicate(plain));
        }

        None
    }

    fn mark_seq_seen(&mut self, seq: u64) {
        self.recent_recv_seqs.push_back(seq);
        self.seen_recv_seqs.insert(seq);
        while self.recent_recv_seqs.len() > TRANSPORT_REPLAY_WINDOW {
            if let Some(evicted) = self.recent_recv_seqs.pop_front() {
                self.seen_recv_seqs.remove(&evicted);
            }
        }
    }
}

fn aead_seal_randomized(key_material: &[u8; 32], info: &[u8], plain: &[u8]) -> String {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce);

    let hk = Hkdf::<Sha256>::new(Some(&salt), key_material.as_ref());
    let mut key = [0u8; KEY_LEN];
    hk.expand(info, &mut key).expect("hkdf expand");

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let mut ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plain)
        .expect("encrypt");

    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.append(&mut ciphertext);
    b64::STANDARD.encode(out)
}

fn aead_open_randomized(key_material: &[u8; 32], info: &[u8], encoded: &str) -> Option<Vec<u8>> {
    let decoded = b64::STANDARD.decode(encoded).ok()?;
    if decoded.len() < SALT_LEN + NONCE_LEN + 16 {
        return None;
    }

    let (salt, rest) = decoded.split_at(SALT_LEN);
    let (nonce, ct) = rest.split_at(NONCE_LEN);

    let hk = Hkdf::<Sha256>::new(Some(salt), key_material.as_ref());
    let mut key = [0u8; KEY_LEN];
    hk.expand(info, &mut key).ok()?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    cipher.decrypt(Nonce::from_slice(nonce), ct).ok()
}

fn transport_direction_key(shared_secret: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; KEY_LEN];
    hk.expand(info, &mut key).expect("transport direction key");
    key
}

fn transport_nonce(seq: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    nonce
}

fn aead_seal_sequenced(transport_key: &[u8; 32], seq: u64, plain: &[u8]) -> String {
    let nonce = transport_nonce(seq);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(transport_key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plain)
        .expect("transport encrypt");

    let mut out = Vec::with_capacity(8 + ciphertext.len());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&ciphertext);
    b64::STANDARD.encode(out)
}

fn aead_open_sequenced(transport_key: &[u8; 32], encoded: &str) -> Option<(u64, Vec<u8>)> {
    let decoded = b64::STANDARD.decode(encoded).ok()?;
    if decoded.len() < 8 + 16 {
        return None;
    }

    let (seq_bytes, ct) = decoded.split_at(8);
    let seq = u64::from_be_bytes(seq_bytes.try_into().ok()?);
    let nonce = transport_nonce(seq);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(transport_key));
    let plain = cipher.decrypt(Nonce::from_slice(&nonce), ct).ok()?;
    Some((seq, plain))
}

pub fn pwd_hash(pwd: &str) -> [u8; 32] {
    let h = Sha256::digest(pwd.as_bytes());
    h[..].try_into().unwrap()
}

pub fn derive_password_transport_key(
    server_pwd_hash: &[u8; 32],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> [u8; 32] {
    derive_transport_key(server_pwd_hash, b"rust-chat password transport v1", &[
        client_nonce,
        server_nonce,
    ])
}

pub fn compute_password_auth_proof(
    server_pwd_hash: &[u8; 32],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> [u8; 32] {
    compute_handshake_proof(server_pwd_hash, AUTH_PROOF_LABEL, &[client_nonce, server_nonce])
}

pub fn compute_invite_token_id(token_secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(INVITE_TOKEN_ID_LABEL);
    hasher.update(token_secret);
    hasher.finalize().into()
}

pub fn derive_invite_transport_key(
    token_secret: &[u8],
    token_id: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> [u8; 32] {
    derive_transport_key(token_secret, b"rust-chat invite transport v1", &[
        token_id,
        client_nonce,
        server_nonce,
    ])
}

pub fn compute_invite_proof(
    token_secret: &[u8],
    token_id: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> [u8; 32] {
    compute_handshake_proof(
        token_secret,
        INVITE_PROOF_LABEL,
        &[token_id, client_nonce, server_nonce],
    )
}

fn derive_transport_key(secret: &[u8], label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut salt = Vec::new();
    for part in parts {
        salt.extend_from_slice(part);
    }
    let hk = Hkdf::<Sha256>::new(Some(&salt), secret);
    let mut out = [0u8; 32];
    hk.expand(label, &mut out).expect("transport key");
    out
}

fn compute_handshake_proof(secret: &[u8], label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("handshake proof");
    mac.update(label);
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}
