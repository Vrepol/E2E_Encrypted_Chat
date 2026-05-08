//! 简易对称加解密
//! 控制行保持明文；聊天行用 `ENC:<base64>` 前缀包裹

use base64::{engine::general_purpose as b64, Engine};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use rand::RngCore;
// ----------------- 常量 -----------------
static mut ROOM_KEY: [u8; 32] = [0u8; 32]; // 自行替换
static mut SERVER_KEY: [u8; 32] = [0u8; 32]; // 自行替换
pub fn set_room_key(md5_hex: &str) {
    let mut buf = [0u8; 16];
    hex::decode_to_slice(md5_hex, &mut buf).expect("md5 hex len != 32");
    unsafe {
        ROOM_KEY[..16].copy_from_slice(&buf);
        ROOM_KEY[16..].copy_from_slice(&buf);
    }
}
pub fn set_server_key(md5_hex: [u8; 32]) {
    unsafe {
        SERVER_KEY[..].copy_from_slice(&md5_hex);
    }
}
// 2) 把内部所有加解密改成使用 ROOM_KEY
fn current_key() -> &'static [u8; 32] {
    let ptr: *const [u8; 32] = &raw const ROOM_KEY;
    unsafe { &*ptr }
}
fn current_server_key() -> &'static [u8; 32] {
    let ptr: *const [u8; 32] = &raw const SERVER_KEY;
    unsafe { &*ptr }
}
// ----------------- 公共 API -----------------
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};      // chacha20poly1305 = "0.10"
use chacha20poly1305::aead::{Aead, KeyInit};               // traits
use hkdf::Hkdf;                                            // hkdf = "0.12"
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;   // ChaCha20-Poly1305 = 96-bit
const KEY_LEN: usize  = 32;    // 256-bit
const ROOM_INFO: &[u8] = b"room-enc";
const SERVER_INFO: &[u8] = b"server-enc";

fn aead_seal(key_material: &[u8; 32], info: &[u8], plain: &[u8]) -> String {
    let mut salt  = [0u8; SALT_LEN];
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

fn aead_open(key_material: &[u8; 32], info: &[u8], encoded: &str) -> Option<Vec<u8>> {
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

pub fn server_seal(plain: String) -> String {
    aead_seal(current_server_key(), SERVER_INFO, plain.as_bytes())
}

pub fn server_open(line: &str) -> Option<String> {
    let plain = aead_open(current_server_key(), SERVER_INFO, line)?;
    String::from_utf8(plain).ok()
}

pub fn seal(plain: &str) -> String {
    let encoded = aead_seal(current_key(), ROOM_INFO, plain.as_bytes());
    format!("ENC:{encoded}")
}

pub fn open(line: &str) -> Option<String> {
    let Some(encoded) = line.strip_prefix("ENC:") else { return None };
    let plain = aead_open(current_key(), ROOM_INFO, encoded)?;
    String::from_utf8(plain).ok()
}
use sha2::{Digest as ShaDigest, Sha256};
use chrono::Utc;

pub const PERIOD: i64 = 30;      // 秒

/// sha256(password) → 32 字节
pub fn pwd_hash(pwd: &str) -> [u8; 32] {
    let h = Sha256::digest(pwd.as_bytes());
    h[..].try_into().unwrap()
}

/// period_key(now) = unix_ts/30s → 32 字节
pub fn period_key(ts: i64) -> [u8; 32] {
    let pid = ts / PERIOD;
    let bytes = pid.to_be_bytes();           // 8 B
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = bytes[i % bytes.len()];
    }
    key
}

/// 单层 ChaCha20-CTR（key = 32 B，nonce 全 0 即可）
pub fn chacha_once(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use hmac::Mac;
    // 1) 生成 16 B salt 并派生子密钥：subkey = HMAC-SHA256(pwd_hash, salt)
    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);
    let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(key).unwrap();
    mac.update(&salt);
    let subkey: [u8; 32] = mac.finalize().into_bytes().into();

    // 2) ChaCha20(nonce = 0) 加密
    let mut buf = data.to_vec();
    let zero_iv = [0u8; 12];
    chacha20::ChaCha20::new(&subkey.into(), &zero_iv.into()).apply_keystream(&mut buf);

    // 3) 输出：salt || cipher
    let mut out = salt.to_vec();
    out.extend(buf);
    out
}
pub fn chacha_salt_open(full: &[u8], pwd_hash: &[u8; 32]) -> Option<Vec<u8>> {
    if full.len() < 16 { return None; }
    let (salt, cipher) = full.split_at(16);
    use hmac::Mac;
    // HMAC-SHA256(pwd_hash, salt) 生成同一把 subkey
    let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(pwd_hash).ok()?;
    mac.update(salt);
    let subkey: [u8; 32] = mac.finalize().into_bytes().into();

    let mut plain = cipher.to_vec();
    let zero_iv = [0u8; 12];
    chacha20::ChaCha20::new(&subkey.into(), &zero_iv.into()).apply_keystream(&mut plain);
    Some(plain)
}
/// 生成 AUTH 的二层密文（→ Base64）
pub fn enc_auth(pwd: &str) -> String {
    enc_auth_from_hash(&pwd_hash(pwd))
}

pub fn enc_auth_from_hash(server_pwd_hash: &[u8; 32]) -> String {
    let now = Utc::now().timestamp();
    let inner = chacha_once(b"OKYOUARECORRECT", server_pwd_hash);      // layer-1
    let outer = chacha_once(&inner, &period_key(now));            // layer-2
    b64::STANDARD.encode(outer)
}

/// 服务器端校验：给定密文 & pwd_hash，尝试 ±30 s
pub fn dec_auth(auth_b64: &str, pwd_hash: &[u8; 32]) -> bool {
    let cipher = match b64::STANDARD.decode(auth_b64) { Ok(v) => v, Err(_) => return false };
    let now = Utc::now().timestamp();
    for delta in [-PERIOD, 0, PERIOD] {
        let outer_key = period_key(now + delta);
        if let Some(layer1) = chacha_salt_open(&cipher, &outer_key) {
            // 再用 pwd_hash 去掉 layer-1
            if let Some(plain) = chacha_salt_open(&layer1, pwd_hash) {
                if plain.as_slice() == b"OKYOUARECORRECT" {
                    return true;
                    }
                }
            }
        }
    false
    }

/// 邀请码里只需放 layer-1（pwd→cipher1→Base64）
pub fn enc_invite_pwd(pwd: &str) -> String {
    let inner = chacha_once(pwd.as_bytes(), &pwd_hash(pwd));
    b64::STANDARD.encode(inner)
}
