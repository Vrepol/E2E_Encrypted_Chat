//! 简易对称加解密（ChaCha20-CTR + Base64）
//! 控制行保持明文；聊天行用 `ENC:<base64>` 前缀包裹

use base64::{engine::general_purpose as b64, Engine};
use chacha20::{cipher::{KeyIvInit, StreamCipher}, ChaCha20};
use rand::RngCore;
// ----------------- 常量 -----------------
static mut ROOM_KEY: [u8; 32] = [0u8; 32]; // 自行替换
pub fn set_room_key(md5_hex: &str) {
    let mut buf = [0u8; 16];
    hex::decode_to_slice(md5_hex, &mut buf).expect("md5 hex len != 32");
    unsafe {
        ROOM_KEY[..16].copy_from_slice(&buf);
        ROOM_KEY[16..].copy_from_slice(&buf);
    }
}

// 2) 把内部所有加解密改成使用 ROOM_KEY
fn current_key() -> &'static [u8; 32] {
    let ptr: *const [u8; 32] = &raw const ROOM_KEY;
    unsafe { &*ptr }
}
// ----------------- 公共 API -----------------
pub fn seal(plain: &str) -> String {
    // 生成随机 12 字节 nonce（IV）
    let mut iv = [0u8; 12];
    rand::rng().fill_bytes(&mut iv);
    // 加密
    let mut data = plain.as_bytes().to_vec();
    ChaCha20::new(current_key().into(), &iv.into()).apply_keystream(&mut data);

    // 拼装：ENC:<base64(iv + cipher)>
    let mut iv_cipher = iv.to_vec();
    iv_cipher.extend(data);
    format!("ENC:{}", b64::STANDARD.encode(iv_cipher))
}

pub fn open(line: &str) -> Option<String> {
    // 非密文行直接返回 None
    let Some(encoded) = line.strip_prefix("ENC:") else { return None };

    let decoded = b64::STANDARD.decode(encoded).ok()?;
    if decoded.len() < 12 { return None; }
    let (iv, cipher) = decoded.split_at(12);

    let mut plain = cipher.to_vec();
    ChaCha20::new(current_key().into(), iv.into()).apply_keystream(&mut plain);
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
    let mut buf = data.to_vec();
    let zero_nonce = [0u8; 12];
    chacha20::ChaCha20::new(key.into(), &zero_nonce.into()).apply_keystream(&mut buf);
    buf
}

/// 生成 AUTH 的二层密文（→ Base64）
pub fn enc_auth(pwd: &str) -> String {
    let now = Utc::now().timestamp();
    let inner = chacha_once(b"OKYOUARECORRECT", &pwd_hash(pwd));      // layer-1
    let outer = chacha_once(&inner, &period_key(now));            // layer-2
    b64::STANDARD.encode(outer)
}

/// 服务器端校验：给定密文 & pwd_hash，尝试 ±30 s
pub fn dec_auth(auth_b64: &str, pwd_hash: &[u8; 32]) -> bool {
    let cipher = match b64::STANDARD.decode(auth_b64) { Ok(v) => v, Err(_) => return false };
    let now = Utc::now().timestamp();
    for delta in [-PERIOD, 0, PERIOD] {
        let outer_key = period_key(now + delta);
        let stage1 = chacha_once(&cipher, &outer_key);            // remove layer-2
        let plain  = chacha_once(&stage1, pwd_hash);              // remove layer-1
        if plain == b"OKYOUARECORRECT" { return true; }                       // 明文用固定串“OK”
    }
    false
}

/// 邀请码里只需放 layer-1（pwd→cipher1→Base64）
pub fn enc_invite_pwd(pwd: &str) -> String {
    let inner = chacha_once(pwd.as_bytes(), &pwd_hash(pwd));
    b64::STANDARD.encode(inner)
}