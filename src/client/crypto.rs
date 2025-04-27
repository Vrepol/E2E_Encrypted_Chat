//! 简易对称加解密（ChaCha20-CTR + Base64）
//! 控制行保持明文；聊天行用 `ENC:<base64>` 前缀包裹

use base64::{engine::general_purpose as b64, Engine};
use chacha20::{cipher::{KeyIvInit, StreamCipher}, ChaCha20};
use rand::{rng, RngCore};

// ----------------- 常量 -----------------
const RAW_KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef"; // 自行替换

// ----------------- 公共 API -----------------
pub fn seal(plain: &str) -> String {
    // 生成随机 12 字节 nonce（IV）
    let mut iv = [0u8; 12];
    rng().fill_bytes(&mut iv);

    // 加密
    let mut data = plain.as_bytes().to_vec();
    ChaCha20::new(RAW_KEY.into(), &iv.into()).apply_keystream(&mut data);

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
    ChaCha20::new(RAW_KEY.into(), iv.into()).apply_keystream(&mut plain);
    String::from_utf8(plain).ok()
}
