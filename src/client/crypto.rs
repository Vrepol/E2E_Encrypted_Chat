//! 简易对称加解密（ChaCha20-CTR + Base64）
//! 控制行保持明文；聊天行用 `ENC:<base64>` 前缀包裹

use base64::{engine::general_purpose as b64, Engine};
use chacha20::{cipher::{KeyIvInit, StreamCipher}, ChaCha20};

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
    let iv = [0u8; 12];

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
