use super::crypto::{open,server_seal};
use super::receiver::ChatMessage;
pub const HELP_TEXT: &str = r#"快捷键与命令说明：

• Ctrl+X       → 贴入剪贴板文本/图片
• Ctrl+C       → 复制当前选中消息 
• Ctrl+Z       → 撤销输入框  
• Ctrl+A       → 清空输入框
• Ctrl+I       → 生成邀请码   
• ←/→          → 移动光标（Ctrl+← 跳3字符，Ctrl+→ 跳至末尾）  
• ↑/↓          → 列表选上下（Ctrl+↑ 跳 5 条，Ctrl+↓ 跳到底部）  
• Tab          → 打开选中行的图片  
• Esc          → 退出房间  "#;
pub const HELP_TEXT_EN: &str = r#"Keyboard Shortcuts and Command Descriptions:

• Ctrl+X       → Paste clipboard text/image
• Ctrl+C       → Copy the currently selected message
• Ctrl+Z       → Undo in input box
• Ctrl+A       → Clear input box
• Ctrl+I       → Generate invite code
• ←/→          → Move cursor (Ctrl+← jump 3 characters, Ctrl+→ jump to end)
• ↑/↓          → Navigate list up/down (Ctrl+↑ jump 5 items, Ctrl+↓ jump to bottom)
• Tab          → Open the image in the selected row
• Esc          → Exit room"#;
pub fn handshake_writeall_macro(line:String) -> Vec<u8> {
    let mut buf = server_seal(line.to_string()).into_bytes();
    buf.push(b'\n');
    buf
}
pub fn parse_text_img(line: &str) -> (String, String) {
    // 1. 先找出第一对 [name]
    let (name, after_name) = if let Some(start) = line.find('[') {
        if let Some(end_rel) = line[start + 1..].find(']') {
            let end = start + 1 + end_rel;
            let name = line[start + 1..end].to_owned();
            let rest = &line[end + 1..];
            (name, rest)
        } else {
            ("???".into(), line)
        }
    } else {
        ("???".into(), line)
    };

    // 2. 剥掉 body 前的空格，尝试解密
    let body_slice = after_name.trim_start();
    let body_plain = open(body_slice).unwrap_or_else(|| body_slice.to_owned());

    (name, body_plain)
}
pub fn parse_name_body(msg: &ChatMessage) -> (String, String, String) {
    match msg {
        ChatMessage::Text(line) => {
            // —— 原来针对 &str 的实现，稍作提取封装 —— //
            // 1. 找 name
            let (name, after_name) = if let Some(start) = line.find('[') {
                if let Some(end_rel) = line[start + 1..].find(']') {
                    let end = start + 1 + end_rel;
                    let name = line[start + 1..end].to_owned();
                    let rest = &line[end + 1..];
                    (name, rest)
                } else {
                    ("???".into(), line.as_str())
                }
            } else {
                ("???".into(), line.as_str())
            };

            // 2. 找 time
            let (time, after_time) = if let Some(start) = after_name.find('[') {
                if let Some(end_rel) = after_name[start + 1..].find(']') {
                    let end = start + 1 + end_rel;
                    let time = after_name[start + 1..end].to_owned();
                    let rest = &after_name[end + 1..];
                    (time, rest)
                } else {
                    ("??:??:??".into(), after_name)
                }
            } else {
                ("??:??:??".into(), after_name)
            };

            // 3. 解密 body
            let body_slice = after_time.trim_start();
            let body_plain = open(body_slice).unwrap_or_else(|| body_slice.to_owned());

            (name, time, body_plain)
        }

        ChatMessage::Image { path,sender, ts } => {
            // 假设文件名格式："img_[uuid].png"
            let file_stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
        
            // 分割成 ["img", name, time, uuid]
            let parts: Vec<&str> = file_stem.split('_').collect();
        
            // 取出 name 和 time（访问越界则用默认值）
            let name = sender.to_string();
            let time = ts.to_string();
        
            // 最后一段是 UUID，当作 body
            let full_uuid = parts.get(1).map(|s| s.to_string()).unwrap_or_default();
            let suffix = if full_uuid.len() > 3 {
                &full_uuid[full_uuid.len() - 3..]
            } else {
                &full_uuid
            };
            let body = format!("[图片_{}]", suffix);
            (name, time, body)
        }
    }
}
use anyhow::Result;
use std::{path::Path};
use tokio::fs;
use base64::{engine::general_purpose, Engine as _};

/// 读取消息的“明文”：
/// - 如果 `msg` 看起来是图片路径（.png/.jpg/.jpeg），就读文件二进制；
/// - 否则当作普通文本，返回 UTF-8 bytes。
pub async fn get_plaintext(msg: &str) -> Result<String> {
    let path = Path::new(msg);
    let is_img = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|ext| matches!(ext.to_lowercase().as_str(), "png" | "jpg" | "jpeg"))
        .unwrap_or(false);

    if is_img {
        // 读整个文件
        let data = fs::read(path).await?;
        // Base64 编码
        let encoded = general_purpose::STANDARD.encode(&data);
        Ok(format!("/IMGDATA{}", encoded))
    } else {
        // 普通文本
        Ok(msg.to_string())
    }
}
use image::{
    codecs::png::PngEncoder,
    ColorType,
    ImageEncoder,
};

pub fn encode_rgba_as_png(
    rgba: &[u8],
    w: u32,
    h: u32,
) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();

    PngEncoder::new(&mut buf).write_image(
        rgba,
        w,
        h,
        ColorType::Rgba8.into(),
    )?;

    Ok(buf)
}
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};
use serde::{Serialize, Deserialize};
use chrono::Utc;
use rand::RngCore;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD};
#[derive(Serialize, Deserialize)]
struct Invite {
    server:   String,
    enc_pwd:  [u8; 32],
    room_id:  String,
    room_key: String,
}
pub const PERIOD_SECS: i64 = 500;
fn derive_invite_key() -> [u8; 32] {
    let period_id = Utc::now().timestamp() / PERIOD_SECS;
    let bytes = period_id.to_be_bytes();
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = bytes[i % bytes.len()];
    }
    key
}
pub fn create_invitation(server_addr:String,server_pwd:String,room_id:String,pwd:String) 
        -> Result<String, Box<dyn std::error::Error>>{
    let key = derive_invite_key();
    // 随机 12 字节 nonce
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    use super::crypto::{pwd_hash};
    //let auth = chacha_once(b"OKYOUARECORRECT", &pwd_hash(&server_pwd));
    let auth = pwd_hash(&server_pwd);
    // 序列化明文
    let inv = Invite {
        server:   server_addr,
        enc_pwd:  auth,
        room_id,
        room_key: pwd,
    };

    let mut buf = serde_json::to_vec(&inv)?;
    // 用 ChaCha20 加密（in-place）
    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    cipher.apply_keystream(&mut buf);

    // 拼接 nonce || 密文，然后 hex 编码
    let mut out = Vec::with_capacity(nonce.len() + buf.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    Ok(URL_SAFE_NO_PAD.encode(out))
}

pub fn parse_invitation(inv: &str) -> Option<(String, [u8; 32], String, String)> {
    let raw = inv.strip_prefix("/INVITE:")?;

    // ---------- A. 尝试 URL-safe Base64 ----------
    let bytes = match URL_SAFE_NO_PAD.decode(raw) {
        Ok(v) => v,
        Err(_) => {
            // ---------- B. 回退到 hex ----------
            if raw.chars().all(|c| c.is_ascii_hexdigit()) {
                hex::decode(raw).ok()?
            } else {
                return None;
            }
        }
    };

    if bytes.len() < 12 { return None; }
    let (nonce, cipher) = bytes.split_at(12);

    let key = derive_invite_key();
    let mut buf = cipher.to_vec();
    let mut chacha = ChaCha20::new(&key.into(), nonce.into());
    chacha.apply_keystream(&mut buf);

    serde_json::from_slice::<Invite>(&buf)
        .map(|v| (v.server,v.enc_pwd , v.room_id, v.room_key))
        .ok()
}

pub fn inviation_clear(inv: &str) -> String{
    if inv.starts_with("/INVITE:"){
        format!("")
    } else {
        inv.to_string()
    }
    
}