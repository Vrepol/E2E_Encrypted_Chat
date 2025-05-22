use super::crypto::open;
use super::receiver::ChatMessage;
pub fn parse_text_img(line: &str) -> (String, String, String) {
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

    // 2. 再找出紧跟的 [time]
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

    // 3. 剥掉 body 前的空格，尝试解密
    let body_slice = after_time.trim_start();
    let body_plain = open(body_slice).unwrap_or_else(|| body_slice.to_owned());

    (name, time, body_plain)
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
use std::path::Path;
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
    ImageEncoder,              // ★ 一定要引入这个 trait
};

pub fn encode_rgba_as_png(
    rgba: &[u8],
    w: u32,
    h: u32,
) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();

    // `write_image` 由 ImageEncoder trait 提供
    PngEncoder::new(&mut buf).write_image(
        rgba,
        w,
        h,
        ColorType::Rgba8.into(),   // 注意要 `.into()` → ExtendedColorType
    )?;

    Ok(buf)
}