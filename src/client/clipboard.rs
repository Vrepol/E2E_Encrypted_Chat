// client/clipboard.rs
use std::borrow::Cow;             // 需要显式引入
use arboard::{Clipboard, ImageData};
use anyhow::{Result, anyhow};
pub enum ClipData {
    Text(String),
    Image(ImageData<'static>),
}
pub fn get() -> Result<ClipData> {
    let mut cb = Clipboard::new()?;

    if let Ok(txt) = cb.get_text() {
        return Ok(ClipData::Text(txt));
    }

    if let Ok(img) = cb.get_image() {
        // 将借用数据转成拥有数据，且保持 Cow 语义
        let owned = ImageData {
            width:  img.width,
            height: img.height,
            bytes:  Cow::Owned(img.bytes.into_owned()),   // ★ 关键改动
        };
        return Ok(ClipData::Image(owned));
    }

    Err(anyhow!("Neither text nor image in clipboard"))
}
pub fn set_text(s: &str) -> Result<()> {
        let mut cb = Clipboard::new()?;
        cb.set_text(s.to_owned())?;
        Ok(())
    }