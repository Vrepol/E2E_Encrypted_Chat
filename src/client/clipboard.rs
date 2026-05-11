// client/clipboard.rs
use anyhow::{anyhow, Result};
use arboard::{Clipboard, ImageData};
use std::{borrow::Cow, path::PathBuf}; // 需要显式引入
pub enum ClipData {
    Text(String),
    Image(ImageData<'static>),
    Files(Vec<PathBuf>),
}
pub fn get() -> Result<ClipData> {
    let mut cb = Clipboard::new()?;

    if let Ok(paths) = cb.get().file_list() {
        if !paths.is_empty() {
            return Ok(ClipData::Files(paths));
        }
    }

    if let Ok(img) = cb.get_image() {
        // 将借用数据转成拥有数据，且保持 Cow 语义
        let owned = ImageData {
            width: img.width,
            height: img.height,
            bytes: Cow::Owned(img.bytes.into_owned()), // ★ 关键改动
        };
        return Ok(ClipData::Image(owned));
    }

    if let Ok(txt) = cb.get_text() {
        return Ok(ClipData::Text(txt));
    }

    Err(anyhow!(
        "Clipboard does not contain supported text, image, or file data"
    ))
}
pub fn set_text(s: &str) -> Result<()> {
    let mut cb = Clipboard::new()?;
    cb.set_text(s.to_owned())?;
    Ok(())
}
