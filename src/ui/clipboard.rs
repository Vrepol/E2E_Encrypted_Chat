use anyhow::{anyhow, Result};
use arboard::{Clipboard, ImageData};
use image::{codecs::png::PngEncoder, ColorType, ImageEncoder};
use std::{borrow::Cow, path::PathBuf};

use crate::client::input::strip_optional_quotes;

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
        let owned = ImageData {
            width: img.width,
            height: img.height,
            bytes: Cow::Owned(img.bytes.into_owned()),
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

pub fn encode_rgba_as_png(rgba: &[u8], w: u32, h: u32) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    PngEncoder::new(&mut buf).write_image(rgba, w, h, ColorType::Rgba8.into())?;
    Ok(buf)
}

pub fn normalize_clipboard_rgba(bytes: &[u8], w: u32, h: u32) -> Result<Vec<u8>> {
    let expected_len = (w as usize)
        .checked_mul(h as usize)
        .and_then(|px| px.checked_mul(4))
        .ok_or_else(|| anyhow!("Clipboard image dimensions are too large"))?;

    if bytes.len() != expected_len {
        return Err(anyhow!(
            "Clipboard image buffer size mismatch: expected {expected_len}, got {}",
            bytes.len()
        ));
    }

    let mut rgba = bytes.to_vec();
    let all_alpha_zero = rgba.chunks_exact(4).all(|px| px[3] == 0);

    if all_alpha_zero {
        for px in rgba.chunks_exact_mut(4) {
            px[3] = 255;
        }
    }

    Ok(rgba)
}

pub fn parse_clipboard_file_paths(text: &str) -> Option<Vec<PathBuf>> {
    let mut paths = Vec::new();

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        let normalized = strip_optional_quotes(line);
        let path = PathBuf::from(normalized);
        if !path.is_absolute() || !path.is_file() {
            return None;
        }
        paths.push(path);
    }

    if paths.is_empty() {
        None
    } else {
        Some(paths)
    }
}
