use std::path::Path;

pub use crate::protocol::AttachmentKind;

pub fn infer_attachment_kind(path: &Path) -> AttachmentKind {
    let ext = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase());

    match ext.as_deref() {
        Some("png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp") => AttachmentKind::Image,
        _ => AttachmentKind::File,
    }
}
