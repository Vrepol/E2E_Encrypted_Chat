use std::path::Path;

use uuid::Uuid;

pub fn file_name_or_default(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "attachment.bin".to_string())
}

pub fn sanitize_attachment_name(name: &str) -> String {
    let cleaned = Path::new(name)
        .file_name()
        .and_then(|raw| raw.to_str())
        .unwrap_or("attachment.bin")
        .trim()
        .chars()
        .map(|ch| match ch {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect::<String>();

    if cleaned.is_empty() {
        format!("attachment-{}.bin", Uuid::new_v4().simple())
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::{file_name_or_default, sanitize_attachment_name};
    use std::path::Path;

    #[test]
    fn file_name_defaults_when_missing() {
        assert_eq!(file_name_or_default(Path::new("")), "attachment.bin");
    }

    #[test]
    fn sanitize_attachment_name_strips_path_traversal() {
        assert_eq!(sanitize_attachment_name("../../evil.txt"), "evil.txt");
    }
}
