use super::crypto::open;

/// 把一行 "[name] body" 拆成 (name, body_plain)
pub fn parse_name_body(line: &str) -> (String, String) {
    // 找到最外层 [] 包住的名字
    if let Some(start) = line.find('[') {
        if let Some(end) = line[start..].find(']') {
            let end = start + end;
            let name = line[start + 1..end].trim().to_owned();

            // body: 先保留原样，再只剥掉 **一个** 前导空格（若存在）
            let mut body_slice = &line[end + 1..];
            if body_slice.starts_with(' ') {
                body_slice = &body_slice[1..];
            }

            // ★ 尝试解密；失败就保持原文（含其尾部空白）
            let body_plain = open(body_slice).unwrap_or_else(|| body_slice.to_owned());
            return (name, body_plain);
        }
    }
    ("???".into(), line.to_owned())
}
