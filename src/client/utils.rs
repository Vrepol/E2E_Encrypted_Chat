pub fn parse_name_body(line: &str) -> (String, String) {
    // 查找第一对 []
    if let Some(start) = line.find('[') {
        if let Some(end) = line[start..].find(']') {
            let end = start + end;
            let name = line[start + 1..end].trim().to_owned();
            let body = line[end + 1..].trim().to_owned();
            return (name, body);
        }
    }
    ("???".into(), line.trim().to_owned())
}