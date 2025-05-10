use super::crypto::open;

pub fn parse_name_body(line: &str) -> (String, String, String) {
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
