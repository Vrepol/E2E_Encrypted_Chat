use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberIdentity {
    pub member_id: String,
    pub nickname: String,
}

impl MemberIdentity {
    pub fn display_name(&self) -> String {
        member_display_name(&self.nickname, &self.member_id)
    }
}

pub fn member_display_name(nickname: &str, member_id: &str) -> String {
    let short_len = member_id.len().min(6);
    format!("{nickname}#{}", &member_id[..short_len])
}

pub fn build_member_list_line(members: &[MemberIdentity]) -> String {
    let encoded = members
        .iter()
        .map(|member| {
            let id_b64 = URL_SAFE_NO_PAD.encode(member.member_id.as_bytes());
            let nick_b64 = URL_SAFE_NO_PAD.encode(member.nickname.as_bytes());
            format!("{id_b64}:{nick_b64}")
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("/member_list {encoded}")
}

pub fn parse_member_list_line(line: &str) -> Option<Vec<MemberIdentity>> {
    let payload = line.strip_prefix("/member_list ")?;
    if payload.trim().is_empty() {
        return Some(Vec::new());
    }

    payload
        .split(',')
        .map(|entry| {
            let mut parts = entry.splitn(2, ':');
            let member_id = String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next()?).ok()?).ok()?;
            let nickname = String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next()?).ok()?).ok()?;
            Some(MemberIdentity {
                member_id,
                nickname,
            })
        })
        .collect()
}
