use sha2::{Digest as ShaDigest, Sha256};

use super::utils::MemberIdentity;

pub const SAFETY_PROTOCOL_V0: &str = "rust-chat-safety-v0";

const SAFETY_EMOJIS: &[&str] = &[
    "🦊", "🌙", "🧊", "🍀", "🦀", "🌊", "🔥", "🌿",
    "⭐", "🍎", "🛰", "🪨", "🐳", "🌻", "🍋", "🦉",
    "🌈", "🍁", "🫐", "⚙️", "🧭", "🥝", "🐼", "🌵",
    "🍄", "🦋", "☁️", "🌺", "🐧", "🌲", "🍇", "🌞",
    "🪐", "🥥", "🦜", "🌼", "🍓", "🐢", "🌪", "🫧",
    "🐝", "🍉", "🌴", "❄️", "🦌", "🌸", "🍒", "🐬",
    "🌅", "🥑", "🦔", "🌱", "🍐", "🐙", "🌌", "🪵",
    "🍊", "🦝", "🌾", "🫚", "🍍", "🐚", "🌧", "🪻",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyTranscript {
    pub protocol_version: String,
    pub room_id: String,
    pub group_epoch: u64,
    pub members: Vec<SafetyMember>,
    pub transcript_hash: Option<Vec<u8>>,
}

impl SafetyTranscript {
    pub fn room_v0(room_id: impl Into<String>, members: &[MemberIdentity]) -> Self {
        let mut transcript_members = members
            .iter()
            .map(|member| SafetyMember {
                member_id: member.member_id.clone(),
                nickname: Some(member.nickname.clone()),
                identity_pubkey: None,
                x25519_pubkey: None,
            })
            .collect::<Vec<_>>();
        transcript_members.sort_by(|a, b| canonical_member_bytes(a).cmp(&canonical_member_bytes(b)));

        Self {
            protocol_version: SAFETY_PROTOCOL_V0.to_string(),
            room_id: room_id.into(),
            group_epoch: 0,
            members: transcript_members,
            transcript_hash: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyMember {
    pub member_id: String,
    pub nickname: Option<String>,
    pub identity_pubkey: Option<Vec<u8>>,
    pub x25519_pubkey: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafetyCode {
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomSafetyState {
    pub transcript: SafetyTranscript,
    pub code: SafetyCode,
}

impl SafetyCode {
    pub fn emoji(&self) -> String {
        safety_code_to_emoji(&self.hash)
    }

    pub fn digits(&self) -> String {
        safety_code_to_digits(&self.hash)
    }
}

pub fn compute_room_safety_code(transcript: &SafetyTranscript) -> SafetyCode {
    let canonical = canonical_transcript_bytes(transcript);
    let hash = Sha256::digest(canonical);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    SafetyCode { hash: out }
}

pub fn compute_room_safety_state(transcript: SafetyTranscript) -> RoomSafetyState {
    let code = compute_room_safety_code(&transcript);
    RoomSafetyState { transcript, code }
}

pub fn safety_code_to_emoji(hash: &[u8; 32]) -> String {
    hash.iter()
        .take(4)
        .map(|byte| SAFETY_EMOJIS[*byte as usize % SAFETY_EMOJIS.len()])
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn safety_code_to_digits(hash: &[u8; 32]) -> String {
    hash[..12]
        .chunks_exact(2)
        .map(|chunk| {
            let value = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            format!("{:05}", value % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn canonical_transcript_bytes(transcript: &SafetyTranscript) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_str_field(&mut bytes, "protocol_version", &transcript.protocol_version);
    push_str_field(&mut bytes, "room_id", &transcript.room_id);
    push_u64_field(&mut bytes, "group_epoch", transcript.group_epoch);

    let mut members = transcript.members.clone();
    members.sort_by(|a, b| canonical_member_bytes(a).cmp(&canonical_member_bytes(b)));
    push_u32_field(&mut bytes, "member_count", members.len() as u32);
    for member in members {
        push_bytes_field(&mut bytes, "member", &canonical_member_bytes(&member));
    }

    match transcript.transcript_hash.as_deref() {
        Some(hash) => push_optional_bytes_field(&mut bytes, "transcript_hash", Some(hash)),
        None => push_optional_bytes_field(&mut bytes, "transcript_hash", None),
    }

    bytes
}

fn canonical_member_bytes(member: &SafetyMember) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_str_field(&mut bytes, "member_id", &member.member_id);
    push_optional_str_field(&mut bytes, "nickname", member.nickname.as_deref());
    push_optional_bytes_field(
        &mut bytes,
        "identity_pubkey",
        member.identity_pubkey.as_deref(),
    );
    push_optional_bytes_field(
        &mut bytes,
        "x25519_pubkey",
        member.x25519_pubkey.as_deref(),
    );
    bytes
}

fn push_optional_str_field(buf: &mut Vec<u8>, label: &str, value: Option<&str>) {
    push_optional_bytes_field(buf, label, value.map(str::as_bytes));
}

fn push_str_field(buf: &mut Vec<u8>, label: &str, value: &str) {
    push_bytes_field(buf, label, value.as_bytes());
}

fn push_u64_field(buf: &mut Vec<u8>, label: &str, value: u64) {
    push_bytes_field(buf, label, &value.to_be_bytes());
}

fn push_u32_field(buf: &mut Vec<u8>, label: &str, value: u32) {
    push_bytes_field(buf, label, &value.to_be_bytes());
}

fn push_optional_bytes_field(buf: &mut Vec<u8>, label: &str, value: Option<&[u8]>) {
    push_bytes_field(buf, "label", label.as_bytes());
    match value {
        Some(bytes) => {
            buf.push(1);
            push_bytes_field(buf, "value", bytes);
        }
        None => buf.push(0),
    }
}

fn push_bytes_field(buf: &mut Vec<u8>, label: &str, value: &[u8]) {
    let label_bytes = label.as_bytes();
    buf.extend_from_slice(&(label_bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(label_bytes);
    buf.extend_from_slice(&(value.len() as u32).to_be_bytes());
    buf.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::{compute_room_safety_code, safety_code_to_digits, SafetyMember, SafetyTranscript};
    use crate::client::utils::MemberIdentity;

    fn member(member_id: &str, nickname: &str) -> MemberIdentity {
        MemberIdentity {
            member_id: member_id.to_string(),
            nickname: nickname.to_string(),
        }
    }

    #[test]
    fn safety_code_is_order_independent_for_same_members() {
        let transcript_a = SafetyTranscript::room_v0(
            "room-a",
            &[member("member-b", "Bob"), member("member-a", "Alice")],
        );
        let transcript_b = SafetyTranscript::room_v0(
            "room-a",
            &[member("member-a", "Alice"), member("member-b", "Bob")],
        );

        assert_eq!(
            compute_room_safety_code(&transcript_a),
            compute_room_safety_code(&transcript_b)
        );
    }

    #[test]
    fn safety_code_changes_when_member_joins() {
        let transcript_a = SafetyTranscript::room_v0("room-a", &[member("member-a", "Alice")]);
        let transcript_b = SafetyTranscript::room_v0(
            "room-a",
            &[member("member-a", "Alice"), member("member-b", "Bob")],
        );

        assert_ne!(
            compute_room_safety_code(&transcript_a),
            compute_room_safety_code(&transcript_b)
        );
    }

    #[test]
    fn safety_code_changes_when_member_leaves() {
        let transcript_a = SafetyTranscript::room_v0(
            "room-a",
            &[member("member-a", "Alice"), member("member-b", "Bob")],
        );
        let transcript_b = SafetyTranscript::room_v0("room-a", &[member("member-a", "Alice")]);

        assert_ne!(
            compute_room_safety_code(&transcript_a),
            compute_room_safety_code(&transcript_b)
        );
    }

    #[test]
    fn safety_code_changes_when_group_epoch_changes() {
        let members = vec![SafetyMember {
            member_id: "member-a".to_string(),
            nickname: Some("Alice".to_string()),
            identity_pubkey: None,
            x25519_pubkey: None,
        }];
        let transcript_a = SafetyTranscript {
            protocol_version: "rust-chat-safety-v1".to_string(),
            room_id: "room-a".to_string(),
            group_epoch: 7,
            members: members.clone(),
            transcript_hash: Some(vec![1, 2, 3]),
        };
        let transcript_b = SafetyTranscript {
            group_epoch: 8,
            ..transcript_a.clone()
        };

        assert_ne!(
            compute_room_safety_code(&transcript_a),
            compute_room_safety_code(&transcript_b)
        );
    }

    #[test]
    fn safety_code_changes_when_member_identity_changes() {
        let transcript_a = SafetyTranscript::room_v0("room-a", &[member("member-a", "Alice")]);
        let transcript_b = SafetyTranscript::room_v0("room-a", &[member("member-a", "Alice-2")]);
        let transcript_c = SafetyTranscript::room_v0("room-a", &[member("member-z", "Alice")]);

        assert_ne!(
            compute_room_safety_code(&transcript_a),
            compute_room_safety_code(&transcript_b)
        );
        assert_ne!(
            compute_room_safety_code(&transcript_a),
            compute_room_safety_code(&transcript_c)
        );
    }

    #[test]
    fn safety_digits_are_stable_and_grouped() {
        let transcript = SafetyTranscript::room_v0(
            "room-a",
            &[member("member-a", "Alice"), member("member-b", "Bob")],
        );
        let code = compute_room_safety_code(&transcript);

        assert_eq!(safety_code_to_digits(&code.hash), code.digits());
        assert_eq!(code.digits().split(' ').count(), 6);
    }
}
