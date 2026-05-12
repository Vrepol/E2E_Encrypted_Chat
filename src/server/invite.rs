use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub(crate) const INVITE_PENDING_TTL_SECS: i64 = 30;

#[derive(Debug)]
pub(crate) enum InviteUseState {
    Unused,
    Pending {
        client_nonce: [u8; 32],
        server_nonce: [u8; 32],
        pending_until: i64,
    },
    Used,
}

#[derive(Debug)]
pub(crate) struct InviteTokenInfo {
    pub(crate) room_id: String,
    pub(crate) expires_at: i64,
    pub(crate) blob_b64: String,
    pub(crate) token_secret: [u8; 32],
    pub(crate) state: InviteUseState,
}

pub(crate) type Invites = Arc<Mutex<HashMap<String, InviteTokenInfo>>>;

pub(crate) fn normalize_invites(invites_map: &mut HashMap<String, InviteTokenInfo>, now: i64) {
    invites_map
        .retain(|_, info| info.expires_at >= now && !matches!(info.state, InviteUseState::Used));
    for info in invites_map.values_mut() {
        if let InviteUseState::Pending { pending_until, .. } = info.state {
            if pending_until < now {
                info.state = InviteUseState::Unused;
            }
        }
    }
}

pub(crate) fn insert_invite_token(
    invites: &Invites,
    token_id_hex: String,
    room_id: String,
    expires_at: i64,
    blob_b64: String,
    token_secret: [u8; 32],
) {
    let mut invites_map = invites.lock().unwrap();
    invites_map.insert(
        token_id_hex,
        InviteTokenInfo {
            room_id,
            expires_at,
            blob_b64,
            token_secret,
            state: InviteUseState::Unused,
        },
    );
}

pub(crate) fn begin_pending_invite(
    invites: &Invites,
    token_id_hex: &str,
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
    now: i64,
) -> Option<([u8; 32], String, String)> {
    let mut invites_map = invites.lock().unwrap();
    normalize_invites(&mut invites_map, now);
    match invites_map.get_mut(token_id_hex) {
        Some(info) => match info.state {
            InviteUseState::Unused => {
                let token_secret = info.token_secret;
                let room_id = info.room_id.clone();
                let blob_b64 = info.blob_b64.clone();
                info.state = InviteUseState::Pending {
                    client_nonce,
                    server_nonce,
                    pending_until: now + INVITE_PENDING_TTL_SECS,
                };
                Some((token_secret, room_id, blob_b64))
            }
            _ => None,
        },
        None => None,
    }
}

pub(crate) fn reset_invite_to_unused(invites: &Invites, token_id_hex: &str, now: i64) {
    let mut invites_map = invites.lock().unwrap();
    normalize_invites(&mut invites_map, now);
    if let Some(info) = invites_map.get_mut(token_id_hex) {
        info.state = InviteUseState::Unused;
    }
}

pub(crate) fn consume_invite_ready(
    invites: &Invites,
    token_id_hex: &str,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    now: i64,
) -> bool {
    let mut invites_map = invites.lock().unwrap();
    normalize_invites(&mut invites_map, now);
    let Some(info) = invites_map.get_mut(token_id_hex) else {
        return false;
    };
    match info.state {
        InviteUseState::Pending {
            client_nonce: pending_client_nonce,
            server_nonce: pending_server_nonce,
            ..
        } if &pending_client_nonce == client_nonce && &pending_server_nonce == server_nonce => {
            info.state = InviteUseState::Used;
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use super::{
        begin_pending_invite, consume_invite_ready, insert_invite_token, normalize_invites,
        InviteTokenInfo, InviteUseState, Invites,
    };

    fn invites() -> Invites {
        Arc::new(Mutex::new(HashMap::new()))
    }

    #[test]
    fn invite_token_is_single_use() {
        let invites = invites();
        insert_invite_token(
            &invites,
            "token-1".to_string(),
            "room-a".to_string(),
            1_000,
            "blob".to_string(),
            [7u8; 32],
        );

        let client_nonce = [1u8; 32];
        let server_nonce = [2u8; 32];
        assert!(
            begin_pending_invite(&invites, "token-1", client_nonce, server_nonce, 10).is_some()
        );
        assert!(consume_invite_ready(
            &invites,
            "token-1",
            &client_nonce,
            &server_nonce,
            11
        ));
        assert!(
            begin_pending_invite(&invites, "token-1", client_nonce, server_nonce, 12).is_none()
        );
    }

    #[test]
    fn expired_tokens_are_removed() {
        let mut invites_map = HashMap::new();
        invites_map.insert(
            "token-1".to_string(),
            InviteTokenInfo {
                room_id: "room-a".to_string(),
                expires_at: 9,
                blob_b64: "blob".to_string(),
                token_secret: [0u8; 32],
                state: InviteUseState::Unused,
            },
        );

        normalize_invites(&mut invites_map, 10);
        assert!(invites_map.is_empty());
    }

    #[test]
    fn pending_timeout_resets_to_unused() {
        let mut invites_map = HashMap::new();
        invites_map.insert(
            "token-1".to_string(),
            InviteTokenInfo {
                room_id: "room-a".to_string(),
                expires_at: 100,
                blob_b64: "blob".to_string(),
                token_secret: [0u8; 32],
                state: InviteUseState::Pending {
                    client_nonce: [1u8; 32],
                    server_nonce: [2u8; 32],
                    pending_until: 9,
                },
            },
        );

        normalize_invites(&mut invites_map, 10);
        assert!(matches!(
            invites_map.get("token-1").map(|info| &info.state),
            Some(InviteUseState::Unused)
        ));
    }
}
