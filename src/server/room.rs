use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use rand::{distr::Alphanumeric, Rng};

use crate::protocol::{build_member_list_line, MemberIdentity};

use super::broadcast::{new_room_broadcast, RoomBroadcast, ServerEvent};

pub(crate) struct RoomInfo {
    pub(crate) broadcast: RoomBroadcast,
    pub(crate) join_credential: String,
    pub(crate) members: HashMap<String, String>,
    pub(crate) owner_member_id: Option<String>,
    pub(crate) owner_capability: Option<String>,
}

pub(crate) type Rooms = Arc<Mutex<HashMap<String, RoomInfo>>>;

pub(crate) struct RoomGuard {
    pub(crate) rooms: Rooms,
    pub(crate) room_id: String,
    pub(crate) member_id: String,
    pub(crate) nickname: String,
    pub(crate) broadcast: RoomBroadcast,
}

impl Drop for RoomGuard {
    fn drop(&mut self) {
        let _ = self.broadcast.high_tx.send(ServerEvent::Plain {
            source_member_id: None,
            plain: format!("⚡ [{}] left.", self.nickname),
        });

        let mut map = self.rooms.lock().unwrap();
        if let Some(info) = map.get_mut(&self.room_id) {
            info.members.remove(&self.member_id);
            if info.owner_member_id.as_deref() == Some(&self.member_id) {
                info.owner_member_id = None;
                info.owner_capability = None;
            }
            broadcast_member_list(info);
            if info.members.is_empty() {
                map.remove(&self.room_id);
            }
        }
    }
}

pub(crate) fn create_room(
    rooms: &Rooms,
    room_id: String,
    join_credential: String,
    member_id: String,
    nickname: String,
) -> Result<(RoomBroadcast, String), &'static str> {
    let mut map = rooms.lock().unwrap();
    if map.contains_key(&room_id) {
        return Err("RoomExists");
    }

    let owner_capability: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let broadcast = new_room_broadcast();
    let mut members = HashMap::new();
    members.insert(member_id.clone(), nickname);
    map.insert(
        room_id,
        RoomInfo {
            broadcast: broadcast.clone(),
            join_credential,
            members,
            owner_member_id: Some(member_id),
            owner_capability: Some(owner_capability.clone()),
        },
    );

    Ok((broadcast, owner_capability))
}

pub(crate) fn join_room(
    rooms: &Rooms,
    room_id: &str,
    join_credential: &str,
    member_id: String,
    nickname: String,
) -> Result<RoomBroadcast, &'static str> {
    let mut map = rooms.lock().unwrap();
    let Some(info) = map.get_mut(room_id) else {
        return Err("NoSuchRoom");
    };
    if info.join_credential != join_credential {
        return Err("BadCredential");
    }
    info.members.insert(member_id, nickname);
    Ok(info.broadcast.clone())
}

pub(crate) fn add_invited_member(
    rooms: &Rooms,
    room_id: &str,
    member_id: String,
    nickname: String,
) -> Option<RoomBroadcast> {
    let mut map = rooms.lock().unwrap();
    let info = map.get_mut(room_id)?;
    info.members.insert(member_id, nickname);
    Some(info.broadcast.clone())
}

pub(crate) fn broadcast_member_list(info: &RoomInfo) {
    let mut members = info
        .members
        .iter()
        .map(|(member_id, nickname)| MemberIdentity {
            member_id: member_id.clone(),
            nickname: nickname.clone(),
        })
        .collect::<Vec<_>>();
    members.sort_by(|a, b| {
        a.nickname
            .cmp(&b.nickname)
            .then_with(|| a.member_id.cmp(&b.member_id))
    });
    let _ = info.broadcast.high_tx.send(ServerEvent::Plain {
        source_member_id: None,
        plain: build_member_list_line(&members),
    });
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use super::{add_invited_member, create_room, join_room, RoomGuard, Rooms};

    fn rooms() -> Rooms {
        Arc::new(Mutex::new(HashMap::new()))
    }

    #[test]
    fn create_room_succeeds_and_duplicate_fails() {
        let rooms = rooms();
        assert!(create_room(
            &rooms,
            "room-a".to_string(),
            "cred".to_string(),
            "alice-id".to_string(),
            "alice".to_string()
        )
        .is_ok());
        assert!(matches!(
            create_room(
                &rooms,
                "room-a".to_string(),
                "cred".to_string(),
                "bob-id".to_string(),
                "bob".to_string()
            ),
            Err("RoomExists")
        ));
    }

    #[test]
    fn join_room_validates_credentials() {
        let rooms = rooms();
        let _ = create_room(
            &rooms,
            "room-a".to_string(),
            "cred".to_string(),
            "alice-id".to_string(),
            "alice".to_string(),
        )
        .unwrap();

        assert!(join_room(
            &rooms,
            "room-a",
            "cred",
            "bob-id".to_string(),
            "bob".to_string()
        )
        .is_ok());
        assert!(matches!(
            join_room(
                &rooms,
                "room-a",
                "wrong",
                "charlie-id".to_string(),
                "charlie".to_string()
            ),
            Err("BadCredential")
        ));
    }

    #[test]
    fn last_member_drop_deletes_room_and_owner_state() {
        let rooms = rooms();
        let (broadcast, _) = create_room(
            &rooms,
            "room-a".to_string(),
            "cred".to_string(),
            "alice-id".to_string(),
            "alice".to_string(),
        )
        .unwrap();
        let _ = add_invited_member(&rooms, "room-a", "bob-id".to_string(), "bob".to_string());

        {
            let guard = RoomGuard {
                rooms: rooms.clone(),
                room_id: "room-a".to_string(),
                member_id: "alice-id".to_string(),
                nickname: "alice".to_string(),
                broadcast: broadcast.clone(),
            };
            drop(guard);
        }

        {
            let map = rooms.lock().unwrap();
            let info = map.get("room-a").expect("room should still exist for bob");
            assert!(info.owner_member_id.is_none());
            assert!(info.owner_capability.is_none());
        }

        let guard = RoomGuard {
            rooms: rooms.clone(),
            room_id: "room-a".to_string(),
            member_id: "bob-id".to_string(),
            nickname: "bob".to_string(),
            broadcast,
        };
        drop(guard);

        assert!(rooms.lock().unwrap().is_empty());
    }
}
