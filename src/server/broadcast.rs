use tokio::sync::broadcast;

#[derive(Clone, Debug)]
pub(crate) enum ServerEvent {
    Plain {
        source_member_id: Option<String>,
        plain: String,
    },
}

#[derive(Clone)]
pub(crate) struct RoomBroadcast {
    pub(crate) high_tx: broadcast::Sender<ServerEvent>,
    pub(crate) low_tx: broadcast::Sender<ServerEvent>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BroadcastPriority {
    High,
    Low,
}

pub(crate) fn new_room_broadcast() -> RoomBroadcast {
    let (high_tx, _) = broadcast::channel::<ServerEvent>(500);
    let (low_tx, _) = broadcast::channel::<ServerEvent>(500);
    RoomBroadcast { high_tx, low_tx }
}

pub(crate) fn packet_priority(packet_id: &str) -> BroadcastPriority {
    if packet_id.starts_with("att-") {
        BroadcastPriority::Low
    } else {
        BroadcastPriority::High
    }
}

pub(crate) fn broadcast_room_event(
    broadcast: &RoomBroadcast,
    priority: BroadcastPriority,
    event: ServerEvent,
) {
    let sender = match priority {
        BroadcastPriority::High => &broadcast.high_tx,
        BroadcastPriority::Low => &broadcast.low_tx,
    };
    let _ = sender.send(event);
}

#[cfg(test)]
mod tests {
    use super::{packet_priority, BroadcastPriority};

    #[test]
    fn attachment_packets_are_low_priority() {
        assert_eq!(packet_priority("att-abc-meta"), BroadcastPriority::Low);
        assert_eq!(packet_priority("att-abc-chunk-0"), BroadcastPriority::Low);
    }

    #[test]
    fn text_packets_are_high_priority() {
        assert_eq!(packet_priority("msg-abc"), BroadcastPriority::High);
        assert_eq!(packet_priority("epoch-1"), BroadcastPriority::High);
    }
}
