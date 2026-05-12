use std::sync::{Arc, Mutex};

use tokio::{
    io::{BufReader, Lines},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
};

use crate::{
    crypto::{GroupCryptoState, RoomCryptoState, TransportCrypto},
    protocol::MemberIdentity,
};

pub type SharedTransportCrypto = Arc<Mutex<TransportCrypto>>;
pub type SharedGroupCrypto = Arc<Mutex<GroupCryptoState>>;

pub struct ConnectedSession {
    pub lines: Lines<BufReader<OwnedReadHalf>>,
    pub writer: OwnedWriteHalf,
    pub server_addr: String,
    pub room_crypto: RoomCryptoState,
    pub group_crypto: SharedGroupCrypto,
    pub transport: SharedTransportCrypto,
    pub local_member: MemberIdentity,
    pub owner_capability: Option<String>,
}
