use anyhow::{anyhow, Result};
use base64::{engine::general_purpose as b64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet, VecDeque},
    time::{SystemTime, UNIX_EPOCH},
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const ROOM_JOIN_LABEL: &[u8] = b"rust-chat room-join-credential v1";
const ROOM_AUTH_LABEL: &[u8] = b"rust-chat room-auth-key v1";
const TRANSPORT_C2S_INFO: &[u8] = b"rust-chat transport c2s key v1";
const TRANSPORT_S2C_INFO: &[u8] = b"rust-chat transport s2c key v1";
const AUTH_PROOF_LABEL: &[u8] = b"rust-chat auth proof v1";
const INVITE_PROOF_LABEL: &[u8] = b"rust-chat invite proof v1";
const INVITE_TOKEN_ID_LABEL: &[u8] = b"rust-chat token id v1";
const TRANSPORT_REPLAY_WINDOW: usize = 1024;
const GROUP_SENDER_CHAIN_ROOT_LABEL: &[u8] = b"rust-chat sender-chain-root v1";
const GROUP_SENDER_CHAIN_LABEL: &[u8] = b"rust-chat sender-chain v1";
const CHAIN_NEXT_LABEL: &[u8] = b"rust-chat chain-next v1";
const CHAIN_AEAD_KEY_LABEL: &[u8] = b"rust-chat chain-aead-key v1";
const CHAIN_NONCE_LABEL: &[u8] = b"rust-chat chain-nonce v1";
const PROPOSER_SORT_LABEL: &[u8] = b"rust-chat proposer v1";
const EPOCH_SECRET_WRAP_LABEL: &[u8] = b"rust-chat epoch-secret-wrap v1";
const EPOCH_COMMIT_CONTEXT_LABEL: &[u8] = b"rust-chat epoch-commit-context v1";
const KEY_ANNOUNCE_MAC_LABEL: &[u8] = b"rust-chat key-announce-mac v1";
const CURRENT_PROTOCOL_VERSION: u8 = 1;
const DEFAULT_MAX_SKIP: u64 = 64;
const DEFAULT_SKIPPED_KEY_TTL_SECS: i64 = 300;
const NONCE96_LEN: usize = 12;
const KEY_ANNOUNCE_NONCE_LEN: usize = 16;

pub type MemberId = String;

#[derive(Debug, Clone)]
pub struct GroupCryptoState {
    pub group_id: String,
    pub epoch: u64,
    pub my_member_id: MemberId,
    pub my_sender_chain: Option<ChainState>,
    pub recv_chains: HashMap<MemberId, RecvChainState>,
    pub members: HashMap<MemberId, MemberCryptoInfo>,
    pub old_epochs: Vec<OldEpochState>,
    pub room_auth_key: [u8; 32],
    pub skipped_key_ttl_secs: i64,
    pub default_max_skip: u64,
    pub key_conflicts: HashSet<MemberId>,
    pub pending_transition: Option<PendingRosterTransition>,
    x25519_secret: [u8; 32],
    x25519_public: [u8; 32],
    roster_initialized: bool,
}

#[derive(Debug, Clone)]
pub struct MemberCryptoInfo {
    pub member_id: MemberId,
    pub nickname: String,
    pub x25519_public: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ChainState {
    pub chain_key: [u8; 32],
    pub msg_no: u64,
}

#[derive(Debug, Clone)]
pub struct RecvChainState {
    pub chain_key: [u8; 32],
    pub next_msg_no: u64,
    pub skipped_keys: HashMap<u64, SkippedKey>,
    pub max_skip: u64,
}

#[derive(Debug, Clone)]
pub struct SkippedKey {
    pub aead_key: [u8; 32],
    pub nonce: [u8; NONCE96_LEN],
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct OldEpochState {
    pub epoch: u64,
    pub members: HashMap<MemberId, MemberCryptoInfo>,
    pub recv_chains: HashMap<MemberId, RecvChainState>,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRosterTransition {
    pub old_members: Vec<MemberId>,
    pub new_members: Vec<MemberId>,
    pub event_type: EpochEventType,
    pub affected_member_id: MemberId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecureMessageHeader {
    pub version: u8,
    pub group_id: String,
    pub epoch: u64,
    pub sender_id: MemberId,
    pub msg_no: u64,
    pub msg_type: SecureMessageType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedMessage {
    pub header: SecureMessageHeader,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecureMessageType {
    Text,
    FileManifest,
    FileChunk2,
    KeyAnnounce,
    EpochCommit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedMessage {
    pub header: SecureMessageHeader,
    pub plaintext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemberKeyAnnounce {
    pub group_id: String,
    pub epoch: u64,
    pub member_id: MemberId,
    pub x25519_public: Vec<u8>,
    pub nonce: Vec<u8>,
    pub mac: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EpochEventType {
    Join,
    Leave,
    Kick,
    Rotate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochCommit {
    pub group_id: String,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub event_type: EpochEventType,
    pub affected_member_id: MemberId,
    pub old_roster_hash: String,
    pub new_roster_hash: String,
    pub proposer_id: MemberId,
    pub proposer_attempt: u32,
    pub wrapped_secrets: Vec<WrappedEpochSecret>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WrappedEpochSecret {
    pub recipient_id: MemberId,
    pub proposer_x25519_pub: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochSecretPlain {
    pub group_id: String,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub event_type: EpochEventType,
    pub recipient_id: MemberId,
    pub group_secret: Vec<u8>,
    pub new_roster_hash: String,
}

#[derive(Debug, Clone)]
struct ChainStep {
    next_chain_key: [u8; 32],
    aead_key: [u8; 32],
    nonce: [u8; NONCE96_LEN],
}

#[derive(Debug, Clone)]
pub(crate) struct EpochCommitContext {
    group_id: String,
    old_epoch: u64,
    new_epoch: u64,
    event_type: EpochEventType,
    affected_member_id: MemberId,
    old_roster_hash: String,
    new_roster_hash: String,
    proposer_id: MemberId,
    proposer_attempt: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomCryptoState {
    room_id: String,
    room_credential: String,
    room_key: [u8; 32],
}

impl RoomCryptoState {
    pub fn from_room_credential(
        room_id: impl Into<String>,
        room_credential: impl Into<String>,
    ) -> Self {
        let room_id = room_id.into();
        let room_credential = room_credential.into();
        let digest = md5::Md5::digest(format!("{room_id}{room_credential}").as_bytes());
        let mut room_key = [0u8; 32];
        room_key[..16].copy_from_slice(&digest);
        room_key[16..].copy_from_slice(&digest);
        Self {
            room_id,
            room_credential,
            room_key,
        }
    }

    pub fn room_id(&self) -> &str {
        &self.room_id
    }

    pub fn room_credential(&self) -> &str {
        &self.room_credential
    }

    pub fn join_credential(&self) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.room_key[..16])
            .expect("room join credential");
        mac.update(ROOM_JOIN_LABEL);
        hex::encode(mac.finalize().into_bytes())
    }

    pub fn room_auth_key(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let hk = Hkdf::<Sha256>::new(Some(ROOM_AUTH_LABEL), &self.room_key);
        hk.expand(b"room-auth", &mut out).expect("room auth key");
        out
    }
}

impl GroupCryptoState {
    pub fn new_single_epoch(
        group_id: impl Into<String>,
        my_member_id: impl Into<String>,
        my_nickname: impl Into<String>,
        epoch: u64,
        group_secret: [u8; 32],
        room_auth_key: [u8; 32],
    ) -> Result<Self> {
        let group_id = group_id.into();
        let my_member_id = my_member_id.into();
        let my_nickname = my_nickname.into();
        let mut state = Self::new_pending_epoch(
            group_id.clone(),
            my_member_id.clone(),
            my_nickname,
            epoch,
            room_auth_key,
        )?;
        state.activate_epoch(epoch, group_secret)?;
        Ok(state)
    }

    pub fn new_pending_epoch(
        group_id: impl Into<String>,
        my_member_id: impl Into<String>,
        my_nickname: impl Into<String>,
        epoch: u64,
        room_auth_key: [u8; 32],
    ) -> Result<Self> {
        let group_id = group_id.into();
        let my_member_id = my_member_id.into();
        let my_nickname = my_nickname.into();
        let x25519_secret = random_secret32();
        let x25519_public = x25519_public_from_secret(&x25519_secret);

        let mut members = HashMap::new();
        members.insert(
            my_member_id.clone(),
            MemberCryptoInfo {
                member_id: my_member_id.clone(),
                nickname: my_nickname,
                x25519_public: Some(x25519_public.to_vec()),
            },
        );

        Ok(Self {
            group_id,
            epoch,
            my_member_id,
            my_sender_chain: None,
            recv_chains: HashMap::new(),
            members,
            old_epochs: Vec::new(),
            room_auth_key,
            skipped_key_ttl_secs: DEFAULT_SKIPPED_KEY_TTL_SECS,
            default_max_skip: DEFAULT_MAX_SKIP,
            key_conflicts: HashSet::new(),
            pending_transition: None,
            x25519_secret,
            x25519_public,
            roster_initialized: false,
        })
    }

    pub fn replace_members<I>(&mut self, members: I) -> Result<()>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let mut previous_members = self.members.keys().cloned().collect::<Vec<_>>();
        previous_members.sort();
        let mut next_members = HashMap::new();

        for (member_id, nickname) in members {
            let x25519_public = if member_id == self.my_member_id {
                Some(self.x25519_public.to_vec())
            } else {
                self.members
                    .get(&member_id)
                    .and_then(|info| info.x25519_public.clone())
            };
            next_members.insert(
                member_id.clone(),
                MemberCryptoInfo {
                    member_id: member_id.clone(),
                    nickname,
                    x25519_public,
                },
            );
        }

        if !next_members.contains_key(&self.my_member_id) {
            let nickname = self
                .members
                .get(&self.my_member_id)
                .map(|info| info.nickname.clone())
                .unwrap_or_else(|| self.my_member_id.clone());
            next_members.insert(
                self.my_member_id.clone(),
                MemberCryptoInfo {
                    member_id: self.my_member_id.clone(),
                    nickname,
                    x25519_public: Some(self.x25519_public.to_vec()),
                },
            );
        }

        let mut next_member_ids = next_members.keys().cloned().collect::<Vec<_>>();
        next_member_ids.sort();
        if self.roster_initialized && previous_members != next_member_ids {
            self.pending_transition =
                detect_roster_transition(previous_members.clone(), next_member_ids.clone());
        } else if !self.roster_initialized {
            self.pending_transition = if self.my_sender_chain.is_some() {
                detect_roster_transition(previous_members, next_member_ids.clone())
            } else {
                detect_initial_join_transition(
                    &self.my_member_id,
                    previous_members,
                    next_member_ids.clone(),
                )
            };
            self.roster_initialized = true;
        }

        self.recv_chains
            .retain(|member_id, _| next_members.contains_key(member_id));
        self.members = next_members;
        Ok(())
    }

    pub fn member_display_name(&self, sender_id: &str) -> Option<String> {
        self.members
            .get(sender_id)
            .map(|member| member.nickname.clone())
    }

    pub fn cleanup_expired_skipped_keys(&mut self) {
        let now = unix_timestamp();
        for recv in self.recv_chains.values_mut() {
            recv.skipped_keys.retain(|_, key| key.expires_at > now);
        }
        self.old_epochs
            .retain(|old_epoch| old_epoch.expires_at > now);
        for old_epoch in &mut self.old_epochs {
            for recv in old_epoch.recv_chains.values_mut() {
                recv.skipped_keys.retain(|_, key| key.expires_at > now);
            }
        }
    }

    pub fn local_key_announce(&self) -> MemberKeyAnnounce {
        let mut nonce = vec![0u8; KEY_ANNOUNCE_NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        MemberKeyAnnounce {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            member_id: self.my_member_id.clone(),
            x25519_public: self.x25519_public.to_vec(),
            mac: compute_key_announce_mac(
                &self.room_auth_key,
                &self.group_id,
                self.epoch,
                &self.my_member_id,
                &self.x25519_public,
                &nonce,
            ),
            nonce,
        }
    }

    pub fn apply_key_announce(&mut self, announce: &MemberKeyAnnounce) -> Result<bool> {
        if announce.group_id != self.group_id {
            return Err(anyhow!("Key announce group mismatch"));
        }
        if announce.x25519_public.len() != 32 {
            return Err(anyhow!("Key announce public key length mismatch"));
        }
        if announce.mac
            != compute_key_announce_mac(
                &self.room_auth_key,
                &announce.group_id,
                announce.epoch,
                &announce.member_id,
                &announce.x25519_public,
                &announce.nonce,
            )
        {
            return Err(anyhow!("Key announce MAC mismatch"));
        }
        let Some(member) = self.members.get_mut(&announce.member_id) else {
            return Ok(false);
        };
        if member.x25519_public.as_deref() == Some(announce.x25519_public.as_slice()) {
            return Ok(false);
        }
        if member.x25519_public.is_some() {
            self.key_conflicts.insert(announce.member_id.clone());
            return Err(anyhow!("Key announce public key conflict"));
        }
        member.x25519_public = Some(announce.x25519_public.clone());
        Ok(true)
    }

    pub fn can_build_join_commit(&self) -> bool {
        self.can_build_pending_epoch_commit()
            && self
                .pending_transition
                .as_ref()
                .is_some_and(|pending| pending.event_type == EpochEventType::Join)
    }

    pub fn can_build_pending_epoch_commit(&self) -> bool {
        if self.my_sender_chain.is_none() {
            return false;
        }
        let Some(pending) = self.pending_transition.as_ref() else {
            return false;
        };
        let proposer = proposer_order(
            &self.group_id,
            self.epoch,
            pending.event_type.clone(),
            &pending.affected_member_id,
            &proposer_candidates_for_event(
                pending.event_type.clone(),
                &pending.old_members,
                &pending.new_members,
            ),
        );
        if proposer.first() != Some(&self.my_member_id) {
            return false;
        }
        pending.new_members.iter().all(|member_id| {
            self.members
                .get(member_id)
                .and_then(|member| member.x25519_public.as_ref())
                .map(|public| public.len() == 32)
                .unwrap_or(false)
        })
    }

    pub fn build_join_epoch_commit(&mut self) -> Result<Option<EpochCommit>> {
        let Some(pending) = self.pending_transition.as_ref() else {
            return Ok(None);
        };
        if pending.event_type != EpochEventType::Join {
            return Ok(None);
        }
        self.build_pending_epoch_commit()
    }

    pub fn build_pending_epoch_commit(&mut self) -> Result<Option<EpochCommit>> {
        if !self.can_build_pending_epoch_commit() {
            return Ok(None);
        }
        let pending = self
            .pending_transition
            .clone()
            .ok_or_else(|| anyhow!("Missing pending transition"))?;
        let candidates = proposer_candidates_for_event(
            pending.event_type.clone(),
            &pending.old_members,
            &pending.new_members,
        );
        let proposer = proposer_order(
            &self.group_id,
            self.epoch,
            pending.event_type.clone(),
            &pending.affected_member_id,
            &candidates,
        );
        if proposer.first() != Some(&self.my_member_id) {
            return Ok(None);
        }

        let mut group_secret = random_secret32();
        let old_roster_hash = roster_hash(&pending.old_members);
        let new_roster_hash = roster_hash(&pending.new_members);
        let context = EpochCommitContext {
            group_id: self.group_id.clone(),
            old_epoch: self.epoch,
            new_epoch: self.epoch.saturating_add(1),
            event_type: pending.event_type.clone(),
            affected_member_id: pending.affected_member_id.clone(),
            old_roster_hash: old_roster_hash.clone(),
            new_roster_hash: new_roster_hash.clone(),
            proposer_id: self.my_member_id.clone(),
            proposer_attempt: 0,
        };

        let mut wrapped_secrets = Vec::with_capacity(pending.new_members.len());
        for recipient_id in &pending.new_members {
            let recipient_public = self
                .members
                .get(recipient_id)
                .and_then(|member| member.x25519_public.as_ref())
                .ok_or_else(|| anyhow!("Missing recipient X25519 public key for {recipient_id}"))?;
            let plain = EpochSecretPlain {
                group_id: context.group_id.clone(),
                old_epoch: context.old_epoch,
                new_epoch: context.new_epoch,
                event_type: context.event_type.clone(),
                recipient_id: recipient_id.clone(),
                group_secret: group_secret.to_vec(),
                new_roster_hash: context.new_roster_hash.clone(),
            };
            wrapped_secrets.push(wrap_epoch_secret_for_recipient(
                recipient_id,
                recipient_public,
                &self.x25519_secret,
                &self.room_auth_key,
                &context,
                &plain,
            )?);
        }
        zeroize(&mut group_secret);

        Ok(Some(EpochCommit {
            group_id: context.group_id,
            old_epoch: context.old_epoch,
            new_epoch: context.new_epoch,
            event_type: context.event_type,
            affected_member_id: context.affected_member_id,
            old_roster_hash: context.old_roster_hash,
            new_roster_hash: context.new_roster_hash,
            proposer_id: context.proposer_id,
            proposer_attempt: context.proposer_attempt,
            wrapped_secrets,
        }))
    }

    pub fn apply_epoch_commit(&mut self, commit: &EpochCommit) -> Result<bool> {
        let pending = match self.pending_transition.clone() {
            Some(pending) => pending,
            None if commit.old_epoch < self.epoch || commit.new_epoch <= self.epoch => {
                return Ok(false);
            }
            None => return Err(anyhow!("Missing pending transition for epoch commit")),
        };
        let expected_old_epoch = if self.can_accept_join_commit_from_later_epoch(&pending, commit) {
            commit.old_epoch
        } else {
            self.epoch
        };

        validate_epoch_commit(
            &self.group_id,
            expected_old_epoch,
            commit,
            &pending.old_members,
            &pending.new_members,
        )?;

        let wrapped = commit
            .wrapped_secrets
            .iter()
            .find(|wrapped| wrapped.recipient_id == self.my_member_id)
            .ok_or_else(|| anyhow!("Epoch commit is missing my wrapped secret"))?;
        let plain = unwrap_epoch_secret_from_commit(
            &self.my_member_id,
            &self.x25519_secret,
            &self.room_auth_key,
            commit,
            wrapped,
        )?;
        if plain.group_id != commit.group_id {
            return Err(anyhow!("Wrapped epoch secret group_id mismatch"));
        }
        if plain.old_epoch != commit.old_epoch {
            return Err(anyhow!("Wrapped epoch secret old_epoch mismatch"));
        }
        if plain.new_epoch != commit.new_epoch {
            return Err(anyhow!("Wrapped epoch secret new_epoch mismatch"));
        }
        if plain.event_type != commit.event_type {
            return Err(anyhow!("Wrapped epoch secret event_type mismatch"));
        }
        if plain.recipient_id != self.my_member_id {
            return Err(anyhow!("Wrapped epoch secret recipient mismatch"));
        }
        if plain.new_roster_hash != commit.new_roster_hash {
            return Err(anyhow!("Wrapped epoch secret roster hash mismatch"));
        }
        if plain.group_secret.len() != 32 {
            return Err(anyhow!("Wrapped epoch secret length mismatch"));
        }

        let mut group_secret = [0u8; 32];
        group_secret.copy_from_slice(&plain.group_secret);
        self.activate_epoch(commit.new_epoch, group_secret)?;
        Ok(true)
    }

    pub fn current_x25519_public(&self) -> &[u8; 32] {
        &self.x25519_public
    }

    #[cfg(test)]
    pub fn current_x25519_secret_for_test(&self) -> [u8; 32] {
        self.x25519_secret
    }

    #[cfg(test)]
    pub fn install_test_recv_chains_for_current_roster(
        &mut self,
        mut group_secret: [u8; 32],
    ) -> Result<()> {
        let mut sender_chain_root =
            derive_sender_chain_root(&group_secret, &self.group_id, self.epoch)?;
        let mut recv_chains = HashMap::new();
        for member_id in self.members.keys() {
            if member_id == &self.my_member_id {
                continue;
            }
            let chain_key = derive_sender_chain_key(&sender_chain_root, member_id)?;
            recv_chains.insert(
                member_id.clone(),
                RecvChainState::new(chain_key, self.default_max_skip),
            );
        }
        self.recv_chains = recv_chains;
        zeroize(&mut sender_chain_root);
        zeroize(&mut group_secret);
        Ok(())
    }

    fn can_accept_join_commit_from_later_epoch(
        &self,
        pending: &PendingRosterTransition,
        commit: &EpochCommit,
    ) -> bool {
        self.epoch < commit.old_epoch
            && pending.event_type == EpochEventType::Join
            && commit.event_type == EpochEventType::Join
            && pending.affected_member_id == self.my_member_id
            && commit.affected_member_id == self.my_member_id
            && !pending.old_members.contains(&self.my_member_id)
            && pending.new_members.contains(&self.my_member_id)
    }

    fn activate_epoch(&mut self, new_epoch: u64, mut group_secret: [u8; 32]) -> Result<()> {
        if self.my_sender_chain.is_some() {
            let expires_at = unix_timestamp() + self.skipped_key_ttl_secs;
            self.old_epochs.push(OldEpochState {
                epoch: self.epoch,
                members: self.members.clone(),
                recv_chains: self.recv_chains.clone(),
                expires_at,
            });
            self.old_epochs
                .retain(|old| old.expires_at > unix_timestamp());
        }

        let mut sender_chain_root =
            derive_sender_chain_root(&group_secret, &self.group_id, new_epoch)?;
        let my_sender_chain = ChainState {
            chain_key: derive_sender_chain_key(&sender_chain_root, &self.my_member_id)?,
            msg_no: 0,
        };

        let mut next_recv_chains = HashMap::new();
        for member_id in self.members.keys() {
            if member_id == &self.my_member_id {
                continue;
            }
            let chain_key = derive_sender_chain_key(&sender_chain_root, member_id)?;
            next_recv_chains.insert(
                member_id.clone(),
                RecvChainState::new(chain_key, self.default_max_skip),
            );
        }
        zeroize(&mut sender_chain_root);

        let mut previous_x25519_secret = self.x25519_secret;
        zeroize(&mut self.x25519_secret);
        self.x25519_secret = random_secret32();
        self.x25519_public = x25519_public_from_secret(&self.x25519_secret);
        zeroize(&mut previous_x25519_secret);
        for (member_id, member) in &mut self.members {
            if member_id == &self.my_member_id {
                member.x25519_public = Some(self.x25519_public.to_vec());
            } else {
                member.x25519_public = None;
            }
        }

        self.epoch = new_epoch;
        self.my_sender_chain = Some(my_sender_chain);
        self.recv_chains = next_recv_chains;
        self.pending_transition = None;
        zeroize(&mut group_secret);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct TransportCrypto {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_seq: u64,
    next_recv_seq: u64,
    recent_recv_seqs: VecDeque<u64>,
    seen_recv_seqs: HashSet<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportSide {
    Client,
    Server,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportOpenResult {
    Fresh(String),
    Duplicate(String),
}

impl TransportCrypto {
    pub fn new(shared_secret: [u8; 32], side: TransportSide) -> Self {
        let (send_info, recv_info) = match side {
            TransportSide::Client => (TRANSPORT_C2S_INFO, TRANSPORT_S2C_INFO),
            TransportSide::Server => (TRANSPORT_S2C_INFO, TRANSPORT_C2S_INFO),
        };
        Self {
            send_key: transport_direction_key(&shared_secret, send_info),
            recv_key: transport_direction_key(&shared_secret, recv_info),
            send_seq: 0,
            next_recv_seq: 0,
            recent_recv_seqs: VecDeque::new(),
            seen_recv_seqs: HashSet::new(),
        }
    }

    pub fn send_key(&self) -> &[u8; 32] {
        &self.send_key
    }

    pub fn recv_key(&self) -> &[u8; 32] {
        &self.recv_key
    }

    pub fn seal(&mut self, plain: &str) -> String {
        let cipher = aead_seal_sequenced(&self.send_key, self.send_seq, plain.as_bytes());
        self.send_seq = self.send_seq.wrapping_add(1);
        cipher
    }

    pub fn open(&mut self, cipher_line: &str) -> Option<TransportOpenResult> {
        let (seq, plain) = aead_open_sequenced(&self.recv_key, cipher_line)?;
        let plain = String::from_utf8(plain).ok()?;

        if seq == self.next_recv_seq {
            self.mark_seq_seen(seq);
            self.next_recv_seq = self.next_recv_seq.wrapping_add(1);
            return Some(TransportOpenResult::Fresh(plain));
        }

        if seq < self.next_recv_seq && self.seen_recv_seqs.contains(&seq) {
            return Some(TransportOpenResult::Duplicate(plain));
        }

        None
    }

    fn mark_seq_seen(&mut self, seq: u64) {
        self.recent_recv_seqs.push_back(seq);
        self.seen_recv_seqs.insert(seq);
        while self.recent_recv_seqs.len() > TRANSPORT_REPLAY_WINDOW {
            if let Some(evicted) = self.recent_recv_seqs.pop_front() {
                self.seen_recv_seqs.remove(&evicted);
            }
        }
    }
}

impl RecvChainState {
    pub fn new(chain_key: [u8; 32], max_skip: u64) -> Self {
        Self {
            chain_key,
            next_msg_no: 0,
            skipped_keys: HashMap::new(),
            max_skip,
        }
    }
}

pub fn hkdf_expand_label(
    secret: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    out: &mut [u8],
) -> Result<()> {
    Hkdf::<Sha256>::new(salt, secret)
        .expand(info, out)
        .map_err(|_| anyhow!("HKDF expand failed"))
}

pub fn zeroize(bytes: &mut [u8]) {
    bytes.fill(0);
}

pub fn encrypt_message(
    state: &mut GroupCryptoState,
    msg_type: SecureMessageType,
    plaintext: &[u8],
) -> Result<EncryptedMessage> {
    state.cleanup_expired_skipped_keys();

    let sender_chain = state
        .my_sender_chain
        .as_mut()
        .ok_or_else(|| anyhow!("Current epoch secret unavailable"))?;
    let mut step = derive_chain_step(&sender_chain.chain_key)?;
    let header = SecureMessageHeader {
        version: CURRENT_PROTOCOL_VERSION,
        group_id: state.group_id.clone(),
        epoch: state.epoch,
        sender_id: state.my_member_id.clone(),
        msg_no: sender_chain.msg_no,
        msg_type,
    };
    let aad = serde_json::to_vec(&header)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&step.aead_key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&step.nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("Secure message encryption failed"))?;

    sender_chain.chain_key = step.next_chain_key;
    sender_chain.msg_no = sender_chain.msg_no.saturating_add(1);
    zeroize(&mut step.aead_key);
    zeroize(&mut step.nonce);

    Ok(EncryptedMessage { header, ciphertext })
}

pub fn decrypt_message(
    state: &mut GroupCryptoState,
    message: &EncryptedMessage,
) -> Result<DecryptedMessage> {
    state.cleanup_expired_skipped_keys();

    if message.header.version != CURRENT_PROTOCOL_VERSION {
        return Err(anyhow!("Unsupported secure message version"));
    }
    if message.header.group_id != state.group_id {
        return Err(anyhow!("Group ID mismatch"));
    }
    if message.header.sender_id == state.my_member_id {
        return Err(anyhow!("Ignoring reflected self message"));
    }
    if message.header.epoch == state.epoch {
        if state.my_sender_chain.is_none() {
            return Err(anyhow!("Current epoch secret unavailable"));
        }
        return decrypt_for_epoch(
            &state.members,
            &mut state.recv_chains,
            state.skipped_key_ttl_secs,
            message,
        );
    }

    if let Some(old_epoch) = state
        .old_epochs
        .iter_mut()
        .find(|old_epoch| old_epoch.epoch == message.header.epoch)
    {
        return decrypt_for_epoch(
            &old_epoch.members,
            &mut old_epoch.recv_chains,
            state.skipped_key_ttl_secs,
            message,
        );
    }

    Err(anyhow!("Epoch mismatch"))
}

pub fn proposer_order(
    group_id: &str,
    old_epoch: u64,
    event_type: EpochEventType,
    affected_member_id: &str,
    candidates: &[MemberId],
) -> Vec<MemberId> {
    let mut ranked = candidates
        .iter()
        .map(|candidate| {
            let mut hasher = Sha256::new();
            hasher.update(PROPOSER_SORT_LABEL);
            hasher.update(group_id.as_bytes());
            hasher.update(old_epoch.to_be_bytes());
            hasher.update(epoch_event_type_tag(&event_type));
            hasher.update(affected_member_id.as_bytes());
            hasher.update(candidate.as_bytes());
            (candidate.clone(), hasher.finalize().to_vec())
        })
        .collect::<Vec<_>>();

    ranked.sort_by(|(left_id, left_hash), (right_id, right_hash)| {
        match left_hash.cmp(right_hash) {
            Ordering::Equal => left_id.cmp(right_id),
            other => other,
        }
    });
    ranked.into_iter().map(|(candidate, _)| candidate).collect()
}

pub fn roster_hash(member_ids: &[MemberId]) -> String {
    let mut canonical = member_ids.to_vec();
    canonical.sort();
    let mut hasher = Sha256::new();
    for member_id in canonical {
        hasher.update(member_id.as_bytes());
        hasher.update([0u8]);
    }
    hex::encode(hasher.finalize())
}

pub fn validate_epoch_commit(
    local_group_id: &str,
    local_epoch: u64,
    commit: &EpochCommit,
    old_members: &[MemberId],
    new_members: &[MemberId],
) -> Result<()> {
    if commit.group_id != local_group_id {
        return Err(anyhow!("Epoch commit group mismatch"));
    }
    if commit.old_epoch != local_epoch {
        return Err(anyhow!("Epoch commit old_epoch mismatch"));
    }
    if commit.new_epoch != commit.old_epoch.saturating_add(1) {
        return Err(anyhow!("Epoch commit new_epoch is not old_epoch + 1"));
    }
    if commit.old_roster_hash != roster_hash(old_members) {
        return Err(anyhow!("Epoch commit old roster hash mismatch"));
    }
    if commit.new_roster_hash != roster_hash(new_members) {
        return Err(anyhow!("Epoch commit new roster hash mismatch"));
    }

    let candidates =
        proposer_candidates_for_event(commit.event_type.clone(), old_members, new_members);
    let ordered = proposer_order(
        &commit.group_id,
        commit.old_epoch,
        commit.event_type.clone(),
        &commit.affected_member_id,
        &candidates,
    );
    let expected = ordered
        .get(commit.proposer_attempt as usize)
        .ok_or_else(|| anyhow!("Epoch commit proposer attempt out of range"))?;
    if expected != &commit.proposer_id {
        return Err(anyhow!("Epoch commit proposer is not locally valid"));
    }

    let mut wrapped_recipients = commit
        .wrapped_secrets
        .iter()
        .map(|wrapped| wrapped.recipient_id.clone())
        .collect::<Vec<_>>();
    wrapped_recipients.sort();
    wrapped_recipients.dedup();
    let mut expected_recipients = new_members.to_vec();
    expected_recipients.sort();
    if wrapped_recipients != expected_recipients {
        return Err(anyhow!("Epoch commit wrapped recipient set mismatch"));
    }

    Ok(())
}

pub(crate) fn wrap_epoch_secret_for_recipient(
    recipient_id: &str,
    recipient_x25519_public: &[u8],
    proposer_x25519_secret: &[u8],
    room_auth_key: &[u8; 32],
    context: &EpochCommitContext,
    plain: &EpochSecretPlain,
) -> Result<WrappedEpochSecret> {
    let proposer_secret = bytes32_from_slice(proposer_x25519_secret)?;
    let recipient_public = bytes32_from_slice(recipient_x25519_public)?;
    let proposer_secret = StaticSecret::from(proposer_secret);
    let recipient_public = X25519PublicKey::from(recipient_public);
    let proposer_public = X25519PublicKey::from(&proposer_secret);
    let dh = proposer_secret.diffie_hellman(&recipient_public);

    let mut wrap_key = [0u8; 32];
    hkdf_expand_label(
        dh.as_bytes(),
        Some(room_auth_key),
        EPOCH_SECRET_WRAP_LABEL,
        &mut wrap_key,
    )?;

    let plain_bytes = serde_json::to_vec(plain)?;
    let aad = epoch_commit_context_hash(context, recipient_id);
    let mut nonce = [0u8; NONCE96_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&wrap_key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plain_bytes.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("Epoch secret wrapping failed"))?;
    zeroize(&mut wrap_key);

    Ok(WrappedEpochSecret {
        recipient_id: recipient_id.to_string(),
        proposer_x25519_pub: proposer_public.as_bytes().to_vec(),
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

pub(crate) fn unwrap_epoch_secret_from_commit(
    my_member_id: &str,
    my_x25519_secret: &[u8],
    room_auth_key: &[u8; 32],
    commit: &EpochCommit,
    wrapped: &WrappedEpochSecret,
) -> Result<EpochSecretPlain> {
    if wrapped.recipient_id != my_member_id {
        return Err(anyhow!("Wrapped epoch secret recipient mismatch"));
    }
    if wrapped.nonce.len() != NONCE96_LEN {
        return Err(anyhow!("Wrapped epoch secret nonce length mismatch"));
    }

    let my_secret = StaticSecret::from(bytes32_from_slice(my_x25519_secret)?);
    let proposer_public = X25519PublicKey::from(bytes32_from_slice(&wrapped.proposer_x25519_pub)?);
    let dh = my_secret.diffie_hellman(&proposer_public);
    let mut wrap_key = [0u8; 32];
    hkdf_expand_label(
        dh.as_bytes(),
        Some(room_auth_key),
        EPOCH_SECRET_WRAP_LABEL,
        &mut wrap_key,
    )?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&wrap_key));
    let context = EpochCommitContext {
        group_id: commit.group_id.clone(),
        old_epoch: commit.old_epoch,
        new_epoch: commit.new_epoch,
        event_type: commit.event_type.clone(),
        affected_member_id: commit.affected_member_id.clone(),
        old_roster_hash: commit.old_roster_hash.clone(),
        new_roster_hash: commit.new_roster_hash.clone(),
        proposer_id: commit.proposer_id.clone(),
        proposer_attempt: commit.proposer_attempt,
    };
    let aad = epoch_commit_context_hash(&context, my_member_id);
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&wrapped.nonce),
            Payload {
                msg: wrapped.ciphertext.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("Epoch secret unwrap failed"))?;
    zeroize(&mut wrap_key);

    serde_json::from_slice(&plaintext).map_err(|err| anyhow!("Invalid wrapped epoch secret: {err}"))
}

fn proposer_candidates_for_event(
    event_type: EpochEventType,
    old_members: &[MemberId],
    new_members: &[MemberId],
) -> Vec<MemberId> {
    match event_type {
        EpochEventType::Join => old_members.to_vec(),
        EpochEventType::Leave | EpochEventType::Kick => new_members.to_vec(),
        EpochEventType::Rotate => new_members.to_vec(),
    }
}

fn compute_key_announce_mac(
    room_auth_key: &[u8; 32],
    group_id: &str,
    epoch: u64,
    member_id: &str,
    x25519_public: &[u8],
    nonce: &[u8],
) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(room_auth_key).expect("key announce mac");
    mac.update(KEY_ANNOUNCE_MAC_LABEL);
    mac.update(&canonical_bytes(&[
        group_id.as_bytes(),
        &epoch.to_be_bytes(),
        member_id.as_bytes(),
        x25519_public,
        nonce,
    ]));
    mac.finalize().into_bytes().to_vec()
}

fn epoch_commit_context_hash(context: &EpochCommitContext, recipient_id: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(EPOCH_COMMIT_CONTEXT_LABEL);
    hasher.update(canonical_bytes(&[
        context.group_id.as_bytes(),
        &context.old_epoch.to_be_bytes(),
        &context.new_epoch.to_be_bytes(),
        epoch_event_type_tag(&context.event_type),
        context.affected_member_id.as_bytes(),
        context.old_roster_hash.as_bytes(),
        context.new_roster_hash.as_bytes(),
        context.proposer_id.as_bytes(),
        &context.proposer_attempt.to_be_bytes(),
        recipient_id.as_bytes(),
    ]));
    hasher.finalize().to_vec()
}

fn canonical_bytes(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for field in fields {
        out.extend_from_slice(&(field.len() as u64).to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

fn transport_direction_key(shared_secret: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; KEY_LEN];
    hk.expand(info, &mut key).expect("transport direction key");
    key
}

fn transport_nonce(seq: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    nonce
}

fn aead_seal_sequenced(transport_key: &[u8; 32], seq: u64, plain: &[u8]) -> String {
    let nonce = transport_nonce(seq);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(transport_key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plain)
        .expect("transport encrypt");

    let mut out = Vec::with_capacity(8 + ciphertext.len());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&ciphertext);
    b64::STANDARD.encode(out)
}

fn aead_open_sequenced(transport_key: &[u8; 32], encoded: &str) -> Option<(u64, Vec<u8>)> {
    let decoded = b64::STANDARD.decode(encoded).ok()?;
    if decoded.len() < 8 + 16 {
        return None;
    }

    let (seq_bytes, ct) = decoded.split_at(8);
    let seq = u64::from_be_bytes(seq_bytes.try_into().ok()?);
    let nonce = transport_nonce(seq);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(transport_key));
    let plain = cipher.decrypt(Nonce::from_slice(&nonce), ct).ok()?;
    Some((seq, plain))
}

fn derive_sender_chain_root(
    group_secret: &[u8; 32],
    group_id: &str,
    epoch: u64,
) -> Result<[u8; 32]> {
    let mut info = Vec::new();
    info.extend_from_slice(GROUP_SENDER_CHAIN_ROOT_LABEL);
    info.extend_from_slice(group_id.as_bytes());
    info.extend_from_slice(&epoch.to_be_bytes());

    let mut out = [0u8; 32];
    hkdf_expand_label(group_secret, None, &info, &mut out)?;
    Ok(out)
}

fn derive_sender_chain_key(sender_chain_root: &[u8; 32], sender_id: &str) -> Result<[u8; 32]> {
    let mut info = Vec::new();
    info.extend_from_slice(GROUP_SENDER_CHAIN_LABEL);
    info.extend_from_slice(sender_id.as_bytes());

    let mut out = [0u8; 32];
    hkdf_expand_label(sender_chain_root, None, &info, &mut out)?;
    Ok(out)
}

fn derive_chain_step(chain_key: &[u8; 32]) -> Result<ChainStep> {
    let mut next_chain_key = [0u8; 32];
    let mut aead_key = [0u8; 32];
    let mut nonce = [0u8; NONCE96_LEN];
    hkdf_expand_label(chain_key, None, CHAIN_NEXT_LABEL, &mut next_chain_key)?;
    hkdf_expand_label(chain_key, None, CHAIN_AEAD_KEY_LABEL, &mut aead_key)?;
    hkdf_expand_label(chain_key, None, CHAIN_NONCE_LABEL, &mut nonce)?;
    Ok(ChainStep {
        next_chain_key,
        aead_key,
        nonce,
    })
}

fn open_with_skipped_key(
    recv: &mut RecvChainState,
    aad: &[u8],
    message: &EncryptedMessage,
) -> Result<DecryptedMessage> {
    let Some(skipped) = recv.skipped_keys.get(&message.header.msg_no).cloned() else {
        return Err(anyhow!("Missing skipped key for stale message"));
    };

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&skipped.aead_key));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&skipped.nonce),
            Payload {
                msg: &message.ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("Skipped secure message authentication failed"))?;
    recv.skipped_keys.remove(&message.header.msg_no);

    Ok(DecryptedMessage {
        header: message.header.clone(),
        plaintext,
    })
}

fn decrypt_for_epoch(
    members: &HashMap<MemberId, MemberCryptoInfo>,
    recv_chains: &mut HashMap<MemberId, RecvChainState>,
    skipped_key_ttl_secs: i64,
    message: &EncryptedMessage,
) -> Result<DecryptedMessage> {
    if !members.contains_key(&message.header.sender_id) {
        return Err(anyhow!("Sender is not in epoch roster"));
    }

    let recv = recv_chains
        .get_mut(&message.header.sender_id)
        .ok_or_else(|| anyhow!("Missing receive chain for sender"))?;

    let aad = serde_json::to_vec(&message.header)?;
    if message.header.msg_no < recv.next_msg_no {
        return open_with_skipped_key(recv, &aad, message);
    }

    let gap = message.header.msg_no.saturating_sub(recv.next_msg_no);
    if gap > recv.max_skip {
        return Err(anyhow!("Message gap exceeds MAX_SKIP"));
    }

    let mut temp_chain_key = recv.chain_key;
    let mut temp_next_msg_no = recv.next_msg_no;
    let mut temp_skipped = recv.skipped_keys.clone();
    let now = unix_timestamp();

    while temp_next_msg_no < message.header.msg_no {
        let step = derive_chain_step(&temp_chain_key)?;
        temp_skipped.insert(
            temp_next_msg_no,
            SkippedKey {
                aead_key: step.aead_key,
                nonce: step.nonce,
                expires_at: now + skipped_key_ttl_secs,
            },
        );
        trim_skipped_keys(&mut temp_skipped, recv.max_skip, now);
        temp_chain_key = step.next_chain_key;
        temp_next_msg_no += 1;
    }

    let mut target_step = derive_chain_step(&temp_chain_key)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&target_step.aead_key));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&target_step.nonce),
            Payload {
                msg: &message.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("Secure message authentication failed"))?;

    recv.chain_key = target_step.next_chain_key;
    recv.next_msg_no = message.header.msg_no.saturating_add(1);
    recv.skipped_keys = temp_skipped;

    zeroize(&mut target_step.aead_key);
    zeroize(&mut target_step.nonce);

    Ok(DecryptedMessage {
        header: message.header.clone(),
        plaintext,
    })
}

fn trim_skipped_keys(skipped_keys: &mut HashMap<u64, SkippedKey>, max_skip: u64, now: i64) {
    skipped_keys.retain(|_, key| key.expires_at > now);
    if skipped_keys.len() <= max_skip as usize {
        return;
    }

    let mut msg_nos = skipped_keys.keys().copied().collect::<Vec<_>>();
    msg_nos.sort_unstable();
    while skipped_keys.len() > max_skip as usize {
        let Some(oldest_msg_no) = msg_nos.first().copied() else {
            break;
        };
        skipped_keys.remove(&oldest_msg_no);
        msg_nos.remove(0);
    }
}

fn epoch_event_type_tag(event_type: &EpochEventType) -> &'static [u8] {
    match event_type {
        EpochEventType::Join => b"join",
        EpochEventType::Leave => b"leave",
        EpochEventType::Kick => b"kick",
        EpochEventType::Rotate => b"rotate",
    }
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

fn detect_roster_transition(
    mut old_members: Vec<MemberId>,
    mut new_members: Vec<MemberId>,
) -> Option<PendingRosterTransition> {
    old_members.sort();
    new_members.sort();

    let added = new_members
        .iter()
        .filter(|member_id| !old_members.contains(*member_id))
        .cloned()
        .collect::<Vec<_>>();
    let removed = old_members
        .iter()
        .filter(|member_id| !new_members.contains(*member_id))
        .cloned()
        .collect::<Vec<_>>();

    match (added.len(), removed.len()) {
        (1, 0) => Some(PendingRosterTransition {
            old_members,
            new_members,
            event_type: EpochEventType::Join,
            affected_member_id: added[0].clone(),
        }),
        (0, 1) => Some(PendingRosterTransition {
            old_members,
            new_members,
            event_type: EpochEventType::Leave,
            affected_member_id: removed[0].clone(),
        }),
        _ => None,
    }
}

fn detect_initial_join_transition(
    my_member_id: &str,
    mut previous_members: Vec<MemberId>,
    mut next_members: Vec<MemberId>,
) -> Option<PendingRosterTransition> {
    previous_members.sort();
    next_members.sort();

    if previous_members != vec![my_member_id.to_string()] {
        return None;
    }
    if next_members.len() <= 1
        || !next_members
            .iter()
            .any(|member_id| member_id == my_member_id)
    {
        return None;
    }

    let old_members = next_members
        .iter()
        .filter(|member_id| member_id.as_str() != my_member_id)
        .cloned()
        .collect::<Vec<_>>();
    if old_members.is_empty() {
        return None;
    }

    Some(PendingRosterTransition {
        old_members,
        new_members: next_members,
        event_type: EpochEventType::Join,
        affected_member_id: my_member_id.to_string(),
    })
}

fn random_secret32() -> [u8; 32] {
    let mut secret = [0u8; 32];
    rand::rng().fill_bytes(&mut secret);
    secret
}

pub fn random_group_secret_epoch_0() -> [u8; 32] {
    random_secret32()
}

#[cfg(test)]
pub fn random_test_epoch_secret() -> [u8; 32] {
    random_secret32()
}

fn x25519_public_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*secret);
    X25519PublicKey::from(&secret).to_bytes()
}

fn bytes32_from_slice(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("Expected a 32-byte field"))
}

pub fn pwd_hash(pwd: &str) -> [u8; 32] {
    let h = Sha256::digest(pwd.as_bytes());
    h[..].try_into().unwrap()
}

pub fn derive_password_transport_key(
    server_pwd_hash: &[u8; 32],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> [u8; 32] {
    derive_transport_key(
        server_pwd_hash,
        b"rust-chat password transport v1",
        &[client_nonce, server_nonce],
    )
}

pub fn compute_password_auth_proof(
    server_pwd_hash: &[u8; 32],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> [u8; 32] {
    compute_handshake_proof(
        server_pwd_hash,
        AUTH_PROOF_LABEL,
        &[client_nonce, server_nonce],
    )
}

pub fn compute_invite_token_id(token_secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(INVITE_TOKEN_ID_LABEL);
    hasher.update(token_secret);
    hasher.finalize().into()
}

pub fn derive_invite_transport_key(
    token_secret: &[u8],
    token_id: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> [u8; 32] {
    derive_transport_key(
        token_secret,
        b"rust-chat invite transport v1",
        &[token_id, client_nonce, server_nonce],
    )
}

pub fn compute_invite_proof(
    token_secret: &[u8],
    token_id: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> [u8; 32] {
    compute_handshake_proof(
        token_secret,
        INVITE_PROOF_LABEL,
        &[token_id, client_nonce, server_nonce],
    )
}

fn derive_transport_key(secret: &[u8], label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut salt = Vec::new();
    for part in parts {
        salt.extend_from_slice(part);
    }
    let hk = Hkdf::<Sha256>::new(Some(&salt), secret);
    let mut out = [0u8; 32];
    hk.expand(label, &mut out).expect("transport key");
    out
}

fn compute_handshake_proof(secret: &[u8], label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("handshake proof");
    mac.update(label);
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}
