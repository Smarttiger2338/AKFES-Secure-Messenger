use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::AkfesError;
use crate::types::{ChainKey, MessageKey, RootKey};

const MAX_SKIP: u32 = 64;
const REPLAY_WINDOW: u32 = 128;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetSnapshot {
    pub root_key: [u8; 32],
    pub send_chain: Option<[u8; 32]>,
    pub recv_chain: Option<[u8; 32]>,
    pub send_count: u32,
    pub recv_count: u32,
    pub skipped: HashMap<u32, [u8; 32]>,
    pub received: HashSet<u32>,
}

#[derive(Clone)]
pub struct RatchetState {
    root_key: RootKey,
    send_chain: Option<ChainKey>,
    recv_chain: Option<ChainKey>,
    send_count: u32,
    recv_count: u32,
    skipped: HashMap<u32, MessageKey>,
    received: HashSet<u32>,
}

impl RatchetState {
    pub fn from_root_key(root_key: RootKey) -> Self {
        Self {
            root_key,
            send_chain: None,
            recv_chain: None,
            send_count: 0,
            recv_count: 0,
            skipped: HashMap::new(),
            received: HashSet::new(),
        }
    }

    pub fn root_key(&self) -> &[u8; 32] {
        &self.root_key.0
    }
    pub fn send_count(&self) -> u32 {
        self.send_count
    }
    pub fn recv_count(&self) -> u32 {
        self.recv_count
    }
    pub fn skipped_count(&self) -> usize {
        self.skipped.len()
    }
    pub fn received_count(&self) -> usize {
        self.received.len()
    }

    fn prune_received(&mut self) {
        let floor = self.recv_count.saturating_sub(REPLAY_WINDOW);
        self.received.retain(|n| *n >= floor);
    }

    pub fn snapshot(&self) -> RatchetSnapshot {
        RatchetSnapshot {
            root_key: self.root_key.0,
            send_chain: self.send_chain.as_ref().map(|v| v.0),
            recv_chain: self.recv_chain.as_ref().map(|v| v.0),
            send_count: self.send_count,
            recv_count: self.recv_count,
            skipped: self.skipped.iter().map(|(k, v)| (*k, v.0)).collect(),
            received: self.received.clone(),
        }
    }

    pub fn from_snapshot(snapshot: RatchetSnapshot) -> Self {
        Self {
            root_key: RootKey(snapshot.root_key),
            send_chain: snapshot.send_chain.map(ChainKey),
            recv_chain: snapshot.recv_chain.map(ChainKey),
            send_count: snapshot.send_count,
            recv_count: snapshot.recv_count,
            skipped: snapshot
                .skipped
                .into_iter()
                .map(|(k, v)| (k, MessageKey(v)))
                .collect(),
            received: snapshot.received,
        }
    }

    pub fn initialize_send_chain(&mut self, chain_seed: [u8; 32]) {
        self.send_chain = Some(ChainKey(chain_seed));
        self.send_count = 0;
    }

    pub fn initialize_recv_chain(&mut self, chain_seed: [u8; 32]) {
        self.recv_chain = Some(ChainKey(chain_seed));
        self.recv_count = 0;
        self.skipped.clear();
        self.received.clear();
    }

    pub fn next_send_key(&mut self) -> Result<(MessageKey, u32), AkfesError> {
        let chain = self
            .send_chain
            .take()
            .ok_or(AkfesError::KeyDerivationFailed)?;
        let (message, next) = kdf_chain(&chain)?;
        let counter = self.send_count;
        self.send_count = self
            .send_count
            .checked_add(1)
            .ok_or(AkfesError::KeyDerivationFailed)?;
        self.send_chain = Some(next);
        Ok((message, counter))
    }

    /// Resolve a received message number. Future messages derive and cache
    /// intermediate keys; old cached keys are consumed exactly once.
    pub fn recv_key_for(&mut self, message_number: u32) -> Result<MessageKey, AkfesError> {
        if self.received.contains(&message_number) {
            return Err(AkfesError::KeyDerivationFailed);
        }

        if message_number < self.recv_count {
            let key = self
                .skipped
                .remove(&message_number)
                .ok_or(AkfesError::KeyDerivationFailed)?;
            self.received.insert(message_number);
            self.prune_received();
            return Ok(key);
        }

        let gap = message_number - self.recv_count;
        if gap > MAX_SKIP {
            return Err(AkfesError::KeyDerivationFailed);
        }

        let mut current = self
            .recv_chain
            .take()
            .ok_or(AkfesError::KeyDerivationFailed)?;
        while self.recv_count < message_number {
            let (skipped_key, next) = kdf_chain(&current)?;
            self.skipped.insert(self.recv_count, skipped_key);
            self.recv_count = self
                .recv_count
                .checked_add(1)
                .ok_or(AkfesError::KeyDerivationFailed)?;
            current = next;
        }

        let (message_key, next) = kdf_chain(&current)?;
        self.recv_count = self
            .recv_count
            .checked_add(1)
            .ok_or(AkfesError::KeyDerivationFailed)?;
        self.recv_chain = Some(next);
        self.received.insert(message_number);
        self.prune_received();
        Ok(message_key)
    }

    pub fn next_recv_key(&mut self) -> Result<(MessageKey, u32), AkfesError> {
        let counter = self.recv_count;
        let key = self.recv_key_for(counter)?;
        Ok((key, counter))
    }

    /// Mix a fresh X25519 DH result into the root key and install a new chain.
    pub fn dh_ratchet(
        &mut self,
        local_secret: [u8; 32],
        remote_public: [u8; 32],
        direction: RatchetDirection,
    ) -> Result<[u8; 32], AkfesError> {
        let secret = StaticSecret::from(local_secret);
        let remote = PublicKey::from(remote_public);
        let shared = secret.diffie_hellman(&remote);

        let (new_root, chain) = kdf_root(&self.root_key.0, shared.as_bytes())?;
        self.root_key = RootKey(new_root);
        self.skipped.clear();
        self.received.clear();

        match direction {
            RatchetDirection::Send => self.initialize_send_chain(chain),
            RatchetDirection::Receive => self.initialize_recv_chain(chain),
        }

        Ok(chain)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RatchetDirection {
    Send,
    Receive,
}

fn kdf_chain(chain: &ChainKey) -> Result<(MessageKey, ChainKey), AkfesError> {
    let hk = Hkdf::<Sha256>::new(None, &chain.0);
    let mut message = [0u8; 32];
    let mut next = [0u8; 32];
    hk.expand(b"AKFES-DR-MessageKey", &mut message)
        .map_err(|_| AkfesError::KeyDerivationFailed)?;
    hk.expand(b"AKFES-DR-ChainKey", &mut next)
        .map_err(|_| AkfesError::KeyDerivationFailed)?;
    Ok((MessageKey(message), ChainKey(next)))
}

fn kdf_root(root: &[u8; 32], dh_output: &[u8]) -> Result<([u8; 32], [u8; 32]), AkfesError> {
    let hk = Hkdf::<Sha256>::new(Some(root), dh_output);
    let mut next_root = [0u8; 32];
    let mut chain = [0u8; 32];
    hk.expand(b"AKFES-DR-RootKey", &mut next_root)
        .map_err(|_| AkfesError::KeyDerivationFailed)?;
    hk.expand(b"AKFES-DR-ChainKey", &mut chain)
        .map_err(|_| AkfesError::KeyDerivationFailed)?;
    Ok((next_root, chain))
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn symmetric_chain_advances() {
        let mut state = RatchetState::from_root_key(RootKey([1u8; 32]));
        state.initialize_send_chain([2u8; 32]);
        let (a, ca) = state.next_send_key().unwrap();
        let (b, cb) = state.next_send_key().unwrap();
        assert_eq!(ca, 0);
        assert_eq!(cb, 1);
        assert_ne!(a.0, b.0);
    }

    #[test]
    fn out_of_order_messages_use_skipped_keys_once() {
        let mut state = RatchetState::from_root_key(RootKey([1u8; 32]));
        state.initialize_recv_chain([2u8; 32]);
        let key2 = state.recv_key_for(2).unwrap();
        assert_eq!(state.recv_count(), 3);
        assert_eq!(state.skipped_count(), 2);
        let key0 = state.recv_key_for(0).unwrap();
        let key1 = state.recv_key_for(1).unwrap();
        assert_ne!(key0.0, key1.0);
        assert_ne!(key1.0, key2.0);
        assert_eq!(state.skipped_count(), 0);
        assert!(state.recv_key_for(0).is_err());
    }

    #[test]
    fn replay_window_is_bounded() {
        let mut state = RatchetState::from_root_key(RootKey([1u8; 32]));
        state.initialize_recv_chain([2u8; 32]);
        for n in 0..300 {
            let _ = state.recv_key_for(n).unwrap();
        }
        assert!(state.received_count() <= (REPLAY_WINDOW as usize + 1));
    }

    #[test]
    fn excessive_gap_is_rejected() {
        let mut state = RatchetState::from_root_key(RootKey([1u8; 32]));
        state.initialize_recv_chain([2u8; 32]);
        assert!(state.recv_key_for(MAX_SKIP + 1).is_err());
        assert_eq!(state.recv_count(), 0);
    }

    #[test]
    fn two_sides_can_perform_same_dh_ratchet() {
        let alice = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let bob = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let alice_pub = PublicKey::from(&alice);
        let bob_pub = PublicKey::from(&bob);
        let root = RootKey([7u8; 32]);
        let mut a = RatchetState::from_root_key(root.clone());
        let mut b = RatchetState::from_root_key(root);
        let ca = a
            .dh_ratchet(alice.to_bytes(), bob_pub.to_bytes(), RatchetDirection::Send)
            .unwrap();
        let cb = b
            .dh_ratchet(bob.to_bytes(), alice_pub.to_bytes(), RatchetDirection::Send)
            .unwrap();
        assert_eq!(a.root_key(), b.root_key());
        assert_eq!(ca, cb);
    }
}
