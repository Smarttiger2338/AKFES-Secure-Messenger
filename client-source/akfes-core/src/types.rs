use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 32-byte public key (X25519 or Ed25519)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicKeyBytes(pub [u8; 32]);

impl PublicKeyBytes {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Shared secret from X25519
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(pub [u8; 32]);

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Root key (32 bytes)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootKey(pub [u8; 32]);

/// Chain key
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChainKey(pub [u8; 32]);

/// Per-message key
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MessageKey(pub [u8; 32]);

impl MessageKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// 12-byte nonce for AES-GCM
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nonce(pub [u8; 12]);

impl Nonce {
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

/// Opaque device identifier
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DeviceId(pub String);
