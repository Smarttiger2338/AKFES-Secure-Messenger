//! AKFES Core — Cryptographic core for AKFES Secure Messenger
//!
//! Responsibilities:
//! - Identity key generation & management
//! - X25519 key exchange
//! - HKDF key derivation
//! - AES-256-GCM (and ChaCha20-Poly1305) authenticated encryption
//! - Basic ratchet primitives (Phase 3)
//! - Safety number generation
//!
//! React / Tauri only receives results. All sensitive operations stay here.

pub mod crypto;
pub mod error;
pub mod identity;
pub mod protocol;
pub mod safety;
pub mod types;

pub use error::AkfesError;
pub use identity::{
    generate_identity_keypair, identity_public_key_from_bytes, verify_identity_signature,
    IdentityKeyPair,
};
pub use types::{DeviceId, MessageKey, Nonce, PublicKeyBytes, SharedSecret};

/// High-level encrypt API for text messages (MVP)
pub fn encrypt_message(
    plaintext: &[u8],
    message_key: &MessageKey,
) -> Result<(Vec<u8>, Nonce), AkfesError> {
    crypto::aead::encrypt_aes_gcm(plaintext, message_key.as_bytes())
}

/// High-level decrypt API
pub fn decrypt_message(
    ciphertext: &[u8],
    nonce: &Nonce,
    message_key: &MessageKey,
) -> Result<Vec<u8>, AkfesError> {
    crypto::aead::decrypt_aes_gcm(ciphertext, nonce, message_key.as_bytes())
}

pub fn encrypt_message_with_aad(
    plaintext: &[u8],
    message_key: &MessageKey,
    aad: &[u8],
) -> Result<(Vec<u8>, Nonce), AkfesError> {
    crypto::aead::encrypt_aes_gcm_with_aad(plaintext, message_key.as_bytes(), aad)
}

pub fn decrypt_message_with_aad(
    ciphertext: &[u8],
    nonce: &Nonce,
    message_key: &MessageKey,
    aad: &[u8],
) -> Result<Vec<u8>, AkfesError> {
    crypto::aead::decrypt_aes_gcm_with_aad(ciphertext, nonce, message_key.as_bytes(), aad)
}

/// Derive initial root/chain keys from X25519 shared secret
pub fn derive_initial_keys(
    shared_secret: &SharedSecret,
) -> Result<(types::RootKey, types::ChainKey), AkfesError> {
    crypto::kdf::derive_root_and_chain(shared_secret)
}

pub use crypto::prekey::{
    derive_prekey_session_key, generate_signed_prekey, verify_signed_prekey, SignedPreKeyBundle,
};
pub use crypto::ratchet::{RatchetDirection, RatchetSnapshot, RatchetState};

/// Encrypt an entire file with a fresh random file key.
pub fn encrypt_file(plaintext: &[u8]) -> Result<crypto::file::EncryptedFile, AkfesError> {
    crypto::file::encrypt_file(plaintext)
}

/// Decrypt an encrypted file and verify its plaintext SHA-256.
pub fn decrypt_file(
    ciphertext: &[u8],
    nonce: &Nonce,
    file_key: &[u8; 32],
    expected_sha256: &[u8; 32],
) -> Result<Vec<u8>, AkfesError> {
    crypto::file::decrypt_file(ciphertext, nonce, file_key, expected_sha256)
}
