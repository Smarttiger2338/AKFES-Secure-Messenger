use thiserror::Error;

#[derive(Error, Debug)]
pub enum AkfesError {
    #[error("Cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("Invalid key length")]
    InvalidKeyLength,

    #[error("Decryption failed (authentication tag mismatch or corrupted data)")]
    DecryptionFailed,

    #[error("Key derivation failed")]
    KeyDerivationFailed,

    #[error("Invalid nonce")]
    InvalidNonce,

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Storage error: {0}")]
    Storage(String),
}
