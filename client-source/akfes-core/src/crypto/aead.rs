use crate::error::AkfesError;
use crate::types::Nonce;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce as AesNonce,
};
use rand::rngs::OsRng;
use rand::RngCore;

pub fn encrypt_aes_gcm(plaintext: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, Nonce), AkfesError> {
    encrypt_aes_gcm_with_aad(plaintext, key, b"")
}

pub fn decrypt_aes_gcm(
    ciphertext: &[u8],
    nonce: &Nonce,
    key: &[u8; 32],
) -> Result<Vec<u8>, AkfesError> {
    decrypt_aes_gcm_with_aad(ciphertext, nonce, key, b"")
}

/// AES-256-GCM with Additional Authenticated Data.  Message metadata that
/// drives routing/ratchet interpretation is authenticated but not encrypted.
pub fn encrypt_aes_gcm_with_aad(
    plaintext: &[u8],
    key: &[u8; 32],
    aad: &[u8],
) -> Result<(Vec<u8>, Nonce), AkfesError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| AkfesError::Crypto(e.to_string()))?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = AesNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| AkfesError::Crypto(e.to_string()))?;
    Ok((ciphertext, Nonce(nonce_bytes)))
}

pub fn decrypt_aes_gcm_with_aad(
    ciphertext: &[u8],
    nonce: &Nonce,
    key: &[u8; 32],
    aad: &[u8],
) -> Result<Vec<u8>, AkfesError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| AkfesError::Crypto(e.to_string()))?;
    let n = AesNonce::from_slice(nonce.as_bytes());
    cipher
        .decrypt(
            n,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AkfesError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_with_aad() {
        let key = [7u8; 32];
        let (ct, n) = encrypt_aes_gcm_with_aad(b"hello", &key, b"meta").unwrap();
        assert_eq!(
            decrypt_aes_gcm_with_aad(&ct, &n, &key, b"meta").unwrap(),
            b"hello"
        );
        assert!(decrypt_aes_gcm_with_aad(&ct, &n, &key, b"tampered").is_err());
    }
    #[test]
    fn legacy_roundtrip() {
        let key = [1u8; 32];
        let (ct, n) = encrypt_aes_gcm(b"x", &key).unwrap();
        assert_eq!(decrypt_aes_gcm(&ct, &n, &key).unwrap(), b"x");
    }
}
