use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce as AesNonce,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::error::AkfesError;
use crate::types::Nonce;

#[derive(Clone, Debug)]
pub struct EncryptedFile {
    pub ciphertext: Vec<u8>,
    pub nonce: Nonce,
    pub file_key: [u8; 32],
    pub sha256: [u8; 32],
}

pub fn encrypt_file(plaintext: &[u8]) -> Result<EncryptedFile, AkfesError> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| AkfesError::Crypto(e.to_string()))?;
    let ciphertext = cipher
        .encrypt(AesNonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| AkfesError::Crypto(e.to_string()))?;
    let digest = Sha256::digest(plaintext);
    let mut sha = [0u8; 32];
    sha.copy_from_slice(&digest);
    Ok(EncryptedFile {
        ciphertext,
        nonce: Nonce(nonce_bytes),
        file_key: key,
        sha256: sha,
    })
}

pub fn decrypt_file(
    ciphertext: &[u8],
    nonce: &Nonce,
    file_key: &[u8; 32],
    expected_sha256: &[u8; 32],
) -> Result<Vec<u8>, AkfesError> {
    let cipher =
        Aes256Gcm::new_from_slice(file_key).map_err(|e| AkfesError::Crypto(e.to_string()))?;
    let plaintext = cipher
        .decrypt(AesNonce::from_slice(nonce.as_bytes()), ciphertext)
        .map_err(|_| AkfesError::DecryptionFailed)?;
    let digest = Sha256::digest(&plaintext);
    if digest.as_slice() != expected_sha256 {
        return Err(AkfesError::DecryptionFailed);
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_roundtrip_and_integrity() {
        let input = b"AKFES encrypted file";
        let enc = encrypt_file(input).unwrap();
        let out = decrypt_file(&enc.ciphertext, &enc.nonce, &enc.file_key, &enc.sha256).unwrap();
        assert_eq!(out, input);
    }
    #[test]
    fn tampering_fails() {
        let enc = encrypt_file(b"secret").unwrap();
        let mut ct = enc.ciphertext.clone();
        ct[0] ^= 1;
        assert!(decrypt_file(&ct, &enc.nonce, &enc.file_key, &enc.sha256).is_err());
    }
}
