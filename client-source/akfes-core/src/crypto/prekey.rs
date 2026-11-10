use ed25519_dalek::{Signature, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;

use super::x25519::X25519KeyPair;
use crate::error::AkfesError;
use crate::identity::IdentityKeyPair;
use crate::types::{PublicKeyBytes, SharedSecret};

#[derive(Clone, Debug)]
pub struct SignedPreKeyBundle {
    pub key_id: u32,
    pub public_key: PublicKeyBytes,
    pub signature: [u8; 64],
}

pub fn generate_signed_prekey(
    identity: &IdentityKeyPair,
    key_id: u32,
) -> (X25519KeyPair, SignedPreKeyBundle) {
    let keypair = X25519KeyPair::generate();
    let public = keypair.public_key_bytes();
    let mut signed = Vec::with_capacity(4 + 32);
    signed.extend_from_slice(&key_id.to_be_bytes());
    signed.extend_from_slice(&public.0);
    let signature = identity.sign(&signed).expect("Ed25519 signing cannot fail");
    (
        keypair,
        SignedPreKeyBundle {
            key_id,
            public_key: public,
            signature,
        },
    )
}

pub fn verify_signed_prekey(
    identity_public: &PublicKeyBytes,
    bundle: &SignedPreKeyBundle,
) -> Result<(), AkfesError> {
    let verifying = VerifyingKey::from_bytes(&identity_public.0)
        .map_err(|_| AkfesError::KeyDerivationFailed)?;
    let signature = Signature::from_bytes(&bundle.signature);
    let mut signed = Vec::with_capacity(4 + 32);
    signed.extend_from_slice(&bundle.key_id.to_be_bytes());
    signed.extend_from_slice(&bundle.public_key.0);
    verifying
        .verify_strict(&signed, &signature)
        .map_err(|_| AkfesError::KeyDerivationFailed)
}

/// Prekey-assisted session derivation used in Phase 2.
/// Initiator computes DH(device_secret, signed_prekey) and optionally
/// DH(device_secret, one_time_prekey). Responder computes the same values
/// with its prekey secret and the initiator device public key.
pub fn derive_prekey_session_key(
    shared_parts: &[SharedSecret],
    conversation_id: &str,
) -> Result<[u8; 32], AkfesError> {
    if shared_parts.is_empty() {
        return Err(AkfesError::KeyDerivationFailed);
    }
    let mut ikm = Vec::with_capacity(shared_parts.len() * 32);
    for part in shared_parts {
        ikm.extend_from_slice(part.as_bytes());
    }
    let salt = format!("AKFES-Session-v2:{conversation_id}");
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), &ikm);
    let mut key = [0u8; 32];
    hk.expand(b"AKFES-E2EE-MessageKey", &mut key)
        .map_err(|_| AkfesError::KeyDerivationFailed)?;
    Ok(key)
}
