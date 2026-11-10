use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::AkfesError;
use crate::types::{PublicKeyBytes, SharedSecret};

/// X25519 key pair used as a per-device transport identity in Phase 1.
pub struct X25519KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl X25519KeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn from_secret_bytes(secret_bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    pub fn public_key_bytes(&self) -> PublicKeyBytes {
        PublicKeyBytes(*self.public.as_bytes())
    }

    /// Perform Diffie-Hellman. x25519-dalek clamps the scalar internally.
    pub fn dh(&self, their_public: &PublicKeyBytes) -> Result<SharedSecret, AkfesError> {
        let their_pk = PublicKey::from(their_public.0);
        let shared = self.secret.diffie_hellman(&their_pk);
        let bytes = *shared.as_bytes();
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(AkfesError::KeyDerivationFailed);
        }
        Ok(SharedSecret(bytes))
    }
}

impl Drop for X25519KeyPair {
    fn drop(&mut self) {
        let mut bytes = self.secret.to_bytes();
        bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dh_shared_secret_matches() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();

        let alice_shared = alice.dh(&bob.public_key_bytes()).unwrap();
        let bob_shared = bob.dh(&alice.public_key_bytes()).unwrap();

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn serialized_secret_restores_public_key() {
        let original = X25519KeyPair::generate();
        let restored = X25519KeyPair::from_secret_bytes(original.secret_key_bytes());
        assert_eq!(original.public_key_bytes(), restored.public_key_bytes());
    }
}
