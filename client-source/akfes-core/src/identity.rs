use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::AkfesError;
use crate::types::PublicKeyBytes;

/// Long-term Ed25519 identity used for future pre-key signatures and safety checks.
pub struct IdentityKeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityPublicKey {
    pub public_key: PublicKeyBytes,
}

impl IdentityKeyPair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn from_secret_bytes(secret: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn public_key(&self) -> IdentityPublicKey {
        IdentityPublicKey {
            public_key: PublicKeyBytes(self.verifying_key.to_bytes()),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64], AkfesError> {
        use ed25519_dalek::Signer;
        Ok(self.signing_key.sign(message).to_bytes())
    }
}

pub fn verify_identity_signature(
    public_key: &PublicKeyBytes,
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), AkfesError> {
    use ed25519_dalek::{Signature, Verifier};
    let verifying_key =
        VerifyingKey::from_bytes(&public_key.0).map_err(|_| AkfesError::KeyDerivationFailed)?;
    verifying_key
        .verify(message, &Signature::from_bytes(signature))
        .map_err(|_| AkfesError::KeyDerivationFailed)
}

pub fn generate_identity_keypair() -> IdentityKeyPair {
    IdentityKeyPair::generate()
}

pub fn identity_public_key_from_bytes(bytes: [u8; 32]) -> Result<IdentityPublicKey, AkfesError> {
    let verifying_key =
        VerifyingKey::from_bytes(&bytes).map_err(|_| AkfesError::KeyDerivationFailed)?;
    Ok(IdentityPublicKey {
        public_key: PublicKeyBytes(verifying_key.to_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialized_identity_restores_public_key() {
        let original = IdentityKeyPair::generate();
        let restored = IdentityKeyPair::from_secret_bytes(original.secret_key_bytes());
        assert_eq!(
            original.public_key().public_key,
            restored.public_key().public_key
        );
    }
}
