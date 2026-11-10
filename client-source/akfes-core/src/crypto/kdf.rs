use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::AkfesError;
use crate::types::{ChainKey, MessageKey, RootKey, SharedSecret};

pub fn derive_root_and_chain(
    shared_secret: &SharedSecret,
) -> Result<(RootKey, ChainKey), AkfesError> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());

    let mut root = [0u8; 32];
    let mut chain = [0u8; 32];

    hk.expand(b"AKFES-RootKey", &mut root)
        .map_err(|_| AkfesError::KeyDerivationFailed)?;
    hk.expand(b"AKFES-ChainKey", &mut chain)
        .map_err(|_| AkfesError::KeyDerivationFailed)?;

    Ok((RootKey(root), ChainKey(chain)))
}

/// Phase 1 direct-chat key. Ratcheting replaces this construction in Phase 3.
/// Both parties canonicalize device IDs so they derive the same key.
pub fn derive_direct_message_key(
    shared_secret: &SharedSecret,
    conversation_id: &str,
    local_device_id: &str,
    remote_device_id: &str,
) -> Result<MessageKey, AkfesError> {
    let (first, second) = if local_device_id <= remote_device_id {
        (local_device_id, remote_device_id)
    } else {
        (remote_device_id, local_device_id)
    };
    let salt = format!("AKFES-Direct-v1:{conversation_id}");
    let info = format!("devices:{first}:{second}");
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), shared_secret.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(info.as_bytes(), &mut key)
        .map_err(|_| AkfesError::KeyDerivationFailed)?;
    Ok(MessageKey(key))
}

pub fn derive_message_key(chain_key: &ChainKey) -> Result<([u8; 32], ChainKey), AkfesError> {
    let hk = Hkdf::<Sha256>::new(None, &chain_key.0);

    let mut msg_key = [0u8; 32];
    let mut next_chain = [0u8; 32];

    hk.expand(b"AKFES-MessageKey", &mut msg_key)
        .map_err(|_| AkfesError::KeyDerivationFailed)?;
    hk.expand(b"AKFES-NextChain", &mut next_chain)
        .map_err(|_| AkfesError::KeyDerivationFailed)?;

    Ok((msg_key, ChainKey(next_chain)))
}

/// Deterministically derives two directional chain seeds from the Phase 2
/// session key. The same pair is obtained by both devices; device ordering
/// assigns which seed is send vs receive.
///
/// Phase 3 uses these chains for the symmetric ratchet. A later protocol
/// revision can replace the root with DH-ratchet steps without changing the
/// message-chain interface.
pub fn derive_directional_chains(
    session_key: &[u8; 32],
    conversation_id: &str,
    local_device_id: &str,
    remote_device_id: &str,
) -> Result<([u8; 32], [u8; 32]), AkfesError> {
    let (first, second) = if local_device_id <= remote_device_id {
        (local_device_id, remote_device_id)
    } else {
        (remote_device_id, local_device_id)
    };
    let salt = format!("AKFES-DR-v1:{conversation_id}:{first}:{second}");
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), session_key);
    let mut first_chain = [0u8; 32];
    let mut second_chain = [0u8; 32];
    hk.expand(b"AKFES-DR-First-SendChain", &mut first_chain)
        .map_err(|_| AkfesError::KeyDerivationFailed)?;
    hk.expand(b"AKFES-DR-Second-SendChain", &mut second_chain)
        .map_err(|_| AkfesError::KeyDerivationFailed)?;
    Ok(if local_device_id <= remote_device_id {
        (first_chain, second_chain)
    } else {
        (second_chain, first_chain)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_root_and_chain_deterministic() {
        let ss = SharedSecret([42u8; 32]);
        let (r1, c1) = derive_root_and_chain(&ss).unwrap();
        let (r2, c2) = derive_root_and_chain(&ss).unwrap();
        assert_eq!(r1.0, r2.0);
        assert_eq!(c1.0, c2.0);
    }

    #[test]
    fn direct_key_is_symmetric_in_device_order() {
        let ss = SharedSecret([7u8; 32]);
        let a = derive_direct_message_key(&ss, "conv", "a", "b").unwrap();
        let b = derive_direct_message_key(&ss, "conv", "b", "a").unwrap();
        assert_eq!(a.0, b.0);
    }

    #[test]
    fn message_key_advances_chain() {
        let chain = ChainKey([9u8; 32]);
        let (mk1, next1) = derive_message_key(&chain).unwrap();
        let (mk2, next2) = derive_message_key(&next1).unwrap();
        assert_ne!(mk1, mk2);
        assert_ne!(next1.0, next2.0);
        assert_ne!(chain.0, next1.0);
    }
}
