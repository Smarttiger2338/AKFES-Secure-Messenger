//! Integration-style tests for akfes-core high-level API

use akfes_core::crypto::kdf::derive_message_key;
use akfes_core::crypto::x25519::X25519KeyPair;
use akfes_core::identity::generate_identity_keypair;
use akfes_core::safety::generate_safety_number;
use akfes_core::types::MessageKey;
use akfes_core::{decrypt_message, derive_initial_keys, encrypt_message};

#[test]
fn full_encrypt_decrypt_flow() {
    // 1. Identity keys
    let alice_id = generate_identity_keypair();
    let bob_id = generate_identity_keypair();

    // 2. X25519 key exchange
    let alice_eph = X25519KeyPair::generate();
    let bob_eph = X25519KeyPair::generate();
    let shared = alice_eph.dh(&bob_eph.public_key_bytes()).unwrap();

    // 3. Derive root + chain
    let (_root, chain) = derive_initial_keys(&shared).unwrap();

    // 4. Derive message key
    let (mk_bytes, _next_chain) = derive_message_key(&chain).unwrap();
    let message_key = MessageKey(mk_bytes);

    // 5. Encrypt / Decrypt
    let plaintext = b"Phase 1 MVP message from Alice to Bob";
    let (ciphertext, nonce) = encrypt_message(plaintext, &message_key).unwrap();
    let decrypted = decrypt_message(&ciphertext, &nonce, &message_key).unwrap();
    assert_eq!(decrypted, plaintext);

    // 6. Safety number is symmetric
    let sn1 = generate_safety_number(
        &alice_id.public_key().public_key,
        &bob_id.public_key().public_key,
    );
    let sn2 = generate_safety_number(
        &bob_id.public_key().public_key,
        &alice_id.public_key().public_key,
    );
    assert_eq!(sn1, sn2);
    assert!(!sn1.is_empty());
}
