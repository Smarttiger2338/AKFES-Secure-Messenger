use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use akfes_core::{
    crypto::{
        aead::{decrypt_aes_gcm_with_aad, encrypt_aes_gcm_with_aad},
        kdf::derive_directional_chains,
        prekey::{
            derive_prekey_session_key, generate_signed_prekey, verify_signed_prekey,
            SignedPreKeyBundle,
        },
        ratchet::RatchetState,
        x25519::X25519KeyPair,
    },
    decrypt_message_with_aad, encrypt_message_with_aad,
    identity::IdentityKeyPair,
    protocol::build_message_aad,
    safety::generate_safety_number,
    types::{MessageKey, Nonce, PublicKeyBytes, RootKey, SharedSecret},
    verify_identity_signature,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use keyring::Entry;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager};
use zeroize::Zeroize;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

const PREKEY_COUNT: usize = 20;
const SIGNED_PREKEY_MAX_AGE_SECS: i64 = 14 * 24 * 60 * 60;
const SESSION_REKEY_MESSAGES: u32 = 32;
const OUTBOUND_KEY_LIMIT: usize = 512;
const PREVIOUS_SIGNED_LIMIT: usize = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredPreKey {
    key_id: u32,
    secret: String,
    public_key: String,
    #[serde(default)]
    created_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreviousSignedPreKey {
    key: StoredPreKey,
    signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredRatchet {
    #[serde(default)]
    session_id: String,
    root_key: String,
    send_chain: Option<String>,
    recv_chain: Option<String>,
    send_count: u32,
    recv_count: u32,
    skipped: HashMap<u32, String>,
    received: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PeerTrustRecord {
    identity_public_key: String,
    verified: bool,
    safety_number: String,
    verified_at_unix: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredIdentity {
    identity_secret: String,
    device_secret: String,
    server_device_id: Option<String>,
    #[serde(default)]
    ratchets: HashMap<String, StoredRatchet>,
    #[serde(default)]
    outbound_sessions: HashMap<String, String>,
    #[serde(default)]
    signed_prekey: Option<StoredPreKey>,
    #[serde(default)]
    signed_prekey_signature: Option<String>,
    #[serde(default)]
    signed_prekey_created_at_unix: i64,
    #[serde(default)]
    previous_signed_prekeys: Vec<PreviousSignedPreKey>,
    #[serde(default)]
    one_time_prekeys: Vec<StoredPreKey>,
    #[serde(default = "default_next_one_time_prekey_id")]
    next_one_time_prekey_id: u32,
    #[serde(default)]
    outbound_message_keys: HashMap<String, String>,
    #[serde(default)]
    outbound_key_order: Vec<String>,
    #[serde(default)]
    inbound_message_keys: HashMap<String, String>,
    #[serde(default)]
    inbound_key_order: Vec<String>,
    #[serde(default)]
    peer_identities: HashMap<String, PeerTrustRecord>,
    #[serde(default)]
    arduino_device_secrets: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedStateBlob {
    nonce: String,
    ciphertext: String,
}

fn default_next_one_time_prekey_id() -> u32 {
    1020
}
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicIdentity {
    identity_public_key: String,
    device_public_key: String,
    device_key_signature: String,
    server_device_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct E2eeBundle {
    identity_public_key: String,
    device_public_key: String,
    device_key_signature: String,
    signed_prekey_id: u32,
    signed_prekey_public_key: String,
    signed_prekey_signature: String,
    one_time_prekeys: Vec<PreKeyPublic>,
    server_device_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PreKeyPublic {
    key_id: u32,
    public_key: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    signature: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PeerIdentityStatus {
    status: String,
    safety_number: String,
    pinned_identity_public_key: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedFilePayload {
    ciphertext: String,
    nonce: String,
    file_key: String,
    sha256: String,
    plaintext_size: usize,
}
#[derive(Debug, Serialize)]
struct DecryptedFilePayload {
    #[serde(rename = "plaintextB64")]
    plaintext_b64: String,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecryptFileArgs {
    ciphertext_b64: String,
    nonce_b64: String,
    file_key_b64: String,
    sha256_b64: String,
}

fn profile_hash(profile: &str) -> Result<String, String> {
    if profile.len() > 512 || !profile.contains('|') || profile.chars().any(|c| c.is_control()) {
        return Err("Invalid local security profile".into());
    }
    Ok(hex::encode(Sha256::digest(profile.as_bytes())))
}
fn profile_username(profile: &str) -> Result<String, String> {
    let u = profile
        .rsplit('|')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if u.is_empty()
        || !u
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err("Invalid profile username".into());
    }
    Ok(u)
}
fn state_path(app: &AppHandle, profile: &str) -> Result<PathBuf, String> {
    let root = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Could not resolve app data directory: {e}"))?;
    fs::create_dir_all(&root).map_err(|e| format!("Could not create app data directory: {e}"))?;
    Ok(root.join(format!("crypto-state-{}.bin", profile_hash(profile)?)))
}
fn wrapping_entry(profile: &str) -> Result<Entry, String> {
    Entry::new(
        "AKFES-Secure-Messenger-WrappingKey-v2",
        &profile_hash(profile)?,
    )
    .map_err(|e| format!("Could not open OS credential store: {e}"))
}
fn get_or_create_wrapping_key(profile: &str, state_exists: bool) -> Result<[u8; 32], String> {
    let entry = wrapping_entry(profile)?;
    match entry.get_password() {
        Ok(v) => decode_fixed::<32>(&v, "wrapping key"),
        Err(_) => {
            if state_exists {
                return Err(
                    "Encrypted crypto state exists but its OS wrapping key is unavailable".into(),
                );
            }
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            entry
                .set_password(&BASE64.encode(key))
                .map_err(|e| format!("Could not save wrapping key: {e}"))?;
            Ok(key)
        }
    }
}
fn legacy_identity_entry(username: &str) -> Result<Entry, String> {
    Entry::new("AKFES-Secure-Messenger", username)
        .map_err(|e| format!("Could not open legacy credential: {e}"))
}
fn legacy_identity_path(app: &AppHandle, username: &str) -> Result<PathBuf, String> {
    let root = app.path().app_data_dir().map_err(|e| e.to_string())?;
    Ok(root.join(format!("identity-{username}.json")))
}

fn decode_fixed<const N: usize>(value: &str, field: &str) -> Result<[u8; N], String> {
    BASE64
        .decode(value)
        .map_err(|_| format!("Invalid base64 in {field}"))?
        .try_into()
        .map_err(|_| format!("{field} must contain exactly {N} bytes"))
}

fn write_identity(app: &AppHandle, profile: &str, identity: &StoredIdentity) -> Result<(), String> {
    let path = state_path(app, profile)?;
    let mut key = get_or_create_wrapping_key(profile, path.exists())?;
    let plaintext = serde_json::to_vec(identity)
        .map_err(|e| format!("Could not serialize crypto state: {e}"))?;
    let (ct, nonce) = encrypt_aes_gcm_with_aad(&plaintext, &key, profile.as_bytes())
        .map_err(|e| format!("Could not encrypt crypto state: {e}"))?;
    key.zeroize();
    let blob = EncryptedStateBlob {
        nonce: BASE64.encode(nonce.0),
        ciphertext: BASE64.encode(ct),
    };
    let bytes = serde_json::to_vec(&blob).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|e| format!("Could not write crypto state: {e}"))?;
    fs::rename(&tmp, &path)
        .map_err(|e| format!("Could not atomically replace crypto state: {e}"))?;
    Ok(())
}
fn load_identity_file(app: &AppHandle, profile: &str) -> Result<Option<StoredIdentity>, String> {
    let path = state_path(app, profile)?;
    if !path.exists() {
        return Ok(None);
    }
    let blob: EncryptedStateBlob =
        serde_json::from_slice(&fs::read(&path).map_err(|e| e.to_string())?)
            .map_err(|e| format!("Invalid encrypted state: {e}"))?;
    let mut key = get_or_create_wrapping_key(profile, true)?;
    let nonce = Nonce(decode_fixed::<12>(&blob.nonce, "state nonce")?);
    let ct = BASE64
        .decode(blob.ciphertext)
        .map_err(|_| "Invalid encrypted state".to_string())?;
    let plain = decrypt_aes_gcm_with_aad(&ct, &nonce, &key, profile.as_bytes())
        .map_err(|_| "Crypto state authentication failed".to_string())?;
    key.zeroize();
    Ok(Some(serde_json::from_slice(&plain).map_err(|e| {
        format!("Could not parse crypto state: {e}")
    })?))
}

fn create_identity() -> StoredIdentity {
    let identity = IdentityKeyPair::generate();
    let device = X25519KeyPair::generate();
    let (signed, bundle) = generate_signed_prekey(&identity, 1);
    let now = now_unix();
    let one_time_prekeys = (0..PREKEY_COUNT)
        .map(|i| {
            let kp = X25519KeyPair::generate();
            StoredPreKey {
                key_id: 1000 + i as u32,
                secret: BASE64.encode(kp.secret_key_bytes()),
                public_key: BASE64.encode(kp.public_key_bytes().0),
                created_at_unix: now,
            }
        })
        .collect();
    StoredIdentity {
        identity_secret: BASE64.encode(identity.secret_key_bytes()),
        device_secret: BASE64.encode(device.secret_key_bytes()),
        server_device_id: None,
        ratchets: HashMap::new(),
        outbound_sessions: HashMap::new(),
        signed_prekey: Some(StoredPreKey {
            key_id: bundle.key_id,
            secret: BASE64.encode(signed.secret_key_bytes()),
            public_key: BASE64.encode(bundle.public_key.0),
            created_at_unix: now,
        }),
        signed_prekey_signature: Some(BASE64.encode(bundle.signature)),
        signed_prekey_created_at_unix: now,
        previous_signed_prekeys: vec![],
        one_time_prekeys,
        next_one_time_prekey_id: 1020,
        outbound_message_keys: HashMap::new(),
        outbound_key_order: vec![],
        inbound_message_keys: HashMap::new(),
        inbound_key_order: vec![],
        peer_identities: HashMap::new(),
        arduino_device_secrets: HashMap::new(),
    }
}
fn ensure_prekeys(identity: &mut StoredIdentity) {
    let now = now_unix();
    let mut idsec = match decode_fixed::<32>(&identity.identity_secret, "identity secret") {
        Ok(v) => v,
        Err(_) => return,
    };
    let id = IdentityKeyPair::from_secret_bytes(idsec);
    idsec.zeroize();
    let signed_age = if identity.signed_prekey_created_at_unix > 0 {
        now - identity.signed_prekey_created_at_unix
    } else {
        SIGNED_PREKEY_MAX_AGE_SECS + 1
    };
    if identity.signed_prekey.is_none()
        || identity.signed_prekey_signature.is_none()
        || signed_age >= SIGNED_PREKEY_MAX_AGE_SECS
    {
        if let (Some(key), Some(sig)) = (
            identity.signed_prekey.take(),
            identity.signed_prekey_signature.take(),
        ) {
            identity.previous_signed_prekeys.push(PreviousSignedPreKey {
                key,
                signature: sig,
            });
            if identity.previous_signed_prekeys.len() > PREVIOUS_SIGNED_LIMIT {
                let d = identity.previous_signed_prekeys.len() - PREVIOUS_SIGNED_LIMIT;
                identity.previous_signed_prekeys.drain(0..d);
            }
        }
        let next = identity
            .previous_signed_prekeys
            .last()
            .map(|v| v.key.key_id + 1)
            .unwrap_or(1);
        let (kp, b) = generate_signed_prekey(&id, next);
        identity.signed_prekey = Some(StoredPreKey {
            key_id: b.key_id,
            secret: BASE64.encode(kp.secret_key_bytes()),
            public_key: BASE64.encode(b.public_key.0),
            created_at_unix: now,
        });
        identity.signed_prekey_signature = Some(BASE64.encode(b.signature));
        identity.signed_prekey_created_at_unix = now;
    }
    let max = identity
        .one_time_prekeys
        .iter()
        .map(|k| k.key_id)
        .max()
        .unwrap_or(999);
    if identity.next_one_time_prekey_id <= max {
        identity.next_one_time_prekey_id = max + 1
    }
    while identity.one_time_prekeys.len() < PREKEY_COUNT {
        let kp = X25519KeyPair::generate();
        let kid = identity.next_one_time_prekey_id;
        identity.next_one_time_prekey_id = identity.next_one_time_prekey_id.saturating_add(1);
        identity.one_time_prekeys.push(StoredPreKey {
            key_id: kid,
            secret: BASE64.encode(kp.secret_key_bytes()),
            public_key: BASE64.encode(kp.public_key_bytes().0),
            created_at_unix: now,
        });
    }
}
fn load_or_create_identity(app: &AppHandle, profile: &str) -> Result<StoredIdentity, String> {
    if let Some(mut v) = load_identity_file(app, profile)? {
        ensure_prekeys(&mut v);
        write_identity(app, profile, &v)?;
        return Ok(v);
    }
    // Migrate old OS-vault/plain-file state only for the matching account name.
    let username = profile_username(profile)?;
    let mut migrated = None;
    if let Ok(entry) = legacy_identity_entry(&username) {
        if let Ok(content) = entry.get_password() {
            if let Ok(v) = serde_json::from_str::<StoredIdentity>(&content) {
                migrated = Some(v)
            }
        }
    }
    if migrated.is_none() {
        let legacy = legacy_identity_path(app, &username)?;
        if legacy.exists() {
            let content = fs::read_to_string(&legacy).map_err(|e| e.to_string())?;
            migrated = Some(
                serde_json::from_str(&content)
                    .map_err(|e| format!("Could not parse legacy identity: {e}"))?,
            );
            let _ = fs::remove_file(legacy);
        }
    }
    let mut v = migrated.unwrap_or_else(create_identity);
    ensure_prekeys(&mut v);
    write_identity(app, profile, &v)?;
    Ok(v)
}

fn public_identity(stored: &StoredIdentity) -> Result<PublicIdentity, String> {
    let mut a = decode_fixed::<32>(&stored.identity_secret, "identity secret")?;
    let mut b = decode_fixed::<32>(&stored.device_secret, "device secret")?;
    let id = IdentityKeyPair::from_secret_bytes(a);
    let dev = X25519KeyPair::from_secret_bytes(b);
    a.zeroize();
    b.zeroize();
    let device_public_key = BASE64.encode(dev.public_key_bytes().0);
    let binding = format!("AKFES-DEVICE-KEY-v1|{}", device_public_key);
    let sig = id.sign(binding.as_bytes()).map_err(|e| e.to_string())?;
    Ok(PublicIdentity {
        identity_public_key: BASE64.encode(id.public_key().public_key.0),
        device_public_key,
        device_key_signature: BASE64.encode(sig),
        server_device_id: stored.server_device_id.clone(),
    })
}
fn bundle(stored: &StoredIdentity) -> Result<E2eeBundle, String> {
    let p = public_identity(stored)?;
    let s = stored
        .signed_prekey
        .as_ref()
        .ok_or("Signed prekey missing")?;
    let sig = stored
        .signed_prekey_signature
        .as_ref()
        .ok_or("Signed prekey signature missing")?;
    Ok(E2eeBundle {
        identity_public_key: p.identity_public_key,
        device_public_key: p.device_public_key,
        device_key_signature: p.device_key_signature,
        signed_prekey_id: s.key_id,
        signed_prekey_public_key: s.public_key.clone(),
        signed_prekey_signature: sig.clone(),
        one_time_prekeys: stored
            .one_time_prekeys
            .iter()
            .map(|k| PreKeyPublic {
                key_id: k.key_id,
                public_key: k.public_key.clone(),
                kind: "one_time".into(),
                signature: None,
            })
            .collect(),
        server_device_id: stored.server_device_id.clone(),
    })
}
fn verify_device_binding(
    identity_public: &str,
    device_public: &str,
    signature_b64: &str,
) -> Result<(), String> {
    let pk = PublicKeyBytes(decode_fixed::<32>(identity_public, "peer identity")?);
    let sig = decode_fixed::<64>(signature_b64, "device key signature")?;
    let msg = format!("AKFES-DEVICE-KEY-v1|{}", device_public);
    verify_identity_signature(&pk, msg.as_bytes(), &sig)
        .map_err(|_| "Peer device public key is not bound to its identity".to_string())
}
fn peer_key(user: &str, device: &str) -> String {
    format!("{user}:{device}")
}
fn safety_for(stored: &StoredIdentity, remote: &str) -> Result<String, String> {
    let local = public_identity(stored)?.identity_public_key;
    Ok(generate_safety_number(
        &PublicKeyBytes(decode_fixed::<32>(&local, "local identity")?),
        &PublicKeyBytes(decode_fixed::<32>(remote, "peer identity")?),
    ))
}
fn require_stable_peer(
    stored: &StoredIdentity,
    user: &str,
    device: &str,
    identity: &str,
) -> Result<(), String> {
    let rec = stored
        .peer_identities
        .get(&peer_key(user, device))
        .ok_or("Peer identity has not been verified")?;
    if rec.identity_public_key != identity {
        return Err("Peer identity changed; sending is blocked until re-verification".into());
    }
    Ok(())
}

fn find_signed<'a>(stored: &'a StoredIdentity, id: u32) -> Option<&'a StoredPreKey> {
    if let Some(k) = stored.signed_prekey.as_ref().filter(|k| k.key_id == id) {
        return Some(k);
    }
    stored
        .previous_signed_prekeys
        .iter()
        .find(|v| v.key.key_id == id)
        .map(|v| &v.key)
}
fn initiator_session_key(
    stored: &StoredIdentity,
    peer_identity: &str,
    peer_device: &str,
    signed_id: u32,
    signed_public: &str,
    signed_signature: &str,
    one_time: Option<(&str, u32)>,
    conversation_id: &str,
) -> Result<([u8; 32], String), String> {
    let identity = PublicKeyBytes(decode_fixed::<32>(
        peer_identity,
        "peer identity public key",
    )?);
    let sig = decode_fixed::<64>(signed_signature, "signed prekey signature")?;
    let bundle = SignedPreKeyBundle {
        key_id: signed_id,
        public_key: PublicKeyBytes(decode_fixed::<32>(
            signed_public,
            "signed prekey public key",
        )?),
        signature: sig,
    };
    verify_signed_prekey(&identity, &bundle)
        .map_err(|_| "Signed prekey verification failed".to_string())?;
    let mut s = decode_fixed::<32>(&stored.device_secret, "device secret")?;
    let static_kp = X25519KeyPair::from_secret_bytes(s);
    s.zeroize();
    let ephemeral = X25519KeyPair::generate();
    let peer_static = PublicKeyBytes(decode_fixed::<32>(peer_device, "peer device public key")?);
    let mut parts: Vec<SharedSecret> = vec![
        static_kp
            .dh(&bundle.public_key)
            .map_err(|e| e.to_string())?,
        ephemeral.dh(&peer_static).map_err(|e| e.to_string())?,
        ephemeral
            .dh(&bundle.public_key)
            .map_err(|e| e.to_string())?,
    ];
    if let Some((otp, _)) = one_time {
        parts.push(
            ephemeral
                .dh(&PublicKeyBytes(decode_fixed::<32>(otp, "one-time prekey")?))
                .map_err(|e| e.to_string())?,
        )
    }
    let key = derive_prekey_session_key(&parts, conversation_id)
        .map_err(|e| format!("Session key derivation failed: {e}"))?;
    Ok((key, BASE64.encode(ephemeral.public_key_bytes().0)))
}
fn responder_session_key(
    stored: &StoredIdentity,
    sender_static: &str,
    ephemeral_public: &str,
    signed_id: u32,
    one_time_id: Option<u32>,
    conversation_id: &str,
) -> Result<[u8; 32], String> {
    let sender = PublicKeyBytes(decode_fixed::<32>(
        sender_static,
        "sender device public key",
    )?);
    let eph = PublicKeyBytes(decode_fixed::<32>(
        ephemeral_public,
        "sender ephemeral public key",
    )?);
    let signed = find_signed(stored, signed_id).ok_or("Required signed prekey is unavailable")?;
    let mut ss = decode_fixed::<32>(&signed.secret, "signed prekey secret")?;
    let spk = X25519KeyPair::from_secret_bytes(ss);
    ss.zeroize();
    let mut rs = decode_fixed::<32>(&stored.device_secret, "device secret")?;
    let receiver = X25519KeyPair::from_secret_bytes(rs);
    rs.zeroize();
    let mut parts = vec![
        spk.dh(&sender).map_err(|e| e.to_string())?,
        receiver.dh(&eph).map_err(|e| e.to_string())?,
        spk.dh(&eph).map_err(|e| e.to_string())?,
    ];
    if let Some(oid) = one_time_id {
        let otp = stored
            .one_time_prekeys
            .iter()
            .find(|k| k.key_id == oid)
            .ok_or("Required one-time prekey is unavailable")?;
        let mut os = decode_fixed::<32>(&otp.secret, "one-time prekey secret")?;
        let okp = X25519KeyPair::from_secret_bytes(os);
        os.zeroize();
        parts.push(okp.dh(&eph).map_err(|e| e.to_string())?)
    }
    derive_prekey_session_key(&parts, conversation_id)
        .map_err(|e| format!("Session key derivation failed: {e}"))
}
fn stored_to_snapshot(s: &StoredRatchet) -> Result<akfes_core::RatchetSnapshot, String> {
    let mut skipped = HashMap::new();
    for (k, v) in &s.skipped {
        skipped.insert(*k, decode_fixed::<32>(v, "skipped message key")?);
    }
    Ok(akfes_core::RatchetSnapshot {
        root_key: decode_fixed::<32>(&s.root_key, "root")?,
        send_chain: s
            .send_chain
            .as_ref()
            .map(|v| decode_fixed::<32>(v, "send chain"))
            .transpose()?,
        recv_chain: s
            .recv_chain
            .as_ref()
            .map(|v| decode_fixed::<32>(v, "recv chain"))
            .transpose()?,
        send_count: s.send_count,
        recv_count: s.recv_count,
        skipped,
        received: s.received.iter().copied().collect(),
    })
}
fn snapshot_to_stored(s: akfes_core::RatchetSnapshot, session_id: String) -> StoredRatchet {
    StoredRatchet {
        session_id,
        root_key: BASE64.encode(s.root_key),
        send_chain: s.send_chain.map(|v| BASE64.encode(v)),
        recv_chain: s.recv_chain.map(|v| BASE64.encode(v)),
        send_count: s.send_count,
        recv_count: s.recv_count,
        skipped: s
            .skipped
            .into_iter()
            .map(|(k, v)| (k, BASE64.encode(v)))
            .collect(),
        received: s.received.into_iter().collect(),
    }
}
fn ratchet_id(conversation: &str, local: &str, remote: &str) -> String {
    format!("{conversation}:{local}:{remote}")
}
fn session_ratchet_id(pair: &str, session_id: &str) -> String {
    format!("{pair}|{session_id}")
}
fn migrate_legacy_ratchet(stored: &mut StoredIdentity, pair: &str) {
    if stored.outbound_sessions.contains_key(pair) {
        return;
    }
    if let Some(legacy) = stored.ratchets.remove(pair) {
        if !legacy.session_id.is_empty() {
            let session_id = legacy.session_id.clone();
            stored
                .ratchets
                .insert(session_ratchet_id(pair, &session_id), legacy);
            stored
                .outbound_sessions
                .insert(pair.to_string(), session_id);
        }
    }
}
fn store_ratchet_session(
    stored: &mut StoredIdentity,
    pair: &str,
    ratchet: StoredRatchet,
    make_outbound: bool,
) {
    let session_id = ratchet.session_id.clone();
    stored
        .ratchets
        .insert(session_ratchet_id(pair, &session_id), ratchet);
    if make_outbound || !stored.outbound_sessions.contains_key(pair) {
        stored
            .outbound_sessions
            .insert(pair.to_string(), session_id.clone());
    }
    let prefix = format!("{pair}|");
    let active = stored
        .outbound_sessions
        .get(pair)
        .cloned()
        .unwrap_or_default();
    let mut keys: Vec<String> = stored
        .ratchets
        .keys()
        .filter(|key| key.starts_with(&prefix))
        .cloned()
        .collect();
    while keys.len() > 8 {
        let old = keys.remove(0);
        if old != session_ratchet_id(pair, &active) {
            stored.ratchets.remove(&old);
        }
    }
}
fn new_ratchet(
    session: [u8; 32],
    conversation: &str,
    local: &str,
    remote: &str,
) -> Result<RatchetState, String> {
    let (send, recv) = derive_directional_chains(&session, conversation, local, remote)
        .map_err(|e| e.to_string())?;
    let mut state = RatchetState::from_root_key(RootKey(session));
    state.initialize_send_chain(send);
    state.initialize_recv_chain(recv);
    Ok(state)
}
fn new_session_id() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}
fn aad(
    conversation: &str,
    sender: &str,
    recipient: &str,
    logical: &str,
    session_id: &str,
    number: u32,
    kind: &str,
) -> Result<Vec<u8>, String> {
    build_message_aad(conversation, sender, recipient, logical, session_id, number, kind)
        .map_err(|e| e.to_string())
}
fn remember_outbound(stored: &mut StoredIdentity, key_id: String, key: &MessageKey) {
    stored
        .outbound_message_keys
        .insert(key_id.clone(), BASE64.encode(key.0));
    stored.outbound_key_order.retain(|v| v != &key_id);
    stored.outbound_key_order.push(key_id);
    while stored.outbound_key_order.len() > OUTBOUND_KEY_LIMIT {
        let old = stored.outbound_key_order.remove(0);
        stored.outbound_message_keys.remove(&old);
    }
}
fn remember_inbound(stored: &mut StoredIdentity, key_id: String, key: &MessageKey) {
    stored
        .inbound_message_keys
        .insert(key_id.clone(), BASE64.encode(key.0));
    stored.inbound_key_order.retain(|v| v != &key_id);
    stored.inbound_key_order.push(key_id);
    while stored.inbound_key_order.len() > OUTBOUND_KEY_LIMIT {
        let old = stored.inbound_key_order.remove(0);
        stored.inbound_message_keys.remove(&old);
    }
}

#[tauri::command]
fn ensure_device_identity(app: AppHandle, profile: String) -> Result<PublicIdentity, String> {
    public_identity(&load_or_create_identity(&app, &profile)?)
}
#[tauri::command]
fn ensure_e2ee_bundle(app: AppHandle, profile: String) -> Result<E2eeBundle, String> {
    bundle(&load_or_create_identity(&app, &profile)?)
}
#[tauri::command]
fn bind_server_device(
    app: AppHandle,
    profile: String,
    server_device_id: String,
) -> Result<(), String> {
    let mut s = load_or_create_identity(&app, &profile)?;
    s.server_device_id = Some(server_device_id);
    write_identity(&app, &profile, &s)
}

#[tauri::command]
fn clear_server_device_binding(app: AppHandle, profile: String) -> Result<(), String> {
    let mut s = load_or_create_identity(&app, &profile)?;
    s.server_device_id = None;
    write_identity(&app, &profile, &s)
}

#[tauri::command]
fn peer_identity_status(
    app: AppHandle,
    profile: String,
    peer_user_id: String,
    peer_device_id: String,
    identity_public_key: String,
    device_public_key: String,
    device_key_signature: String,
) -> Result<PeerIdentityStatus, String> {
    verify_device_binding(
        &identity_public_key,
        &device_public_key,
        &device_key_signature,
    )?;
    let mut s = load_or_create_identity(&app, &profile)?;
    let k = peer_key(&peer_user_id, &peer_device_id);
    let safety = safety_for(&s, &identity_public_key)?;
    let result = match s.peer_identities.get(&k) {
        None => {
            s.peer_identities.insert(
                k,
                PeerTrustRecord {
                    identity_public_key: identity_public_key.clone(),
                    verified: false,
                    safety_number: safety.clone(),
                    verified_at_unix: None,
                },
            );
            write_identity(&app, &profile, &s)?;
            PeerIdentityStatus {
                status: "unverified".into(),
                safety_number: safety,
                pinned_identity_public_key: Some(identity_public_key),
            }
        }
        Some(r) if r.identity_public_key == identity_public_key => PeerIdentityStatus {
            status: if r.verified { "verified" } else { "unverified" }.into(),
            safety_number: safety,
            pinned_identity_public_key: Some(r.identity_public_key.clone()),
        },
        Some(r) => PeerIdentityStatus {
            status: "changed".into(),
            safety_number: safety,
            pinned_identity_public_key: Some(r.identity_public_key.clone()),
        },
    };
    Ok(result)
}
#[tauri::command]
fn verify_peer_identity(
    app: AppHandle,
    profile: String,
    peer_user_id: String,
    peer_device_id: String,
    identity_public_key: String,
    device_public_key: String,
    device_key_signature: String,
    confirmed_safety_number: String,
) -> Result<PeerIdentityStatus, String> {
    verify_device_binding(
        &identity_public_key,
        &device_public_key,
        &device_key_signature,
    )?;
    let mut s = load_or_create_identity(&app, &profile)?;
    let safety = safety_for(&s, &identity_public_key)?;
    let norm = |v: &str| v.chars().filter(|c| c.is_ascii_digit()).collect::<String>();
    if norm(&safety) != norm(&confirmed_safety_number) {
        return Err("Safety number does not match".into());
    }
    let k = peer_key(&peer_user_id, &peer_device_id);
    s.peer_identities.insert(
        k,
        PeerTrustRecord {
            identity_public_key: identity_public_key.clone(),
            verified: true,
            safety_number: safety.clone(),
            verified_at_unix: Some(now_unix()),
        },
    );
    write_identity(&app, &profile, &s)?;
    Ok(PeerIdentityStatus {
        status: "verified".into(),
        safety_number: safety,
        pinned_identity_public_key: Some(identity_public_key),
    })
}

#[tauri::command]
fn has_ratchet_session(
    app: AppHandle,
    profile: String,
    conversation_id: String,
    local_device_id: String,
    remote_device_id: String,
) -> Result<bool, String> {
    let s = load_or_create_identity(&app, &profile)?;
    let pair = ratchet_id(&conversation_id, &local_device_id, &remote_device_id);
    let active = s
        .outbound_sessions
        .get(&pair)
        .and_then(|sid| s.ratchets.get(&session_ratchet_id(&pair, sid)))
        .or_else(|| s.ratchets.get(&pair));
    Ok(active
        .map(|r| r.send_count < SESSION_REKEY_MESSAGES)
        .unwrap_or(false))
}

#[tauri::command]
fn encrypt_text_with_ratchet(
    app: AppHandle,
    profile: String,
    plaintext: String,
    peer_user_id: String,
    peer_identity_public_key: String,
    peer_device_public_key: String,
    peer_device_key_signature: String,
    signed_prekey_id: u32,
    signed_prekey_public_key: String,
    signed_prekey_signature: String,
    one_time_prekey: Option<PreKeyPublic>,
    conversation_id: String,
    local_device_id: String,
    remote_device_id: String,
    logical_message_id: String,
    message_type: String,
    trusted_own_device: Option<bool>,
) -> Result<serde_json::Value, String> {
    verify_device_binding(
        &peer_identity_public_key,
        &peer_device_public_key,
        &peer_device_key_signature,
    )?;
    let mut s = load_or_create_identity(&app, &profile)?;
    if !trusted_own_device.unwrap_or(false) {
        require_stable_peer(
            &s,
            &peer_user_id,
            &remote_device_id,
            &peer_identity_public_key,
        )?;
        if message_type.starts_with("secret_") {
            let record = s.peer_identities.get(&peer_key(&peer_user_id, &remote_device_id));
            if !record.map(|value| value.verified).unwrap_or(false) {
                return Err("Secret messages require Safety Number verification".into());
            }
        }
    }
    let rid = ratchet_id(&conversation_id, &local_device_id, &remote_device_id);
    migrate_legacy_ratchet(&mut s, &rid);
    let active_key = s
        .outbound_sessions
        .get(&rid)
        .map(|sid| session_ratchet_id(&rid, sid));
    let need_new = s
        .ratchets
        .get(active_key.as_deref().unwrap_or(""))
        .map(|r| r.send_count >= SESSION_REKEY_MESSAGES || r.session_id.is_empty())
        .unwrap_or(true);
    if need_new {
        s.outbound_sessions.remove(&rid);
    }
    let mut ephemeral = None;
    let mut emitted_otp = None;
    let active_key = s
        .outbound_sessions
        .get(&rid)
        .map(|sid| session_ratchet_id(&rid, sid));
    let (mut state, session_id) =
        if let Some(saved) = active_key.as_ref().and_then(|key| s.ratchets.get(key)) {
            (
                RatchetState::from_snapshot(stored_to_snapshot(saved)?),
                saved.session_id.clone(),
            )
        } else {
            let otp = one_time_prekey
                .as_ref()
                .map(|k| (k.public_key.as_str(), k.key_id));
            let (session, eph) = initiator_session_key(
                &s,
                &peer_identity_public_key,
                &peer_device_public_key,
                signed_prekey_id,
                &signed_prekey_public_key,
                &signed_prekey_signature,
                otp,
                &conversation_id,
            )?;
            ephemeral = Some(eph);
            emitted_otp = one_time_prekey.as_ref().map(|k| k.key_id);
            (
                new_ratchet(
                    session,
                    &conversation_id,
                    &local_device_id,
                    &remote_device_id,
                )?,
                new_session_id(),
            )
        };
    let (key, number) = state
        .next_send_key()
        .map_err(|e| format!("Ratchet send failed: {e}"))?;
    let ad = aad(
        &conversation_id,
        &local_device_id,
        &remote_device_id,
        &logical_message_id,
        &session_id,
        number,
        &message_type,
    )?;
    let (ct, nonce) = encrypt_message_with_aad(plaintext.as_bytes(), &key, &ad)
        .map_err(|e| format!("Encryption failed: {e}"))?;
    remember_outbound(
        &mut s,
        format!(
            "{}:{}:{}:{}:{}",
            conversation_id, local_device_id, remote_device_id, session_id, number
        ),
        &key,
    );
    store_ratchet_session(
        &mut s,
        &rid,
        snapshot_to_stored(state.snapshot(), session_id.clone()),
        true,
    );
    write_identity(&app, &profile, &s)?;
    Ok(
        serde_json::json!({"ciphertext":BASE64.encode(ct),"nonce":BASE64.encode(nonce.0),"e2ee_version":4u8,"ratchet_version":2u8,"message_number":number,"ratchet_session_id":session_id,"signed_prekey_id":signed_prekey_id,"one_time_prekey_id":emitted_otp,"ephemeral_public_key":ephemeral}),
    )
}

#[tauri::command]
fn decrypt_text_with_ratchet(
    app: AppHandle,
    profile: String,
    ciphertext: String,
    nonce: String,
    sender_device_public_key: String,
    signed_prekey_id: u32,
    one_time_prekey_id: Option<u32>,
    ephemeral_public_key: Option<String>,
    ratchet_session_id: String,
    conversation_id: String,
    local_device_id: String,
    remote_device_id: String,
    sender_message_number: u32,
    logical_message_id: String,
    message_type: String,
) -> Result<String, String> {
    if ratchet_session_id.len() < 16
        || ratchet_session_id.len() > 64
        || !ratchet_session_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err("Invalid ratchet session id".into());
    }
    let mut s = load_or_create_identity(&app, &profile)?;
    let rid = ratchet_id(&conversation_id, &local_device_id, &remote_device_id);
    migrate_legacy_ratchet(&mut s, &rid);
    let session_key = session_ratchet_id(&rid, &ratchet_session_id);
    let cache_id = format!(
        "{}:{}:{}:{}:{}",
        conversation_id,
        remote_device_id,
        local_device_id,
        ratchet_session_id,
        sender_message_number
    );
    let ct = BASE64
        .decode(ciphertext)
        .map_err(|_| "Invalid ciphertext encoding".to_string())?;
    let n = Nonce(decode_fixed::<12>(&nonce, "nonce")?);
    let ad = aad(
        &conversation_id,
        &remote_device_id,
        &local_device_id,
        &logical_message_id,
        &ratchet_session_id,
        sender_message_number,
        &message_type,
    )?;
    if let Some(encoded) = s.inbound_message_keys.get(&cache_id) {
        let key = MessageKey(decode_fixed::<32>(encoded, "cached inbound message key")?);
        let plain = decrypt_message_with_aad(&ct, &n, &key, &ad)
            .map_err(|_| "Cached message authentication failed".to_string())?;
        return String::from_utf8(plain).map_err(|_| "Decrypted message is not UTF-8".into());
    }
    let mut state = if let Some(eph) = ephemeral_public_key.as_ref() {
        let session = responder_session_key(
            &s,
            &sender_device_public_key,
            eph,
            signed_prekey_id,
            one_time_prekey_id,
            &conversation_id,
        )?;
        new_ratchet(
            session,
            &conversation_id,
            &local_device_id,
            &remote_device_id,
        )?
    } else {
        let saved = s
            .ratchets
            .get(&session_key)
            .ok_or("Missing ratchet session; a fresh ephemeral session is required")?;
        RatchetState::from_snapshot(stored_to_snapshot(saved)?)
    };
    let key = state
        .recv_key_for(sender_message_number)
        .map_err(|_| "Ratchet message rejected or replayed".to_string())?;
    let plain = decrypt_message_with_aad(&ct, &n, &key, &ad)
        .map_err(|_| "Message authentication failed".to_string())?;
    remember_inbound(&mut s, cache_id, &key);
    store_ratchet_session(
        &mut s,
        &rid,
        snapshot_to_stored(state.snapshot(), ratchet_session_id),
        false,
    );
    write_identity(&app, &profile, &s)?;
    String::from_utf8(plain).map_err(|_| "Decrypted message is not UTF-8".into())
}

#[tauri::command]
fn decrypt_own_sent_ratchet(
    app: AppHandle,
    profile: String,
    ciphertext: String,
    nonce: String,
    ratchet_session_id: String,
    conversation_id: String,
    local_device_id: String,
    remote_device_id: String,
    sender_message_number: u32,
    logical_message_id: String,
    message_type: String,
) -> Result<String, String> {
    let s = load_or_create_identity(&app, &profile)?;
    let id = format!(
        "{}:{}:{}:{}:{}",
        conversation_id,
        local_device_id,
        remote_device_id,
        ratchet_session_id,
        sender_message_number
    );
    let enc = s
        .outbound_message_keys
        .get(&id)
        .ok_or("Outbound message key is unavailable")?;
    let key = MessageKey(decode_fixed::<32>(enc, "outbound message key")?);
    let ct = BASE64
        .decode(ciphertext)
        .map_err(|_| "Invalid ciphertext".to_string())?;
    let n = Nonce(decode_fixed::<12>(&nonce, "nonce")?);
    let ad = aad(
        &conversation_id,
        &local_device_id,
        &remote_device_id,
        &logical_message_id,
        &ratchet_session_id,
        sender_message_number,
        &message_type,
    )?;
    let p = decrypt_message_with_aad(&ct, &n, &key, &ad)
        .map_err(|_| "Message authentication failed".to_string())?;
    String::from_utf8(p).map_err(|_| "Decrypted message is not UTF-8".into())
}

#[tauri::command]
fn consume_local_one_time_prekey(
    app: AppHandle,
    profile: String,
    key_id: u32,
) -> Result<E2eeBundle, String> {
    let mut s = load_or_create_identity(&app, &profile)?;
    s.one_time_prekeys.retain(|k| k.key_id != key_id);
    ensure_prekeys(&mut s);
    write_identity(&app, &profile, &s)?;
    bundle(&s)
}

#[tauri::command]
fn encrypt_file_bytes(plaintext_b64: String) -> Result<EncryptedFilePayload, String> {
    const MAX: usize = 25 * 1024 * 1024;
    let p = BASE64
        .decode(plaintext_b64)
        .map_err(|_| "Invalid file base64".to_string())?;
    if p.len() > MAX {
        return Err("File exceeds 25 MiB".into());
    }
    let e = akfes_core::encrypt_file(&p).map_err(|x| x.to_string())?;
    Ok(EncryptedFilePayload {
        ciphertext: BASE64.encode(e.ciphertext),
        nonce: BASE64.encode(e.nonce.0),
        file_key: BASE64.encode(e.file_key),
        sha256: BASE64.encode(e.sha256),
        plaintext_size: p.len(),
    })
}
#[tauri::command]
fn decrypt_file_bytes(args: DecryptFileArgs) -> Result<DecryptedFilePayload, String> {
    let ct = BASE64
        .decode(args.ciphertext_b64)
        .map_err(|_| "Invalid ciphertext".to_string())?;
    let n = Nonce(decode_fixed::<12>(&args.nonce_b64, "file nonce")?);
    let k = decode_fixed::<32>(&args.file_key_b64, "file key")?;
    let h = decode_fixed::<32>(&args.sha256_b64, "sha256")?;
    let p = akfes_core::decrypt_file(&ct, &n, &k, &h)
        .map_err(|_| "File authentication or integrity verification failed".to_string())?;
    Ok(DecryptedFilePayload {
        plaintext_b64: BASE64.encode(p),
    })
}

#[tauri::command]
fn sign_device_proof(
    app: AppHandle,
    profile: String,
    account_username: String,
    challenge_id: String,
    nonce: String,
    device_id: String,
) -> Result<String, String> {
    let s = load_or_create_identity(&app, &profile)?;
    let mut sec = decode_fixed::<32>(&s.identity_secret, "identity secret")?;
    let id = IdentityKeyPair::from_secret_bytes(sec);
    sec.zeroize();
    let normalized = account_username.trim().to_lowercase();
    let msg = format!("AKFES-DEVICE-POP-v1|{challenge_id}|{normalized}|{device_id}|{nonce}");
    Ok(BASE64.encode(id.sign(msg.as_bytes()).map_err(|e| e.to_string())?))
}

#[tauri::command]
fn sign_secret_gate(
    app: AppHandle,
    profile: String,
    device_id: String,
    public_key: String,
) -> Result<String, String> {
    let s = load_or_create_identity(&app, &profile)?;
    let mut sec = decode_fixed::<32>(&s.identity_secret, "identity secret")?;
    let id = IdentityKeyPair::from_secret_bytes(sec);
    sec.zeroize();
    let msg = format!("AKFES-SECRET-GATE-v1|{device_id}|{public_key}");
    Ok(BASE64.encode(id.sign(msg.as_bytes()).map_err(|e| e.to_string())?))
}

#[tauri::command]
fn verify_secret_gate(
    identity_public_key: String,
    device_id: String,
    public_key: String,
    signature: String,
) -> Result<bool, String> {
    let identity = PublicKeyBytes(decode_fixed::<32>(&identity_public_key, "peer identity")?);
    let sig = decode_fixed::<64>(&signature, "secret gate signature")?;
    let msg = format!("AKFES-SECRET-GATE-v1|{device_id}|{public_key}");
    verify_identity_signature(&identity, msg.as_bytes(), &sig)
        .map_err(|_| "Secret gate public key is not bound to the device identity".to_string())?;
    Ok(true)
}

#[tauri::command]
fn sign_call_signal(app: AppHandle, profile: String, payload: String) -> Result<String, String> {
    if payload.len() > 16_000 { return Err("Call signal is too large".to_string()); }
    let s = load_or_create_identity(&app, &profile)?;
    let mut sec = decode_fixed::<32>(&s.identity_secret, "identity secret")?;
    let id = IdentityKeyPair::from_secret_bytes(sec);
    sec.zeroize();
    let msg = format!("AKFES-CALL-SIGNAL-v1|{payload}");
    Ok(BASE64.encode(id.sign(msg.as_bytes()).map_err(|e| e.to_string())?))
}

#[tauri::command]
fn verify_call_signal(identity_public_key: String, payload: String, signature: String) -> Result<bool, String> {
    if payload.len() > 16_000 { return Err("Call signal is too large".to_string()); }
    let identity = PublicKeyBytes(decode_fixed::<32>(&identity_public_key, "peer identity")?);
    let sig = decode_fixed::<64>(&signature, "call signal signature")?;
    let msg = format!("AKFES-CALL-SIGNAL-v1|{payload}");
    verify_identity_signature(&identity, msg.as_bytes(), &sig).map_err(|_| "Call signal identity signature is invalid".to_string())?;
    Ok(true)
}

fn parse_arduino_response_line(line: &[u8]) -> Option<Result<String, String>> {
    let line = String::from_utf8_lossy(line);
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    if let Some(value) = line.strip_prefix("RESPONSE ") {
        let response = value.trim().to_lowercase();
        if response.len() == 64 && response.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some(Ok(response));
        }
        return Some(Err(
            "Arduino returned a malformed RESPONSE. Upload the generated AKFES firmware again."
                .into(),
        ));
    }
    let error = match line {
        "ERROR NOT_PROVISIONED" => Some(
            "Arduino firmware is not provisioned for this device. Generate the per-device sketch and upload it."
                .to_string(),
        ),
        "ERROR INVALID_COMMAND" => Some(
            "Arduino firmware rejected the AKFES command. Upload the compatible generated firmware again."
                .to_string(),
        ),
        "ERROR LINE_TOO_LONG" => Some(
            "Arduino reported an oversized command. Close other serial programs and retry."
                .to_string(),
        ),
        "ERROR PIN_TIMEOUT" => Some(
            "Keypad PIN entry timed out. Start again and press the configured confirm key within 60 seconds."
                .to_string(),
        ),
        "ERROR PIN_MISMATCH" => Some(
            "The two PIN entries on the Arduino keypad did not match. Start PIN setup again."
                .to_string(),
        ),
        _ if line.starts_with("ERROR ") => {
            Some("Arduino firmware reported an error. Upload the generated AKFES firmware again.".into())
        }
        _ => None,
    };
    error.map(Err)
}

fn parse_arduino_pin_key_line(line: &[u8]) -> Option<Result<String, String>> {
    let text = String::from_utf8_lossy(line);
    let text = text.trim();
    if let Some(value) = text.strip_prefix("PINKEY ") {
        let key = value.trim().to_ascii_lowercase();
        return Some(
            if key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                Ok(key)
            } else {
                Err("Arduino returned an invalid keypad enrollment key.".into())
            },
        );
    }
    parse_arduino_response_line(line)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ArduinoPortInfo {
    port: String,
    label: String,
    board: Option<String>,
    supported: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ArduinoProvisionResult {
    port: String,
    board: String,
    sketch_path: String,
    firmware_verified: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ArduinoKeypadConfig {
    columns: usize,
    row_pins: Vec<u8>,
    column_pins: Vec<u8>,
    keymap: String,
    clear_key: String,
    confirm_key: String,
}

fn validate_keypad_config(config: &ArduinoKeypadConfig, fqbn: &str) -> Result<(), String> {
    if !matches!(config.columns, 3 | 4)
        || config.row_pins.len() != 4
        || config.column_pins.len() != config.columns
    {
        return Err("Keypad must be a 4x3 or 4x4 matrix.".into());
    }
    let max_pin = if fqbn == "arduino:avr:mega" { 69 } else { 19 };
    let pins = config
        .row_pins
        .iter()
        .chain(config.column_pins.iter())
        .copied()
        .collect::<Vec<_>>();
    if pins.iter().any(|pin| *pin < 2 || *pin > max_pin) {
        return Err(format!("Keypad GPIO pins must be between 2 and {max_pin}."));
    }
    let unique = pins
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    if unique.len() != pins.len() {
        return Err("Each keypad row and column must use a different GPIO pin.".into());
    }
    let keys = config.keymap.as_bytes();
    if keys.len() != 4 * config.columns
        || keys
            .iter()
            .any(|key| !matches!(*key, b'0'..=b'9' | b'A'..=b'D' | b'*' | b'#'))
    {
        return Err(
            "Key binding must contain exactly one supported character per keypad position.".into(),
        );
    }
    for digit in b'0'..=b'9' {
        if keys.iter().filter(|key| **key == digit).count() != 1 {
            return Err("Key binding must contain each digit 0 through 9 exactly once.".into());
        }
    }
    let action_key = |value: &str| {
        value.as_bytes().len() == 1
            && matches!(value.as_bytes()[0], b'A'..=b'D' | b'*' | b'#')
            && keys.contains(&value.as_bytes()[0])
    };
    if !action_key(&config.clear_key)
        || !action_key(&config.confirm_key)
        || config.clear_key == config.confirm_key
    {
        return Err(
            "Clear and confirm must be different non-numeric keys present in the key binding."
                .into(),
        );
    }
    Ok(())
}

fn apply_keypad_config(mut sketch: String, config: &ArduinoKeypadConfig) -> String {
    let row_pins = config
        .row_pins
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let column_pins = config
        .column_pins
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    sketch = sketch.replace(
        "#define AKFES_KEYPAD_COLUMNS 3",
        &format!("#define AKFES_KEYPAD_COLUMNS {}", config.columns),
    );
    sketch = sketch.replace(
        "#define AKFES_KEYPAD_ROW_PINS {2, 3, 4, 5}",
        &format!("#define AKFES_KEYPAD_ROW_PINS {{{row_pins}}}"),
    );
    sketch = sketch.replace(
        "#define AKFES_KEYPAD_COLUMN_PINS {6, 7, 8}",
        &format!("#define AKFES_KEYPAD_COLUMN_PINS {{{column_pins}}}"),
    );
    sketch = sketch.replace(
        "#define AKFES_KEYPAD_KEYMAP \"123456789*0#\"",
        &format!("#define AKFES_KEYPAD_KEYMAP \"{}\"", config.keymap),
    );
    sketch = sketch.replace(
        "#define AKFES_KEYPAD_CLEAR_KEY '*'",
        &format!("#define AKFES_KEYPAD_CLEAR_KEY '{}'", config.clear_key),
    );
    sketch.replace(
        "#define AKFES_KEYPAD_CONFIRM_KEY '#'",
        &format!("#define AKFES_KEYPAD_CONFIRM_KEY '{}'", config.confirm_key),
    )
}

fn arduino_board_for_usb(
    vid: u16,
    pid: u16,
    description: &str,
) -> Option<(&'static str, &'static str)> {
    let description = description.to_ascii_lowercase();
    // Common Uno-compatible CH340/CP210x USB bridges do not advertise
    // "Arduino Uno" in their product string. They still use the Uno AVR
    // bootloader in the supported wiring, so expose them as Uno candidates
    // instead of making firmware setup look like a serial-only connection.
    let uno_clone = matches!((vid, pid),
        (0x1A86, 0x7523 | 0x5523) |
        (0x10C4, 0xEA60) |
        (0x0403, 0x6001)
    );
    if matches!(
        (vid, pid),
        (0x2341, 0x0043 | 0x0001) | (0x2a03, 0x0043 | 0x0001)
    ) || description.contains("arduino uno") || uno_clone
    {
        return Some(("arduino:avr:uno", "Arduino Uno"));
    }
    if matches!((vid, pid), (0x2341, 0x0058) | (0x2a03, 0x0058))
        || description.contains("arduino nano")
    {
        return Some(("arduino:avr:nano", "Arduino Nano"));
    }
    if matches!((vid, pid), (0x2341, 0x0042) | (0x2a03, 0x0042))
        || description.contains("arduino mega")
    {
        return Some(("arduino:avr:mega", "Arduino Mega 2560"));
    }
    None
}

fn available_arduino_ports() -> Result<Vec<ArduinoPortInfo>, String> {
    let mut result = serialport::available_ports()
        .map_err(|e| format!("Could not enumerate serial ports: {e}"))?
        .into_iter()
        .map(|port| match port.port_type {
            serialport::SerialPortType::UsbPort(usb) => {
                let description = [usb.manufacturer.as_deref(), usb.product.as_deref()]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" ");
                let board = arduino_board_for_usb(usb.vid, usb.pid, &description);
                ArduinoPortInfo {
                    label: if description.trim().is_empty() {
                        format!("{} · USB {:04X}:{:04X}", port.port_name, usb.vid, usb.pid)
                    } else {
                        format!("{} · {}", port.port_name, description.trim())
                    },
                    port: port.port_name,
                    board: board.map(|(_, name)| name.to_string()),
                    supported: board.is_some(),
                }
            }
            _ => ArduinoPortInfo {
                label: format!("{} · serial device", port.port_name),
                port: port.port_name,
                board: None,
                supported: false,
            },
        })
        .collect::<Vec<_>>();
    result.sort_by_key(|port| (!port.supported, port.port.clone()));
    Ok(result)
}

#[tauri::command]
fn list_arduino_ports() -> Result<Vec<ArduinoPortInfo>, String> {
    available_arduino_ports()
}

fn valid_device_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

const ARDUINO_SKETCH_TEMPLATE: &str =
    include_str!("../../../arduino/AKFES_Device_Authenticator/AKFES_Device_Authenticator.ino");
const ARDUINO_SHA256_HEADER: &str =
    include_str!("../../../arduino/AKFES_Device_Authenticator/akfes_sha256.h");

fn copy_directory(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination)
        .map_err(|e| format!("Could not create bundled Arduino directory: {e}"))?;
    for entry in fs::read_dir(source)
        .map_err(|e| format!("Could not read bundled Arduino directory: {e}"))?
    {
        let entry = entry.map_err(|e| format!("Could not inspect bundled Arduino file: {e}"))?;
        let target = destination.join(entry.file_name());
        let kind = entry
            .file_type()
            .map_err(|e| format!("Could not inspect bundled Arduino file type: {e}"))?;
        if kind.is_dir() {
            copy_directory(&entry.path(), &target)?
        } else if kind.is_file() {
            fs::copy(entry.path(), target)
                .map_err(|e| format!("Could not install bundled Arduino file: {e}"))?;
        } else {
            return Err("Bundled Arduino resources contain an unsupported link".into());
        }
    }
    Ok(())
}

fn find_arduino_cli(app: &AppHandle) -> Result<(PathBuf, Option<PathBuf>), String> {
    // The Windows installer places the offline toolchain next to the executable.
    // A raw Cargo release build has no Tauri bundle resource directory, so looking
    // only in resource_dir() made a correctly installed toolchain invisible.
    let mut bundled_locations = Vec::new();
    if let Ok(executable) = std::env::current_exe() {
        if let Some(directory) = executable.parent() {
            bundled_locations.push(directory.join("arduino-toolchain"));
        }
    }
    if let Ok(resources) = app.path().resource_dir() {
        bundled_locations.push(resources.join("arduino-toolchain"));
    }
    for bundled in bundled_locations {
        if bundled.join("arduino-cli.exe").is_file() && bundled.join("READY").is_file() {
            let bundled_bootloader = bundled.join(
                "data/packages/arduino/hardware/avr/1.8.6/bootloaders/atmega/ATmegaBOOT_168_atmega1280.hex",
            );
            if !bundled_bootloader.is_file() {
                return Err(format!(
                    "The bundled Arduino AVR toolchain is incomplete (missing {}). Reinstall the latest AKFES client installer.",
                    bundled_bootloader.display()
                ));
            }
            let local = std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .ok_or("LOCALAPPDATA is unavailable")?
                .join("AKFES/arduino-toolchain-1.5.1");
            let bundled_ready = fs::read_to_string(bundled.join("READY"))
                .map_err(|e| format!("Could not verify bundled Arduino toolchain: {e}"))?;
            let installed_ready = fs::read_to_string(local.join("READY")).unwrap_or_default();
            let installed_core = local.join("data/packages/arduino/hardware/avr/1.8.6/boards.txt");
            let installed_compiler = local.join(
                "data/packages/arduino/tools/avr-gcc/7.3.0-atmel3.6.1-arduino7/bin/avr-g++.exe",
            );
            let installed_device_specs = local.join(
                "data/packages/arduino/tools/avr-gcc/7.3.0-atmel3.6.1-arduino7/lib/gcc/avr/7.3.0/device-specs/specs-atmega328p",
            );
            let installed_bootloader = local.join(
                "data/packages/arduino/hardware/avr/1.8.6/bootloaders/atmega/ATmegaBOOT_168_atmega1280.hex",
            );
            if bundled_ready != installed_ready
                || !local.join("arduino-cli.exe").is_file()
                || !installed_core.is_file()
                || !installed_compiler.is_file()
                || !installed_device_specs.is_file()
                || !installed_bootloader.is_file()
            {
                copy_directory(&bundled, &local)?;
            }
            let data = local.join("data");
            let downloads = local.join("downloads");
            let user = local.join("user");
            fs::create_dir_all(&downloads)
                .map_err(|e| format!("Could not create Arduino download cache: {e}"))?;
            fs::create_dir_all(&user)
                .map_err(|e| format!("Could not create Arduino user directory: {e}"))?;
            let yaml=format!("board_manager:\n  additional_urls: []\ndirectories:\n  data: {}\n  downloads: {}\n  user: {}\nupdater:\n  enable_notification: false\n",data.to_string_lossy().replace('\\',"/"),downloads.to_string_lossy().replace('\\',"/"),user.to_string_lossy().replace('\\',"/"));
            let config = local.join("arduino-cli.yaml");
            fs::write(&config, yaml)
                .map_err(|e| format!("Could not configure bundled Arduino CLI: {e}"))?;
            return Ok((local.join("arduino-cli.exe"), Some(config)));
        }
    }
    let mut candidates = Vec::new();
    for variable in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(base) = std::env::var_os(variable) {
            candidates.push(
                PathBuf::from(base)
                    .join("Arduino IDE/resources/app/lib/backend/resources/arduino-cli.exe"),
            );
        }
    }
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .map(|path| (path, None))
        .ok_or_else(|| {
            "The bundled Arduino toolchain is missing. Reinstall AKFES with the complete installer."
                .into()
        })
}

fn hidden_command(program: &Path) -> Command {
    let mut command = Command::new(program);
    #[cfg(windows)]
    command.creation_flags(0x0800_0000);
    command
}

fn command_error(stage: &str, output: &Output) -> String {
    let text = if output.stderr.is_empty() {
        &output.stdout
    } else {
        &output.stderr
    };
    let mut text = String::from_utf8_lossy(text)
        .replace('\r', " ")
        .replace('\n', " ");
    text.retain(|character| !character.is_control());
    if text.len() > 800 {
        text.truncate(800);
    }
    format!("Arduino {stage} failed: {}", text.trim())
}

fn provision_local_arduino_impl(
    app: &AppHandle,
    profile: &str,
    device_id: String,
    port: String,
    mut device_secret: String,
    keypad_config: ArduinoKeypadConfig,
) -> Result<ArduinoProvisionResult, String> {
    let device_id = device_id.trim().to_ascii_lowercase();
    let port = port.trim().to_string();
    if !valid_device_id(&device_id) {
        return Err("The server device ID is invalid.".into());
    }
    let detected = serialport::available_ports()
        .map_err(|e| format!("Could not enumerate serial ports: {e}"))?
        .into_iter()
        .find(|candidate| candidate.port_name.eq_ignore_ascii_case(&port))
        .ok_or_else(|| "The selected Arduino is no longer connected.".to_string())?;
    let usb = match detected.port_type {
        serialport::SerialPortType::UsbPort(usb) => usb,
        _ => return Err("The selected serial device is not a supported Arduino USB board.".into()),
    };
    let description = [usb.manufacturer.as_deref(), usb.product.as_deref()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    let (fqbn, board) = arduino_board_for_usb(usb.vid, usb.pid, &description).ok_or_else(|| {
        "This Arduino model is not supported by automatic upload yet.".to_string()
    })?;
    validate_keypad_config(&keypad_config, fqbn)?;

    device_secret = device_secret.trim().to_ascii_lowercase();
    if device_secret.len() != 64 || !device_secret.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        device_secret.zeroize();
        return Err("The server returned an invalid Arduino device key.".into());
    }

    const PLACEHOLDER: &str = "AKFES_DEVICE_SECRET_HEX_PLACEHOLDER";
    if ARDUINO_SKETCH_TEMPLATE.matches(PLACEHOLDER).count() != 1 {
        device_secret.zeroize();
        return Err("The bundled Arduino firmware template is invalid.".into());
    }
    let local_app_data = std::env::var_os("LOCALAPPDATA")
        .ok_or_else(|| "LOCALAPPDATA is unavailable.".to_string())?;
    let sketch_dir = PathBuf::from(local_app_data)
        .join("AKFES/arduino")
        .join(&device_id)
        .join("AKFES_Device_Authenticator");
    fs::create_dir_all(&sketch_dir)
        .map_err(|e| format!("Could not create the Arduino sketch folder: {e}"))?;
    let mut sketch = apply_keypad_config(
        ARDUINO_SKETCH_TEMPLATE.replace(PLACEHOLDER, &device_secret),
        &keypad_config,
    );
    let sketch_write = fs::write(sketch_dir.join("AKFES_Device_Authenticator.ino"), &sketch);
    sketch.zeroize();
    if let Err(error) = sketch_write {
        device_secret.zeroize();
        return Err(format!("Could not write the provisioned Arduino sketch: {error}"));
    }
    fs::write(sketch_dir.join("akfes_sha256.h"), ARDUINO_SHA256_HEADER)
        .map_err(|e| format!("Could not write the Arduino SHA-256 header: {e}"))?;

    let (cli, config) = find_arduino_cli(app)?;
    let mut compile_command = hidden_command(&cli);
    if let Some(path) = config.as_ref() {
        compile_command.arg("--config-file").arg(path);
    }
    let compile = compile_command
        .args(["compile", "--fqbn", fqbn])
        .arg(&sketch_dir)
        .output()
        .map_err(|e| format!("Could not start Arduino compilation: {e}"))?;
    if !compile.status.success() {
        let _ = fs::remove_file(sketch_dir.join("AKFES_Device_Authenticator.ino"));
        device_secret.zeroize();
        return Err(command_error("compilation", &compile));
    }
    let mut upload_command = hidden_command(&cli);
    if let Some(path) = config.as_ref() {
        upload_command.arg("--config-file").arg(path);
    }
    let upload = upload_command
        .args(["upload", "--port", &port, "--fqbn", fqbn])
        .arg(&sketch_dir)
        .output()
        .map_err(|e| format!("Could not start Arduino upload: {e}"))?;
    if !upload.status.success() {
        let _ = fs::remove_file(sketch_dir.join("AKFES_Device_Authenticator.ino"));
        device_secret.zeroize();
        return Err(command_error("upload", &upload));
    }
    // Arduino upload tools and USB serial drivers can leave one stale line or
    // an extra reset transition immediately after flashing. Verify the actual
    // sketch over the production protocol before reporting success to the UI.
    let mut probe_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut probe_nonce);
    std::thread::sleep(Duration::from_millis(1000));
    let probe_result = arduino_challenge(port.clone(), hex::encode(probe_nonce), false);
    probe_nonce.zeroize();
    if let Err(error) = probe_result {
        let _ = fs::remove_file(sketch_dir.join("AKFES_Device_Authenticator.ino"));
        device_secret.zeroize();
        return Err(format!("Firmware uploaded but verification failed: {error}"));
    }
    let mut identity = match load_or_create_identity(app, profile) {
        Ok(identity) => identity,
        Err(error) => {
            let _ = fs::remove_file(sketch_dir.join("AKFES_Device_Authenticator.ino"));
            device_secret.zeroize();
            return Err(error);
        }
    };
    identity
        .arduino_device_secrets
        .insert(device_id.clone(), device_secret.clone());
    if let Err(error) = write_identity(app, profile, &identity) {
        let _ = fs::remove_file(sketch_dir.join("AKFES_Device_Authenticator.ino"));
        device_secret.zeroize();
        return Err(error);
    }
    device_secret.zeroize();
    fs::remove_file(sketch_dir.join("AKFES_Device_Authenticator.ino"))
        .map_err(|e| format!("Firmware was uploaded, but its temporary secret-bearing sketch could not be removed: {e}"))?;
    Ok(ArduinoProvisionResult {
        port,
        board: board.to_string(),
        sketch_path: sketch_dir.to_string_lossy().into_owned(),
        firmware_verified: true,
    })
}

#[tauri::command]
fn provision_local_arduino(
    app: AppHandle,
    profile: String,
    device_id: String,
    port: String,
    device_secret_hex: String,
    keypad_config: ArduinoKeypadConfig,
) -> Result<ArduinoProvisionResult, String> {
    provision_local_arduino_impl(&app, &profile, device_id, port, device_secret_hex, keypad_config)
}

#[tauri::command]
fn upgrade_local_arduino_keypad(
    app: AppHandle,
    profile: String,
    device_id: String,
    port: String,
    keypad_config: ArduinoKeypadConfig,
) -> Result<ArduinoProvisionResult, String> {
    let canonical_device_id = device_id.trim().to_ascii_lowercase();
    if !valid_device_id(&canonical_device_id) {
        return Err("The server device ID is invalid.".into());
    }
    let identity = load_or_create_identity(&app, &profile)?;
    let mut device_secret = if let Some(secret) = identity.arduino_device_secrets.get(&canonical_device_id) {
        secret.clone()
    } else {
        // One-time migration for clients built before encrypted Arduino recovery
        // records existed. The legacy source is deleted by the provisioner.
        let local_app_data = std::env::var_os("LOCALAPPDATA")
            .ok_or_else(|| "LOCALAPPDATA is unavailable.".to_string())?;
        let existing_sketch = PathBuf::from(local_app_data)
            .join("AKFES/arduino")
            .join(&canonical_device_id)
            .join("AKFES_Device_Authenticator/AKFES_Device_Authenticator.ino");
        let mut source = fs::read_to_string(&existing_sketch).map_err(|_| {
            "This PC does not have the encrypted recovery record for this Arduino. Authenticate it from the original PC, then use PIN reset, or register this PC as a new device."
                .to_string()
        })?;
        const PREFIX: &str = "#define AKFES_DEVICE_SECRET_HEX \"";
        let secret = source
            .split_once(PREFIX)
            .and_then(|(_, remainder)| remainder.split_once('"').map(|(value, _)| value.to_string()))
            .ok_or_else(|| "The previous Arduino device binding is invalid.".to_string())?;
        source.zeroize();
        secret
    };
    if device_secret.len() != 64 || !device_secret.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        device_secret.zeroize();
        return Err("The previous Arduino device binding is invalid.".into());
    }
    let result = provision_local_arduino_impl(
        &app,
        &profile,
        canonical_device_id,
        port,
        device_secret.clone(),
        keypad_config,
    );
    device_secret.zeroize();
    result
}

fn arduino_challenge_once(port: &str, nonce: &str, keypad: bool) -> Result<String, String> {
    let mut serial = serialport::new(port, 115_200)
        .timeout(Duration::from_millis(2500))
        .open()
        .map_err(|e| format!("Could not open Arduino serial port: {e}"))?;
    // Arduino Uno/Nano-class boards commonly reset when the COM port opens.
    // Give the bootloader time to hand control to the sketch, then discard any
    // startup bytes before sending the one-shot challenge.
    std::thread::sleep(Duration::from_millis(2500));
    let _ = serial.clear(serialport::ClearBuffer::All);
    // avrdude can leave a partial, unterminated frame in the Uno UART path.
    // The first newline then correctly produces LINE_TOO_LONG and resets the
    // firmware parser. Repeat the challenge on the same open connection so we
    // do not toggle DTR and reset the board a second time.
    'send: for send_attempt in 0..2 {
        let command = if keypad {
            format!("AUTH {nonce}\n")
        } else {
            format!("CHALLENGE {nonce}\n")
        };
        serial
            .write_all(command.as_bytes())
            .map_err(|e| e.to_string())?;
        serial.flush().map_err(|e| e.to_string())?;
        let deadline = std::time::Instant::now() + Duration::from_secs(if keypad { 65 } else { 5 });
        let mut pending = Vec::new();
        let mut saw_nonempty_line = false;
        let mut buf = [0u8; 128];
        while std::time::Instant::now() < deadline {
            match serial.read(&mut buf) {
                Ok(n) => {
                    pending.extend_from_slice(&buf[..n]);
                    while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
                        let line: Vec<u8> = pending.drain(..=end).collect();
                        saw_nonempty_line |= !String::from_utf8_lossy(&line).trim().is_empty();
                        if let Some(result) = parse_arduino_response_line(&line) {
                            if send_attempt == 0 && retry_same_arduino_connection(&result) {
                                let _ = serial.clear(serialport::ClearBuffer::Input);
                                std::thread::sleep(Duration::from_millis(150));
                                continue 'send;
                            }
                            return result;
                        }
                    }
                    if pending.len() > 1024 {
                        return Err(
                            "Arduino sent too much unrecognized serial data. Close Serial Monitor and upload the generated AKFES firmware."
                                .into(),
                        );
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => return Err(format!("Serial read failed: {e}")),
            }
        }
        if !pending.is_empty() {
            saw_nonempty_line |= !String::from_utf8_lossy(&pending).trim().is_empty();
            if let Some(result) = parse_arduino_response_line(&pending) {
                return result;
            }
        }
        if saw_nonempty_line {
            return Err("Arduino did not return an AKFES RESPONSE. Upload the generated per-device firmware and close Serial Monitor.".into());
        }
        if send_attempt == 1 {
            return Err("Arduino did not respond. Check the COM port, close Serial Monitor, reconnect the board, and retry.".into());
        }
    }
    Err("Arduino did not respond after an in-place serial retry.".into())
}

fn retry_same_arduino_connection(result: &Result<String, String>) -> bool {
    matches!(result, Err(error) if error.contains("oversized command"))
}

fn retryable_arduino_error(error: &str) -> bool {
    error.contains("oversized command")
        || error.contains("did not respond")
        || error.contains("did not return an AKFES RESPONSE")
        || error.contains("malformed RESPONSE")
        || error.contains("too much unrecognized serial data")
}

#[tauri::command]
fn arduino_challenge(port: String, nonce: String, keypad: bool) -> Result<String, String> {
    if nonce.len() != 64 || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Challenge must be 64 hexadecimal characters".into());
    }
    let first = arduino_challenge_once(&port, &nonce, keypad);
    match first {
        Ok(response) => Ok(response),
        Err(error) if !keypad && retryable_arduino_error(&error) => {
            std::thread::sleep(Duration::from_millis(500));
            arduino_challenge_once(&port, &nonce, false)
        }
        Err(error) => Err(error),
    }
}

#[tauri::command]
fn arduino_enroll_pin(port: String) -> Result<String, String> {
    let mut serial = serialport::new(port.trim(), 115_200)
        .timeout(Duration::from_millis(2500))
        .open()
        .map_err(|e| format!("Could not open Arduino serial port: {e}"))?;
    std::thread::sleep(Duration::from_millis(2500));
    let _ = serial.clear(serialport::ClearBuffer::All);
    serial.write_all(b"ENROLL\n").map_err(|e| e.to_string())?;
    serial.flush().map_err(|e| e.to_string())?;
    let deadline = std::time::Instant::now() + Duration::from_secs(130);
    let mut pending = Vec::new();
    let mut buffer = [0u8; 128];
    while std::time::Instant::now() < deadline {
        match serial.read(&mut buffer) {
            Ok(count) => {
                pending.extend_from_slice(&buffer[..count]);
                while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
                    let line: Vec<u8> = pending.drain(..=end).collect();
                    if let Some(result) = parse_arduino_pin_key_line(&line) {
                        return result;
                    }
                }
                if pending.len() > 1024 {
                    return Err("Arduino sent too much data during keypad PIN setup.".into());
                }
            }
            Err(ref error) if error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(error) => return Err(format!("Serial read failed: {error}")),
        }
    }
    Err("Arduino keypad PIN setup timed out. Enter the PIN twice and press the confirm key after each entry.".into())
}

#[cfg(test)]
mod arduino_response_tests {
    use super::{
        arduino_board_for_usb, arduino_challenge, parse_arduino_pin_key_line,
        parse_arduino_response_line, retry_same_arduino_connection, retryable_arduino_error,
        session_ratchet_id, store_ratchet_session, valid_device_id, validate_keypad_config,
        ArduinoKeypadConfig, PreKeyPublic, StoredIdentity, StoredRatchet,
    };
    use std::collections::HashMap;

    #[test]
    fn prekey_upload_fields_remain_server_compatible() {
        let value = serde_json::to_value(PreKeyPublic {
            key_id: 1000,
            public_key: "AA==".into(),
            kind: "one_time".into(),
            signature: None,
        })
        .expect("serialize prekey");
        assert_eq!(value["key_id"], 1000);
        assert_eq!(value["public_key"], "AA==");
        assert!(value.get("keyId").is_none());
        assert!(value.get("publicKey").is_none());
    }

    #[test]
    fn accepts_a_valid_response() {
        let response = format!("RESPONSE {}\r\n", "a1".repeat(32));
        assert_eq!(
            parse_arduino_response_line(response.as_bytes())
                .expect("response line")
                .expect("valid response"),
            "a1".repeat(32)
        );
    }

    #[test]
    fn accepts_a_derived_key_from_physical_keypad_enrollment() {
        let line = format!("PINKEY {}\n", "4f".repeat(32));
        assert_eq!(
            parse_arduino_pin_key_line(line.as_bytes())
                .expect("line")
                .expect("key"),
            "4f".repeat(32)
        );
    }

    #[test]
    fn explains_an_unprovisioned_board() {
        let error = parse_arduino_response_line(b"ERROR NOT_PROVISIONED\n")
            .expect("error line")
            .expect_err("must fail");
        assert!(error.contains("not provisioned"));
    }

    #[test]
    fn ignores_unrelated_startup_text() {
        assert!(parse_arduino_response_line(b"boot banner\n").is_none());
    }

    #[test]
    fn rejects_a_malformed_response() {
        let error = parse_arduino_response_line(b"RESPONSE xyz\n")
            .expect("response line")
            .expect_err("must fail");
        assert!(error.contains("malformed"));
    }

    #[test]
    fn recognizes_the_connected_uno_model() {
        assert_eq!(
            arduino_board_for_usb(0x2341, 0x0043, "Arduino Uno"),
            Some(("arduino:avr:uno", "Arduino Uno"))
        );
    }

    #[test]
    fn validates_server_device_ids_without_allowing_paths() {
        assert!(valid_device_id("012659f4-c6c6-474d-9b8a-5ee5a84cd8d8"));
        assert!(!valid_device_id("../../deploy/windows-zerotrust/.env"));
    }

    #[test]
    fn validates_keypad_bindings_and_gpio_uniqueness() {
        let valid = ArduinoKeypadConfig {
            columns: 3,
            row_pins: vec![2, 3, 4, 5],
            column_pins: vec![6, 7, 8],
            keymap: "123456789*0#".into(),
            clear_key: "*".into(),
            confirm_key: "#".into(),
        };
        assert!(validate_keypad_config(&valid, "arduino:avr:uno").is_ok());
        let mut duplicate = valid.clone();
        duplicate.column_pins[0] = 2;
        assert!(validate_keypad_config(&duplicate, "arduino:avr:uno").is_err());
    }

    #[test]
    fn retries_only_transient_serial_protocol_failures() {
        assert!(retryable_arduino_error(
            "Arduino reported an oversized command. Close other serial programs and retry."
        ));
        assert!(retryable_arduino_error("Arduino did not respond."));
        assert!(!retryable_arduino_error(
            "Arduino firmware is not provisioned for this device."
        ));
    }

    #[test]
    fn oversized_frames_retry_without_resetting_the_board() {
        assert!(retry_same_arduino_connection(&Err(
            "Arduino reported an oversized command.".to_string()
        )));
        assert!(!retry_same_arduino_connection(&Err(
            "Arduino firmware is not provisioned.".to_string()
        )));
    }

    #[test]
    fn crossed_initial_sessions_do_not_replace_the_outbound_session() {
        let mut identity = StoredIdentity {
            identity_secret: String::new(),
            device_secret: String::new(),
            server_device_id: None,
            ratchets: HashMap::new(),
            outbound_sessions: HashMap::new(),
            signed_prekey: None,
            signed_prekey_signature: None,
            signed_prekey_created_at_unix: 0,
            previous_signed_prekeys: Vec::new(),
            one_time_prekeys: Vec::new(),
            next_one_time_prekey_id: 1020,
            outbound_message_keys: HashMap::new(),
            outbound_key_order: Vec::new(),
            inbound_message_keys: HashMap::new(),
            inbound_key_order: Vec::new(),
            peer_identities: HashMap::new(),
            arduino_device_secrets: HashMap::new(),
        };
        let ratchet = |session_id: &str| StoredRatchet {
            session_id: session_id.into(),
            root_key: "AA==".into(),
            send_chain: None,
            recv_chain: None,
            send_count: 0,
            recv_count: 0,
            skipped: HashMap::new(),
            received: Vec::new(),
        };
        let pair = "conversation|local|remote";
        store_ratchet_session(&mut identity, pair, ratchet("outbound"), true);
        store_ratchet_session(&mut identity, pair, ratchet("inbound"), false);
        assert!(identity
            .ratchets
            .contains_key(&session_ratchet_id(pair, "outbound")));
        assert!(identity
            .ratchets
            .contains_key(&session_ratchet_id(pair, "inbound")));
        assert_eq!(
            identity.outbound_sessions.get(pair).map(String::as_str),
            Some("outbound")
        );
    }

    #[test]
    #[ignore = "requires AKFES_ARDUINO_TEST_PORT and a connected provisioned board"]
    fn connected_board_answers_through_the_native_serial_path() {
        let port = std::env::var("AKFES_ARDUINO_TEST_PORT").expect("test port");
        let response = arduino_challenge(port, "ab".repeat(32), false).expect("Arduino response");
        assert_eq!(response.len(), 64);
        assert!(response.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[cfg(feature = "local-test-provisioning")]
    #[test]
    fn embedded_firmware_is_an_unprovisioned_template() {
        assert_eq!(
            super::ARDUINO_SKETCH_TEMPLATE
                .matches("AKFES_DEVICE_SECRET_HEX_PLACEHOLDER")
                .count(),
            1
        );
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            ensure_device_identity,
            ensure_e2ee_bundle,
            bind_server_device,
            clear_server_device_binding,
            peer_identity_status,
            verify_peer_identity,
            encrypt_text_with_ratchet,
            decrypt_text_with_ratchet,
            decrypt_own_sent_ratchet,
            has_ratchet_session,
            consume_local_one_time_prekey,
            encrypt_file_bytes,
            decrypt_file_bytes,
            sign_device_proof,
            sign_secret_gate,
            verify_secret_gate,
            sign_call_signal,
            verify_call_signal,
            list_arduino_ports,
            provision_local_arduino,
            upgrade_local_arduino_keypad,
            arduino_challenge,
            arduino_enroll_pin
        ])
        .run(tauri::generate_context!())
        .expect("failed to run AKFES Secure Messenger");
}
