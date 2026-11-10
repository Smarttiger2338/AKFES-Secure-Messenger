const COMMANDS: &[&str] = &[
    "ensure_device_identity",
    "ensure_e2ee_bundle",
    "bind_server_device",
    "clear_server_device_binding",
    "peer_identity_status",
    "verify_peer_identity",
    "encrypt_text_with_ratchet",
    "decrypt_text_with_ratchet",
    "decrypt_own_sent_ratchet",
    "has_ratchet_session",
    "consume_local_one_time_prekey",
    "encrypt_file_bytes",
    "decrypt_file_bytes",
    "sign_device_proof",
    "list_arduino_ports",
    "provision_local_arduino",
    "upgrade_local_arduino_keypad",
    "arduino_challenge",
    "arduino_enroll_pin",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("failed to build Tauri ACL manifest");
}
