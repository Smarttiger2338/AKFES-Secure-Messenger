-- Phase 4: encrypted file blobs. No plaintext file key or filename is stored.
CREATE TABLE IF NOT EXISTS encrypted_files (
    id VARCHAR(36) PRIMARY KEY,
    conversation_id VARCHAR(36) NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    sender_device_id VARCHAR(36) NOT NULL REFERENCES devices(device_id),
    stored_name VARCHAR(128) NOT NULL UNIQUE,
    size_bytes INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_encrypted_files_conversation_id ON encrypted_files(conversation_id);
