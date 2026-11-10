-- AKFES Secure Messenger — Initial schema (MVP)
-- Compatible with SQLite (dev) and PostgreSQL (prod)

-- Users
CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,          -- UUID
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Devices (one user can have many devices)
CREATE TABLE IF NOT EXISTS devices (
    device_id           TEXT PRIMARY KEY,      -- UUID
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    identity_public_key TEXT NOT NULL,         -- base64
    device_public_key   TEXT,                  -- base64 (optional)
    device_name         TEXT NOT NULL,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen           TEXT,
    revoked_at          TEXT                   -- NULL = active
);

CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);

-- PreKeys (one-time / signed prekeys)
CREATE TABLE IF NOT EXISTS prekeys (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    prekey_id       INTEGER NOT NULL,
    public_key      TEXT NOT NULL,             -- base64
    signature       TEXT,                      -- base64 (for signed prekey)
    kind            TEXT NOT NULL DEFAULT 'one_time', -- signed / one_time
    used            INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(device_id, prekey_id)
);

-- Conversations
CREATE TABLE IF NOT EXISTS conversations (
    id              TEXT PRIMARY KEY,          -- UUID
    type            TEXT NOT NULL CHECK(type IN ('direct', 'group')),
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Conversation members
CREATE TABLE IF NOT EXISTS conversation_members (
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    joined_at       TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (conversation_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_conv_members_user ON conversation_members(user_id);

-- Messages (only ciphertext stored)
CREATE TABLE IF NOT EXISTS messages (
    id                  TEXT PRIMARY KEY,      -- UUID
    conversation_id     TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    sender_device_id    TEXT NOT NULL REFERENCES devices(device_id),
    ciphertext          TEXT NOT NULL,         -- base64
    nonce               TEXT NOT NULL,         -- base64
    e2ee_version        INTEGER NOT NULL DEFAULT 2,
    signed_prekey_id    INTEGER,
    one_time_prekey_id  INTEGER,
    message_type        TEXT NOT NULL DEFAULT 'text',
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_messages_conv_time ON messages(conversation_id, created_at);

-- Attachments (encrypted files)
CREATE TABLE IF NOT EXISTS attachments (
    id                  TEXT PRIMARY KEY,
    message_id          TEXT REFERENCES messages(id) ON DELETE SET NULL,
    encrypted_file_path TEXT NOT NULL,
    encrypted_size      INTEGER NOT NULL,
    content_hash        TEXT,                  -- hash of ciphertext
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Sessions (optional, can also live in Redis)
CREATE TABLE IF NOT EXISTS sessions (
    token               TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id           TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
