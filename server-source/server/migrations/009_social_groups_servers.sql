BEGIN;

CREATE TABLE IF NOT EXISTS friendships (
    id VARCHAR(36) PRIMARY KEY,
    pair_key VARCHAR(73) NOT NULL UNIQUE,
    requester_user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    addressee_user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(16) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_friendships_status CHECK (status IN ('pending','accepted','blocked'))
);
CREATE INDEX IF NOT EXISTS ix_friendships_pair_key ON friendships(pair_key);

CREATE TABLE IF NOT EXISTS community_servers (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(80) NOT NULL,
    owner_user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS community_server_members (
    server_id VARCHAR(36) NOT NULL REFERENCES community_servers(id) ON DELETE CASCADE,
    user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(16) NOT NULL DEFAULT 'member',
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(server_id,user_id),
    CONSTRAINT ck_community_server_members_role CHECK (role IN ('owner','admin','member'))
);

ALTER TABLE conversations ADD COLUMN IF NOT EXISTS title VARCHAR(80);
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS server_id VARCHAR(36) REFERENCES community_servers(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS ix_conversations_server_id ON conversations(server_id);
ALTER TABLE conversation_members ADD COLUMN IF NOT EXISTS role VARCHAR(16) NOT NULL DEFAULT 'member';

COMMIT;
