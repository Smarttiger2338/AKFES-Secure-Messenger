ALTER TABLE conversations
    ADD COLUMN IF NOT EXISTS status VARCHAR(16) NOT NULL DEFAULT 'accepted';

ALTER TABLE conversations
    ADD COLUMN IF NOT EXISTS requested_by_user_id VARCHAR(36)
    REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS ix_conversations_status ON conversations (status);
