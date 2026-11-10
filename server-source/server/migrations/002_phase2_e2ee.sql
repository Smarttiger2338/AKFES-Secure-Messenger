-- Phase 2 E2EE migration
ALTER TABLE prekeys ADD COLUMN kind TEXT NOT NULL DEFAULT 'one_time';
ALTER TABLE messages ADD COLUMN e2ee_version INTEGER NOT NULL DEFAULT 2;
ALTER TABLE messages ADD COLUMN signed_prekey_id INTEGER;
ALTER TABLE messages ADD COLUMN one_time_prekey_id INTEGER;
