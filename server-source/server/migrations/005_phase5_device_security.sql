-- Phase 5: device trust, approval, key-change detection and session revocation.
ALTER TABLE devices ADD COLUMN pending_identity_public_key TEXT;
ALTER TABLE devices ADD COLUMN pending_device_public_key TEXT;
ALTER TABLE devices ADD COLUMN status VARCHAR(16) NOT NULL DEFAULT 'approved';
ALTER TABLE devices ADD COLUMN session_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE devices ADD COLUMN approved_at TIMESTAMP;
ALTER TABLE devices ADD COLUMN key_changed_at TIMESTAMP;

UPDATE devices
SET status = 'approved'
WHERE status IS NULL OR status = '';

UPDATE devices
SET approved_at = created_at
WHERE approved_at IS NULL;
