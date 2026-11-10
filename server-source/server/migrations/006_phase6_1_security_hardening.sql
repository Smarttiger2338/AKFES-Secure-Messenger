-- Phase 6.1: Arduino one-time grants and security audit trail.
CREATE TABLE IF NOT EXISTS arduino_grants (
    grant_id VARCHAR(36) PRIMARY KEY,
    challenge_id VARCHAR(36) NOT NULL UNIQUE,
    user_id VARCHAR(36) NOT NULL,
    device_id VARCHAR(36) NOT NULL,
    action VARCHAR(64) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_arduino_grants_device_action
    ON arduino_grants(device_id, action, used_at, expires_at);

CREATE TABLE IF NOT EXISTS security_audit_events (
    event_id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NULL,
    device_id VARCHAR(36) NULL,
    action VARCHAR(64) NOT NULL,
    result VARCHAR(32) NOT NULL,
    target_device_id VARCHAR(36) NULL,
    details TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS ix_security_audit_user_created
    ON security_audit_events(user_id, created_at);
