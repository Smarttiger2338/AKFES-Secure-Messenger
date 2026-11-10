-- Execute as akfes_api after SQLAlchemy created/migrated the schema.
-- Revoke first so redeploying this file also removes permissions accidentally
-- granted by an earlier, broader release.
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM akfes_auth, akfes_node2;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM akfes_auth, akfes_node2;

-- Authentication/physical-auth service: account/device/session state only.
GRANT SELECT, INSERT, UPDATE ON TABLE users, devices TO akfes_auth;
GRANT SELECT, INSERT, UPDATE ON TABLE arduino_grants TO akfes_auth;
GRANT INSERT ON TABLE security_audit_events TO akfes_auth;
-- SQLAlchemy uses INSERT ... RETURNING created_at for this model. PostgreSQL
-- requires SELECT on the returned column even when INSERT is already granted.
-- Grant only that generated column, not read access to audit event contents.
GRANT SELECT (created_at) ON TABLE security_audit_events TO akfes_auth;

-- Node2 is intentionally a read-only WebSocket verifier. It may validate a
-- JWT against current user/device revocation state, but cannot mutate data.
GRANT SELECT ON TABLE users, devices, conversations, conversation_members TO akfes_node2;

-- Future tables created by the API owner are private unless explicitly added
-- here. This prevents accidental privilege expansion during schema updates.
ALTER DEFAULT PRIVILEGES FOR ROLE akfes_api IN SCHEMA public REVOKE ALL ON TABLES FROM akfes_auth, akfes_node2;
ALTER DEFAULT PRIVILEGES FOR ROLE akfes_api IN SCHEMA public REVOKE ALL ON SEQUENCES FROM akfes_auth, akfes_node2;
