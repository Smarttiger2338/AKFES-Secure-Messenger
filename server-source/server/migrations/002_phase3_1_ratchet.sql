-- Phase 3.1: Ratchet message-number uniqueness / replay defense.
-- NULL message_number remains allowed for legacy E2EE v2 messages.
ALTER TABLE messages ADD COLUMN message_number INTEGER;
CREATE UNIQUE INDEX IF NOT EXISTS uq_message_ratchet_number
ON messages(conversation_id, sender_device_id, message_number)
WHERE message_number IS NOT NULL;
