-- Phase 3: symmetric ratchet message metadata.
-- Local ratchet secrets remain client-side; the server stores only metadata.
ALTER TABLE messages ADD COLUMN message_number INTEGER;
