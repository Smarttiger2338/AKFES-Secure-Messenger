DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'ck_conversations_status'
    ) THEN
        ALTER TABLE conversations
            ADD CONSTRAINT ck_conversations_status
            CHECK (status IN ('pending','accepted','rejected','blocked'));
    END IF;
END $$;
