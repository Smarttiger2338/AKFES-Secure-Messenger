import ssl
from pathlib import Path
from sqlalchemy import inspect,text
from sqlalchemy.ext.asyncio import AsyncSession,async_sessionmaker,create_async_engine
from sqlalchemy.orm import DeclarativeBase
from app.core.config import settings

def _db_ssl_context():
    if not settings.DB_TLS_ENABLED:return None
    ca,cert,key=map(Path,[settings.DB_TLS_CA_FILE,settings.DB_TLS_CERT_FILE,settings.DB_TLS_KEY_FILE])
    for p,label in [(ca,'DB_TLS_CA_FILE'),(cert,'DB_TLS_CERT_FILE'),(key,'DB_TLS_KEY_FILE')]:
        if not p.is_file():raise RuntimeError(f'{label} is missing: {p!s}')
    ctx=ssl.create_default_context(ssl.Purpose.SERVER_AUTH,cafile=str(ca));ctx.minimum_version=ssl.TLSVersion.TLSv1_2;ctx.check_hostname=True;ctx.load_cert_chain(str(cert),str(key));return ctx
engine_kwargs={'echo':settings.DEBUG,'pool_pre_ping':True}
if settings.DATABASE_URL.startswith('postgresql+'):
    engine_kwargs.update(pool_size=settings.DB_POOL_SIZE,max_overflow=settings.DB_MAX_OVERFLOW,pool_timeout=settings.DB_POOL_TIMEOUT_SECONDS,pool_recycle=settings.DB_POOL_RECYCLE_SECONDS)
    ctx=_db_ssl_context()
    if ctx:engine_kwargs['connect_args']={'ssl':ctx}
engine=create_async_engine(settings.DATABASE_URL,**engine_kwargs);AsyncSessionLocal=async_sessionmaker(engine,class_=AsyncSession,expire_on_commit=False)
class Base(DeclarativeBase):pass

async def init_db():
    if not settings.AUTO_CREATE_SCHEMA:return
    from app.models import admin,conversation,device,file,key,message,security,social,user  # noqa
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        def migrate(c):
            insp=inspect(c);tables=set(insp.get_table_names())
            if 'users' in tables:
                cols={x['name'] for x in insp.get_columns('users')}
                if c.dialect.name=='postgresql':c.execute(text('ALTER TABLE users ALTER COLUMN password_hash TYPE VARCHAR(255)'))
                if 'nickname' not in cols:c.execute(text('ALTER TABLE users ADD COLUMN nickname VARCHAR(64)'))
                if 'bio' not in cols:c.execute(text('ALTER TABLE users ADD COLUMN bio VARCHAR(160)'))
                if 'status_text' not in cols:c.execute(text('ALTER TABLE users ADD COLUMN status_text VARCHAR(48)'))
                if 'accent_color' not in cols:c.execute(text('ALTER TABLE users ADD COLUMN accent_color VARCHAR(7)'))
                if 'profile_visibility' not in cols:c.execute(text("ALTER TABLE users ADD COLUMN profile_visibility VARCHAR(16) DEFAULT 'friends'"))
                bool_default='TRUE' if c.dialect.name=='postgresql' else '1'
                if 'discoverable_by_username' not in cols:c.execute(text(f'ALTER TABLE users ADD COLUMN discoverable_by_username BOOLEAN DEFAULT {bool_default} NOT NULL'))
                if 'share_read_receipts' not in cols:c.execute(text(f'ALTER TABLE users ADD COLUMN share_read_receipts BOOLEAN DEFAULT {bool_default} NOT NULL'))
                if 'share_typing_indicators' not in cols:c.execute(text(f'ALTER TABLE users ADD COLUMN share_typing_indicators BOOLEAN DEFAULT {bool_default} NOT NULL'))
                if 'avatar_data_url' not in cols:c.execute(text('ALTER TABLE users ADD COLUMN avatar_data_url TEXT'))
                if 'cover_data_url' not in cols:c.execute(text('ALTER TABLE users ADD COLUMN cover_data_url TEXT'))
                if 'email' not in cols:c.execute(text('ALTER TABLE users ADD COLUMN email VARCHAR(254)'))
                if 'email_verified_at' not in cols:c.execute(text('ALTER TABLE users ADD COLUMN email_verified_at TIMESTAMP WITH TIME ZONE'))
                if 'phone_e164' not in cols:c.execute(text('ALTER TABLE users ADD COLUMN phone_e164 VARCHAR(20)'))
                if 'phone_verified_at' not in cols:c.execute(text('ALTER TABLE users ADD COLUMN phone_verified_at TIMESTAMP WITH TIME ZONE'))
                if 'disabled_at' not in cols:c.execute(text('ALTER TABLE users ADD COLUMN disabled_at TIMESTAMP WITH TIME ZONE'))
                c.execute(text('CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email ON users (email)'))
                c.execute(text('CREATE UNIQUE INDEX IF NOT EXISTS ix_users_phone_e164 ON users (phone_e164)'))
            if 'devices' in tables:
                cols={x['name'] for x in insp.get_columns('devices')}
                if 'device_key_signature' not in cols:c.execute(text('ALTER TABLE devices ADD COLUMN device_key_signature TEXT'))
                if 'pending_device_key_signature' not in cols:c.execute(text('ALTER TABLE devices ADD COLUMN pending_device_key_signature TEXT'))
                if 'arduino_pin_key_wrapped' not in cols:c.execute(text('ALTER TABLE devices ADD COLUMN arduino_pin_key_wrapped VARCHAR(64)'))
                if 'secret_gate_public_key' not in cols:c.execute(text('ALTER TABLE devices ADD COLUMN secret_gate_public_key TEXT'))
                if 'secret_gate_key_signature' not in cols:c.execute(text('ALTER TABLE devices ADD COLUMN secret_gate_key_signature TEXT'))
            if 'encrypted_files' in tables:
                cols={x['name'] for x in insp.get_columns('encrypted_files')}
                if 'sha256_hex' not in cols:c.execute(text('ALTER TABLE encrypted_files ADD COLUMN sha256_hex VARCHAR(64)'))
                if 'storage_state' not in cols:c.execute(text("ALTER TABLE encrypted_files ADD COLUMN storage_state VARCHAR(16) DEFAULT 'ready' NOT NULL"))
            if 'conversations' in tables:
                cols={x['name'] for x in insp.get_columns('conversations')}
                if 'direct_key' not in cols:c.execute(text('ALTER TABLE conversations ADD COLUMN direct_key VARCHAR(64)'))
                if 'status' not in cols:c.execute(text("ALTER TABLE conversations ADD COLUMN status VARCHAR(16) DEFAULT 'accepted' NOT NULL"))
                if 'requested_by_user_id' not in cols:c.execute(text('ALTER TABLE conversations ADD COLUMN requested_by_user_id VARCHAR(36)'))
                if 'title' not in cols:c.execute(text('ALTER TABLE conversations ADD COLUMN title VARCHAR(80)'))
                if 'server_id' not in cols:c.execute(text('ALTER TABLE conversations ADD COLUMN server_id VARCHAR(36)'))
                c.execute(text('CREATE UNIQUE INDEX IF NOT EXISTS ix_conversations_direct_key ON conversations (direct_key)'))
                c.execute(text('CREATE INDEX IF NOT EXISTS ix_conversations_server_id ON conversations (server_id)'))
                if c.dialect.name=='postgresql':
                    invalid=int(c.execute(text("SELECT count(*) FROM conversations WHERE status NOT IN ('pending','accepted','rejected','blocked')")).scalar_one())
                    if invalid:raise RuntimeError(f'Cannot enforce conversation state policy: {invalid} invalid rows')
                    constraints={x['name'] for x in insp.get_check_constraints('conversations')}
                    if 'ck_conversations_status' not in constraints:
                        c.execute(text("ALTER TABLE conversations ADD CONSTRAINT ck_conversations_status CHECK (status IN ('pending','accepted','rejected','blocked'))"))
            if 'conversation_members' in tables:
                cols={x['name'] for x in insp.get_columns('conversation_members')}
                bool_default='FALSE' if c.dialect.name=='postgresql' else '0'
                if 'pinned' not in cols:c.execute(text(f'ALTER TABLE conversation_members ADD COLUMN pinned BOOLEAN DEFAULT {bool_default} NOT NULL'))
                if 'muted' not in cols:c.execute(text(f'ALTER TABLE conversation_members ADD COLUMN muted BOOLEAN DEFAULT {bool_default} NOT NULL'))
                if 'archived' not in cols:c.execute(text(f'ALTER TABLE conversation_members ADD COLUMN archived BOOLEAN DEFAULT {bool_default} NOT NULL'))
                if 'last_read_at' not in cols:c.execute(text('ALTER TABLE conversation_members ADD COLUMN last_read_at TIMESTAMP WITH TIME ZONE'))
                if 'role' not in cols:c.execute(text("ALTER TABLE conversation_members ADD COLUMN role VARCHAR(16) DEFAULT 'member' NOT NULL"))
            if 'messages' in tables:
                cols={x['name'] for x in insp.get_columns('messages')}
                if 'logical_message_id' not in cols:c.execute(text('ALTER TABLE messages ADD COLUMN logical_message_id VARCHAR(36)'))
                if 'recipient_device_id' not in cols:c.execute(text('ALTER TABLE messages ADD COLUMN recipient_device_id VARCHAR(36)'))
                if 'ephemeral_public_key' not in cols:c.execute(text('ALTER TABLE messages ADD COLUMN ephemeral_public_key VARCHAR(64)'))
                if 'ratchet_session_id' not in cols:c.execute(text('ALTER TABLE messages ADD COLUMN ratchet_session_id VARCHAR(64)'))
                c.execute(text('UPDATE messages SET logical_message_id=id WHERE logical_message_id IS NULL'))
                c.execute(text('CREATE INDEX IF NOT EXISTS ix_messages_logical_message_id ON messages (logical_message_id)'))
                c.execute(text('CREATE INDEX IF NOT EXISTS ix_messages_recipient_device_id ON messages (recipient_device_id)'))
                c.execute(text('CREATE INDEX IF NOT EXISTS ix_messages_ratchet_session_id ON messages (ratchet_session_id)'))
                if c.dialect.name=='postgresql':
                    c.execute(text('ALTER TABLE messages DROP CONSTRAINT IF EXISTS uq_message_ratchet_number'))
                    c.execute(text('CREATE UNIQUE INDEX IF NOT EXISTS uq_message_ratchet_number_v4 ON messages (conversation_id,sender_device_id,recipient_device_id,ratchet_session_id,message_number)'))
        await conn.run_sync(migrate)
async def database_ready():
    try:
        async with engine.connect() as conn:await conn.execute(text('SELECT 1'))
        return True
    except Exception:return False
async def get_db():
    async with AsyncSessionLocal() as s:
        try:yield s;await s.commit()
        except Exception:await s.rollback();raise
