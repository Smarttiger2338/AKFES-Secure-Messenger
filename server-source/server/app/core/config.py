from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', case_sensitive=True)
    APP_NAME: str = 'AKFES Secure Messenger'
    DEBUG: bool = True
    ROUTE_PROFILE: str = 'all'  # all (local only) | auth | api | realtime
    CONTROL_PLANE_ENABLED: bool = True

    JWT_ALGORITHM: str = 'HS256'
    JWT_ISSUER: str = 'akfes-auth'
    JWT_AUDIENCE: str = 'akfes-api'
    JWT_PRIVATE_KEY_FILE: str = ''
    JWT_PUBLIC_KEY_FILE: str = ''
    AUTH_ISSUER_ENABLED: bool = True
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    SECRET_KEY: str = 'change-me-in-production-use-openssl-rand-hex-32'

    DATABASE_URL: str = 'sqlite+aiosqlite:///./akfes.db'
    DB_TLS_ENABLED: bool = False
    DB_TLS_CA_FILE: str = ''
    DB_TLS_CERT_FILE: str = ''
    DB_TLS_KEY_FILE: str = ''
    # Security state (rate limits / device proof / Arduino) and realtime Pub/Sub
    # are intentionally separable. REDIS_URL remains a development fallback.
    REDIS_URL: str = 'redis://localhost:6379/0'
    REDIS_SECURITY_URL: str = ''
    REDIS_REALTIME_URL: str = ''
    REDIS_TLS_ENABLED: bool = False
    REDIS_TLS_CA_FILE: str = ''
    REDIS_TLS_CERT_FILE: str = ''
    REDIS_TLS_KEY_FILE: str = ''
    REDIS_REALTIME_ENABLED: bool = True
    REDIS_REALTIME_SUBSCRIBE_ENABLED: bool = True
    REDIS_REQUIRED_FOR_READY: bool = False
    # Single-process local testing may use bounded in-memory, one-time security
    # challenges.  Keep disabled in production so Redis outages fail closed.
    SECURITY_STATE_LOCAL_FALLBACK: bool = False
    AUTO_CREATE_SCHEMA: bool = True
    DB_POOL_SIZE: int = 6
    DB_MAX_OVERFLOW: int = 2
    DB_POOL_TIMEOUT_SECONDS: int = 8
    DB_POOL_RECYCLE_SECONDS: int = 1800

    CORS_ORIGINS: List[str] = ['http://localhost:1420','http://localhost:5173','tauri://localhost','http://tauri.localhost']
    TRUSTED_HOSTS: List[str] = ['127.0.0.1','localhost']
    WS_ALLOWED_ORIGINS: List[str] = ['http://localhost:1420','http://localhost:5173','tauri://localhost','http://tauri.localhost']

    FILES_DIR: str = './encrypted-files'
    FILES_ENABLED: bool = True
    MAX_FILE_BYTES: int = 25 * 1024 * 1024 + 16
    FILE_USER_QUOTA_BYTES: int = 2 * 1024 * 1024 * 1024
    FILE_DAILY_UPLOAD_BYTES: int = 512 * 1024 * 1024
    FILE_MIN_FREE_BYTES: int = 1024 * 1024 * 1024
    FILE_STREAM_CHUNK_BYTES: int = 256 * 1024

    ARDUINO_MASTER_SECRET: str = 'CHANGE-ME-ARDUINO-MASTER-SECRET'
    ARDUINO_VERIFIER_ENABLED: bool = True
    ARDUINO_ACTIONS: List[str] = ['device.bootstrap','device.approve','device.revoke','device.revoke_all','arduino.connect','arduino.pin_setup','secret.gate_register']

    RATE_LIMIT_LOGIN: int = 8
    RATE_LIMIT_REGISTER: int = 4
    RATE_LIMIT_DEVICE_CHALLENGE: int = 12
    RATE_LIMIT_PREKEY_CLAIM: int = 12
    RATE_LIMIT_PREKEY_TARGET_CLAIMS: int = 20
    RATE_LIMIT_ARDUINO_CHALLENGE: int = 10
    RATE_LIMIT_USER_SEARCH: int = 30
    RATE_LIMIT_CONVERSATION_REQUEST: int = 10
    RATE_LIMIT_CONVERSATION_TARGET: int = 30
    RATE_LIMIT_FILE_UPLOAD: int = 12
    RATE_LIMIT_FILE_DOWNLOAD: int = 120
    RATE_LIMIT_MESSAGE_SEND: int = 60
    RATE_LIMIT_WS_MESSAGES: int = 60
    RATE_LIMIT_WS_CONNECT: int = 30
    RATE_LIMIT_WINDOW_SECONDS: int = 60
    RATE_LIMIT_FAIL_CLOSED: bool = False

    REQUIRE_FIRST_DEVICE_ARDUINO: bool = False
    REQUIRE_DEVICE_POP: bool = False
    REGISTRATION_INVITE_SHA256: str = ''
    PASSWORD_MAX_BYTES: int = 256

    PREKEY_CLAIM_LEASE_SECONDS: int = 3600
    PREKEY_SIGNED_MAX_AGE_DAYS: int = 14
    PREKEY_MIN_RESERVE: int = 10

    MAX_ACTIVE_DEVICES_PER_USER: int = 8

    ADMIN_USERNAMES: List[str] = []
    ADMIN_MFA_ENCRYPTION_KEY: str = ''
    ADMIN_WEBAUTHN_RP_ID: str = 'localhost'
    ADMIN_WEBAUTHN_ORIGIN: str = 'http://localhost:1420'
    ADMIN_STEP_UP_SECONDS: int = 300

    EMAIL_SMTP_HOST: str = ''
    EMAIL_SMTP_PORT: int = 587
    EMAIL_SMTP_USERNAME: str = ''
    EMAIL_SMTP_PASSWORD: str = ''
    EMAIL_FROM: str = ''
    EMAIL_SMTP_STARTTLS: bool = True
    SMS_WEBHOOK_URL: str = ''
    SMS_WEBHOOK_BEARER: str = ''
    CONTACT_VERIFICATION_TTL_SECONDS: int = 600

    WS_SESSION_REVALIDATE_SECONDS: int = 30
    WS_MAX_FRAME_BYTES: int = 16 * 1024
    WS_MAX_CONNECTIONS_PER_USER: int = 8
    WS_MAX_CONNECTIONS_PER_DEVICE: int = 3
    WS_SEND_TIMEOUT_SECONDS: float = 3.0
    WS_IDLE_TIMEOUT_SECONDS: int = 90

    MAX_JSON_BODY_BYTES: int = 1_200_000

settings = Settings()
