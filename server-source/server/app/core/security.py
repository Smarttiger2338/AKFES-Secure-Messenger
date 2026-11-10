from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
import secrets
import uuid

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from jwt.exceptions import InvalidTokenError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from app.core.config import settings
from app.core.database import get_db
from app.models.device import Device
from app.models.user import User

_password_hasher = PasswordHasher(time_cost=2, memory_cost=19 * 1024, parallelism=1, hash_len=32, salt_len=16)
security_scheme = HTTPBearer(auto_error=True)
DUMMY_PASSWORD_HASH = _password_hasher.hash(secrets.token_urlsafe(32))


def _password_bytes_ok(password: str) -> bool:
    return len(password.encode('utf-8')) <= settings.PASSWORD_MAX_BYTES


def hash_password(password: str) -> str:
    if not _password_bytes_ok(password):
        raise ValueError('Password is too long')
    return _password_hasher.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    if not _password_bytes_ok(plain):
        return False
    if hashed.startswith('$argon2'):
        try:
            return _password_hasher.verify(hashed, plain)
        except (VerifyMismatchError, InvalidHashError):
            return False
    if hashed.startswith(('$2a$', '$2b$', '$2y$')):
        try:
            return bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('ascii'))
        except (ValueError, TypeError):
            return False
    return False


def needs_password_rehash(hashed: str) -> bool:
    if not hashed.startswith('$argon2'):
        return True
    try:
        return _password_hasher.check_needs_rehash(hashed)
    except InvalidHashError:
        return True


async def hash_password_async(password: str) -> str:
    return await run_in_threadpool(hash_password, password)


async def verify_password_async(plain: str, hashed: str) -> bool:
    return await run_in_threadpool(verify_password, plain, hashed)


@lru_cache(maxsize=16)
def _read_key_versioned(path: str, mtime_ns: int) -> str:
    del mtime_ns
    return Path(path).read_text(encoding='utf-8')


def _read_key(path: str, label: str) -> str:
    p = Path(path)
    if not path or not p.is_file():
        raise RuntimeError(f'{label} is missing: {path!r}')
    return _read_key_versioned(str(p), p.stat().st_mtime_ns)


def create_access_token(user_id: str, device_id: str, session_version: int = 1) -> str:
    if not settings.AUTH_ISSUER_ENABLED:
        raise HTTPException(status_code=503, detail='Authentication issuer is not available on this node')
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        'sub': user_id, 'device_id': device_id, 'exp': expire, 'iat': now,
        'nbf': now, 'typ': 'access', 'sv': session_version,
        'iss': settings.JWT_ISSUER, 'aud': settings.JWT_AUDIENCE,
        'jti': str(uuid.uuid4()),
    }
    if settings.JWT_ALGORITHM == 'RS256':
        return jwt.encode(payload, _read_key(settings.JWT_PRIVATE_KEY_FILE, 'JWT_PRIVATE_KEY_FILE'), algorithm='RS256')
    if settings.DEBUG and settings.JWT_ALGORITHM == 'HS256':
        return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    raise RuntimeError('Production JWT_ALGORITHM must be RS256')


def decode_access_token(token: str) -> tuple[str, str, int]:
    exc = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate credentials')
    try:
        if settings.JWT_ALGORITHM == 'RS256':
            payload = jwt.decode(
                token,
                _read_key(settings.JWT_PUBLIC_KEY_FILE, 'JWT_PUBLIC_KEY_FILE'),
                algorithms=['RS256'], issuer=settings.JWT_ISSUER, audience=settings.JWT_AUDIENCE,
                options={'require': ['exp', 'iat', 'nbf']},
            )
        elif settings.DEBUG and settings.JWT_ALGORITHM == 'HS256':
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'], issuer=settings.JWT_ISSUER, audience=settings.JWT_AUDIENCE)
        else:
            raise exc
        if payload.get('typ') != 'access':
            raise exc
        user_id, device_id, sv = payload.get('sub'), payload.get('device_id'), payload.get('sv', 1)
        if not isinstance(user_id, str) or not isinstance(device_id, str) or not isinstance(sv, int):
            raise exc
        return user_id, device_id, sv
    except (InvalidTokenError, RuntimeError) as e:
        raise exc from e


async def resolve_session_token(token: str, db: AsyncSession, allow_pending: bool=False) -> tuple[User, Device]:
    user_id, device_id, sv = decode_access_token(token)
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=401, detail='Could not validate credentials')
    if user.disabled_at is not None:
        raise HTTPException(status_code=403, detail='Account suspended')
    device = (await db.execute(select(Device).where(Device.device_id == device_id, Device.user_id == user_id))).scalar_one_or_none()
    if device is None or device.revoked_at is not None:
        raise HTTPException(status_code=403, detail='Device revoked or not found')
    if device.session_version != sv:
        raise HTTPException(status_code=401, detail='Session revoked')
    # Legacy devices that predate the identity-to-device-key binding must be
    # re-approved before a production session can be used. This prevents an
    # old unsigned X25519 key from silently remaining trusted after upgrade.
    if not settings.DEBUG and device.status == 'approved' and (not device.device_public_key or not device.device_key_signature):
        raise HTTPException(status_code=403, detail='Device cryptographic binding reapproval required')
    if not allow_pending and device.status != 'approved':
        raise HTTPException(status_code=403, detail='Device approval required')
    return user, device


async def get_current_user(credentials: HTTPAuthorizationCredentials=Depends(security_scheme), db: AsyncSession=Depends(get_db)) -> tuple[User,Device]:
    return await resolve_session_token(credentials.credentials, db)


async def get_current_user_allow_pending(credentials: HTTPAuthorizationCredentials=Depends(security_scheme), db: AsyncSession=Depends(get_db)) -> tuple[User,Device]:
    return await resolve_session_token(credentials.credentials, db, allow_pending=True)
