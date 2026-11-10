import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid
from threading import Lock
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from app.core.audit import record_security_event
from app.core.config import settings
from app.core.database import get_db
from app.core.rate_limit import allow_device_challenge, allow_login, allow_registration
from app.core.redis_client import make_redis_client
from app.core.security import (
    DUMMY_PASSWORD_HASH, create_access_token, get_current_user, hash_password_async,
    needs_password_rehash, resolve_session_token, security_scheme, verify_password_async,
)
from app.models import schemas
from app.models.device import Device
from app.models.user import User
from app.realtime import event_bus

router = APIRouter()
DEVICE_CHALLENGE_TTL = 90
_local_device_challenges:dict[str,tuple[float,str]]={}
_local_device_challenges_lock=Lock()

def _device_challenge_key(challenge_id: str) -> str:
    return f"akfes:device-pop:{challenge_id}"

def _device_pop_message(challenge_id: str, username: str, device_id: str, nonce: str) -> bytes:
    return f"AKFES-DEVICE-POP-v1|{challenge_id}|{username}|{device_id}|{nonce}".encode()

def _store_local_device_challenge(key:str,value:str)->bool:
    now=time.time()
    with _local_device_challenges_lock:
        expired=[item for item,(expires,_) in _local_device_challenges.items() if expires<=now]
        for item in expired:_local_device_challenges.pop(item,None)
        if key in _local_device_challenges:return False
        # A local developer process must stay bounded even under malformed use.
        if len(_local_device_challenges)>=1024:
            oldest=min(_local_device_challenges,key=lambda item:_local_device_challenges[item][0])
            _local_device_challenges.pop(oldest,None)
        _local_device_challenges[key]=(now+DEVICE_CHALLENGE_TTL,value)
        return True

def _take_local_device_challenge(key:str)->str|None:
    now=time.time()
    with _local_device_challenges_lock:
        entry=_local_device_challenges.pop(key,None)
    if entry is None or entry[0]<=now:return None
    return entry[1]

def _verify_invite(invite_code: str | None) -> bool:
    if settings.DEBUG and not settings.REGISTRATION_INVITE_SHA256:
        return True
    if not settings.REGISTRATION_INVITE_SHA256 or not invite_code:
        return False
    return hmac.compare_digest(hashlib.sha256(invite_code.encode()).hexdigest(), settings.REGISTRATION_INVITE_SHA256.lower())

async def _is_bootstrap_device(db:AsyncSession,user_id:str,device:Device)->bool:
    if device.status!='pending' or device.approved_at is not None or device.pending_identity_public_key is not None:
        return False
    approved=(await db.execute(select(func.count()).select_from(Device).where(Device.user_id==user_id,Device.status=='approved',Device.revoked_at.is_(None)))).scalar_one()
    return approved==0

async def _account_has_arduino(db:AsyncSession,user_id:str)->bool:
    configured=(await db.execute(select(func.count()).select_from(Device).where(
        Device.user_id==user_id,Device.status=='approved',Device.revoked_at.is_(None),Device.arduino_pin_key_wrapped.is_not(None)
    ))).scalar_one()
    return configured>0

async def _enforce_active_device_limit(db:AsyncSession,user_id:str)->None:
    active=(await db.execute(select(func.count()).select_from(Device).where(
        Device.user_id==user_id,Device.revoked_at.is_(None)
    ))).scalar_one()
    if active>=settings.MAX_ACTIVE_DEVICES_PER_USER:
        raise HTTPException(409,'Active device limit reached; revoke an old device first')

def normalize_username(username: str) -> str:
    return username.strip().lower()

def _approval_code(device:Device)->str:
    identity=device.pending_identity_public_key or device.identity_public_key
    return hashlib.sha256(identity.encode()).hexdigest()[:8].upper()

def _verify_device_key_binding(identity_public_key: str, device_public_key: str, signature_b64: str) -> None:
    try:
        identity_raw=base64.b64decode(identity_public_key,validate=True);signature=base64.b64decode(signature_b64,validate=True)
        if len(identity_raw)!=32 or len(signature)!=64:raise ValueError('invalid key length')
        message=f"AKFES-DEVICE-KEY-v1|{device_public_key}".encode()
        Ed25519PublicKey.from_public_bytes(identity_raw).verify(signature,message)
    except (ValueError,InvalidSignature) as exc:
        raise HTTPException(400,'Device public key is not signed by the submitted identity') from exc

async def _consume_device_challenge(challenge_id: str, username: str, device_id: str) -> str:
    client = make_redis_client(socket_connect_timeout=1, socket_timeout=2)
    try:
        raw = await client.getdel(_device_challenge_key(challenge_id))
    except Exception as exc:
        if not settings.SECURITY_STATE_LOCAL_FALLBACK:
            raise HTTPException(503, "Device proof service unavailable") from exc
        raw=_take_local_device_challenge(_device_challenge_key(challenge_id))
    finally:
        try: await client.aclose()
        except Exception: pass
    if raw is None:
        raise HTTPException(401, "Invalid device proof")
    try: record = json.loads(raw)
    except Exception as exc: raise HTTPException(401, "Invalid device proof") from exc
    if record.get('username') != username or record.get('device_id') != device_id:
        raise HTTPException(401, "Invalid device proof")
    return str(record.get('nonce') or '')

@router.post('/device-challenge', response_model=schemas.DeviceChallengeResponse)
async def device_challenge(body: schemas.DeviceChallengeRequest, request: Request):
    if not settings.AUTH_ISSUER_ENABLED:
        raise HTTPException(503, 'Authentication issuer is not enabled on this node')
    client_ip = request.client.host if request.client else 'unknown'
    if not await allow_device_challenge(client_ip):
        raise HTTPException(429, 'Too many device proof attempts; try again later')
    challenge_id, nonce = str(uuid.uuid4()), secrets.token_urlsafe(32)
    value=json.dumps({'username':normalize_username(body.username),'device_id':body.device_id,'nonce':nonce},separators=(',',':'))
    client=make_redis_client(socket_connect_timeout=1,socket_timeout=2)
    try: ok=await client.set(_device_challenge_key(challenge_id),value,ex=DEVICE_CHALLENGE_TTL,nx=True)
    except Exception as exc:
        if not settings.SECURITY_STATE_LOCAL_FALLBACK:raise HTTPException(503,'Device proof service unavailable') from exc
        ok=_store_local_device_challenge(_device_challenge_key(challenge_id),value)
    finally:
        try: await client.aclose()
        except Exception: pass
    if not ok: raise HTTPException(503,'Could not allocate device proof challenge')
    return schemas.DeviceChallengeResponse(challenge_id=challenge_id,nonce=nonce,expires_at=str(int(time.time()+DEVICE_CHALLENGE_TTL)))

@router.post('/register', response_model=schemas.AuthResponse, status_code=status.HTTP_201_CREATED)
async def register(body: schemas.RegisterRequest, request: Request, db: AsyncSession=Depends(get_db)):
    if not settings.AUTH_ISSUER_ENABLED: raise HTTPException(503,'Authentication issuer is not enabled on this node')
    client_ip=request.client.host if request.client else 'unknown'
    if not await allow_registration(client_ip): raise HTTPException(429,'Too many registration attempts; try again later')
    # Keep public failure text intentionally generic to reduce account/invite enumeration.
    if not _verify_invite(body.invite_code): raise HTTPException(403,'Registration is not available')
    username=normalize_username(body.username)
    existing=(await db.execute(select(User).where(func.lower(User.username)==username))).scalar_one_or_none()
    if existing is not None:
        password_ok=await verify_password_async(body.password,existing.password_hash)
        approved=(await db.execute(select(func.count()).select_from(Device).where(Device.user_id==existing.id,Device.approved_at.is_not(None)))).scalar_one()
        # A registration interrupted before its first device is activated is
        # resumable with the same account password and invite.  Arduino is an
        # optional secret-chat factor, not a prerequisite for an account.
        if not password_ok or approved!=0:
            raise HTTPException(403,'Registration is not available')
        _verify_device_key_binding(body.identity_public_key,body.device_public_key,body.device_key_signature)
        now=datetime.now(timezone.utc)
        pending=list((await db.execute(select(Device).where(Device.user_id==existing.id,Device.approved_at.is_(None)).order_by(Device.created_at))).scalars().all())
        device=next((candidate for candidate in pending if candidate.revoked_at is None),None)
        if device is None:
            await _enforce_active_device_limit(db,existing.id)
            device=Device(device_id=str(uuid.uuid4()),user_id=existing.id,identity_public_key=body.identity_public_key,
                device_public_key=body.device_public_key,device_key_signature=body.device_key_signature,device_name=body.device_name.strip(),status='pending' if settings.REQUIRE_FIRST_DEVICE_ARDUINO else 'approved',approved_at=None if settings.REQUIRE_FIRST_DEVICE_ARDUINO else now,last_seen=now)
            db.add(device)
        else:
            device.identity_public_key=body.identity_public_key;device.device_public_key=body.device_public_key;device.device_key_signature=body.device_key_signature
            device.pending_identity_public_key=None;device.pending_device_public_key=None;device.pending_device_key_signature=None
            device.device_name=body.device_name.strip();device.status='pending' if settings.REQUIRE_FIRST_DEVICE_ARDUINO else 'approved';device.approved_at=None if settings.REQUIRE_FIRST_DEVICE_ARDUINO else now;device.revoked_at=None;device.last_seen=now;device.arduino_pin_key_wrapped=None;device.session_version+=1
        for stale in pending:
            if stale is device: continue
            stale.status='revoked';stale.revoked_at=now;stale.session_version+=1
        await db.flush()
        await record_security_event(db,'account.registration_resume','allowed',user_id=existing.id,device_id=device.device_id)
        token=create_access_token(existing.id,device.device_id,device.session_version)
        return schemas.AuthResponse(user_id=existing.id,username=existing.username,device_id=device.device_id,session_token=token,
            is_new_device=False,requires_approval=settings.REQUIRE_FIRST_DEVICE_ARDUINO,bootstrap_required=settings.REQUIRE_FIRST_DEVICE_ARDUINO,registration_resumed=True,arduino_setup_required=not await _account_has_arduino(db,existing.id),approval_code=_approval_code(device))
    _verify_device_key_binding(body.identity_public_key,body.device_public_key,body.device_key_signature)
    user=User(id=str(uuid.uuid4()),username=username,nickname=username,password_hash=await hash_password_async(body.password))
    db.add(user); await db.flush()
    now=datetime.now(timezone.utc)
    device=Device(device_id=str(uuid.uuid4()),user_id=user.id,identity_public_key=body.identity_public_key,
                  device_public_key=body.device_public_key,device_key_signature=body.device_key_signature,device_name=body.device_name.strip(),
                  status='pending' if settings.REQUIRE_FIRST_DEVICE_ARDUINO else 'approved',
                  approved_at=None if settings.REQUIRE_FIRST_DEVICE_ARDUINO else now,last_seen=now)
    db.add(device); await db.flush()
    await record_security_event(db,'account.register','allowed',user_id=user.id,device_id=device.device_id)
    token=create_access_token(user.id,device.device_id,device.session_version)
    return schemas.AuthResponse(user_id=user.id,username=user.username,device_id=device.device_id,session_token=token,
        is_new_device=True,requires_approval=settings.REQUIRE_FIRST_DEVICE_ARDUINO,bootstrap_required=settings.REQUIRE_FIRST_DEVICE_ARDUINO,
        arduino_setup_required=not await _account_has_arduino(db,user.id),approval_code=_approval_code(device))

@router.post('/login', response_model=schemas.AuthResponse)
async def login(body: schemas.LoginRequest, request: Request, db: AsyncSession=Depends(get_db)):
    if not settings.AUTH_ISSUER_ENABLED: raise HTTPException(503,'Authentication issuer is not enabled on this node')
    client_ip=request.client.host if request.client else 'unknown'; username=normalize_username(body.username)
    if not await allow_login(f'{client_ip}:{username}'): raise HTTPException(429,'Too many login attempts; try again later')
    user=(await db.execute(select(User).where(func.lower(User.username)==username))).scalar_one_or_none()
    if user is None:
        await verify_password_async(body.password,DUMMY_PASSWORD_HASH)
        raise HTTPException(401,'Invalid credentials')
    if not await verify_password_async(body.password,user.password_hash):
        await record_security_event(db,'auth.login','denied',user_id=user.id,details='invalid_credentials')
        raise HTTPException(401,'Invalid credentials')
    if user.disabled_at is not None:
        raise HTTPException(403,'Account suspended')
    # Seamlessly migrate legacy bcrypt hashes after a correct login.
    if needs_password_rehash(user.password_hash):
        user.password_hash=await hash_password_async(body.password)

    device=None; is_new=False; key_changed=False
    if body.device_id:
        device=(await db.execute(select(Device).where(Device.device_id==body.device_id,Device.user_id==user.id))).scalar_one_or_none()
        if device and device.revoked_at is not None: raise HTTPException(403,'Device revoked')
        if device and not settings.DEBUG and (not device.device_public_key or not device.device_key_signature):
            if not body.identity_public_key or not body.device_public_key or not body.device_key_signature:
                raise HTTPException(403,'Device cryptographic binding reapproval required')
        if device and settings.REQUIRE_DEVICE_POP:
            if not body.device_challenge_id or not body.device_proof_b64: raise HTTPException(401,'Device proof required')
            nonce=await _consume_device_challenge(body.device_challenge_id,username,device.device_id)
            try:
                pub=base64.b64decode(device.identity_public_key,validate=True); sig=base64.b64decode(body.device_proof_b64,validate=True)
                if len(pub)!=32 or len(sig)!=64: raise ValueError('length')
                Ed25519PublicKey.from_public_bytes(pub).verify(sig,_device_pop_message(body.device_challenge_id,username,device.device_id,nonce))
            except (ValueError,InvalidSignature) as exc:
                await record_security_event(db,'auth.device_pop','denied',user_id=user.id,device_id=device.device_id)
                raise HTTPException(401,'Invalid device proof') from exc
    if device is None:
        if not body.identity_public_key or not body.device_public_key or not body.device_key_signature: raise HTTPException(400,'identity_public_key, device_public_key, and device_key_signature are required for a new device')
        _verify_device_key_binding(body.identity_public_key,body.device_public_key,body.device_key_signature)
        now=datetime.now(timezone.utc)
        ever_approved=(await db.execute(select(func.count()).select_from(Device).where(Device.user_id==user.id,Device.approved_at.is_not(None)))).scalar_one()
        # A normal browser or desktop login creates an immediately usable
        # E2EE device. Arduino is deliberately reserved for secret-chat
        # hardware approval, not account or browser admission.
        bootstrap_recovery=ever_approved==0
        if bootstrap_recovery:
            stale=list((await db.execute(select(Device).where(Device.user_id==user.id,Device.revoked_at.is_(None)))).scalars().all())
            for candidate in stale:
                candidate.status='revoked';candidate.revoked_at=now;candidate.session_version+=1
        else:
            await _enforce_active_device_limit(db,user.id)
        device=Device(device_id=str(uuid.uuid4()),user_id=user.id,identity_public_key=body.identity_public_key,
            device_public_key=body.device_public_key,device_key_signature=body.device_key_signature,
            pending_identity_public_key=body.identity_public_key if settings.REQUIRE_FIRST_DEVICE_ARDUINO and not bootstrap_recovery else None,
            pending_device_public_key=body.device_public_key if settings.REQUIRE_FIRST_DEVICE_ARDUINO and not bootstrap_recovery else None,
            pending_device_key_signature=body.device_key_signature if settings.REQUIRE_FIRST_DEVICE_ARDUINO and not bootstrap_recovery else None,device_name=(body.device_name or 'Unknown Device').strip(),
            status='pending' if settings.REQUIRE_FIRST_DEVICE_ARDUINO else 'approved',approved_at=None if settings.REQUIRE_FIRST_DEVICE_ARDUINO else now,last_seen=now)
        db.add(device); await db.flush(); is_new=True
    else:
        device.last_seen=datetime.now(timezone.utc)
        if body.identity_public_key and body.device_public_key and body.device_key_signature and (body.identity_public_key!=device.identity_public_key or body.device_public_key!=device.device_public_key or body.device_key_signature!=device.device_key_signature):
            _verify_device_key_binding(body.identity_public_key,body.device_public_key,body.device_key_signature)
            device.pending_identity_public_key=body.identity_public_key; device.pending_device_public_key=body.device_public_key; device.pending_device_key_signature=body.device_key_signature
            device.key_changed_at=datetime.now(timezone.utc); device.status='pending'; device.session_version+=1; key_changed=True
    await record_security_event(db,'auth.login','allowed',user_id=user.id,device_id=device.device_id)
    token=create_access_token(user.id,device.device_id,device.session_version)
    bootstrap_required=await _is_bootstrap_device(db,user.id,device)
    return schemas.AuthResponse(user_id=user.id,username=user.username,device_id=device.device_id,session_token=token,
        is_new_device=is_new,requires_approval=device.status!='approved',key_changed=key_changed,bootstrap_required=bootstrap_required,
        arduino_setup_required=device.status=='approved' and not await _account_has_arduino(db,user.id),approval_code=_approval_code(device))

@router.get('/device-status', response_model=schemas.AuthResponse)
async def device_status(credentials:HTTPAuthorizationCredentials=Depends(security_scheme),db:AsyncSession=Depends(get_db)):
    user,device=await resolve_session_token(credentials.credentials,db,allow_pending=True)
    return schemas.AuthResponse(user_id=user.id,username=user.username,device_id=device.device_id,session_token=credentials.credentials,
        requires_approval=device.status!='approved',key_changed=device.pending_identity_public_key is not None,bootstrap_required=await _is_bootstrap_device(db,user.id,device),
        arduino_setup_required=device.status=='approved' and not await _account_has_arduino(db,user.id),approval_code=_approval_code(device))

@router.post('/refresh', response_model=schemas.AuthResponse)
async def refresh_session(current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    """Rotate an active in-memory access token without weakening device checks.

    The normal authentication dependency validates the current signature,
    expiry, account state, device approval, and session version before a new
    short-lived token is issued.  No persistent refresh credential is stored
    in the browser.
    """
    user,device=current
    device.last_seen=datetime.now(timezone.utc)
    token=create_access_token(user.id,device.device_id,device.session_version)
    await db.flush()
    return schemas.AuthResponse(
        user_id=user.id,username=user.username,device_id=device.device_id,session_token=token,
        requires_approval=False,key_changed=False,bootstrap_required=False,
        arduino_setup_required=not await _account_has_arduino(db,user.id),approval_code=_approval_code(device)
    )

@router.post('/logout',status_code=204)
async def logout(current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    user,device=current; device.session_version+=1
    await record_security_event(db,'auth.logout','allowed',user_id=user.id,device_id=device.device_id)
    await db.flush(); await db.commit()
    await event_bus.publish_to_user(user.id,{'type':'session_revoked','device_id':device.device_id})
    return None
