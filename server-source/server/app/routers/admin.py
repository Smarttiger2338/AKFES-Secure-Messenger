import base64
import hashlib
import hmac
import json
import secrets
import struct
import time
import urllib.parse
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import record_security_event
from app.core.config import settings
from app.core.database import get_db
from app.core.rate_limit import allow
from app.core.redis_client import make_redis_client
from app.core.security import get_current_user, verify_password_async
from app.models.admin import AdminMfa, AdminPasskey
from app.models.device import Device
from app.models.security import SecurityAuditEvent
from app.models.user import User
from app.realtime import event_bus

router=APIRouter()


class PasswordBody(BaseModel): password:str=Field(...,min_length=10,max_length=128)
ADMIN_GRANT_ACTIONS=frozenset({'admin.user_suspend','admin.user_reactivate','admin.user_revoke_devices','admin.passkey_register','admin.totp_rotate'})


class GrantScope(BaseModel):
    action:str=Field(...,min_length=1,max_length=64)
    target_id:str=Field(...,min_length=1,max_length=64)
class TotpBody(GrantScope): code:str=Field(...,pattern=r'^[0-9]{6}$')
class TotpConfirmBody(BaseModel):
    code:str=Field(...,pattern=r'^[0-9]{6}$')
    setup_id:str=Field(...,min_length=36,max_length=64)
class PasskeyRegisterBody(BaseModel):
    challenge_id:str=Field(...,min_length=16,max_length=64);credential_id:str=Field(...,min_length=16,max_length=1024);public_key_spki_b64:str=Field(...,min_length=80,max_length=2048);client_data_json_b64:str=Field(...,min_length=16,max_length=4096);name:str=Field(default='Passkey',min_length=1,max_length=64)
class PasskeyAssertionBody(GrantScope):
    challenge_id:str=Field(...,min_length=16,max_length=64);credential_id:str=Field(...,min_length=16,max_length=1024);client_data_json_b64:str=Field(...,min_length=16,max_length=4096);authenticator_data_b64:str=Field(...,min_length=48,max_length=2048);signature_b64:str=Field(...,min_length=32,max_length=2048)
class SuspendBody(BaseModel): suspended:bool


def _b64u(data:bytes)->str:return base64.urlsafe_b64encode(data).decode().rstrip('=')
def _unb64u(value:str)->bytes:return base64.urlsafe_b64decode(value+'='*((4-len(value)%4)%4))
def _admin(user:User)->bool:return user.username.lower() in {v.strip().lower() for v in settings.ADMIN_USERNAMES if v.strip()}
def _require_admin(current:tuple=Depends(get_current_user))->tuple:
    user,_=current
    if not _admin(user):raise HTTPException(403,'Administrator access required')
    return current


def _mfa_key()->bytes:
    if len(settings.ADMIN_MFA_ENCRYPTION_KEY)<32:raise HTTPException(503,'Administrator MFA encryption is not configured')
    return hashlib.sha256(settings.ADMIN_MFA_ENCRYPTION_KEY.encode()).digest()
def _seal(secret:str)->str:
    nonce=secrets.token_bytes(12);return _b64u(nonce+AESGCM(_mfa_key()).encrypt(nonce,secret.encode(),b'akfes-admin-totp-v1'))
def _open(value:str)->str:
    raw=_unb64u(value);return AESGCM(_mfa_key()).decrypt(raw[:12],raw[12:],b'akfes-admin-totp-v1').decode()


def _totp(secret:str,counter:int)->str:
    key=base64.b32decode(secret);digest=hmac.new(key,struct.pack('>Q',counter),hashlib.sha1).digest();offset=digest[-1]&15
    return f'{(struct.unpack(">I",digest[offset:offset+4])[0]&0x7fffffff)%1_000_000:06d}'
def _verify_totp(secret:str,code:str)->bool:
    counter=int(time.time())//30
    return any(hmac.compare_digest(_totp(secret,counter+delta),code) for delta in (-1,0,1))


def _validate_grant_scope(action:str,target_id:str)->None:
    if action not in ADMIN_GRANT_ACTIONS:raise HTTPException(400,'Unsupported administrator action')
    if not target_id or len(target_id)>64:raise HTTPException(400,'Invalid administrator action target')


async def _grant(user:User,device:Device,action:str,target_id:str)->str:
    _validate_grant_scope(action,target_id)
    token=secrets.token_urlsafe(32);key='akfes:admin:grant:'+hashlib.sha256(token.encode()).hexdigest();client=make_redis_client(purpose='security')
    try:stored=await client.set(key,json.dumps({'user_id':user.id,'device_id':device.device_id,'action':action,'target_id':target_id},separators=(',',':')),ex=settings.ADMIN_STEP_UP_SECONDS,nx=True)
    finally:await client.aclose()
    if not stored:raise HTTPException(503,'Could not allocate administrator authorization')
    return token
async def _consume_grant(token:str|None,user:User,device:Device,action:str,target_id:str)->None:
    _validate_grant_scope(action,target_id)
    if not token:raise HTTPException(401,'Administrator step-up authentication required')
    key='akfes:admin:grant:'+hashlib.sha256(token.encode()).hexdigest();client=make_redis_client(purpose='security')
    try:raw=await client.getdel(key)
    finally:await client.aclose()
    if raw is None:raise HTTPException(401,'Administrator step-up expired or already used')
    data=json.loads(raw)
    if data.get('user_id')!=user.id or data.get('device_id')!=device.device_id or data.get('action')!=action or data.get('target_id')!=target_id:raise HTTPException(401,'Administrator step-up scope mismatch')


async def _challenge(kind:str,user:User,device:Device)->dict:
    challenge=_b64u(secrets.token_bytes(32));challenge_id=_b64u(secrets.token_bytes(18));client=make_redis_client(purpose='security')
    value=json.dumps({'kind':kind,'user_id':user.id,'device_id':device.device_id,'challenge':challenge},separators=(',',':'))
    try:await client.set(f'akfes:admin:webauthn:{challenge_id}',value,ex=180,nx=True)
    finally:await client.aclose()
    return {'challenge_id':challenge_id,'challenge':challenge}
async def _take_challenge(challenge_id:str,kind:str,user:User,device:Device)->str:
    client=make_redis_client(purpose='security')
    try:raw=await client.getdel(f'akfes:admin:webauthn:{challenge_id}')
    finally:await client.aclose()
    if raw is None:raise HTTPException(400,'Unknown or expired passkey challenge')
    data=json.loads(raw)
    if data.get('kind')!=kind or data.get('user_id')!=user.id or data.get('device_id')!=device.device_id:raise HTTPException(400,'Passkey challenge mismatch')
    return str(data['challenge'])
def _client_data(value:str,challenge:str,expected_type:str)->bytes:
    raw=_unb64u(value)
    try:data=json.loads(raw)
    except Exception as exc:raise HTTPException(400,'Invalid passkey client data') from exc
    if data.get('type')!=expected_type or data.get('challenge')!=challenge or data.get('origin')!=settings.ADMIN_WEBAUTHN_ORIGIN:
        raise HTTPException(400,'Passkey origin or challenge mismatch')
    return raw


@router.get('/status')
async def status(current:tuple=Depends(_require_admin),db:AsyncSession=Depends(get_db)):
    user,_=current;mfa=(await db.execute(select(AdminMfa).where(AdminMfa.user_id==user.id))).scalar_one_or_none()
    count=(await db.execute(select(func.count()).select_from(AdminPasskey).where(AdminPasskey.user_id==user.id))).scalar_one()
    return {'is_admin':True,'totp_enabled':bool(mfa and mfa.totp_enabled),'passkey_count':count,'rp_id':settings.ADMIN_WEBAUTHN_RP_ID,'origin':settings.ADMIN_WEBAUTHN_ORIGIN}


@router.post('/totp/setup')
async def setup_totp(body:PasswordBody,current:tuple=Depends(_require_admin),db:AsyncSession=Depends(get_db),x_admin_step_up:str|None=Header(default=None)):
    user,device=current
    if not await allow('admin-mfa-setup',device.device_id,5):raise HTTPException(429,'Too many administrator MFA setup attempts')
    if not await verify_password_async(body.password,user.password_hash):raise HTTPException(401,'Invalid password')
    existing=(await db.execute(select(AdminMfa).where(AdminMfa.user_id==user.id,AdminMfa.totp_enabled.is_(True)))).scalar_one_or_none()
    if existing is not None:await _consume_grant(x_admin_step_up,user,device,'admin.totp_rotate',user.id)
    secret=base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=');setup_id=secrets.token_urlsafe(24);client=make_redis_client(purpose='security')
    try:await client.set(f'akfes:admin:totp-setup:{setup_id}',json.dumps({'user_id':user.id,'device_id':device.device_id,'secret':secret},separators=(',',':')),ex=600,nx=True)
    finally:await client.aclose()
    label=urllib.parse.quote(f'AKFES:{user.username}');issuer=urllib.parse.quote('AKFES Secure Messenger')
    return {'setup_id':setup_id,'secret':secret,'otpauth_uri':f'otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30'}


@router.post('/totp/confirm')
async def confirm_totp(body:TotpConfirmBody,current:tuple=Depends(_require_admin),db:AsyncSession=Depends(get_db)):
    user,device=current;client=make_redis_client(purpose='security')
    try:raw=await client.getdel(f'akfes:admin:totp-setup:{body.setup_id}')
    finally:await client.aclose()
    if raw is None:raise HTTPException(400,'Unknown or expired TOTP setup')
    data=json.loads(raw)
    if data.get('user_id')!=user.id or data.get('device_id')!=device.device_id or not _verify_totp(data['secret'],body.code):raise HTTPException(400,'Invalid TOTP code')
    row=(await db.execute(select(AdminMfa).where(AdminMfa.user_id==user.id))).scalar_one_or_none()
    if row is None:row=AdminMfa(user_id=user.id);db.add(row)
    row.totp_secret_encrypted=_seal(data['secret']);row.totp_enabled=True
    await record_security_event(db,'admin.totp_enable','allowed',user_id=user.id,device_id=device.device_id)
    return {'configured':True}


@router.post('/step-up/totp')
async def step_up_totp(body:TotpBody,current:tuple=Depends(_require_admin),db:AsyncSession=Depends(get_db)):
    user,device=current
    _validate_grant_scope(body.action,body.target_id)
    if not await allow('admin-step-up',device.device_id,8):raise HTTPException(429,'Too many administrator authentication attempts')
    row=(await db.execute(select(AdminMfa).where(AdminMfa.user_id==user.id,AdminMfa.totp_enabled.is_(True)))).scalar_one_or_none()
    if row is None or not row.totp_secret_encrypted or not _verify_totp(_open(row.totp_secret_encrypted),body.code):
        await record_security_event(db,'admin.step_up_totp','denied',user_id=user.id,device_id=device.device_id);raise HTTPException(401,'Invalid TOTP code')
    replay_key=f'akfes:admin:totp-used:{user.id}:{body.code}';client=make_redis_client(purpose='security')
    try:fresh=await client.set(replay_key,'1',ex=90,nx=True)
    finally:await client.aclose()
    if not fresh:raise HTTPException(401,'This TOTP code was already used')
    token=await _grant(user,device,body.action,body.target_id);await record_security_event(db,'admin.step_up_totp','allowed',user_id=user.id,device_id=device.device_id,details=f'action={body.action};target={body.target_id}')
    return {'grant_token':token,'expires_in':settings.ADMIN_STEP_UP_SECONDS}


@router.post('/passkeys/register/options')
async def passkey_register_options(current:tuple=Depends(_require_admin)):
    user,device=current;data=await _challenge('create',user,device)
    return {**data,'rp':{'id':settings.ADMIN_WEBAUTHN_RP_ID,'name':'AKFES Admin'},'user':{'id':_b64u(user.id.encode()),'name':user.username,'displayName':user.nickname or user.username}}


@router.post('/passkeys/register')
async def passkey_register(body:PasskeyRegisterBody,current:tuple=Depends(_require_admin),db:AsyncSession=Depends(get_db),x_admin_step_up:str|None=Header(default=None)):
    user,device=current;await _consume_grant(x_admin_step_up,user,device,'admin.passkey_register',user.id);challenge=await _take_challenge(body.challenge_id,'create',user,device);_client_data(body.client_data_json_b64,challenge,'webauthn.create')
    try:
        credential_raw=_unb64u(body.credential_id)
        if len(credential_raw)<16 or len(credential_raw)>1024:raise ValueError()
        public=serialization.load_der_public_key(base64.b64decode(body.public_key_spki_b64,validate=True))
        if not isinstance(public,ec.EllipticCurvePublicKey) or not isinstance(public.curve,ec.SECP256R1):raise ValueError()
    except Exception as exc:raise HTTPException(400,'Only P-256 passkeys are supported') from exc
    db.add(AdminPasskey(credential_id=body.credential_id,user_id=user.id,public_key_spki_b64=body.public_key_spki_b64,name=body.name.strip()))
    await record_security_event(db,'admin.passkey_register','allowed',user_id=user.id,device_id=device.device_id)
    return {'registered':True}


@router.post('/passkeys/auth/options')
async def passkey_auth_options(current:tuple=Depends(_require_admin),db:AsyncSession=Depends(get_db)):
    user,device=current
    if not await allow('admin-passkey-options',device.device_id,12):raise HTTPException(429,'Too many passkey requests')
    keys=(await db.execute(select(AdminPasskey).where(AdminPasskey.user_id==user.id))).scalars().all()
    if not keys:raise HTTPException(400,'No passkeys registered')
    return {**await _challenge('get',user,device),'rp_id':settings.ADMIN_WEBAUTHN_RP_ID,'allow_credentials':[k.credential_id for k in keys]}


@router.post('/step-up/passkey')
async def step_up_passkey(body:PasskeyAssertionBody,current:tuple=Depends(_require_admin),db:AsyncSession=Depends(get_db)):
    user,device=current;_validate_grant_scope(body.action,body.target_id);challenge=await _take_challenge(body.challenge_id,'get',user,device);client_data=_client_data(body.client_data_json_b64,challenge,'webauthn.get')
    key=(await db.execute(select(AdminPasskey).where(AdminPasskey.credential_id==body.credential_id,AdminPasskey.user_id==user.id))).scalar_one_or_none()
    if key is None:raise HTTPException(401,'Unknown passkey')
    auth=_unb64u(body.authenticator_data_b64)
    if len(auth)<37 or auth[:32]!=hashlib.sha256(settings.ADMIN_WEBAUTHN_RP_ID.encode()).digest() or not(auth[32]&1) or not(auth[32]&4):raise HTTPException(401,'Passkey user verification is required')
    count=int.from_bytes(auth[33:37],'big');signed=auth+hashlib.sha256(client_data).digest()
    try:serialization.load_der_public_key(base64.b64decode(key.public_key_spki_b64)).verify(_unb64u(body.signature_b64),signed,ec.ECDSA(hashes.SHA256()))
    except (ValueError,InvalidSignature) as exc:raise HTTPException(401,'Invalid passkey signature') from exc
    if count and key.sign_count and count<=key.sign_count:raise HTTPException(401,'Passkey counter rollback detected')
    key.sign_count=max(key.sign_count,count);key.last_used_at=datetime.now(timezone.utc);token=await _grant(user,device,body.action,body.target_id)
    await record_security_event(db,'admin.step_up_passkey','allowed',user_id=user.id,device_id=device.device_id,details=f'action={body.action};target={body.target_id}')
    return {'grant_token':token,'expires_in':settings.ADMIN_STEP_UP_SECONDS}


@router.get('/users')
async def list_users(q:str|None=Query(default=None,max_length=64),current:tuple=Depends(_require_admin),db:AsyncSession=Depends(get_db)):
    del current;query=select(User).order_by(desc(User.created_at)).limit(200)
    if q:query=query.where(func.lower(User.username).contains(q.strip().lower()))
    users=(await db.execute(query)).scalars().all();result=[]
    for user in users:
        devices=(await db.execute(select(func.count()).select_from(Device).where(Device.user_id==user.id,Device.revoked_at.is_(None)))).scalar_one()
        result.append({'user_id':user.id,'username':user.username,'nickname':user.nickname or user.username,'email_verified':user.email_verified_at is not None,'phone_verified':user.phone_verified_at is not None,'active_devices':devices,'suspended':user.disabled_at is not None,'created_at':user.created_at.isoformat() if user.created_at else None})
    return {'users':result}


@router.get('/audit')
async def admin_audit(current:tuple=Depends(_require_admin),db:AsyncSession=Depends(get_db)):
    del current;events=(await db.execute(select(SecurityAuditEvent).order_by(desc(SecurityAuditEvent.created_at)).limit(300))).scalars().all()
    return {'events':[{'event_id':e.event_id,'user_id':e.user_id,'device_id':e.device_id,'action':e.action,'result':e.result,'target_device_id':e.target_device_id,'details':e.details,'created_at':e.created_at.isoformat() if e.created_at else None} for e in events]}


@router.post('/users/{user_id}/suspension')
async def set_suspension(user_id:str,body:SuspendBody,current:tuple=Depends(_require_admin),db:AsyncSession=Depends(get_db),x_admin_step_up:str|None=Header(default=None)):
    admin,device=current;action='admin.user_suspend' if body.suspended else 'admin.user_reactivate';await _consume_grant(x_admin_step_up,admin,device,action,user_id)
    target=(await db.execute(select(User).where(User.id==user_id))).scalar_one_or_none()
    if target is None:raise HTTPException(404,'User not found')
    if _admin(target):raise HTTPException(400,'Administrator accounts must be changed through protected server configuration')
    target.disabled_at=datetime.now(timezone.utc) if body.suspended else None
    if body.suspended:
        for item in (await db.execute(select(Device).where(Device.user_id==target.id,Device.revoked_at.is_(None)))).scalars().all():item.session_version+=1
    await record_security_event(db,'admin.user_suspend' if body.suspended else 'admin.user_reactivate','allowed',user_id=admin.id,device_id=device.device_id,details=f'target_user={target.id}')
    if body.suspended:await event_bus.publish_to_user(target.id,{'type':'session_revoked','reason':'account_suspended'})
    return {'user_id':target.id,'suspended':body.suspended}


@router.post('/users/{user_id}/revoke-devices')
async def revoke_user_devices(user_id:str,current:tuple=Depends(_require_admin),db:AsyncSession=Depends(get_db),x_admin_step_up:str|None=Header(default=None)):
    admin,device=current;await _consume_grant(x_admin_step_up,admin,device,'admin.user_revoke_devices',user_id)
    target=(await db.execute(select(User).where(User.id==user_id))).scalar_one_or_none()
    if target is None:raise HTTPException(404,'User not found')
    if _admin(target):raise HTTPException(400,'Administrator accounts must be changed through protected server configuration')
    devices=(await db.execute(select(Device).where(Device.user_id==user_id,Device.revoked_at.is_(None)))).scalars().all();now=datetime.now(timezone.utc)
    for item in devices:item.status='revoked';item.revoked_at=now;item.session_version+=1
    await record_security_event(db,'admin.user_revoke_devices','allowed',user_id=admin.id,device_id=device.device_id,details=f'target_user={user_id};count={len(devices)}')
    await event_bus.publish_to_user(user_id,{'type':'session_revoked','reason':'devices_revoked'})
    return {'revoked_count':len(devices)}
