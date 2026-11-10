import base64
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import settings
from app.core.database import get_db
from app.core.rate_limit import allow_prekey_claim, allow_prekey_target_claim
from app.core.roles import require_control_plane
from app.core.high_risk import require_arduino_grant
from app.core.security import get_current_user
from app.models import schemas
from app.models.device import Device
from app.models.key import PreKey, PreKeyClaimLease
from app.services.conversation_policy import require_accepted_relationship

router=APIRouter()

async def _require_key_relationship(db:AsyncSession,current_user_id:str,target_user_id:str)->None:
    await require_accepted_relationship(db,current_user_id,target_user_id)

def _verify_signed_prekey(device:Device,item:schemas.PreKeyItem)->None:
    if item.kind!='signed': return
    try:
        identity=base64.b64decode(device.identity_public_key,validate=True)
        public=base64.b64decode(item.public_key,validate=True)
        signature=base64.b64decode(item.signature or '',validate=True)
        if len(identity)!=32 or len(public)!=32 or len(signature)!=64: raise ValueError('invalid key material')
        Ed25519PublicKey.from_public_bytes(identity).verify(signature,item.key_id.to_bytes(4,'big')+public)
    except (ValueError,InvalidSignature) as exc:
        raise HTTPException(400,'Signed PreKey signature is invalid') from exc

async def _signed(db:AsyncSession,device_id:str)->PreKey|None:
    cutoff=datetime.now(timezone.utc)-timedelta(days=settings.PREKEY_SIGNED_MAX_AGE_DAYS)
    return (await db.execute(select(PreKey).where(
        PreKey.device_id==device_id,PreKey.kind=='signed',PreKey.used.is_(False),PreKey.created_at>=cutoff
    ).order_by(PreKey.created_at.desc(),PreKey.prekey_id.desc()).limit(1))).scalar_one_or_none()

def _signed_schema(k:PreKey|None):
    return schemas.SignedPreKey(key_id=k.prekey_id,public_key=k.public_key,signature=k.signature or '',created_at=k.created_at.isoformat() if k and k.created_at else None) if k else None

async def _bundle(db:AsyncSession,device:Device,otp:PreKey|None=None):
    signed=await _signed(db,device.device_id)
    return schemas.DeviceKeyInfo(device_id=device.device_id,identity_public_key=device.identity_public_key,device_public_key=device.device_public_key,device_key_signature=device.device_key_signature,secret_gate_public_key=device.secret_gate_public_key,secret_gate_key_signature=device.secret_gate_key_signature,
        signed_prekey=_signed_schema(signed),one_time_prekey=schemas.OneTimePreKey(key_id=otp.prekey_id,public_key=otp.public_key) if otp else None)

@router.post('/secret-gate',status_code=204)
async def set_secret_gate_key(body:schemas.SecretGateKeyRequest,current:tuple=Depends(require_arduino_grant('secret.gate_register')),db:AsyncSession=Depends(get_db)):
    require_control_plane(); _,device=current
    try:
        raw=base64.b64decode(body.public_key,validate=True)
        identity=base64.b64decode(device.identity_public_key,validate=True)
        signature=base64.b64decode(body.signature,validate=True)
        if len(raw)!=32 or len(identity)!=32 or len(signature)!=64:raise ValueError('invalid key material')
        message=f'AKFES-SECRET-GATE-v1|{device.device_id}|{body.public_key}'.encode()
        Ed25519PublicKey.from_public_bytes(identity).verify(signature,message)
    except (ValueError,InvalidSignature) as exc:raise HTTPException(400,'Secret gate key or identity signature is invalid') from exc
    if device.secret_gate_public_key and (device.secret_gate_public_key!=body.public_key or device.secret_gate_key_signature!=body.signature):
        raise HTTPException(409,'Secret gate key is immutable; revoke and re-enroll this device to replace it')
    device.secret_gate_public_key=body.public_key; device.secret_gate_key_signature=body.signature
    await db.flush()

@router.get('/{user_id}',response_model=schemas.UserKeysResponse)
async def get_user_keys(user_id:str,current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    require_control_plane();current_user,_=current;await _require_key_relationship(db,current_user.id,user_id)
    devices=(await db.execute(select(Device).where(Device.user_id==user_id,Device.revoked_at.is_(None),Device.status=='approved',Device.device_public_key.is_not(None),Device.device_key_signature.is_not(None)).order_by(Device.created_at))).scalars().all()
    if not devices: raise HTTPException(404,'User or devices not found')
    return schemas.UserKeysResponse(user_id=user_id,devices=[await _bundle(db,d) for d in devices])

@router.post('/{user_id}/{device_id}/claim',response_model=schemas.DeviceKeyInfo)
async def claim_device_prekey(user_id:str,device_id:str,current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    require_control_plane(); current_user,current_device=current
    await _require_key_relationship(db,current_user.id,user_id)
    # A sender must be able to establish a distinct encrypted session with its
    # other approved devices for multi-device history synchronization.  The
    # current device remains excluded to prevent self-target loops.
    if user_id==current_user.id and device_id==current_device.device_id:
        raise HTTPException(400,'Cannot claim a one-time prekey from the current device')
    if not await allow_prekey_claim(f'{current_device.device_id}:{device_id}'): raise HTTPException(429,'Too many prekey claims; try again later')
    if not await allow_prekey_target_claim(device_id): raise HTTPException(429,'Target device is receiving too many new-session requests')
    target=(await db.execute(select(Device).where(Device.device_id==device_id,Device.user_id==user_id,Device.revoked_at.is_(None),Device.status=='approved'))).scalar_one_or_none()
    if target is None: raise HTTPException(404,'Device not found')
    now=datetime.now(timezone.utc)
    lease_stmt=select(PreKeyClaimLease).where(PreKeyClaimLease.requester_device_id==current_device.device_id,PreKeyClaimLease.target_device_id==device_id)
    if db.bind is not None and db.bind.dialect.name=='postgresql': lease_stmt=lease_stmt.with_for_update()
    lease=(await db.execute(lease_stmt)).scalar_one_or_none()
    # A claim lease prevents repeated requests from draining a target's one-time pool.
    if lease and lease.expires_at>now:
        otp=(await db.execute(select(PreKey).where(PreKey.device_id==device_id,PreKey.prekey_id==lease.prekey_id,PreKey.kind=='one_time'))).scalar_one_or_none()
        if otp: return await _bundle(db,target,otp)
    unused=(await db.execute(select(func.count()).select_from(PreKey).where(
        PreKey.device_id==device_id,PreKey.kind=='one_time',PreKey.used.is_(False)
    ))).scalar_one()
    # Keep a reserve so remote accounts cannot make the target completely
    # unavailable. The caller can still establish a signed-prekey-only session.
    if unused <= settings.PREKEY_MIN_RESERVE:
        return await _bundle(db,target,None)
    otp_stmt=select(PreKey).where(PreKey.device_id==device_id,PreKey.kind=='one_time',PreKey.used.is_(False)).order_by(PreKey.created_at,PreKey.prekey_id).limit(1)
    if db.bind is not None and db.bind.dialect.name=='postgresql': otp_stmt=otp_stmt.with_for_update(skip_locked=True)
    otp=(await db.execute(otp_stmt)).scalar_one_or_none()
    if otp is None: return await _bundle(db,target,None)
    otp.used=True; expiry=now+timedelta(seconds=settings.PREKEY_CLAIM_LEASE_SECONDS)
    if lease:
        lease.prekey_id=otp.prekey_id; lease.expires_at=expiry
    else:
        db.add(PreKeyClaimLease(requester_device_id=current_device.device_id,target_device_id=device_id,prekey_id=otp.prekey_id,expires_at=expiry))
    await db.flush()
    return await _bundle(db,target,otp)

@router.get('/status/prekeys',response_model=dict)
async def prekey_status(current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    require_control_plane(); _,device=current
    unused=(await db.execute(select(func.count()).select_from(PreKey).where(PreKey.device_id==device.device_id,PreKey.kind=='one_time',PreKey.used.is_(False)))).scalar_one()
    signed=await _signed(db,device.device_id)
    signed_age=None
    if signed and signed.created_at: signed_age=max(0,(datetime.now(timezone.utc)-signed.created_at).days)
    return {'unused_one_time':unused,'minimum_recommended':settings.PREKEY_MIN_RESERVE,'signed_prekey_age_days':signed_age,'rotate_signed_prekey':signed_age is None or signed_age>=settings.PREKEY_SIGNED_MAX_AGE_DAYS}

@router.post('/prekeys',status_code=201)
async def upload_prekeys(body:schemas.UploadPreKeysRequest,current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    require_control_plane(); _,device=current
    if body.device_id!=device.device_id: raise HTTPException(403,'Can only upload prekeys for own device')
    signed_items=[p for p in body.prekeys if p.kind=='signed']
    if len(signed_items)>1: raise HTTPException(400,'Upload at most one signed prekey per request')
    if signed_items and not signed_items[0].signature: raise HTTPException(400,'Signed prekeys require a signature')
    for signed in signed_items: _verify_signed_prekey(device,signed)
    existing=set((await db.execute(select(PreKey.prekey_id).where(PreKey.device_id==body.device_id))).scalars().all())
    if signed_items:
        # Re-uploading the current bundle replenishes one-time keys and must not
        # retire the identical Signed PreKey.  The previous implementation
        # marked it used and then skipped the insert because its id existed,
        # making the device disappear from subsequent sender key refreshes.
        incoming=signed_items[0]
        signed_rows=(await db.execute(select(PreKey).where(PreKey.device_id==body.device_id,PreKey.kind=='signed'))).scalars().all()
        for key in signed_rows:
            if key.prekey_id==incoming.key_id:
                if key.public_key!=incoming.public_key or (key.signature or '')!=(incoming.signature or ''):
                    raise HTTPException(409,'Signed PreKey id is already bound to different key material')
                key.used=False
            elif not key.used:
                # Keep old signed keys in DB for delayed initial messages, but
                # only the newly uploaded key remains advertised.
                key.used=True
    created=0
    for p in body.prekeys:
        if p.key_id in existing: continue
        db.add(PreKey(device_id=body.device_id,prekey_id=p.key_id,public_key=p.public_key,signature=p.signature,kind=p.kind)); created+=1
    await db.flush(); return {'status':'ok','count':created}
