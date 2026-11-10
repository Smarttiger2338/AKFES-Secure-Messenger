from __future__ import annotations
import hashlib,hmac,json,secrets,time,uuid
from datetime import datetime,timedelta,timezone
from fastapi import APIRouter,Depends,HTTPException,Response
from sqlalchemy import func,select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.audit import record_security_event, safe_security_log
from app.core.config import settings
from app.core.redis_client import make_redis_client
from app.core.database import get_db
from app.core.security import get_current_user, get_current_user_allow_pending
from app.core.high_risk import require_arduino_grant
from app.core.rate_limit import allow_arduino_challenge
from app.models import schemas
from app.models.device import Device
from app.models.security import ArduinoGrant
router=APIRouter(); TTL_SECONDS=90; PIN_SETUP_TTL_SECONDS=600

def _secret(device_id:str)->bytes:
    return hmac.new(settings.ARDUINO_MASTER_SECRET.encode(),('akfes-arduino-device-v1:'+device_id).encode(),hashlib.sha256).digest()
def _pin_key(device_id:str,pin:str)->bytes:
    return hmac.new(_secret(device_id),('akfes-pin-v1:'+pin).encode('ascii'),hashlib.sha256).digest()
def _pin_wrap_mask(device_id:str)->bytes:
    return hmac.new(settings.ARDUINO_MASTER_SECRET.encode(),('akfes-pin-wrap-v1:'+device_id).encode(),hashlib.sha256).digest()
def _wrap_pin_key(device_id:str,key:bytes)->str:
    return bytes(a^b for a,b in zip(key,_pin_wrap_mask(device_id),strict=True)).hex()
def _unwrap_pin_key(device_id:str,wrapped:str)->bytes:
    raw=bytes.fromhex(wrapped)
    if len(raw)!=32: raise ValueError('invalid wrapped PIN key')
    return bytes(a^b for a,b in zip(raw,_pin_wrap_mask(device_id),strict=True))
def _challenge_key(cid:str)->str: return f'akfes:arduino:challenge:{cid}'
def _pin_setup_key(setup_id:str)->str: return f'akfes:arduino:pin-setup:{setup_id}'
def _redis_client(): return make_redis_client(socket_connect_timeout=1,socket_timeout=2)
def _validate_action(action:str)->None:
    if action not in set(settings.ARDUINO_ACTIONS): raise HTTPException(status_code=400,detail='Unsupported physical-authentication action')

@router.post('/bootstrap-provisioning',response_model=schemas.ArduinoBootstrapProvisioningResponse)
async def bootstrap_provisioning(body:schemas.ArduinoBootstrapProvisioningRequest,response:Response,current:tuple=Depends(get_current_user_allow_pending),db:AsyncSession=Depends(get_db)):
    if not settings.ARDUINO_VERIFIER_ENABLED: raise HTTPException(status_code=503,detail='Physical authentication verifier is not enabled on this node')
    user,device=current
    candidate=_pin_key(device.device_id,body.pin) if body.pin else None
    if device.status=='pending':
        # Only the original registration/bootstrap slot may self-provision.
        # Later pending devices must first be approved from a trusted device.
        if device.approved_at is not None or device.pending_identity_public_key is not None:
            raise HTTPException(status_code=403,detail='Arduino bootstrap provisioning is not available for this device')
        approved_count=(await db.execute(select(func.count()).select_from(Device).where(Device.user_id==user.id,Device.status=='approved',Device.revoked_at.is_(None)))).scalar_one()
        if approved_count!=0: raise HTTPException(status_code=403,detail='Approve this device before enrolling its Arduino')
    elif device.status=='approved':
        # An already Arduino-approved secondary device may enroll its own board
        # exactly once. Retrying the same PIN is allowed after an upload failure.
        if device.arduino_pin_key_wrapped:
            if candidate is None:
                raise HTTPException(status_code=409,detail='Arduino is already configured; use authenticated PIN change')
            try: existing=_unwrap_pin_key(device.device_id,device.arduino_pin_key_wrapped)
            except ValueError as exc: raise HTTPException(status_code=503,detail='Physical authentication key state is invalid') from exc
            if not hmac.compare_digest(existing,candidate):
                raise HTTPException(status_code=409,detail='Arduino is already configured; use authenticated PIN change')
    else:
        raise HTTPException(status_code=403,detail='Arduino provisioning is not available for this device')
    setup_id=None
    if candidate is not None:
        # Compatibility for the immediately preceding Windows client. New
        # clients never send the PIN to the app or server.
        device.arduino_pin_key_wrapped=_wrap_pin_key(device.device_id,candidate)
    else:
        setup_id=str(uuid.uuid4());client=_redis_client()
        # A normal account may add Arduino later for secret chat.  Preserve
        # the stricter bootstrap rules only for legacy pending first devices.
        record=json.dumps({'device_id':device.device_id,'mode':'bootstrap' if device.status=='pending' else 'initial'},separators=(',',':'))
        try: stored=await client.set(_pin_setup_key(setup_id),record,ex=PIN_SETUP_TTL_SECONDS,nx=True)
        except Exception as exc: raise HTTPException(status_code=503,detail='PIN provisioning temporarily unavailable') from exc
        finally: await client.aclose()
        if not stored: raise HTTPException(status_code=503,detail='Could not allocate PIN provisioning state')
    response.headers['Cache-Control']='no-store'
    response.headers['Pragma']='no-cache'
    await record_security_event(db,'arduino.device_provisioning','allowed',user_id=user.id,device_id=device.device_id)
    return schemas.ArduinoBootstrapProvisioningResponse(device_id=device.device_id,device_secret_hex=_secret(device.device_id).hex(),setup_id=setup_id)

@router.post('/pin-provisioning/start',response_model=schemas.ArduinoPinProvisioningResponse)
async def start_pin_provisioning(body:schemas.ArduinoPinProvisioningRequest,response:Response,current:tuple=Depends(require_arduino_grant('arduino.pin_setup')),db:AsyncSession=Depends(get_db)):
    if not settings.ARDUINO_VERIFIER_ENABLED: raise HTTPException(status_code=503,detail='Physical authentication verifier is not enabled on this node')
    user,device=current;setup_id=str(uuid.uuid4())
    client=_redis_client()
    record={'device_id':device.device_id,'mode':'change'}
    if body.pin: record['pin_key_wrapped']=_wrap_pin_key(device.device_id,_pin_key(device.device_id,body.pin))
    record=json.dumps(record,separators=(',',':'))
    try: stored=await client.set(_pin_setup_key(setup_id),record,ex=PIN_SETUP_TTL_SECONDS,nx=True)
    except Exception as exc: raise HTTPException(status_code=503,detail='PIN provisioning temporarily unavailable') from exc
    finally: await client.aclose()
    if not stored: raise HTTPException(status_code=503,detail='Could not allocate PIN provisioning state')
    response.headers['Cache-Control']='no-store';response.headers['Pragma']='no-cache'
    await record_security_event(db,'arduino.pin_setup_start','allowed',user_id=user.id,device_id=device.device_id)
    return schemas.ArduinoPinProvisioningResponse(device_id=device.device_id,device_secret_hex=_secret(device.device_id).hex(),setup_id=setup_id)

@router.post('/pin-provisioning/commit',response_model=schemas.ArduinoPinCommitResponse)
async def commit_pin_provisioning(body:schemas.ArduinoPinCommitRequest,current:tuple=Depends(get_current_user_allow_pending),db:AsyncSession=Depends(get_db)):
    user,device=current;client=_redis_client()
    try: raw=await client.getdel(_pin_setup_key(body.setup_id))
    except Exception as exc: raise HTTPException(status_code=503,detail='PIN provisioning temporarily unavailable') from exc
    finally: await client.aclose()
    if raw is None: raise HTTPException(status_code=400,detail='Unknown or expired PIN setup')
    try: record=json.loads(raw);setup_device_id=str(record['device_id']);mode=str(record.get('mode','change'))
    except Exception as exc: raise HTTPException(status_code=400,detail='Invalid PIN setup state') from exc
    if setup_device_id!=device.device_id: raise HTTPException(status_code=400,detail='PIN setup mismatch')
    if mode=='bootstrap':
        if device.status!='pending' or device.approved_at is not None or device.pending_identity_public_key is not None:
            raise HTTPException(status_code=403,detail='Bootstrap PIN setup is no longer available')
        approved_count=(await db.execute(select(func.count()).select_from(Device).where(Device.user_id==user.id,Device.status=='approved',Device.revoked_at.is_(None)))).scalar_one()
        if approved_count!=0: raise HTTPException(status_code=403,detail='Another device was approved before bootstrap PIN setup completed')
    elif mode not in {'initial','change'} or device.status!='approved': raise HTTPException(status_code=403,detail='PIN setup requires an approved device')
    if body.pin_key_hex:
        try: pin_key=bytes.fromhex(body.pin_key_hex)
        except ValueError as exc: raise HTTPException(status_code=400,detail='Invalid keypad PIN key') from exc
        if len(pin_key)!=32: raise HTTPException(status_code=400,detail='Invalid keypad PIN key')
        pin_key_wrapped=_wrap_pin_key(device.device_id,pin_key)
    else:
        pin_key_wrapped=str(record.get('pin_key_wrapped',''))
    if len(pin_key_wrapped)!=64: raise HTTPException(status_code=400,detail='Physical keypad PIN key is required')
    device.arduino_pin_key_wrapped=pin_key_wrapped
    await record_security_event(db,'arduino.pin_setup_commit','allowed',user_id=user.id,device_id=device.device_id)
    return schemas.ArduinoPinCommitResponse(status='configured',device_id=device.device_id)

@router.post('/challenge',response_model=schemas.ArduinoChallengeResponse)
async def create_challenge(body:schemas.ArduinoChallengeRequest,current:tuple=Depends(get_current_user_allow_pending),db:AsyncSession=Depends(get_db)):
    if not settings.ARDUINO_VERIFIER_ENABLED: raise HTTPException(status_code=503,detail='Physical authentication verifier is not enabled on this node')
    _validate_action(body.action)
    user,device=current
    if not await allow_arduino_challenge(device.device_id): raise HTTPException(status_code=429,detail='Too many physical authentication challenges')
    if device.status!='approved' and body.action!='device.bootstrap': raise HTTPException(status_code=403,detail='Pending devices may only perform bootstrap authentication')
    pin_required=bool(device.arduino_pin_key_wrapped)
    if body.action!='device.bootstrap':
        configured=(await db.execute(select(func.count()).select_from(Device).where(
            Device.user_id==user.id,Device.status=='approved',Device.revoked_at.is_(None),Device.arduino_pin_key_wrapped.is_not(None)
        ))).scalar_one()
        if configured==0: raise HTTPException(status_code=409,detail='Configure an Arduino in the Windows app first')
        pin_required=True
    cid=str(uuid.uuid4()); nonce=secrets.token_hex(32); expires=time.time()+TTL_SECONDS
    client=_redis_client()
    try: stored=await client.set(_challenge_key(cid),json.dumps({'device_id':device.device_id,'nonce':nonce,'action':body.action},separators=(',',':')),ex=TTL_SECONDS,nx=True)
    except Exception as exc: raise HTTPException(status_code=503,detail='Physical authentication temporarily unavailable') from exc
    finally: await client.aclose()
    if not stored: raise HTTPException(status_code=503,detail='Could not allocate physical authentication challenge')
    return schemas.ArduinoChallengeResponse(challenge_id=cid,nonce=nonce,expires_at=str(int(expires)),action=body.action,pin_required=pin_required)

@router.post('/verify',response_model=schemas.ArduinoVerifyResponse)
async def verify_challenge(body:schemas.ArduinoVerifyRequest,current:tuple=Depends(get_current_user_allow_pending),db:AsyncSession=Depends(get_db)):
    if not settings.ARDUINO_VERIFIER_ENABLED: raise HTTPException(status_code=503,detail='Physical authentication verifier is not enabled on this node')
    _validate_action(body.action)
    user,device=current
    if device.status!='approved' and body.action!='device.bootstrap': raise HTTPException(status_code=403,detail='Pending devices may only perform bootstrap authentication')
    client=_redis_client()
    try: raw=await client.getdel(_challenge_key(body.challenge_id))
    except Exception as exc: raise HTTPException(status_code=503,detail='Physical authentication temporarily unavailable') from exc
    finally: await client.aclose()
    if raw is None: raise HTTPException(status_code=400,detail='Unknown, expired, or already-used challenge')
    try: record=json.loads(raw); device_id=str(record['device_id']); nonce=str(record['nonce']); expected_action=str(record['action'])
    except Exception as exc: raise HTTPException(status_code=400,detail='Invalid challenge state') from exc
    if device_id!=device.device_id or body.action!=expected_action: raise HTTPException(status_code=400,detail='Challenge mismatch')
    if body.action=='device.bootstrap':
        try: challenge_secrets=[_unwrap_pin_key(device.device_id,device.arduino_pin_key_wrapped) if device.arduino_pin_key_wrapped else _secret(device.device_id)]
        except ValueError as exc: raise HTTPException(status_code=503,detail='Physical authentication key state is invalid') from exc
    else:
        configured=list((await db.execute(select(Device).where(
            Device.user_id==user.id,Device.status=='approved',Device.revoked_at.is_(None),Device.arduino_pin_key_wrapped.is_not(None)
        ))).scalars().all())
        try: challenge_secrets=[_unwrap_pin_key(candidate.device_id,candidate.arduino_pin_key_wrapped) for candidate in configured]
        except ValueError as exc: raise HTTPException(status_code=503,detail='Physical authentication key state is invalid') from exc
    verified=any(hmac.compare_digest(hmac.new(secret,nonce.encode('ascii'),hashlib.sha256).hexdigest(),body.response_hex.lower()) for secret in challenge_secrets)
    if not verified:
        safe_security_log('arduino.verify','denied',user_id=user.id,device_id=device.device_id,details={'action':body.action})
        raise HTTPException(status_code=403,detail='Arduino authentication failed')
    grant_id=str(uuid.uuid4())
    if body.action=='arduino.connect':
        await record_security_event(db,'arduino.connect','allowed',user_id=user.id,device_id=device.device_id)
        return schemas.ArduinoVerifyResponse(verified=True,challenge_id=body.challenge_id,grant_id=grant_id,action=body.action,message='Arduino connection verified')
    if body.action=='device.bootstrap':
        if device.status!='pending' or device.approved_at is not None: raise HTTPException(status_code=400,detail='Device is not awaiting bootstrap approval')
        device.status='approved'; device.approved_at=datetime.now(timezone.utc); device.pending_identity_public_key=None; device.pending_device_public_key=None; device.pending_device_key_signature=None; device.session_version+=1
        await record_security_event(db,'arduino.bootstrap','allowed',user_id=user.id,device_id=device.device_id)
        await db.flush()
        return schemas.ArduinoVerifyResponse(verified=True,challenge_id=body.challenge_id,grant_id=grant_id,action=body.action,message='Bootstrap approved; sign in again')
    db.add(ArduinoGrant(grant_id=grant_id,challenge_id=body.challenge_id,user_id=user.id,device_id=device.device_id,action=body.action,expires_at=datetime.now(timezone.utc)+timedelta(seconds=60)))
    await record_security_event(db,'arduino.grant','allowed',user_id=user.id,device_id=device.device_id,details=body.action)
    return schemas.ArduinoVerifyResponse(verified=True,challenge_id=body.challenge_id,grant_id=grant_id,action=body.action,message='One-time physical-authentication grant issued')
