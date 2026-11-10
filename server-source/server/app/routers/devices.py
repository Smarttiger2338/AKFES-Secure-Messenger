from datetime import datetime, timezone
import hashlib

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import record_security_event
from app.core.database import get_db
from app.core.security import get_current_user
from app.models import schemas
from app.models.device import Device
from app.core.high_risk import require_arduino_grant
from app.realtime import event_bus

router = APIRouter()


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]

def approval_code(device: Device) -> str:
    identity = device.pending_identity_public_key or device.identity_public_key
    return hashlib.sha256(identity.encode()).hexdigest()[:8].upper()


def device_info(device: Device, current_device_id: str) -> schemas.DeviceInfo:
    displayed_identity = device.pending_identity_public_key or device.identity_public_key
    return schemas.DeviceInfo(
        device_id=device.device_id,
        device_name=device.device_name,
        identity_public_key=displayed_identity,
        device_public_key=device.pending_device_public_key or device.device_public_key,
        device_key_signature=device.pending_device_key_signature or device.device_key_signature,
        status=device.status,
        key_fingerprint=fingerprint(displayed_identity),
        created_at=device.created_at.isoformat() if device.created_at else None,
        approved_at=device.approved_at.isoformat() if device.approved_at else None,
        last_seen=device.last_seen.isoformat() if device.last_seen else None,
        key_changed_at=device.key_changed_at.isoformat() if device.key_changed_at else None,
        is_current=device.device_id == current_device_id,
        arduino_configured=bool(device.arduino_pin_key_wrapped),
        approval_code=approval_code(device),
    )


@router.get("", response_model=schemas.DeviceListResponse)
async def list_devices(current: tuple = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    user, current_device = current
    current_device.last_seen = datetime.now(timezone.utc)
    result = await db.execute(
        select(Device).where(Device.user_id == user.id).order_by(Device.created_at.desc())
    )
    devices = result.scalars().all()
    return schemas.DeviceListResponse(devices=[device_info(d, current_device.device_id) for d in devices])


@router.post("/{device_id}/approve", response_model=schemas.DeviceActionResponse)
async def approve_device(device_id: str, current: tuple = Depends(require_arduino_grant("device.approve")), db: AsyncSession = Depends(get_db)):
    user, current_device = current
    if current_device.device_id == device_id:
        raise HTTPException(status_code=400, detail="Current device is already trusted")
    result = await db.execute(select(Device).where(Device.device_id == device_id, Device.user_id == user.id))
    device = result.scalar_one_or_none()
    if device is None or device.revoked_at is not None:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.status == "approved":
        return schemas.DeviceActionResponse(status="ok", device_id=device_id, message="Device already approved")
    pending_identity = device.pending_identity_public_key or (device.identity_public_key if device.approved_at is None else None)
    pending_device = device.pending_device_public_key or (device.device_public_key if device.approved_at is None else None)
    pending_signature = device.pending_device_key_signature or (device.device_key_signature if device.approved_at is None else None)
    if not pending_identity or not pending_device or not pending_signature:
        raise HTTPException(status_code=400, detail="No pending device key material")

    device.identity_public_key = pending_identity
    device.device_public_key = pending_device
    device.device_key_signature = pending_signature
    device.pending_identity_public_key = None
    device.pending_device_public_key = None
    device.pending_device_key_signature = None
    device.status = "approved"
    device.approved_at = datetime.now(timezone.utc)
    device.session_version += 1
    await record_security_event(db,"device.approve","allowed",user_id=user.id,device_id=current_device.device_id,target_device_id=device_id)
    await db.flush()
    return schemas.DeviceActionResponse(status="approved", device_id=device_id, message="Device approved; sign in again on that device")


@router.post("/{device_id}/revoke", response_model=schemas.DeviceActionResponse)
async def revoke_device(device_id: str, current: tuple = Depends(require_arduino_grant("device.revoke")), db: AsyncSession = Depends(get_db)):
    user, current_device = current
    if current_device.device_id == device_id:
        raise HTTPException(status_code=400, detail="Use logout for the current device")
    result = await db.execute(select(Device).where(Device.device_id == device_id, Device.user_id == user.id))
    device = result.scalar_one_or_none()
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    device.status = "revoked"
    device.revoked_at = datetime.now(timezone.utc)
    device.session_version += 1
    device.pending_identity_public_key = None
    device.pending_device_public_key = None
    device.pending_device_key_signature = None
    await record_security_event(db,"device.revoke","allowed",user_id=user.id,device_id=current_device.device_id,target_device_id=device_id)
    await db.flush()
    await db.commit()
    await event_bus.publish_to_user(user.id, {'type':'device_revoked','device_id':device_id})
    return schemas.DeviceActionResponse(status='revoked', device_id=device_id, message='Device revoked')


@router.post("/revoke-all-except-current", response_model=schemas.DeviceActionResponse)
async def revoke_all_except_current(current: tuple = Depends(require_arduino_grant("device.revoke_all")), db: AsyncSession = Depends(get_db)):
    user, current_device = current
    result = await db.execute(
        select(Device).where(Device.user_id == user.id, Device.device_id != current_device.device_id, Device.revoked_at.is_(None))
    )
    devices = list(result.scalars().all())
    revoked_ids: list[str] = []
    for device in devices:
        device.status = "revoked"
        device.revoked_at = datetime.now(timezone.utc)
        device.session_version += 1
        device.pending_identity_public_key = None
        device.pending_device_public_key = None
        device.pending_device_key_signature = None
        revoked_ids.append(device.device_id)
    await record_security_event(db,"device.revoke_all","allowed",user_id=user.id,device_id=current_device.device_id,details=f"revoked_count={len(revoked_ids)}")
    await db.flush()
    await db.commit()
    for did in revoked_ids:
        await event_bus.publish_to_user(user.id, {"type": "device_revoked", "device_id": did})
    return schemas.DeviceActionResponse(
        status="revoked",
        device_id=current_device.device_id,
        message=f"Revoked {len(revoked_ids)} other device(s)",
    )
