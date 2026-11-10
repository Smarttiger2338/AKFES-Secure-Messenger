from datetime import datetime, timezone

from fastapi import Depends, Header, HTTPException
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import safe_security_log
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.security import ArduinoGrant, SecurityAuditEvent


async def record_audit(
    db: AsyncSession,
    user_id: str | None,
    device_id: str | None,
    action: str,
    result: str,
    target_device_id: str | None = None,
    details: str | None = None,
):
    safe_security_log(action, result, user_id=user_id, device_id=device_id, details={"target_device_id":target_device_id,"details":details} if target_device_id or details else None)
    db.add(SecurityAuditEvent(
        user_id=user_id,
        device_id=device_id,
        action=action,
        result=result,
        target_device_id=target_device_id,
        details=details,
    ))


def require_arduino_grant(action: str):
    async def dependency(
        current: tuple = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
        x_arduino_grant: str | None = Header(default=None, alias="X-Arduino-Grant"),
    ):
        user, device = current
        if not x_arduino_grant:
            await record_audit(db, user.id, device.device_id, action, "denied", details="arduino_grant_required")
            raise HTTPException(status_code=428, detail="Arduino authentication required")
        now = datetime.now(timezone.utc)
        result = await db.execute(
            update(ArduinoGrant)
            .where(
                ArduinoGrant.grant_id == x_arduino_grant,
                ArduinoGrant.user_id == user.id,
                ArduinoGrant.device_id == device.device_id,
                ArduinoGrant.action == action,
                ArduinoGrant.used_at.is_(None),
                ArduinoGrant.expires_at > now,
            )
            .values(used_at=now)
            .returning(ArduinoGrant.grant_id)
        )
        consumed_grant_id = result.scalar_one_or_none()
        if consumed_grant_id is None:
            await record_audit(db, user.id, device.device_id, action, "denied", details="invalid_expired_or_used_grant")
            raise HTTPException(status_code=403, detail="Invalid, expired, or already used Arduino authentication grant")
        await record_audit(db, user.id, device.device_id, action, "allowed", details="arduino_grant_consumed")
        return current
    return dependency
