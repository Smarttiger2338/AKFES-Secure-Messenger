from fastapi import APIRouter, Depends
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user
from app.models import schemas
from app.models.security import SecurityAuditEvent

router = APIRouter()


class SecurityAuditResponse(schemas.BaseModel):
    event_id: str
    action: str
    result: str
    target_device_id: str | None = None
    created_at: str | None = None


@router.get("/audit", response_model=list[SecurityAuditResponse])
async def audit_log(current: tuple = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    user, _ = current
    result = await db.execute(
        select(SecurityAuditEvent)
        .where(SecurityAuditEvent.user_id == user.id)
        .order_by(desc(SecurityAuditEvent.created_at))
        .limit(100)
    )
    return [SecurityAuditResponse(
        event_id=e.event_id,
        action=e.action,
        result=e.result,
        target_device_id=e.target_device_id,
        created_at=e.created_at.isoformat() if e.created_at else None,
    ) for e in result.scalars().all()]
