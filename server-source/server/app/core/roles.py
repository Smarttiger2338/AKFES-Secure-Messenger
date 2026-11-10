from fastapi import HTTPException
from app.core.config import settings

def require_control_plane() -> None:
    if not settings.CONTROL_PLANE_ENABLED:
        raise HTTPException(status_code=503, detail='Control-plane operation is not enabled on this node')
