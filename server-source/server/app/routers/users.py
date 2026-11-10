from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select
from app.core.database import get_db
from app.core.security import get_current_user
from app.core.rate_limit import allow_user_search
from app.models.user import User
from app.models import schemas
router=APIRouter()

@router.get('/search',response_model=schemas.UserSearchResponse)
async def search_users(q:str=Query(...,min_length=3,max_length=64,pattern=r'^[A-Za-z0-9_.-]+$'),current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    user,device=current
    if not await allow_user_search(device.device_id): raise HTTPException(status_code=429,detail='Too many searches')
    normalized=q.strip().lower()
    result=await db.execute(select(User).where(
        func.lower(User.username)==normalized,
        User.id!=user.id,
        User.disabled_at.is_(None),
        User.discoverable_by_username.is_(True),
    ).limit(1))
    return schemas.UserSearchResponse(users=[schemas.UserPublic(user_id=u.id,username=u.username,nickname=u.nickname or u.username) for u in result.scalars().all()])
