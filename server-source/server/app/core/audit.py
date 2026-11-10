import json
import logging
from typing import Any
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.security import SecurityAuditEvent

log=logging.getLogger('akfes.security')

def safe_security_log(event:str, result:str, *, user_id:str|None=None, device_id:str|None=None, details:dict[str,Any]|None=None)->None:
    payload={'event':event,'result':result,'user_id':user_id,'device_id':device_id}
    if details: payload['details']=details
    log.info(json.dumps(payload,separators=(',',':'),sort_keys=True))

async def record_security_event(db:AsyncSession,event:str,result:str,*,user_id:str|None=None,device_id:str|None=None,target_device_id:str|None=None,details:str|None=None)->None:
    db.add(SecurityAuditEvent(user_id=user_id,device_id=device_id,action=event,result=result,target_device_id=target_device_id,details=details))
    safe_security_log(event,result,user_id=user_id,device_id=device_id,details={'target_device_id':target_device_id} if target_device_id else None)
