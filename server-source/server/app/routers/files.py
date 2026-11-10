import asyncio,hashlib,os,shutil,uuid
from datetime import datetime,timedelta,timezone
from pathlib import Path
from fastapi import APIRouter,Depends,File,HTTPException,Query,UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import func,select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool
from app.core.config import settings
from app.core.database import get_db
from app.core.rate_limit import allow_file_download,allow_file_upload
from app.core.roles import require_control_plane
from app.core.security import get_current_user
from app.models.device import Device
from app.models.file import EncryptedFile
from app.services.conversation_policy import require_conversation_access
router=APIRouter();_upload_slots=asyncio.Semaphore(2)

async def _user_usage(db,user_id):
    states=('pending','ready')
    total=(await db.execute(select(func.coalesce(func.sum(EncryptedFile.size_bytes),0)).join(Device,Device.device_id==EncryptedFile.sender_device_id).where(Device.user_id==user_id,EncryptedFile.storage_state.in_(states)))).scalar_one()
    since=datetime.now(timezone.utc)-timedelta(days=1)
    daily=(await db.execute(select(func.coalesce(func.sum(EncryptedFile.size_bytes),0)).join(Device,Device.device_id==EncryptedFile.sender_device_id).where(Device.user_id==user_id,EncryptedFile.created_at>=since,EncryptedFile.storage_state.in_(states)))).scalar_one()
    return int(total or 0),int(daily or 0)

async def cleanup_stale_pending(db:AsyncSession)->None:
    cutoff=datetime.now(timezone.utc)-timedelta(hours=1)
    rows=list((await db.execute(select(EncryptedFile).where(EncryptedFile.storage_state=='pending',EncryptedFile.created_at<cutoff).limit(100))).scalars().all())
    base=Path(settings.FILES_DIR).resolve()
    for row in rows:
        # stored_name is server generated; still verify it before deletion so a
        # corrupted DB row cannot escape the encrypted-file directory.
        if row.stored_name==f'{row.id}.akfenc':
            path=(base/row.stored_name).resolve()
            if path.parent==base:await run_in_threadpool(lambda p=path:p.unlink(missing_ok=True))
        await db.delete(row)
    if rows:await db.flush()

@router.post('',status_code=201)
async def upload_encrypted_file(conversation_id:str=Query(...,min_length=36,max_length=36),upload:UploadFile=File(...),current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    require_control_plane()
    if not settings.FILES_ENABLED:raise HTTPException(503,'File service is not enabled on this node')
    user,device=current
    if not await allow_file_upload(device.device_id):raise HTTPException(429,'Too many uploads; try again later')
    await require_conversation_access(db,conversation_id,user.id,'file')
    await cleanup_stale_pending(db)
    current_total,current_daily=await _user_usage(db,user.id)
    if current_total>=settings.FILE_USER_QUOTA_BYTES or current_daily>=settings.FILE_DAILY_UPLOAD_BYTES:raise HTTPException(429,'Encrypted file quota exceeded')
    free=await run_in_threadpool(lambda:shutil.disk_usage(settings.FILES_DIR).free)
    if free<settings.FILE_MIN_FREE_BYTES+settings.MAX_FILE_BYTES:raise HTTPException(507,'File storage is temporarily unavailable')
    file_id=str(uuid.uuid4());stored=f'{file_id}.akfenc';dest=Path(settings.FILES_DIR)/stored;temp=Path(settings.FILES_DIR)/f'.{file_id}.uploading'
    total=0;digest=hashlib.sha256()
    try:
        async with _upload_slots:
            output=await run_in_threadpool(lambda:temp.open('xb'))
            try:
                while True:
                    chunk=await upload.read(settings.FILE_STREAM_CHUNK_BYTES)
                    if not chunk:break
                    total+=len(chunk)
                    if total>settings.MAX_FILE_BYTES or current_total+total>settings.FILE_USER_QUOTA_BYTES or current_daily+total>settings.FILE_DAILY_UPLOAD_BYTES:
                        raise HTTPException(413,'Encrypted file exceeds configured quota')
                    digest.update(chunk);await run_in_threadpool(output.write,chunk)
                await run_in_threadpool(output.flush);await run_in_threadpool(os.fsync,output.fileno())
            finally:await run_in_threadpool(output.close)
        row=EncryptedFile(id=file_id,conversation_id=conversation_id,sender_device_id=device.device_id,stored_name=stored,size_bytes=total,sha256_hex=digest.hexdigest(),storage_state='pending')
        db.add(row);await db.flush();await run_in_threadpool(os.replace,temp,dest);await db.commit()
        return {'file_id':file_id,'size_bytes':total,'sha256':row.sha256_hex}
    except Exception:
        await run_in_threadpool(lambda:temp.unlink(missing_ok=True));await run_in_threadpool(lambda:dest.unlink(missing_ok=True))
        try:
            await db.rollback();existing=(await db.execute(select(EncryptedFile).where(EncryptedFile.id==file_id))).scalar_one_or_none()
            if existing is not None and existing.storage_state!='ready':await db.delete(existing);await db.commit()
        except Exception:await db.rollback()
        raise
    finally:await upload.close()

@router.post('/{file_id}/discard',status_code=204)
async def discard_pending_file(file_id:str,current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    """Remove only an upload that was never attached to a committed message.

    A retry after an ambiguous network response is safe: message commit changes
    the row to ``ready`` in the same transaction, and ready files are never
    deleted by this endpoint.
    """
    require_control_plane()
    if not settings.FILES_ENABLED:raise HTTPException(503,'File service is not enabled on this node')
    _,device=current
    row=(await db.execute(select(EncryptedFile).where(
        EncryptedFile.id==file_id,EncryptedFile.sender_device_id==device.device_id
    ))).scalar_one_or_none()
    if row is None:return None
    if row.storage_state!='pending':raise HTTPException(409,'Committed encrypted files cannot be discarded')
    base=Path(settings.FILES_DIR).resolve()
    if row.stored_name!=f'{row.id}.akfenc':raise HTTPException(409,'Encrypted file metadata is invalid')
    path=(base/row.stored_name).resolve()
    if path.parent!=base:raise HTTPException(409,'Encrypted file path is invalid')
    await run_in_threadpool(lambda:path.unlink(missing_ok=True))
    await db.delete(row);await db.commit()
    return None

@router.get('/{file_id}')
async def download_encrypted_file(file_id:str,current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    require_control_plane()
    if not settings.FILES_ENABLED:raise HTTPException(503,'File service is not enabled on this node')
    user,device=current
    if not await allow_file_download(device.device_id):raise HTTPException(429,'Too many downloads; try again later')
    row=(await db.execute(select(EncryptedFile).where(EncryptedFile.id==file_id))).scalar_one_or_none()
    if row is None or row.storage_state!='ready':raise HTTPException(404,'File not found')
    await require_conversation_access(db,row.conversation_id,user.id,'file')
    base=Path(settings.FILES_DIR).resolve()
    if row.stored_name!=f'{row.id}.akfenc':raise HTTPException(404,'Encrypted file metadata is invalid')
    path=(base/row.stored_name).resolve()
    if path.parent!=base:raise HTTPException(404,'Encrypted file path is invalid')
    if not path.is_file():raise HTTPException(404,'Encrypted file data is missing')
    async def stream():
        f=await run_in_threadpool(lambda:path.open('rb'))
        try:
            while True:
                chunk=await run_in_threadpool(f.read,settings.FILE_STREAM_CHUNK_BYTES)
                if not chunk:break
                yield chunk
        finally:await run_in_threadpool(f.close)
    headers={'Cache-Control':'no-store','X-AKFES-SHA256':row.sha256_hex or '', 'Content-Disposition':f'attachment; filename="{row.stored_name}"','Content-Length':str(row.size_bytes)}
    return StreamingResponse(stream(),media_type='application/octet-stream',headers=headers)
