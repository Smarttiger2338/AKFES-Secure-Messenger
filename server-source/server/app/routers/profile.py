import hashlib
import hmac
import json
import re
import secrets
import smtplib
import urllib.request
import uuid
from datetime import datetime, timezone
from email.message import EmailMessage

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from app.core.audit import record_security_event
from app.core.config import settings
from app.core.database import get_db
from app.core.rate_limit import allow
from app.core.redis_client import make_redis_client
from app.core.security import get_current_user
from app.models.user import User
from app.models.social import Friendship

router = APIRouter()
EMAIL_RE = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
PHONE_RE = re.compile(r'^\+[1-9][0-9]{7,14}$')


class ProfileResponse(BaseModel):
    user_id: str
    username: str
    nickname: str
    email: str | None = None
    email_verified: bool = False
    phone_e164: str | None = None
    phone_verified: bool = False
    bio: str = ''
    status_text: str = ''
    accent_color: str = '#7867f5'
    profile_visibility: str = 'friends'
    discoverable_by_username: bool = True
    share_read_receipts: bool = True
    share_typing_indicators: bool = True
    avatar_data_url: str | None = None
    cover_data_url: str | None = None


class ProfileUpdate(BaseModel):
    nickname: str = Field(..., min_length=1, max_length=64)
    bio: str = Field('', max_length=160)
    status_text: str = Field('', max_length=48)
    accent_color: str = Field('#7867f5', pattern=r'^#[0-9a-fA-F]{6}$')
    profile_visibility: str = Field('friends', pattern=r'^(public|friends|private)$')
    discoverable_by_username: bool | None = None
    share_read_receipts: bool | None = None
    share_typing_indicators: bool | None = None
    avatar_data_url: str | None = None
    cover_data_url: str | None = None


class AvatarResponse(BaseModel):
    avatar_data_url: str | None = None
    accent_color: str = '#7867f5'


class ContactStart(BaseModel):
    kind: str = Field(..., pattern=r'^(email|phone)$')
    target: str = Field(..., min_length=5, max_length=254)


class ContactConfirm(BaseModel):
    verification_id: str = Field(..., min_length=36, max_length=36)
    code: str = Field(..., pattern=r'^[0-9]{6}$')


def _response(user: User) -> ProfileResponse:
    return ProfileResponse(user_id=user.id, username=user.username, nickname=user.nickname or user.username,
        email=user.email, email_verified=user.email_verified_at is not None,
        phone_e164=user.phone_e164, phone_verified=user.phone_verified_at is not None,
        bio=user.bio or '', status_text=user.status_text or '', accent_color=user.accent_color or '#7867f5',
        profile_visibility=user.profile_visibility or 'friends',
        discoverable_by_username=user.discoverable_by_username,
        share_read_receipts=user.share_read_receipts,
        share_typing_indicators=user.share_typing_indicators,
        avatar_data_url=user.avatar_data_url,
        cover_data_url=user.cover_data_url)


def _profile_image(value: str | None, *, max_bytes: int) -> str | None:
    if value is None or value == '':
        return None
    match=re.fullmatch(r'data:image/(png|jpeg|webp);base64,([A-Za-z0-9+/=]+)',value)
    if not match:raise HTTPException(400,'Profile images must be PNG, JPEG, or WebP')
    import base64
    try:data=base64.b64decode(match.group(2),validate=True)
    except Exception as exc:raise HTTPException(400,'Invalid profile image') from exc
    if len(data)>max_bytes:raise HTTPException(413,'Profile image is too large')
    signatures={'png':data.startswith(b'\x89PNG\r\n\x1a\n'),'jpeg':data.startswith(b'\xff\xd8\xff'),'webp':len(data)>=12 and data[:4]==b'RIFF' and data[8:12]==b'WEBP'}
    if not signatures[match.group(1)]:raise HTTPException(400,'Profile image content does not match its type')
    return value


def _normalize(kind: str, target: str) -> str:
    value=target.strip().lower() if kind=='email' else re.sub(r'[\s()-]', '', target)
    if kind=='email' and (len(value)>254 or not EMAIL_RE.fullmatch(value)):raise HTTPException(400,'Invalid email address')
    if kind=='phone' and not PHONE_RE.fullmatch(value):raise HTTPException(400,'Phone number must use E.164 format, for example +821012345678')
    return value


def _digest(verification_id: str, code: str) -> str:
    key=(settings.ADMIN_MFA_ENCRYPTION_KEY or settings.SECRET_KEY).encode()
    return hmac.new(key,f'{verification_id}|{code}'.encode(),hashlib.sha256).hexdigest()


def _send_email(target: str, code: str) -> None:
    if not settings.EMAIL_SMTP_HOST or not settings.EMAIL_FROM:raise RuntimeError('Email verification provider is not configured')
    message=EmailMessage();message['Subject']='AKFES 이메일 인증 코드';message['From']=settings.EMAIL_FROM;message['To']=target
    message.set_content(f'AKFES 인증 코드는 {code} 입니다. {settings.CONTACT_VERIFICATION_TTL_SECONDS//60}분 안에 입력하세요.')
    with smtplib.SMTP(settings.EMAIL_SMTP_HOST,settings.EMAIL_SMTP_PORT,timeout=10) as smtp:
        if settings.EMAIL_SMTP_STARTTLS:smtp.starttls()
        if settings.EMAIL_SMTP_USERNAME:smtp.login(settings.EMAIL_SMTP_USERNAME,settings.EMAIL_SMTP_PASSWORD)
        smtp.send_message(message)


def _send_sms(target: str, code: str) -> None:
    if not settings.SMS_WEBHOOK_URL:raise RuntimeError('SMS verification provider is not configured')
    if not settings.DEBUG and not settings.SMS_WEBHOOK_URL.startswith('https://'):raise RuntimeError('SMS webhook must use HTTPS')
    body=json.dumps({'to':target,'message':f'AKFES 인증 코드: {code}'}).encode()
    headers={'Content-Type':'application/json'}
    if settings.SMS_WEBHOOK_BEARER:headers['Authorization']=f'Bearer {settings.SMS_WEBHOOK_BEARER}'
    with urllib.request.urlopen(urllib.request.Request(settings.SMS_WEBHOOK_URL,data=body,headers=headers,method='POST'),timeout=10) as response:
        if response.status>=300:raise RuntimeError('SMS provider rejected the request')


@router.get('/me',response_model=ProfileResponse)
async def get_profile(current:tuple=Depends(get_current_user)):
    user,_=current;return _response(user)


@router.get('/{user_id}/avatar',response_model=AvatarResponse)
async def get_profile_avatar(user_id:str,current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    viewer,_=current
    target=(await db.execute(select(User).where(User.id==user_id,User.disabled_at.is_(None)))).scalar_one_or_none()
    if target is None:raise HTTPException(404,'Profile not found')
    visibility=target.profile_visibility or 'friends'
    allowed=viewer.id==target.id or visibility=='public'
    if not allowed and visibility=='friends':
        pair_key=':'.join(sorted((viewer.id,target.id)))
        allowed=(await db.execute(select(Friendship.id).where(Friendship.pair_key==pair_key,Friendship.status=='accepted'))).scalar_one_or_none() is not None
    if not allowed:raise HTTPException(404,'Profile not found')
    return AvatarResponse(avatar_data_url=target.avatar_data_url,accent_color=target.accent_color or '#7867f5')


@router.patch('/me',response_model=ProfileResponse)
async def update_profile(body:ProfileUpdate,current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    user,device=current;nickname=' '.join(body.nickname.strip().split())
    if not nickname:raise HTTPException(400,'Nickname cannot be empty')
    user.nickname=nickname
    user.bio=' '.join(body.bio.strip().split())
    user.status_text=' '.join(body.status_text.strip().split())
    user.accent_color=body.accent_color.lower()
    user.profile_visibility=body.profile_visibility
    # Optional fields preserve privacy choices when an older client updates
    # only the legacy profile fields.
    if body.discoverable_by_username is not None:user.discoverable_by_username=body.discoverable_by_username
    if body.share_read_receipts is not None:user.share_read_receipts=body.share_read_receipts
    if body.share_typing_indicators is not None:user.share_typing_indicators=body.share_typing_indicators
    user.avatar_data_url=_profile_image(body.avatar_data_url,max_bytes=700_000)
    user.cover_data_url=_profile_image(body.cover_data_url,max_bytes=1_400_000)
    await record_security_event(db,'profile.update','allowed',user_id=user.id,device_id=device.device_id)
    return _response(user)


@router.post('/contact/start')
async def start_contact_verification(body:ContactStart,current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    user,device=current
    if not await allow('contact-verify',device.device_id,5):raise HTTPException(429,'Too many verification requests')
    target=_normalize(body.kind,body.target);column=User.email if body.kind=='email' else User.phone_e164
    if (await db.execute(select(User.id).where(func.lower(column)==target if body.kind=='email' else column==target))).scalar_one_or_none():
        raise HTTPException(409,'This contact address is already in use')
    verification_id=str(uuid.uuid4());code=f'{secrets.randbelow(1_000_000):06d}'
    record=json.dumps({'user_id':user.id,'device_id':device.device_id,'kind':body.kind,'target':target,'digest':_digest(verification_id,code),'attempts':0},separators=(',',':'))
    client=make_redis_client(purpose='security',socket_connect_timeout=1,socket_timeout=2)
    try:await client.set(f'akfes:contact:{verification_id}',record,ex=settings.CONTACT_VERIFICATION_TTL_SECONDS,nx=True)
    finally:await client.aclose()
    try:await run_in_threadpool(_send_email if body.kind=='email' else _send_sms,target,code)
    except Exception as exc:
        client=make_redis_client(purpose='security');
        try:await client.delete(f'akfes:contact:{verification_id}')
        finally:await client.aclose()
        raise HTTPException(503,'Contact verification provider is unavailable') from exc
    await record_security_event(db,f'profile.{body.kind}_verification_start','allowed',user_id=user.id,device_id=device.device_id)
    result={'verification_id':verification_id,'expires_in':settings.CONTACT_VERIFICATION_TTL_SECONDS}
    if settings.DEBUG:result['debug_code']=code
    return result


@router.post('/contact/confirm',response_model=ProfileResponse)
async def confirm_contact(body:ContactConfirm,current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    user,device=current;key=f'akfes:contact:{body.verification_id}';client=make_redis_client(purpose='security')
    try:
        raw=await client.get(key)
        if raw is None:raise HTTPException(400,'Unknown or expired verification')
        record=json.loads(raw)
        if record.get('user_id')!=user.id or record.get('device_id')!=device.device_id:raise HTTPException(400,'Verification owner mismatch')
        attempts=int(record.get('attempts',0))+1
        if attempts>5:await client.delete(key);raise HTTPException(429,'Too many verification attempts')
        if not hmac.compare_digest(str(record.get('digest')), _digest(body.verification_id,body.code)):
            record['attempts']=attempts;await client.set(key,json.dumps(record,separators=(',',':')),keepttl=True);raise HTTPException(400,'Invalid verification code')
        await client.delete(key)
    finally:await client.aclose()
    now=datetime.now(timezone.utc)
    if record['kind']=='email':user.email=record['target'];user.email_verified_at=now
    else:user.phone_e164=record['target'];user.phone_verified_at=now
    try:await db.flush()
    except IntegrityError as exc:raise HTTPException(409,'This contact address is already in use') from exc
    await record_security_event(db,f"profile.{record['kind']}_verified",'allowed',user_id=user.id,device_id=device.device_id)
    return _response(user)
