from __future__ import annotations
import hashlib
import hmac
from collections import defaultdict, deque
from time import monotonic, time
from threading import Lock
from fastapi import HTTPException
from app.core.config import settings
from app.core.redis_client import make_redis_client

class SlidingWindowLimiter:
    def __init__(self, limit: int, window_seconds: int):
        self.limit=limit; self.window=window_seconds; self._events=defaultdict(deque); self._lock=Lock()
    def allow(self,key:str)->bool:
        now=monotonic()
        with self._lock:
            q=self._events[key]; cutoff=now-self.window
            while q and q[0] <= cutoff: q.popleft()
            if len(q) >= self.limit: return False
            q.append(now); return True

_limiters={}
def _opaque_key(kind:str,key:str)->str:
    """Keep IPs, usernames and device IDs out of Redis key names."""
    return hmac.new(settings.SECRET_KEY.encode('utf-8'),f'{kind}\0{key}'.encode('utf-8'),hashlib.sha256).hexdigest()

def _local(kind,limit):
    key=(kind,limit)
    if key not in _limiters: _limiters[key]=SlidingWindowLimiter(limit,settings.RATE_LIMIT_WINDOW_SECONDS)
    return _limiters[key]

async def allow(kind:str,key:str,limit:int)->bool:
    bucket=int(time()//settings.RATE_LIMIT_WINDOW_SECONDS)
    opaque_key=_opaque_key(kind,key)
    redis_key=f'akfes:ratelimit:{kind}:{bucket}:{opaque_key}'
    client=make_redis_client(socket_connect_timeout=0.5,socket_timeout=0.5)
    try:
        count=await client.incr(redis_key)
        if count==1: await client.expire(redis_key,settings.RATE_LIMIT_WINDOW_SECONDS+2)
        return count <= limit
    except Exception as exc:
        if settings.RATE_LIMIT_FAIL_CLOSED:
            raise HTTPException(status_code=503,detail='Security rate limiter unavailable') from exc
        return _local(kind,limit).allow(opaque_key)
    finally:
        try: await client.aclose()
        except Exception: pass

async def allow_login(k): return await allow('login',k,settings.RATE_LIMIT_LOGIN)
async def allow_registration(k): return await allow('register',k,settings.RATE_LIMIT_REGISTER)
async def allow_device_challenge(k): return await allow('device-challenge',k,settings.RATE_LIMIT_DEVICE_CHALLENGE)
async def allow_prekey_claim(k): return await allow('prekey-claim',k,settings.RATE_LIMIT_PREKEY_CLAIM)
async def allow_prekey_target_claim(k): return await allow('prekey-target',k,settings.RATE_LIMIT_PREKEY_TARGET_CLAIMS)
async def allow_arduino_challenge(k): return await allow('arduino',k,settings.RATE_LIMIT_ARDUINO_CHALLENGE)
async def allow_user_search(k): return await allow('user-search',k,settings.RATE_LIMIT_USER_SEARCH)
async def allow_conversation_request(k): return await allow('conversation-request',k,settings.RATE_LIMIT_CONVERSATION_REQUEST)
async def allow_conversation_target(k): return await allow('conversation-target',k,settings.RATE_LIMIT_CONVERSATION_TARGET)
async def allow_file_upload(k): return await allow('file-upload',k,settings.RATE_LIMIT_FILE_UPLOAD)
async def allow_file_download(k): return await allow('file-download',k,settings.RATE_LIMIT_FILE_DOWNLOAD)
async def allow_message_send(k): return await allow('message-send',k,settings.RATE_LIMIT_MESSAGE_SEND)
async def allow_ws_message(k): return await allow('ws-message',k,settings.RATE_LIMIT_WS_MESSAGES)
async def allow_ws_connect(k): return await allow('ws-connect',k,settings.RATE_LIMIT_WS_CONNECT)
