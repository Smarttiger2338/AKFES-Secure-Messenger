from __future__ import annotations
import asyncio,json,logging
from collections import defaultdict
from contextlib import suppress
from typing import Any
from fastapi import WebSocket
from app.core.config import settings
from app.core.redis_client import make_redis_client
log=logging.getLogger(__name__)

class ConnectionManager:
    def __init__(self): self.active:dict[str,dict[WebSocket,str]]=defaultdict(dict)
    def counts(self,user_id:str,device_id:str)->tuple[int,int]:
        sockets=self.active.get(user_id,{})
        return len(sockets),sum(1 for d in sockets.values() if d==device_id)
    async def register_accepted(self,user_id:str,device_id:str,ws:WebSocket)->bool:
        u,d=self.counts(user_id,device_id)
        if u>=settings.WS_MAX_CONNECTIONS_PER_USER or d>=settings.WS_MAX_CONNECTIONS_PER_DEVICE: return False
        self.active[user_id][ws]=device_id; return True
    def disconnect(self,user_id,ws):
        sockets=self.active.get(user_id)
        if not sockets:return
        sockets.pop(ws,None)
        if not sockets:self.active.pop(user_id,None)
    async def _send_one(self,user_id:str,ws:WebSocket,data:dict[str,Any]):
        try: await asyncio.wait_for(ws.send_json(data),timeout=settings.WS_SEND_TIMEOUT_SECONDS); return True
        except Exception:
            with suppress(Exception): await ws.close(code=1013,reason='Slow or unavailable consumer')
            self.disconnect(user_id,ws); return False
    async def send_to_user(self,user_id:str,data:dict[str,Any]):
        target=data.get('recipient_device_id')
        sockets=[ws for ws,did in tuple(self.active.get(user_id,{}).items()) if not target or did==target]
        if sockets: await asyncio.gather(*(self._send_one(user_id,ws,data) for ws in sockets),return_exceptions=True)
    async def close_device(self,user_id,device_id,code=4003,reason='Session revoked'):
        for ws,did in tuple(self.active.get(user_id,{}).items()):
            if did!=device_id:continue
            with suppress(Exception):await ws.close(code=code,reason=reason)
            self.disconnect(user_id,ws)

class RedisEventBus:
    prefix='akfes:realtime:user:'
    def __init__(self,manager): self.manager=manager; self._client=None; self._task=None; self._stop=asyncio.Event()
    def _client_from_settings(self):return make_redis_client(purpose='realtime')
    async def start(self):
        if not settings.REDIS_REALTIME_ENABLED or not settings.REDIS_REALTIME_SUBSCRIBE_ENABLED or self._task is not None:return
        self._stop.clear();self._task=asyncio.create_task(self._subscriber_loop(),name='akfes-redis-pubsub')
    async def stop(self):
        self._stop.set()
        if self._task:
            self._task.cancel()
            with suppress(asyncio.CancelledError):await self._task
            self._task=None
        if self._client:
            with suppress(Exception):await self._client.aclose()
            self._client=None
    async def publish_to_user(self,user_id,data):
        if not settings.REDIS_REALTIME_ENABLED: await self._dispatch_local(user_id,data);return
        client=self._client or self._client_from_settings();self._client=client
        try:await client.publish(f'{self.prefix}{user_id}',json.dumps(data,separators=(',',':')))
        except Exception as exc:
            # Realtime delivery may degrade locally, but stored ciphertext remains authoritative.
            log.warning('Redis realtime publish failed; local delivery only: %s',exc);await self._dispatch_local(user_id,data)
    async def _dispatch_local(self,user_id,data):
        if data.get('type') in {'device_revoked','session_revoked'} and isinstance(data.get('device_id'),str):
            await self.manager.close_device(user_id,data['device_id']);return
        await self.manager.send_to_user(user_id,data)
    async def _subscriber_loop(self):
        delay=1.0
        while not self._stop.is_set():
            client=self._client_from_settings();pubsub=client.pubsub(ignore_subscribe_messages=True)
            try:
                await pubsub.psubscribe(f'{self.prefix}*');delay=1.0
                while not self._stop.is_set():
                    msg=await pubsub.get_message(timeout=1.0)
                    if not msg or msg.get('type') not in {'pmessage','message'}:continue
                    channel=str(msg.get('channel') or '')
                    if not channel.startswith(self.prefix):continue
                    try:payload=json.loads(str(msg.get('data') or '{}'))
                    except json.JSONDecodeError:continue
                    if isinstance(payload,dict):await self._dispatch_local(channel[len(self.prefix):],payload)
            except asyncio.CancelledError:raise
            except Exception as exc:
                log.warning('Redis subscriber disconnected: %s',exc);await asyncio.sleep(delay);delay=min(delay*2,15)
            finally:
                with suppress(Exception):await pubsub.aclose()
                with suppress(Exception):await client.aclose()
manager=ConnectionManager();event_bus=RedisEventBus(manager)
