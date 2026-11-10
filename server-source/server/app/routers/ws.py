import asyncio, base64, json, logging
from time import monotonic
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.rate_limit import allow_ws_connect, allow_ws_message
from app.core.security import resolve_session_token
from app.models.conversation import ConversationMember
from app.models.user import User
from app.realtime import event_bus, manager
from app.core.call_signals import call_signal_payload
from app.services.conversation_policy import require_conversation_access

router = APIRouter()
AUTH_FRAME_MAX = 8192
logger = logging.getLogger(__name__)

@router.websocket('/ws')
async def websocket_endpoint(websocket: WebSocket):
    origin = websocket.headers.get('origin')
    client_ip = websocket.client.host if websocket.client else 'unknown'
    if not await allow_ws_connect(client_ip):
        # Accept only to return the application close code to the browser.
        # Closing before accept becomes an opaque HTTP 403/1006 and makes the
        # client retry a permanent rate-limit/configuration failure forever.
        await websocket.accept()
        await websocket.close(code=4008, reason='WebSocket connection rate limit exceeded')
        return
    if origin and origin not in settings.WS_ALLOWED_ORIGINS:
        await websocket.accept()
        await websocket.close(code=1008, reason='Origin not allowed')
        return
    await websocket.accept()
    token = ''
    user = device = None
    try:
        raw_auth = await asyncio.wait_for(websocket.receive_text(), timeout=5)
        if len(raw_auth.encode('utf-8')) > AUTH_FRAME_MAX:
            raise ValueError('auth too large')
        auth = json.loads(raw_auth)
        if auth.get('type') != 'auth' or not isinstance(auth.get('token'), str):
            raise ValueError('invalid auth')
        token = auth['token']
    except Exception:
        await websocket.close(code=4001, reason='Invalid authentication frame')
        return
    try:
        async with AsyncSessionLocal() as db:
            user, device = await resolve_session_token(token, db)
    except HTTPException as exc:
        if exc.status_code >= 500:
            logger.warning('WebSocket authentication dependency unavailable: %s', exc.detail)
            await websocket.close(code=1013, reason='Authentication service temporarily unavailable')
            return
        await websocket.close(code=4001, reason='Unauthorized')
        return
    except Exception:
        logger.exception('Unexpected WebSocket authentication failure')
        await websocket.close(code=1013, reason='Authentication service temporarily unavailable')
        return

    if not await manager.register_accepted(user.id, device.device_id, websocket):
        await websocket.close(code=4008, reason='Too many WebSocket connections')
        return
    await websocket.send_json({'type':'ready','user_id':user.id,'device_id':device.device_id})
    next_verify = monotonic() + settings.WS_SESSION_REVALIDATE_SECONDS
    last_activity = monotonic()
    typing_conversation_id = None
    typing_targets = []
    try:
        while True:
            deadline = min(next_verify, last_activity + settings.WS_IDLE_TIMEOUT_SECONDS)
            try:
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=max(.25, deadline-monotonic()))
            except asyncio.TimeoutError:
                raw = None
            now = monotonic()
            if now - last_activity >= settings.WS_IDLE_TIMEOUT_SECONDS:
                await websocket.close(code=1001, reason='Idle timeout')
                return
            if now >= next_verify:
                try:
                    async with AsyncSessionLocal() as vdb:
                        await resolve_session_token(token, vdb)
                except HTTPException as exc:
                    if exc.status_code >= 500:
                        logger.warning('WebSocket session revalidation dependency unavailable: %s', exc.detail)
                        await websocket.close(code=1013, reason='Authentication service temporarily unavailable')
                        return
                    await websocket.close(code=4003, reason='Session revoked')
                    return
                except Exception:
                    logger.exception('Unexpected WebSocket session revalidation failure')
                    await websocket.close(code=1013, reason='Authentication service temporarily unavailable')
                    return
                next_verify = now + settings.WS_SESSION_REVALIDATE_SECONDS
            if raw is None:
                continue
            last_activity = now
            if len(raw.encode('utf-8')) > settings.WS_MAX_FRAME_BYTES:
                await websocket.close(code=1009, reason='Frame too large')
                return
            if not await allow_ws_message(device.device_id):
                await websocket.close(code=4008, reason='WebSocket rate limit exceeded')
                return
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_json({'type':'error','code':'INVALID_JSON'})
                continue
            if data.get('type') == 'ping':
                await websocket.send_json({'type':'pong'})
                continue
            if data.get('type') in {'typing_start','typing_stop'}:
                conversation_id=data.get('conversation_id')
                if not isinstance(conversation_id,str) or len(conversation_id)!=36:
                    await websocket.send_json({'type':'error','code':'INVALID_TYPING_EVENT'})
                    continue
                async with AsyncSessionLocal() as tdb:
                    sharing_typing=(await tdb.execute(select(User.share_typing_indicators).where(User.id==user.id))).scalar_one_or_none()
                    # Query the current value for every start event. The User
                    # loaded during WS authentication may be stale after a
                    # preference change made over REST.
                    if data.get('type') == 'typing_start' and sharing_typing is not True:
                        continue
                    try:
                        await require_conversation_access(tdb,conversation_id,user.id,'typing')
                    except HTTPException as exc:
                        await websocket.send_json({'type':'error','code':'CONVERSATION_NOT_ACCEPTED' if exc.status_code==409 else 'NOT_A_CONVERSATION_MEMBER'})
                        continue
                    targets=list((await tdb.execute(select(ConversationMember.user_id).where(ConversationMember.conversation_id==conversation_id,ConversationMember.user_id!=user.id))).scalars().all())
                event={'type':data['type'],'conversation_id':conversation_id,'user_id':user.id,'expires_in_ms':5000}
                for target in targets:await event_bus.publish_to_user(target,event)
                if data['type']=='typing_start':typing_conversation_id=conversation_id;typing_targets=targets
                elif typing_conversation_id==conversation_id:typing_conversation_id=None;typing_targets=[]
                continue
            if data.get('type') in {'call_offer','call_answer','call_ice','call_reject','call_end'}:
                event_type=data['type'];conversation_id=data.get('conversation_id');call_id=data.get('call_id')
                if not isinstance(conversation_id,str) or len(conversation_id)!=36 or not isinstance(call_id,str) or len(call_id)!=36:
                    await websocket.send_json({'type':'error','code':'INVALID_CALL_EVENT'});continue
                async with AsyncSessionLocal() as cdb:
                    try:access=await require_conversation_access(cdb,conversation_id,user.id,'call')
                    except HTTPException as exc:
                        await websocket.send_json({'type':'error','code':'CONVERSATION_NOT_ACCEPTED' if exc.status_code==409 else 'NOT_A_CONVERSATION_MEMBER'});continue
                    if access.conversation.type!='direct':
                        await websocket.send_json({'type':'error','code':'GROUP_CALLS_NOT_SUPPORTED'});continue
                    targets=list((await cdb.execute(select(ConversationMember.user_id).where(
                        ConversationMember.conversation_id==conversation_id,ConversationMember.user_id!=user.id
                    ))).scalars().all())
                if len(targets)!=1:
                    await websocket.send_json({'type':'error','code':'INVALID_CALL_TARGET'});continue
                event={'type':event_type,'conversation_id':conversation_id,'call_id':call_id,
                    'caller_user_id':user.id,'sender_device_id':device.device_id}
                signature=data.get('signature')
                if not isinstance(signature,str) or not 80<=len(signature)<=128:
                    await websocket.send_json({'type':'error','code':'INVALID_CALL_SIGNATURE'});continue
                event['signature']=signature
                if event_type in {'call_offer','call_answer'}:
                    description=data.get('description')
                    if not isinstance(description,dict) or description.get('type') not in {'offer','answer'} or not isinstance(description.get('sdp'),str) or len(description['sdp'])>12000:
                        await websocket.send_json({'type':'error','code':'INVALID_CALL_DESCRIPTION'});continue
                    if (event_type=='call_offer')!=(description['type']=='offer'):
                        await websocket.send_json({'type':'error','code':'INVALID_CALL_DESCRIPTION'});continue
                    event['description']={'type':description['type'],'sdp':description['sdp']}
                    event['media']='video' if data.get('media')=='video' else 'audio'
                elif event_type=='call_ice':
                    candidate=data.get('candidate')
                    if not isinstance(candidate,dict) or not isinstance(candidate.get('candidate'),str) or len(candidate['candidate'])>2048:
                        await websocket.send_json({'type':'error','code':'INVALID_ICE_CANDIDATE'});continue
                    event['candidate']={k:candidate.get(k) for k in ('candidate','sdpMid','sdpMLineIndex','usernameFragment')}
                target_device_id=data.get('target_device_id')
                if target_device_id is not None:
                    if not isinstance(target_device_id,str) or len(target_device_id)!=36:
                        await websocket.send_json({'type':'error','code':'INVALID_CALL_TARGET_DEVICE'});continue
                    event['recipient_device_id']=target_device_id
                description_payload=''
                if event_type in {'call_offer','call_answer'}:
                    description_payload=f"{event['description']['type']}|{event['description']['sdp']}"
                candidate_payload=''
                if event_type=='call_ice':
                    candidate_payload=json.dumps([event['candidate'].get('candidate') or '',event['candidate'].get('sdpMid'),
                        event['candidate'].get('sdpMLineIndex'),event['candidate'].get('usernameFragment')],separators=(',',':'))
                media_payload=event.get('media') or ''
                signed_payload=call_signal_payload(call_id,conversation_id,event_type,device.device_id,description_payload or candidate_payload,media_payload)
                try:
                    identity=base64.b64decode(device.identity_public_key,validate=True)
                    raw_signature=base64.b64decode(signature,validate=True)
                    if len(identity)!=32 or len(raw_signature)!=64:raise ValueError('invalid call signature size')
                    Ed25519PublicKey.from_public_bytes(identity).verify(raw_signature,f'AKFES-CALL-SIGNAL-v1|{signed_payload}'.encode())
                except (ValueError,InvalidSignature):
                    await websocket.send_json({'type':'error','code':'INVALID_CALL_SIGNATURE'});continue
                await event_bus.publish_to_user(targets[0],event)
                if event_type=='call_answer':
                    await event_bus.publish_to_user(user.id,{'type':'call_claimed','conversation_id':conversation_id,
                        'call_id':call_id,'sender_device_id':device.device_id,'description':event['description'],
                        'media':event['media'],'signature':signature})
                continue
            # The realtime node deliberately rejects data-plane message writes.
            # Only ephemeral typing presence is accepted here. All E2EE envelopes
            # and durable read state are committed through authenticated REST.
            await websocket.send_json({'type':'error','code':'RECEIVE_ONLY_CHANNEL'})
    except WebSocketDisconnect:
        pass
    finally:
        if user is not None and typing_conversation_id:
            event={'type':'typing_stop','conversation_id':typing_conversation_id,'user_id':user.id,'expires_in_ms':0}
            for target in typing_targets:
                await event_bus.publish_to_user(target,event)
        if user is not None:
            manager.disconnect(user.id, websocket)
