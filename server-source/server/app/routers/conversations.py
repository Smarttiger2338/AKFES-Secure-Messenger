import hashlib
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, delete, distinct, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.core.roles import require_control_plane
from app.core.security import get_current_user
from app.core.rate_limit import allow_conversation_request, allow_conversation_target, allow_message_send
from app.models import schemas
from app.models.conversation import Conversation, ConversationMember
from app.models.device import Device
from app.models.message import Message
from app.models.file import EncryptedFile
from app.models.key import PreKeyClaimLease
from app.models.user import User
from app.realtime import event_bus
from app.services.conversation_policy import require_conversation_access, transition_conversation

router=APIRouter()

async def require_membership(db:AsyncSession,conversation_id:str,user_id:str,*,accepted:bool=True)->None:
    # Compatibility shim for older internal callers. New callers must name the
    # intended action so policy cannot silently become less strict.
    await require_conversation_access(db,conversation_id,user_id,'message' if accepted else 'settings')

async def recipient_for_message(db:AsyncSession,conversation_id:str,sender_user_id:str,sender_device_id:str,recipient_device_id:str)->tuple[Device,str]:
    device=(await db.execute(select(Device).where(Device.device_id==recipient_device_id,Device.revoked_at.is_(None),Device.status=='approved'))).scalar_one_or_none()
    if device is None: raise HTTPException(404,'Recipient device not found')
    if device.device_id==sender_device_id: raise HTTPException(400,'Recipient must be a different device')
    # Envelopes for another approved device belonging to the sender provide
    # E2EE history synchronization without exposing plaintext to the server.
    if device.user_id==sender_user_id: return device,device.user_id
    member=(await db.execute(select(ConversationMember.user_id).where(ConversationMember.conversation_id==conversation_id,ConversationMember.user_id==device.user_id))).scalar_one_or_none()
    if member is None: raise HTTPException(403,'Recipient device is not in this conversation')
    return device,device.user_id

def message_response(m:Message)->schemas.MessageResponse:
    return schemas.MessageResponse(message_id=m.id,logical_message_id=m.logical_message_id,conversation_id=m.conversation_id,
        sender_device_id=m.sender_device_id,recipient_device_id=m.recipient_device_id,ciphertext=m.ciphertext,nonce=m.nonce,
        e2ee_version=m.e2ee_version,signed_prekey_id=m.signed_prekey_id,one_time_prekey_id=m.one_time_prekey_id,
        message_number=m.message_number,ratchet_session_id=m.ratchet_session_id,ephemeral_public_key=m.ephemeral_public_key,message_type=m.message_type,
        created_at=m.created_at.isoformat() if m.created_at else None)

async def persist_message(db:AsyncSession,*,conversation_id:str,sender_user_id:str,sender_device_id:str,body:schemas.SendMessageRequest)->tuple[Message,str,bool]:
    _,recipient_user_id=await recipient_for_message(db,conversation_id,sender_user_id,sender_device_id,body.recipient_device_id)
    if body.message_number is not None:
        duplicate=(await db.execute(select(Message).where(Message.conversation_id==conversation_id,Message.sender_device_id==sender_device_id,
            Message.recipient_device_id==body.recipient_device_id,Message.ratchet_session_id==body.ratchet_session_id,Message.message_number==body.message_number).limit(1))).scalar_one_or_none()
        if duplicate:
            same=(duplicate.logical_message_id==body.logical_message_id and duplicate.ciphertext==body.ciphertext and duplicate.nonce==body.nonce and
                duplicate.message_type==body.message_type and duplicate.ephemeral_public_key==body.ephemeral_public_key and duplicate.one_time_prekey_id==body.one_time_prekey_id)
            if not same: raise HTTPException(409,'Ratchet message number conflicts with different ciphertext')
            return duplicate,recipient_user_id,False
    if body.one_time_prekey_id is not None:
        lease=(await db.execute(select(PreKeyClaimLease).where(
            PreKeyClaimLease.requester_device_id==sender_device_id,
            PreKeyClaimLease.target_device_id==body.recipient_device_id,
            PreKeyClaimLease.prekey_id==body.one_time_prekey_id,
            PreKeyClaimLease.expires_at>datetime.now(timezone.utc),
        ))).scalar_one_or_none()
        if lease is None: raise HTTPException(409,'One-time prekey was not leased to this sender session')
    message=Message(id=str(uuid.uuid4()),logical_message_id=body.logical_message_id,conversation_id=conversation_id,sender_device_id=sender_device_id,
        recipient_device_id=body.recipient_device_id,ciphertext=body.ciphertext,nonce=body.nonce,e2ee_version=body.e2ee_version,
        signed_prekey_id=body.signed_prekey_id,one_time_prekey_id=body.one_time_prekey_id,message_number=body.message_number,ratchet_session_id=body.ratchet_session_id,
        ephemeral_public_key=body.ephemeral_public_key,message_type=body.message_type)
    db.add(message); await db.flush(); await db.refresh(message)
    # A one-time prekey lease is idempotent while a session is being created.
    # Once the first envelope referencing that prekey is durably staged, the
    # lease is completed by deleting it, allowing a future *new* session to
    # consume another OTP instead of reusing the same one.
    if body.one_time_prekey_id is not None:
        await db.execute(delete(PreKeyClaimLease).where(
            PreKeyClaimLease.requester_device_id==sender_device_id,
            PreKeyClaimLease.target_device_id==body.recipient_device_id,
            PreKeyClaimLease.prekey_id==body.one_time_prekey_id,
        ))
    return message,recipient_user_id,True

async def prepare_encrypted_file(db:AsyncSession,conversation_id:str,sender_device_id:str,file_id:str|None)->EncryptedFile|None:
    if file_id is None:return None
    row=(await db.execute(select(EncryptedFile).where(EncryptedFile.id==file_id,EncryptedFile.conversation_id==conversation_id,
        EncryptedFile.sender_device_id==sender_device_id))).scalar_one_or_none()
    if row is None or row.storage_state not in {'pending','ready'}:raise HTTPException(409,'Encrypted file is unavailable for this message')
    return row

@router.get('',response_model=schemas.ConversationListResponse)
async def list_conversations(current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    require_control_plane(); user,_=current
    rows=(await db.execute(select(Conversation,ConversationMember).join(ConversationMember).where(ConversationMember.user_id==user.id,Conversation.status!='rejected'))).all()
    conversation_ids=[conversation.id for conversation,_ in rows]
    if not conversation_ids:return schemas.ConversationListResponse(conversations=[])

    # Fetch list metadata in batches. The previous implementation executed
    # member, last-message, and unread-count queries once per conversation,
    # making sidebar latency grow linearly with 3N additional round trips.
    all_member_rows=(await db.execute(
        select(ConversationMember.conversation_id,User,ConversationMember)
        .join(User,User.id==ConversationMember.user_id)
        .where(ConversationMember.conversation_id.in_(conversation_ids))
        .order_by(ConversationMember.conversation_id,User.username)
    )).all()
    members_by_conversation:dict[str,list[tuple[User,ConversationMember]]]={conversation_id:[] for conversation_id in conversation_ids}
    for conversation_id,member,member_membership in all_member_rows:
        members_by_conversation[conversation_id].append((member,member_membership))

    ranked_messages=select(
        Message.id.label('message_id'),
        func.row_number().over(
            partition_by=Message.conversation_id,
            order_by=(Message.created_at.desc(),Message.id.desc()),
        ).label('message_rank'),
    ).where(Message.conversation_id.in_(conversation_ids)).subquery()
    last_messages=(await db.execute(
        select(Message).join(ranked_messages,ranked_messages.c.message_id==Message.id)
        .where(ranked_messages.c.message_rank==1)
    )).scalars().all()
    last_by_conversation={message.conversation_id:message for message in last_messages}

    unread_rows=(await db.execute(
        select(Message.conversation_id,func.count(distinct(Message.logical_message_id)))
        .join(Device,Device.device_id==Message.sender_device_id)
        .join(ConversationMember,and_(
            ConversationMember.conversation_id==Message.conversation_id,
            ConversationMember.user_id==user.id,
        ))
        .where(
            Message.conversation_id.in_(conversation_ids),
            Device.user_id!=user.id,
            or_(ConversationMember.last_read_at.is_(None),Message.created_at>ConversationMember.last_read_at),
        )
        .group_by(Message.conversation_id)
    )).all()
    unread_by_conversation={conversation_id:int(count or 0) for conversation_id,count in unread_rows}

    items=[]
    for c,membership in rows:
        peer=None;peer_last_read_at=None
        member_rows=members_by_conversation[c.id]
        public_members=[schemas.ConversationMemberPublic(user_id=member.id,username=member.username,
            nickname=member.nickname or member.username,role=member_membership.role) for member,member_membership in member_rows]
        if c.type=='direct':
            peer_row=next(((member,member_membership) for member,member_membership in member_rows if member.id!=user.id),None)
            if peer_row:
                pu,peer_membership=peer_row;peer=schemas.UserPublic(user_id=pu.id,username=pu.username,nickname=pu.nickname or pu.username)
                if pu.share_read_receipts:
                    peer_last_read_at=peer_membership.last_read_at.isoformat() if peer_membership.last_read_at else None
        last=last_by_conversation.get(c.id)
        preview=schemas.LastMessagePreview(message_id=last.id,sender_device_id=last.sender_device_id,message_type=last.message_type,created_at=last.created_at.isoformat() if last.created_at else None) if last else None
        unread=unread_by_conversation.get(c.id,0)
        items.append(schemas.ConversationSummary(conversation_id=c.id,type=c.type,peer=peer,title=c.title,
            server_id=c.server_id,members=public_members,last_message=preview,unread_count=unread,pinned=membership.pinned,
            muted=membership.muted,archived=membership.archived,peer_last_read_at=peer_last_read_at,
            request_status=c.status,incoming_request=c.status=='pending' and c.requested_by_user_id!=user.id))
    items.sort(key=lambda i:(not i.pinned,i.archived,-(datetime.fromisoformat(i.last_message.created_at).timestamp() if i.last_message and i.last_message.created_at else 0)))
    return schemas.ConversationListResponse(conversations=items)

@router.patch('/{conversation_id}/settings',response_model=schemas.ConversationSettingsResponse)
async def update_conversation_settings(conversation_id:str,body:schemas.ConversationSettingsRequest,current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    require_control_plane();user,_=current
    access=await require_conversation_access(db,conversation_id,user.id,'settings');member=access.membership
    if body.pinned is not None:member.pinned=body.pinned
    if body.muted is not None:member.muted=body.muted
    if body.archived is not None:member.archived=body.archived
    await db.commit()
    return schemas.ConversationSettingsResponse(conversation_id=conversation_id,pinned=member.pinned,muted=member.muted,archived=member.archived)

@router.post('/{conversation_id}/read',response_model=schemas.ConversationSettingsResponse)
async def mark_conversation_read(conversation_id:str,current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    require_control_plane();user,_=current
    access=await require_conversation_access(db,conversation_id,user.id,'read');member=access.membership
    read_at=datetime.now(timezone.utc);member.last_read_at=read_at;await db.commit()
    member_ids=list((await db.execute(select(ConversationMember.user_id).where(ConversationMember.conversation_id==conversation_id))).scalars().all())
    event={'type':'read_receipt','conversation_id':conversation_id,'reader_user_id':user.id,'read_at':read_at.isoformat()}
    # Always synchronize the reader's own devices. Sharing the timestamp with
    # other participants is a separate, user-controlled privacy decision.
    targets=member_ids if user.share_read_receipts else [user.id]
    for member_id in targets:await event_bus.publish_to_user(member_id,event)
    return schemas.ConversationSettingsResponse(conversation_id=conversation_id,pinned=member.pinned,muted=member.muted,archived=member.archived,unread_count=0,last_read_at=read_at.isoformat())

@router.post('/direct',response_model=schemas.ConversationSummary)
async def get_or_create_direct(body:schemas.CreateDirectRequest,current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    require_control_plane(); user,_=current
    if body.peer_user_id==user.id: raise HTTPException(400,'Cannot create conversation with yourself')
    if not await allow_conversation_request(user.id):raise HTTPException(429,'Too many conversation requests; try again later')
    if not await allow_conversation_target(body.peer_user_id):raise HTTPException(429,'This account is receiving too many conversation requests')
    peer=(await db.execute(select(User).where(User.id==body.peer_user_id))).scalar_one_or_none()
    if peer is None: raise HTTPException(404,'User not found')
    direct_key=hashlib.sha256(':'.join(sorted([user.id,body.peer_user_id])).encode()).hexdigest()
    existing=(await db.execute(select(Conversation).where(Conversation.direct_key==direct_key))).scalar_one_or_none()
    if existing: return schemas.ConversationSummary(conversation_id=existing.id,type='direct',peer=schemas.UserPublic(user_id=peer.id,username=peer.username,nickname=peer.nickname or peer.username),request_status=existing.status,incoming_request=existing.status=='pending' and existing.requested_by_user_id!=user.id)
    c=Conversation(id=str(uuid.uuid4()),type='direct',direct_key=direct_key,status='pending',requested_by_user_id=user.id); db.add(c)
    try: await db.flush()
    except IntegrityError:
        await db.rollback(); c=(await db.execute(select(Conversation).where(Conversation.direct_key==direct_key))).scalar_one()
        return schemas.ConversationSummary(conversation_id=c.id,type='direct',peer=schemas.UserPublic(user_id=peer.id,username=peer.username,nickname=peer.nickname or peer.username),request_status=c.status,incoming_request=c.status=='pending' and c.requested_by_user_id!=user.id)
    db.add_all([ConversationMember(conversation_id=c.id,user_id=user.id),ConversationMember(conversation_id=c.id,user_id=peer.id)]); await db.flush()
    await db.commit();await event_bus.publish_to_user(peer.id,{'type':'conversation_request','conversation_id':c.id,'requester_user_id':user.id})
    return schemas.ConversationSummary(conversation_id=c.id,type='direct',peer=schemas.UserPublic(user_id=peer.id,username=peer.username,nickname=peer.nickname or peer.username),request_status='pending',incoming_request=False)

@router.post('/{conversation_id}/accept',response_model=schemas.ConversationSummary)
async def accept_conversation(conversation_id:str,current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    require_control_plane();user,_=current
    c,changed=await transition_conversation(db,conversation_id,user.id,'accepted');await db.commit()
    requester=c.requested_by_user_id
    if changed and requester:await event_bus.publish_to_user(requester,{'type':'conversation_accepted','conversation_id':c.id})
    peer=(await db.execute(select(User).join(ConversationMember,ConversationMember.user_id==User.id).where(ConversationMember.conversation_id==c.id,ConversationMember.user_id!=user.id))).scalar_one()
    return schemas.ConversationSummary(conversation_id=c.id,type=c.type,peer=schemas.UserPublic(user_id=peer.id,username=peer.username,nickname=peer.nickname or peer.username),request_status='accepted')

@router.post('/{conversation_id}/reject',status_code=204)
async def reject_conversation(conversation_id:str,current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    require_control_plane();user,_=current
    await transition_conversation(db,conversation_id,user.id,'rejected');await db.commit();return None

@router.post('/{conversation_id}/messages/batch',response_model=schemas.MessageBatchResponse,status_code=201)
async def send_message_batch(conversation_id:str,body:schemas.SendMessageBatchRequest,current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    require_control_plane();user,device=current;await require_conversation_access(db,conversation_id,user.id,'message')
    if not await allow_message_send(device.device_id):raise HTTPException(429,'Too many messages; try again later')
    file_row=await prepare_encrypted_file(db,conversation_id,device.device_id,body.messages[0].encrypted_file_id)
    stored=[];recipients=[];created=[]
    # Validate and stage every device envelope before committing any of them.
    for envelope in body.messages:
        m,recipient_user,is_created=await persist_message(db,conversation_id=conversation_id,sender_user_id=user.id,sender_device_id=device.device_id,body=envelope)
        stored.append(m);recipients.append(recipient_user);created.append(is_created)
    if file_row is not None:file_row.storage_state='ready'
    await db.commit()
    responses=[message_response(m) for m in stored]
    for recipient_user,response,is_created in zip(recipients,responses,created):
        if is_created:await event_bus.publish_to_user(recipient_user,{'type':'new_message',**response.model_dump()})
    return schemas.MessageBatchResponse(messages=responses)

@router.post('/{conversation_id}/messages',response_model=schemas.MessageResponse,status_code=201)
async def send_message(conversation_id:str,body:schemas.SendMessageRequest,current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    require_control_plane(); user,device=current; await require_conversation_access(db,conversation_id,user.id,'message')
    if not await allow_message_send(device.device_id):raise HTTPException(429,'Too many messages; try again later')
    file_row=await prepare_encrypted_file(db,conversation_id,device.device_id,body.encrypted_file_id)
    m,recipient_user,is_created=await persist_message(db,conversation_id=conversation_id,sender_user_id=user.id,sender_device_id=device.device_id,body=body)
    if file_row is not None:file_row.storage_state='ready'
    await db.commit()
    response=message_response(m)
    if is_created:await event_bus.publish_to_user(recipient_user,{'type':'new_message',**response.model_dump()})
    return response

@router.get('/{conversation_id}/messages',response_model=schemas.MessageListResponse)
async def get_messages(conversation_id:str,limit:int=Query(50,ge=1,le=100),before:str|None=None,current:tuple=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    require_control_plane(); user,device=current; await require_conversation_access(db,conversation_id,user.id,'message')
    q=select(Message).where(Message.conversation_id==conversation_id,or_(Message.sender_device_id==device.device_id,Message.recipient_device_id==device.device_id))
    if before:
        cursor=(await db.execute(select(Message).where(Message.id==before,Message.conversation_id==conversation_id))).scalar_one_or_none()
        if cursor is None: raise HTTPException(400,'Invalid message cursor')
        q=q.where(or_(Message.created_at<cursor.created_at,and_(Message.created_at==cursor.created_at,Message.id<cursor.id)))
    # Fan-out creates multiple outgoing rows. Pull extra rows, then show one logical outgoing item.
    rows=list((await db.execute(q.order_by(Message.created_at.desc(),Message.id.desc()).limit((limit+1)*8))).scalars().all())
    dedup=[]; seen_out=set()
    for m in rows:
        if m.sender_device_id==device.device_id:
            if m.logical_message_id in seen_out: continue
            seen_out.add(m.logical_message_id)
        dedup.append(m)
        if len(dedup)>=limit+1: break
    has_more=len(dedup)>limit; dedup=dedup[:limit]; dedup.reverse()
    return schemas.MessageListResponse(messages=[message_response(m) for m in dedup],has_more=has_more)
