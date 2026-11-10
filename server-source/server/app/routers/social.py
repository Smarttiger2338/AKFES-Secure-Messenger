import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.roles import require_control_plane
from app.core.rate_limit import allow_conversation_request, allow_conversation_target
from app.core.security import get_current_user
from app.models import schemas
from app.models.conversation import Conversation, ConversationMember
from app.models.social import CommunityServer, CommunityServerMember, Friendship
from app.models.user import User
from app.realtime import event_bus

router = APIRouter()


def _pair_key(a: str, b: str) -> str:
    return ':'.join(sorted((a, b)))


async def _accepted_friends(db: AsyncSession, current_user_id: str, user_ids: set[str]) -> None:
    if not user_ids:
        return
    rows = (await db.execute(select(Friendship).where(
        Friendship.status == 'accepted',
        or_(Friendship.requester_user_id == current_user_id, Friendship.addressee_user_id == current_user_id),
    ))).scalars().all()
    allowed = {r.addressee_user_id if r.requester_user_id == current_user_id else r.requester_user_id for r in rows}
    missing = user_ids - allowed
    if missing:
        raise HTTPException(409, 'Only accepted friends can be added')


async def _server_membership(db: AsyncSession, server_id: str, user_id: str, *, manage: bool = False) -> CommunityServerMember:
    member = (await db.execute(select(CommunityServerMember).where(
        CommunityServerMember.server_id == server_id,
        CommunityServerMember.user_id == user_id,
    ))).scalar_one_or_none()
    if member is None:
        raise HTTPException(404, 'Server not found')
    if manage and member.role not in {'owner', 'admin'}:
        raise HTTPException(403, 'Server manager permission required')
    return member


@router.get('/friends', response_model=schemas.FriendshipListResponse)
async def list_friends(current: tuple = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_control_plane(); user, _ = current
    rows = (await db.execute(select(Friendship).where(or_(
        Friendship.requester_user_id == user.id,
        Friendship.addressee_user_id == user.id,
    )).order_by(Friendship.updated_at.desc()))).scalars().all()
    other_ids = {r.addressee_user_id if r.requester_user_id == user.id else r.requester_user_id for r in rows}
    users = {u.id: u for u in (await db.execute(select(User).where(User.id.in_(other_ids)))).scalars().all()} if other_ids else {}
    result = []
    for row in rows:
        other_id = row.addressee_user_id if row.requester_user_id == user.id else row.requester_user_id
        other = users.get(other_id)
        if other:
            result.append(schemas.FriendshipInfo(
                friendship_id=row.id, status=row.status,
                incoming=row.status == 'pending' and row.addressee_user_id == user.id,
                user=schemas.UserPublic(user_id=other.id, username=other.username, nickname=other.nickname or other.username),
            ))
    return schemas.FriendshipListResponse(friends=result)


@router.post('/friends/requests', response_model=schemas.FriendshipInfo, status_code=201)
async def request_friend(body: schemas.FriendRequestCreate, current: tuple = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_control_plane(); user, _ = current
    if body.user_id == user.id:
        raise HTTPException(400, 'Cannot add yourself')
    if not await allow_conversation_request(user.id):
        raise HTTPException(429, 'Too many social requests; try again later')
    if not await allow_conversation_target(body.user_id):
        raise HTTPException(429, 'This account is receiving too many social requests')
    peer = (await db.execute(select(User).where(User.id == body.user_id, User.disabled_at.is_(None)))).scalar_one_or_none()
    if peer is None:
        raise HTTPException(404, 'User not found')
    pair = _pair_key(user.id, peer.id)
    row = (await db.execute(select(Friendship).where(Friendship.pair_key == pair))).scalar_one_or_none()
    if row:
        if row.status == 'blocked':
            raise HTTPException(409, 'Friend relationship is blocked')
        if row.status == 'pending' and row.addressee_user_id == user.id:
            row.status = 'accepted'
        await db.commit()
    else:
        row = Friendship(id=str(uuid.uuid4()), pair_key=pair, requester_user_id=user.id, addressee_user_id=peer.id, status='pending')
        db.add(row)
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            row = (await db.execute(select(Friendship).where(Friendship.pair_key == pair))).scalar_one()
    await event_bus.publish_to_user(peer.id, {'type': 'friendship_changed', 'friendship_id': row.id})
    return schemas.FriendshipInfo(friendship_id=row.id, status=row.status, incoming=False,
        user=schemas.UserPublic(user_id=peer.id, username=peer.username, nickname=peer.nickname or peer.username))


@router.post('/friends/{friendship_id}/accept', response_model=schemas.FriendshipInfo)
async def accept_friend(friendship_id: str, current: tuple = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_control_plane(); user, _ = current
    row = (await db.execute(select(Friendship).where(Friendship.id == friendship_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, 'Friend request not found')
    if row.addressee_user_id != user.id or row.status != 'pending':
        raise HTTPException(409, 'Friend request is not awaiting your approval')
    row.status = 'accepted'; await db.commit()
    peer = (await db.execute(select(User).where(User.id == row.requester_user_id))).scalar_one()
    await event_bus.publish_to_user(peer.id, {'type': 'friendship_changed', 'friendship_id': row.id})
    return schemas.FriendshipInfo(friendship_id=row.id, status='accepted', incoming=False,
        user=schemas.UserPublic(user_id=peer.id, username=peer.username, nickname=peer.nickname or peer.username))


@router.delete('/friends/{friendship_id}', status_code=204)
async def remove_friend(friendship_id: str, current: tuple = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_control_plane(); user, _ = current
    row = (await db.execute(select(Friendship).where(
        Friendship.id == friendship_id,
        or_(Friendship.requester_user_id == user.id, Friendship.addressee_user_id == user.id),
    ))).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, 'Friend relationship not found')
    peer_id = row.addressee_user_id if row.requester_user_id == user.id else row.requester_user_id
    await db.delete(row); await db.commit()
    await event_bus.publish_to_user(peer_id, {'type': 'friendship_changed', 'friendship_id': friendship_id})


@router.post('/groups', response_model=schemas.ConversationSummary, status_code=201)
async def create_group(body: schemas.CreateGroupRequest, current: tuple = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_control_plane(); user, _ = current
    member_ids = set(body.member_user_ids)
    member_ids.discard(user.id)
    if not member_ids:
        raise HTTPException(400, 'A group needs at least one other member')
    if not await allow_conversation_request(user.id):
        raise HTTPException(429, 'Too many group operations; try again later')
    await _accepted_friends(db, user.id, member_ids)
    existing = set((await db.execute(select(User.id).where(User.id.in_(member_ids), User.disabled_at.is_(None)))).scalars().all())
    if existing != member_ids:
        raise HTTPException(404, 'One or more members were not found')
    conversation = Conversation(id=str(uuid.uuid4()), type='group', title=body.name.strip(), status='accepted', requested_by_user_id=user.id)
    db.add(conversation); await db.flush()
    db.add(ConversationMember(conversation_id=conversation.id, user_id=user.id, role='owner'))
    for member_id in sorted(member_ids):
        db.add(ConversationMember(conversation_id=conversation.id, user_id=member_id, role='member'))
    await db.commit()
    for member_id in member_ids:
        await event_bus.publish_to_user(member_id, {'type': 'conversation_accepted', 'conversation_id': conversation.id})
    return schemas.ConversationSummary(conversation_id=conversation.id, type='group', title=conversation.title,
        request_status='accepted', members=[])


@router.get('/servers', response_model=schemas.CommunityListResponse)
async def list_servers(current: tuple = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_control_plane(); user, _ = current
    memberships = (await db.execute(select(CommunityServerMember, CommunityServer).join(
        CommunityServer, CommunityServer.id == CommunityServerMember.server_id
    ).where(CommunityServerMember.user_id == user.id).order_by(CommunityServer.created_at))).all()
    result = []
    for membership, server in memberships:
        server_member_rows = (await db.execute(select(CommunityServerMember, User).join(
            User, User.id == CommunityServerMember.user_id
        ).where(CommunityServerMember.server_id == server.id).order_by(User.username))).all()
        member_count = len(server_member_rows)
        channels = (await db.execute(select(Conversation).join(ConversationMember).where(
            Conversation.server_id == server.id, ConversationMember.user_id == user.id
        ).order_by(Conversation.created_at))).scalars().all()
        result.append(schemas.CommunityInfo(server_id=server.id, name=server.name, role=membership.role,
            member_count=member_count, channels=[schemas.ConversationSummary(
                conversation_id=c.id, type='channel', title=c.title, server_id=server.id, request_status='accepted'
            ) for c in channels], members=[schemas.ConversationMemberPublic(
                user_id=member_user.id, username=member_user.username, nickname=member_user.nickname or member_user.username,
                role=member.role
            ) for member, member_user in server_member_rows]))
    return schemas.CommunityListResponse(servers=result)


@router.post('/servers', response_model=schemas.CommunityInfo, status_code=201)
async def create_server(body: schemas.CommunityCreate, current: tuple = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_control_plane(); user, _ = current
    owned = int((await db.execute(select(func.count()).select_from(CommunityServer).where(
        CommunityServer.owner_user_id == user.id))).scalar_one())
    if owned >= 20:
        raise HTTPException(409, 'Server limit reached')
    server = CommunityServer(id=str(uuid.uuid4()), name=body.name.strip(), owner_user_id=user.id)
    channel = Conversation(id=str(uuid.uuid4()), type='channel', title='일반', server_id=server.id, status='accepted', requested_by_user_id=user.id)
    db.add(server); await db.flush(); db.add(CommunityServerMember(server_id=server.id, user_id=user.id, role='owner'))
    db.add(channel); await db.flush(); db.add(ConversationMember(conversation_id=channel.id, user_id=user.id, role='owner'))
    await db.commit()
    return schemas.CommunityInfo(server_id=server.id, name=server.name, role='owner', member_count=1,
        channels=[schemas.ConversationSummary(conversation_id=channel.id, type='channel', title=channel.title, server_id=server.id, request_status='accepted')],
        members=[schemas.ConversationMemberPublic(user_id=user.id,username=user.username,nickname=user.nickname or user.username,role='owner')])


@router.post('/servers/{server_id}/members', response_model=schemas.CommunityInfo)
async def add_server_member(server_id: str, body: schemas.CommunityMemberAdd, current: tuple = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_control_plane(); user, _ = current
    membership = await _server_membership(db, server_id, user.id, manage=True)
    if body.user_id == user.id:
        raise HTTPException(409, 'Already a server member')
    await _accepted_friends(db, user.id, {body.user_id})
    target = (await db.execute(select(User).where(User.id == body.user_id, User.disabled_at.is_(None)))).scalar_one_or_none()
    if target is None:
        raise HTTPException(404, 'User not found')
    existing = (await db.execute(select(CommunityServerMember).where(
        CommunityServerMember.server_id == server_id, CommunityServerMember.user_id == body.user_id
    ))).scalar_one_or_none()
    if existing:
        raise HTTPException(409, 'Already a server member')
    current_count = int((await db.execute(select(func.count()).select_from(CommunityServerMember).where(
        CommunityServerMember.server_id == server_id))).scalar_one())
    if current_count >= 20:
        raise HTTPException(409, 'Encrypted server member limit reached')
    db.add(CommunityServerMember(server_id=server_id, user_id=body.user_id, role='member'))
    channels = (await db.execute(select(Conversation).where(Conversation.server_id == server_id))).scalars().all()
    for channel in channels:
        db.add(ConversationMember(conversation_id=channel.id, user_id=body.user_id, role='member'))
    await db.commit()
    server = (await db.execute(select(CommunityServer).where(CommunityServer.id == server_id))).scalar_one()
    count = int((await db.execute(select(func.count()).select_from(CommunityServerMember).where(CommunityServerMember.server_id == server_id))).scalar_one())
    await event_bus.publish_to_user(body.user_id, {'type': 'conversation_accepted', 'server_id': server_id})
    return schemas.CommunityInfo(server_id=server.id, name=server.name, role=membership.role, member_count=count)


@router.patch('/servers/{server_id}/members/{target_user_id}/role', response_model=schemas.CommunityInfo)
async def update_server_member_role(server_id: str, target_user_id: str, body: schemas.CommunityRoleUpdate,
                                    current: tuple = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_control_plane(); user, _ = current
    actor = await _server_membership(db, server_id, user.id)
    if actor.role != 'owner':
        raise HTTPException(403, 'Only the server owner can change roles')
    target = await _server_membership(db, server_id, target_user_id)
    if target.role == 'owner':
        raise HTTPException(409, 'The owner role cannot be changed')
    target.role = body.role; await db.commit()
    server = (await db.execute(select(CommunityServer).where(CommunityServer.id == server_id))).scalar_one()
    count = int((await db.execute(select(func.count()).select_from(CommunityServerMember).where(
        CommunityServerMember.server_id == server_id))).scalar_one())
    await event_bus.publish_to_user(target_user_id, {'type': 'conversation_accepted', 'server_id': server_id})
    return schemas.CommunityInfo(server_id=server.id, name=server.name, role=actor.role, member_count=count)


@router.delete('/servers/{server_id}/members/{target_user_id}', status_code=204)
async def remove_server_member(server_id: str, target_user_id: str, current: tuple = Depends(get_current_user),
                               db: AsyncSession = Depends(get_db)):
    require_control_plane(); user, _ = current
    actor = await _server_membership(db, server_id, user.id)
    target = await _server_membership(db, server_id, target_user_id)
    if target.role == 'owner':
        raise HTTPException(409, 'Transfer or delete the server before removing its owner')
    if target_user_id != user.id and actor.role not in {'owner', 'admin'}:
        raise HTTPException(403, 'Server manager permission required')
    if actor.role == 'admin' and target.role == 'admin':
        raise HTTPException(403, 'Administrators cannot remove other administrators')
    channel_ids = list((await db.execute(select(Conversation.id).where(Conversation.server_id == server_id))).scalars().all())
    if channel_ids:
        memberships = (await db.execute(select(ConversationMember).where(
            ConversationMember.user_id == target_user_id,
            ConversationMember.conversation_id.in_(channel_ids),
        ))).scalars().all()
        for membership in memberships:
            await db.delete(membership)
    await db.delete(target); await db.commit()
    await event_bus.publish_to_user(target_user_id, {'type': 'conversation_accepted', 'server_id': server_id})


@router.post('/servers/{server_id}/channels', response_model=schemas.ConversationSummary, status_code=201)
async def create_server_channel(server_id: str, body: schemas.CommunityChannelCreate, current: tuple = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_control_plane(); user, _ = current
    await _server_membership(db, server_id, user.id, manage=True)
    members = (await db.execute(select(CommunityServerMember).where(CommunityServerMember.server_id == server_id))).scalars().all()
    channel_count = int((await db.execute(select(func.count()).select_from(Conversation).where(
        Conversation.server_id == server_id))).scalar_one())
    if channel_count >= 100:
        raise HTTPException(409, 'Channel limit reached')
    channel = Conversation(id=str(uuid.uuid4()), type='channel', title=body.name.strip(), server_id=server_id,
        status='accepted', requested_by_user_id=user.id)
    db.add(channel); await db.flush()
    for member in members:
        db.add(ConversationMember(conversation_id=channel.id, user_id=member.user_id,
            role='owner' if member.role == 'owner' else 'member'))
    await db.commit()
    for member in members:
        if member.user_id != user.id:
            await event_bus.publish_to_user(member.user_id, {'type': 'conversation_accepted', 'conversation_id': channel.id})
    return schemas.ConversationSummary(conversation_id=channel.id, type='channel', title=channel.title,
        server_id=server_id, request_status='accepted')
