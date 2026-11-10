import json
from dataclasses import dataclass
from typing import Literal

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import record_security_event
from app.models.conversation import Conversation, ConversationMember

ConversationAction = Literal['settings', 'message', 'file', 'key', 'typing', 'read', 'call']
ConversationTransition = Literal['accepted', 'rejected']
_ACCEPTED_ACTIONS = frozenset({'message', 'file', 'key', 'typing', 'read', 'call'})
_VALID_STATES = frozenset({'pending', 'accepted', 'rejected', 'blocked'})


@dataclass(frozen=True)
class ConversationAccess:
    conversation: Conversation
    membership: ConversationMember


def authorize_conversation_state(*, is_member: bool, status: str, action: ConversationAction) -> None:
    """Pure policy decision shared by HTTP, file, key and WebSocket paths."""
    if not is_member:
        raise HTTPException(403, 'Not a conversation member')
    if status not in _VALID_STATES:
        # Unknown states must never inherit accepted authority during a rollout.
        raise HTTPException(409, 'Conversation security state is invalid')
    if action in _ACCEPTED_ACTIONS and status != 'accepted':
        raise HTTPException(409, 'Conversation request must be accepted first')


def authorize_conversation_transition(*, status: str, requester_user_id: str | None,
                                      actor_user_id: str, target: ConversationTransition) -> bool:
    """Validate a recipient-owned request transition.

    Returns False for an idempotent retry and True when a mutation is required.
    """
    if target not in {'accepted', 'rejected'}:
        raise HTTPException(400, 'Unsupported conversation transition')
    if requester_user_id == actor_user_id:
        raise HTTPException(403, f'Only the recipient can {target[:-2]} this request')
    if status == target:
        return False
    if status != 'pending':
        raise HTTPException(409, 'Conversation request is not pending')
    return True


async def require_conversation_access(db: AsyncSession, conversation_id: str, user_id: str,
                                      action: ConversationAction) -> ConversationAccess:
    row = (await db.execute(
        select(Conversation, ConversationMember)
        .join(ConversationMember, ConversationMember.conversation_id == Conversation.id)
        .where(Conversation.id == conversation_id, ConversationMember.user_id == user_id)
    )).one_or_none()
    authorize_conversation_state(is_member=row is not None, status=row[0].status if row else '', action=action)
    conversation, membership = row
    return ConversationAccess(conversation=conversation, membership=membership)


async def require_accepted_relationship(db: AsyncSession, current_user_id: str, target_user_id: str) -> None:
    """Authorize user-key discovery only across an accepted relationship."""
    if current_user_id == target_user_id:
        return
    allowed = (await db.execute(
        select(Conversation.id)
        .join(ConversationMember, ConversationMember.conversation_id == Conversation.id)
        .where(
            Conversation.status == 'accepted',
            ConversationMember.user_id == current_user_id,
            Conversation.id.in_(
                select(ConversationMember.conversation_id)
                .where(ConversationMember.user_id == target_user_id)
            ),
        )
        .limit(1)
    )).scalar_one_or_none()
    if allowed is None:
        raise HTTPException(403, 'Accept the conversation request before accessing device keys')


async def transition_conversation(db: AsyncSession, conversation_id: str, actor_user_id: str,
                                  target: ConversationTransition) -> tuple[Conversation, bool]:
    statement = (
        select(Conversation)
        .join(ConversationMember, ConversationMember.conversation_id == Conversation.id)
        .where(Conversation.id == conversation_id, ConversationMember.user_id == actor_user_id)
    )
    if db.bind is not None and db.bind.dialect.name == 'postgresql':
        statement = statement.with_for_update()
    conversation = (await db.execute(statement)).scalar_one_or_none()
    if conversation is None:
        raise HTTPException(404, 'Conversation request not found')
    changed = authorize_conversation_transition(
        status=conversation.status,
        requester_user_id=conversation.requested_by_user_id,
        actor_user_id=actor_user_id,
        target=target,
    )
    if changed:
        conversation.status = target
        await record_security_event(
            db,
            'conversation.transition',
            target,
            user_id=actor_user_id,
            details=json.dumps({'conversation_id': conversation_id}, separators=(',', ':')),
        )
        await db.flush()
    return conversation, changed
