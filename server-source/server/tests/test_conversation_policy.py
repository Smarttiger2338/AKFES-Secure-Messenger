import os

os.environ.setdefault('DEBUG','true')
os.environ.setdefault('DATABASE_URL','sqlite+aiosqlite:///:memory:')
os.environ.setdefault('AUTO_CREATE_SCHEMA','true')
os.environ.setdefault('REQUIRE_FIRST_DEVICE_ARDUINO','true')
os.environ.setdefault('REQUIRE_DEVICE_POP','false')
os.environ.setdefault('REDIS_REALTIME_ENABLED','false')

import pytest
from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.database import Base
from app.models import Conversation, ConversationMember, SecurityAuditEvent, User
from app.services.conversation_policy import (
    authorize_conversation_state,
    authorize_conversation_transition,
    transition_conversation,
)


@pytest.mark.parametrize('action', ['message', 'file', 'key', 'typing', 'read', 'call'])
def test_data_plane_requires_accepted_conversation(action):
    for status in ('pending', 'rejected', 'blocked'):
        with pytest.raises(HTTPException) as denied:
            authorize_conversation_state(is_member=True, status=status, action=action)
        assert denied.value.status_code == 409
    authorize_conversation_state(is_member=True, status='accepted', action=action)


def test_unknown_state_and_non_member_fail_closed():
    with pytest.raises(HTTPException) as unknown:
        authorize_conversation_state(is_member=True, status='future-state', action='message')
    assert unknown.value.status_code == 409
    with pytest.raises(HTTPException) as outsider:
        authorize_conversation_state(is_member=False, status='accepted', action='message')
    assert outsider.value.status_code == 403


def test_only_recipient_can_accept_or_reject_and_retries_are_idempotent():
    assert authorize_conversation_transition(
        status='pending', requester_user_id='sender', actor_user_id='recipient', target='accepted'
    ) is True
    assert authorize_conversation_transition(
        status='accepted', requester_user_id='sender', actor_user_id='recipient', target='accepted'
    ) is False
    with pytest.raises(HTTPException) as requester:
        authorize_conversation_transition(
            status='pending', requester_user_id='sender', actor_user_id='sender', target='accepted'
        )
    assert requester.value.status_code == 403
    with pytest.raises(HTTPException) as terminal:
        authorize_conversation_transition(
            status='rejected', requester_user_id='sender', actor_user_id='recipient', target='accepted'
        )
    assert terminal.value.status_code == 409


@pytest.mark.asyncio
async def test_transition_is_atomic_idempotent_and_audited():
    engine=create_async_engine('sqlite+aiosqlite:///:memory:')
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        sessions=async_sessionmaker(engine,expire_on_commit=False)
        async with sessions() as db:
            db.add_all([
                User(id='sender',username='policy_sender',password_hash='unused'),
                User(id='recipient',username='policy_recipient',password_hash='unused'),
                Conversation(id='conversation',type='direct',status='pending',requested_by_user_id='sender'),
                ConversationMember(conversation_id='conversation',user_id='sender'),
                ConversationMember(conversation_id='conversation',user_id='recipient'),
            ])
            await db.commit()
            conversation,changed=await transition_conversation(db,'conversation','recipient','accepted')
            assert conversation.status=='accepted' and changed is True
            await db.commit()
            _,changed_again=await transition_conversation(db,'conversation','recipient','accepted')
            assert changed_again is False
            assert (await db.execute(select(func.count()).select_from(SecurityAuditEvent))).scalar_one()==1
    finally:
        await engine.dispose()
