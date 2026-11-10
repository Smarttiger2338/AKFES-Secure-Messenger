import base64
import hashlib
import os
import uuid

os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("AUTO_CREATE_SCHEMA", "true")
os.environ.setdefault("REQUIRE_FIRST_DEVICE_ARDUINO", "true")
os.environ.setdefault("REQUIRE_DEVICE_POP", "false")
os.environ.setdefault("REDIS_REALTIME_ENABLED", "false")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient
from fastapi import HTTPException
import pytest

from app.core.database import AsyncSessionLocal, init_db
from app.main import app
from app.routers.arduino import _pin_key, _unwrap_pin_key, _wrap_pin_key
from app.routers.admin import _consume_grant, _grant, _open, _seal, _totp, _verify_totp
from app.routers.auth import _approval_code
from app.routers.devices import device_info
from app.routers.profile import _normalize
from app.core.config import settings
from app.routers.conversations import recipient_for_message
from app.models.conversation import Conversation, ConversationMember
from app.models.device import Device
from app.models.user import User


def _device_payload(username: str, password: str, device_name: str = "Test Windows") -> dict:
    identity = Ed25519PrivateKey.generate()
    identity_public = base64.b64encode(
        identity.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    device_public = base64.b64encode(
        X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    signature = base64.b64encode(
        identity.sign(f"AKFES-DEVICE-KEY-v1|{device_public}".encode())
    ).decode()
    return {
        "username": username,
        "password": password,
        "device_name": device_name,
        "identity_public_key": identity_public,
        "device_public_key": device_public,
        "device_key_signature": signature,
    }


def test_interrupted_registration_can_resume_and_replacement_login_can_bootstrap():
    first = _device_payload("resume_user", "correct horse battery staple")
    with TestClient(app, base_url="http://localhost") as client:
        created = client.post("/api/auth/register", json=first)
        assert created.status_code == 201, created.text
        assert created.json()["bootstrap_required"] is True

        resumed = client.post("/api/auth/register", json=first)
        assert resumed.status_code == 201, resumed.text
        assert resumed.json()["registration_resumed"] is True
        assert resumed.json()["bootstrap_required"] is True

        replacement = _device_payload("resume_user", first["password"], "Replacement Web")
        login = client.post("/api/auth/login", json=replacement)
        assert login.status_code == 200, login.text
        assert login.json()["requires_approval"] is True
        assert login.json()["bootstrap_required"] is True


def test_active_session_can_rotate_its_memory_only_access_token(monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_FIRST_DEVICE_ARDUINO", False)
    username = f"refresh_{uuid.uuid4().hex[:10]}"
    payload = _device_payload(username, "correct horse battery staple")
    with TestClient(app, base_url="http://localhost") as client:
        created = client.post("/api/auth/register", json=payload)
        assert created.status_code == 201, created.text
        first = created.json()["session_token"]
        refreshed = client.post("/api/auth/refresh", headers={"Authorization": f"Bearer {first}"})
        assert refreshed.status_code == 200, refreshed.text
        data = refreshed.json()
        assert data["user_id"] == created.json()["user_id"]
        assert data["device_id"] == created.json()["device_id"]
        assert data["session_token"] != first


def test_pin_key_is_device_and_pin_bound_without_storing_plain_pin():
    a = _pin_key("00000000-0000-0000-0000-000000000001", "123456")
    b = _pin_key("00000000-0000-0000-0000-000000000001", "654321")
    c = _pin_key("00000000-0000-0000-0000-000000000002", "123456")
    assert len(a) == 32
    assert a != b
    assert a != c
    wrapped=_wrap_pin_key("00000000-0000-0000-0000-000000000001",a)
    assert bytes.fromhex(wrapped)!=a
    assert _unwrap_pin_key("00000000-0000-0000-0000-000000000001",wrapped)==a


def test_reapproval_code_and_fingerprint_use_the_pending_identity():
    device = Device(
        device_id=str(uuid.uuid4()),
        user_id=str(uuid.uuid4()),
        identity_public_key="old-identity",
        pending_identity_public_key="new-identity",
        device_name="Changed Device",
        status="pending",
    )
    expected = hashlib.sha256(b"new-identity").hexdigest()
    assert _approval_code(device) == expected[:8].upper()
    info = device_info(device, "another-device")
    assert info.identity_public_key == "new-identity"
    assert info.key_fingerprint == expected[:32]


def test_admin_totp_and_encrypted_secret_storage(monkeypatch):
    monkeypatch.setattr(settings,"ADMIN_MFA_ENCRYPTION_KEY","a"*64)
    monkeypatch.setattr("app.routers.admin.time.time",lambda:59)
    secret="JBSWY3DPEHPK3PXP"
    code=_totp(secret,1)
    assert _verify_totp(secret,code)
    sealed=_seal(secret)
    assert secret not in sealed
    assert _open(sealed)==secret


@pytest.mark.asyncio
async def test_admin_step_up_is_single_use_and_bound_to_action_and_target(monkeypatch):
    class FakeRedis:
        def __init__(self): self.values={}
        async def set(self,key,value,**kwargs):
            if kwargs.get("nx") and key in self.values:return False
            self.values[key]=value
            return True
        async def getdel(self,key): return self.values.pop(key,None)
        async def aclose(self): return None

    redis=FakeRedis()
    monkeypatch.setattr("app.routers.admin.make_redis_client",lambda **_kwargs:redis)
    user=User(id=str(uuid.uuid4()),username="admin",password_hash="unused")
    device=Device(device_id=str(uuid.uuid4()),user_id=user.id,identity_public_key="identity",device_name="Admin device",status="approved")
    target_a=str(uuid.uuid4());target_b=str(uuid.uuid4())

    wrong_action=await _grant(user,device,"admin.user_suspend",target_a)
    with pytest.raises(HTTPException,match="scope mismatch"):
        await _consume_grant(wrong_action,user,device,"admin.user_revoke_devices",target_a)

    wrong_target=await _grant(user,device,"admin.user_suspend",target_a)
    with pytest.raises(HTTPException,match="scope mismatch"):
        await _consume_grant(wrong_target,user,device,"admin.user_suspend",target_b)

    valid=await _grant(user,device,"admin.user_suspend",target_a)
    await _consume_grant(valid,user,device,"admin.user_suspend",target_a)
    with pytest.raises(HTTPException,match="expired or already used"):
        await _consume_grant(valid,user,device,"admin.user_suspend",target_a)


def test_profile_contact_normalization_keeps_login_id_separate():
    assert _normalize("email"," Person@Example.COM ")=="person@example.com"
    assert _normalize("phone","+82 10-1234-5678")=="+821012345678"


@pytest.mark.asyncio
async def test_another_approved_device_of_sender_is_a_valid_sync_recipient():
    await init_db()
    user_id=str(uuid.uuid4());sender_id=str(uuid.uuid4());sync_id=str(uuid.uuid4());conversation_id=str(uuid.uuid4())
    async with AsyncSessionLocal() as db:
        db.add(User(id=user_id,username=f"sync_{user_id[:8]}",password_hash="unused"))
        db.add_all([
            Device(device_id=sender_id,user_id=user_id,identity_public_key="sender",device_name="Sender",status="approved"),
            Device(device_id=sync_id,user_id=user_id,identity_public_key="sync",device_name="Sync",status="approved"),
        ])
        db.add(Conversation(id=conversation_id,type="direct"))
        db.add(ConversationMember(conversation_id=conversation_id,user_id=user_id))
        await db.commit()
        device,recipient_user=await recipient_for_message(db,conversation_id,user_id,sender_id,sync_id)
        assert device.device_id==sync_id
        assert recipient_user==user_id
        with pytest.raises(HTTPException):
            await recipient_for_message(db,conversation_id,user_id,sender_id,sender_id)


def test_typing_presence_and_read_receipt_are_scoped_to_conversation_members(monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_FIRST_DEVICE_ARDUINO", False)
    async def allow_test_registration(_key):return True
    monkeypatch.setattr("app.routers.auth.allow_registration",allow_test_registration)
    suffix=uuid.uuid4().hex[:10]
    first=_device_payload(f"presence_a_{suffix}","correct horse battery staple")
    second=_device_payload(f"presence_b_{suffix}","correct horse battery staple")
    with TestClient(app,base_url="http://localhost") as client:
        a=client.post("/api/auth/register",json=first);b=client.post("/api/auth/register",json=second)
        assert a.status_code==201,a.text;assert b.status_code==201,b.text
        a_data=a.json();b_data=b.json()
        conversation=client.post("/api/conversations/direct",json={"peer_user_id":b_data["user_id"]},headers={"Authorization":f"Bearer {a_data['session_token']}"})
        assert conversation.status_code==200,conversation.text
        conversation_id=conversation.json()["conversation_id"]
        assert conversation.json()["request_status"]=="pending"
        pending_read=client.post(f"/api/conversations/{conversation_id}/read",headers={"Authorization":f"Bearer {b_data['session_token']}"})
        assert pending_read.status_code==409,pending_read.text
        accepted=client.post(f"/api/conversations/{conversation_id}/accept",headers={"Authorization":f"Bearer {b_data['session_token']}"})
        assert accepted.status_code==200,accepted.text
        assert accepted.json()["request_status"]=="accepted"
        ws_headers={"origin":"http://localhost:1420","host":"localhost"}
        with client.websocket_connect("/ws",headers=ws_headers) as a_ws,client.websocket_connect("/ws",headers=ws_headers) as b_ws:
            a_ws.send_json({"type":"auth","token":a_data["session_token"]});b_ws.send_json({"type":"auth","token":b_data["session_token"]})
            assert a_ws.receive_json()["type"]=="ready";assert b_ws.receive_json()["type"]=="ready"
            a_ws.send_json({"type":"typing_start","conversation_id":conversation_id})
            typing=b_ws.receive_json();assert typing["type"]=="typing_start";assert typing["conversation_id"]==conversation_id;assert typing["user_id"]==a_data["user_id"]
            read=client.post(f"/api/conversations/{conversation_id}/read",headers={"Authorization":f"Bearer {b_data['session_token']}"})
            assert read.status_code==200,read.text;assert read.json()["last_read_at"]
            receipt=a_ws.receive_json();assert receipt["type"]=="read_receipt";assert receipt["reader_user_id"]==b_data["user_id"]
        listed=client.get("/api/conversations",headers={"Authorization":f"Bearer {a_data['session_token']}"})
        assert listed.status_code==200,listed.text
        summary=next(item for item in listed.json()["conversations"] if item["conversation_id"]==conversation_id)
        assert summary["peer_last_read_at"] is not None
