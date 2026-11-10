import asyncio
import base64
import os
import uuid

os.environ.setdefault("DEBUG","true")
os.environ.setdefault("DATABASE_URL","sqlite+aiosqlite:///:memory:")
os.environ.setdefault("CONTROL_PLANE_ENABLED","true")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

from app.models import schemas
from app.models.device import Device
from app.models.key import PreKey
from app.models.user import User
from app.routers.keys import upload_prekeys


class _Scalars:
    def __init__(self,items):self.items=items
    def all(self):return self.items


class _Result:
    def __init__(self,items):self.items=items
    def scalars(self):return _Scalars(self.items)


class _Session:
    def __init__(self,signed_id:int,stored:PreKey):self.calls=0;self.added=[];self.signed_id=signed_id;self.stored=stored
    async def execute(self,_statement):
        self.calls+=1
        return _Result([self.signed_id] if self.calls==1 else [self.stored])
    def add(self,item):self.added.append(item)
    async def flush(self):pass


def test_reuploading_current_signed_prekey_does_not_retire_it():
    """One-time-key replenishment must keep the advertised signed key usable."""
    async def scenario():
        user_id=str(uuid.uuid4());device_id=str(uuid.uuid4())
        identity=Ed25519PrivateKey.generate()
        identity_public=base64.b64encode(identity.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
        signed_public_raw=X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        signed_public=base64.b64encode(signed_public_raw).decode();signed_id=101
        signed_signature=base64.b64encode(identity.sign(signed_id.to_bytes(4,"big")+signed_public_raw)).decode()
        user=User(id=user_id,username=f"prekey_{user_id[:8]}",password_hash="unused")
        device=Device(device_id=device_id,user_id=user_id,identity_public_key=identity_public,device_name="PreKey Test",status="approved")
        stored=PreKey(device_id=device_id,prekey_id=signed_id,public_key=signed_public,signature=signed_signature,kind="signed",used=False)
        body=schemas.UploadPreKeysRequest(device_id=device_id,prekeys=[
            schemas.PreKeyItem(key_id=signed_id,public_key=signed_public,signature=signed_signature,kind="signed"),
        ])
        db=_Session(signed_id,stored)
        result=await upload_prekeys(body,current=(user,device),db=db)  # type: ignore[arg-type]
        assert result=={"status":"ok","count":0}
        assert stored.used is False
        assert db.added==[]
    asyncio.run(scenario())
