import json
import os
import uuid

os.environ.setdefault("DATABASE_URL","sqlite+aiosqlite:///:memory:")

from app.routers.auth import (
    _device_challenge_key,
    _local_device_challenges,
    _store_local_device_challenge,
    _take_local_device_challenge,
)


def test_local_device_challenge_is_one_time_and_account_bound():
    challenge_id=str(uuid.uuid4());key=_device_challenge_key(challenge_id)
    value=json.dumps({"username":"alice-test","device_id":str(uuid.uuid4()),"nonce":"nonce"})
    _local_device_challenges.clear()
    assert _store_local_device_challenge(key,value) is True
    assert _store_local_device_challenge(key,value) is False
    assert _take_local_device_challenge(key)==value
    assert _take_local_device_challenge(key) is None
