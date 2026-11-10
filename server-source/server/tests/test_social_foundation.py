import pytest
from pydantic import ValidationError

from app.models import schemas
from app.routers.social import _pair_key


def test_friend_pair_key_is_canonical():
    assert _pair_key('user-a', 'user-b') == _pair_key('user-b', 'user-a')
    assert _pair_key('user-a', 'user-b') == 'user-a:user-b'


def test_group_member_ids_are_unique_and_bounded():
    member = '00000000-0000-0000-0000-000000000001'
    request = schemas.CreateGroupRequest(name=' Security team ', member_user_ids=[member])
    assert request.name == 'Security team'
    with pytest.raises(ValidationError):
        schemas.CreateGroupRequest(name='team', member_user_ids=[member, member])
    with pytest.raises(ValidationError):
        schemas.CreateGroupRequest(name='team', member_user_ids=['not-a-user-id'])


@pytest.mark.parametrize('model', [schemas.CommunityCreate, schemas.CommunityChannelCreate])
def test_server_and_channel_names_reject_whitespace(model):
    with pytest.raises(ValidationError):
        model(name='   ')
