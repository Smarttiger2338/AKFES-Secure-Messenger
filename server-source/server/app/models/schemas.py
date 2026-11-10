from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

class StrictRequest(BaseModel):
    model_config=ConfigDict(extra='forbid')

class RegisterRequest(StrictRequest):
    username:str=Field(...,min_length=3,max_length=64,pattern=r'^[A-Za-z0-9_.-]+$')
    password:str=Field(...,min_length=10,max_length=128)
    device_name:str=Field(default='Desktop',min_length=1,max_length=128)
    identity_public_key:str=Field(...,min_length=40,max_length=64)
    device_public_key:str=Field(...,min_length=40,max_length=64)
    device_key_signature:str=Field(...,min_length=80,max_length=128)
    invite_code:Optional[str]=Field(default=None,min_length=16,max_length=256)
    @field_validator('password')
    @classmethod
    def password_bytes(cls,v):
        if len(v.encode('utf-8'))>256: raise ValueError('password is too long')
        return v

class DeviceChallengeRequest(StrictRequest):
    username:str=Field(...,min_length=3,max_length=64,pattern=r'^[A-Za-z0-9_.-]+$')
    device_id:str=Field(...,min_length=36,max_length=36)
class DeviceChallengeResponse(BaseModel): challenge_id:str; nonce:str; expires_at:str
class LoginRequest(StrictRequest):
    username:str=Field(...,min_length=3,max_length=64,pattern=r'^[A-Za-z0-9_.-]+$')
    password:str=Field(...,min_length=10,max_length=128)
    device_id:Optional[str]=Field(default=None,min_length=36,max_length=36)
    device_name:Optional[str]=Field(default=None,max_length=128)
    identity_public_key:Optional[str]=Field(default=None,max_length=64)
    device_public_key:Optional[str]=Field(default=None,max_length=64)
    device_key_signature:Optional[str]=Field(default=None,max_length=128)
    device_challenge_id:Optional[str]=Field(default=None,max_length=36)
    device_proof_b64:Optional[str]=Field(default=None,max_length=128)
    @field_validator('password')
    @classmethod
    def password_bytes(cls,v):
        if len(v.encode('utf-8'))>256: raise ValueError('password is too long')
        return v
class AuthResponse(BaseModel):
    user_id:str; username:str; device_id:str; session_token:str
    is_new_device:bool=False; requires_approval:bool=False; key_changed:bool=False; bootstrap_required:bool=False; registration_resumed:bool=False; arduino_setup_required:bool=False; approval_code:Optional[str]=None

class UserPublic(BaseModel): user_id:str; username:str; nickname:Optional[str]=None
class UserSearchResponse(BaseModel): users:List[UserPublic]
class DeviceInfo(BaseModel):
    device_id:str; device_name:str; identity_public_key:str; device_public_key:Optional[str]=None; device_key_signature:Optional[str]=None; status:str='approved'; key_fingerprint:str
    created_at:Optional[str]=None; approved_at:Optional[str]=None; last_seen:Optional[str]=None; key_changed_at:Optional[str]=None; is_current:bool=False; arduino_configured:bool=False; approval_code:Optional[str]=None
class DeviceListResponse(BaseModel): devices:List[DeviceInfo]
class DeviceActionResponse(BaseModel): status:str; device_id:str; message:str

class CreateDirectRequest(StrictRequest): peer_user_id:str=Field(...,min_length=36,max_length=36)
class CreateGroupRequest(StrictRequest):
    name:str=Field(...,min_length=1,max_length=80)
    member_user_ids:List[str]=Field(...,min_length=1,max_length=19)
    @field_validator('name')
    @classmethod
    def group_name_not_blank(cls,v):
        value=v.strip()
        if not value:raise ValueError('group name cannot be blank')
        return value
    @field_validator('member_user_ids')
    @classmethod
    def unique_member_ids(cls,v):
        if any(len(user_id)!=36 for user_id in v):raise ValueError('member IDs must be UUID strings')
        if len(set(v))!=len(v):raise ValueError('member IDs must be unique')
        return v
class ConversationMemberPublic(BaseModel):
    user_id:str;username:str;nickname:Optional[str]=None;role:str='member'
class LastMessagePreview(BaseModel): message_id:str; sender_device_id:str; message_type:str; created_at:Optional[str]=None
class ConversationSummary(BaseModel):
    conversation_id:str; type:str; peer:Optional[UserPublic]=None; last_message:Optional[LastMessagePreview]=None
    title:Optional[str]=None; server_id:Optional[str]=None; members:List[ConversationMemberPublic]=Field(default_factory=list)
    unread_count:int=0; pinned:bool=False; muted:bool=False; archived:bool=False; peer_last_read_at:Optional[str]=None
    request_status:str='accepted'; incoming_request:bool=False
class ConversationListResponse(BaseModel): conversations:List[ConversationSummary]
class ConversationSettingsRequest(StrictRequest):
    pinned:Optional[bool]=None; muted:Optional[bool]=None; archived:Optional[bool]=None
    @model_validator(mode='after')
    def at_least_one_setting(self):
        if self.pinned is None and self.muted is None and self.archived is None:raise ValueError('at least one setting is required')
        return self
class ConversationSettingsResponse(BaseModel):
    conversation_id:str; pinned:bool; muted:bool; archived:bool; unread_count:int=0; last_read_at:Optional[str]=None

class SendMessageRequest(StrictRequest):
    logical_message_id:str=Field(...,min_length=36,max_length=36)
    recipient_device_id:str=Field(...,min_length=36,max_length=36)
    ciphertext:str=Field(...,min_length=1,max_length=900_000)
    nonce:str=Field(...,min_length=16,max_length=64)
    message_type:str=Field(default='text',pattern=r'^(text|file|secret_text|secret_file)$')
    e2ee_version:int=Field(default=4,ge=4,le=4)
    signed_prekey_id:Optional[int]=Field(default=None,ge=0)
    one_time_prekey_id:Optional[int]=Field(default=None,ge=0)
    message_number:Optional[int]=Field(default=None,ge=0)
    ratchet_session_id:str=Field(...,min_length=16,max_length=64,pattern=r'^[A-Za-z0-9_-]+$')
    ephemeral_public_key:Optional[str]=Field(default=None,min_length=40,max_length=64)
    encrypted_file_id:Optional[str]=Field(default=None,min_length=36,max_length=36)
    @model_validator(mode='after')
    def file_metadata_matches_type(self):
        if self.message_type in {'file','secret_file'} and not self.encrypted_file_id:
            raise ValueError('file messages require encrypted_file_id')
        if self.message_type not in {'file','secret_file'} and self.encrypted_file_id is not None:
            raise ValueError('encrypted_file_id is only valid for file messages')
        return self
class SendMessageBatchRequest(StrictRequest):
    messages:List[SendMessageRequest]=Field(...,min_length=1,max_length=100)
    @model_validator(mode='after')
    def consistent_batch(self):
        logical={m.logical_message_id for m in self.messages}
        recipients={m.recipient_device_id for m in self.messages}
        types={m.message_type for m in self.messages}
        files={m.encrypted_file_id for m in self.messages}
        if len(logical)!=1 or len(types)!=1 or len(files)!=1 or len(recipients)!=len(self.messages):
            raise ValueError('batch must contain one logical message and unique recipient devices')
        return self

class MessageBatchResponse(BaseModel):
    messages:List['MessageResponse']

class MessageResponse(BaseModel):
    message_id:str; logical_message_id:str; conversation_id:str; sender_device_id:str; recipient_device_id:Optional[str]=None
    ciphertext:str; nonce:str; e2ee_version:int=4; signed_prekey_id:Optional[int]=None; one_time_prekey_id:Optional[int]=None
    message_number:Optional[int]=None; ratchet_session_id:Optional[str]=None; ephemeral_public_key:Optional[str]=None; message_type:str; created_at:Optional[str]=None
class MessageListResponse(BaseModel): messages:List[MessageResponse]; has_more:bool=False

class FriendRequestCreate(StrictRequest): user_id:str=Field(...,min_length=36,max_length=36)
class FriendshipInfo(BaseModel):
    friendship_id:str;status:str;incoming:bool;user:UserPublic
class FriendshipListResponse(BaseModel): friends:List[FriendshipInfo]
class CommunityCreate(StrictRequest):
    name:str=Field(...,min_length=1,max_length=80)
    @field_validator('name')
    @classmethod
    def server_name_not_blank(cls,v):
        value=v.strip()
        if not value:raise ValueError('server name cannot be blank')
        return value
class CommunityMemberAdd(StrictRequest): user_id:str=Field(...,min_length=36,max_length=36)
class CommunityRoleUpdate(StrictRequest): role:str=Field(...,pattern=r'^(admin|member)$')
class CommunityChannelCreate(StrictRequest):
    name:str=Field(...,min_length=1,max_length=80)
    @field_validator('name')
    @classmethod
    def channel_name_not_blank(cls,v):
        value=v.strip()
        if not value:raise ValueError('channel name cannot be blank')
        return value
class CommunityInfo(BaseModel):
    server_id:str;name:str;role:str;member_count:int;channels:List[ConversationSummary]=Field(default_factory=list)
    members:List[ConversationMemberPublic]=Field(default_factory=list)
class CommunityListResponse(BaseModel): servers:List[CommunityInfo]

class SignedPreKey(BaseModel): key_id:int; public_key:str; signature:str; created_at:Optional[str]=None
class OneTimePreKey(BaseModel): key_id:int; public_key:str
class DeviceKeyInfo(BaseModel):
    device_id:str; identity_public_key:str; device_public_key:Optional[str]=None; device_key_signature:Optional[str]=None; secret_gate_public_key:Optional[str]=None; secret_gate_key_signature:Optional[str]=None; signed_prekey:Optional[SignedPreKey]=None; one_time_prekey:Optional[OneTimePreKey]=None
class UserKeysResponse(BaseModel): user_id:str; devices:List[DeviceKeyInfo]
class SecretGateKeyRequest(StrictRequest):
    public_key:str=Field(...,min_length=40,max_length=64)
    signature:str=Field(...,min_length=80,max_length=128)
class PreKeyItem(StrictRequest):
    key_id:int=Field(...,ge=0,le=2_147_483_647); public_key:str=Field(...,min_length=40,max_length=64)
    signature:Optional[str]=Field(default=None,min_length=80,max_length=128); kind:str=Field(default='one_time',pattern=r'^(signed|one_time)$')
class UploadPreKeysRequest(StrictRequest):
    device_id:str=Field(...,min_length=36,max_length=36); prekeys:List[PreKeyItem]=Field(...,min_length=1,max_length=100)

class ArduinoChallengeRequest(StrictRequest): action:str=Field(...,min_length=3,max_length=64,pattern=r'^[a-z0-9_.-]+$')
class ArduinoChallengeResponse(BaseModel): challenge_id:str; nonce:str; expires_at:str; action:str; pin_required:bool=False
class ArduinoBootstrapProvisioningRequest(StrictRequest):
    # Optional only for the temporary legacy migration path. New clients enroll
    # the derived key from the physical keypad without sending the PIN.
    pin:Optional[str]=Field(default=None,min_length=6,max_length=12,pattern=r'^[0-9]+$')
class ArduinoBootstrapProvisioningResponse(BaseModel): device_id:str; device_secret_hex:str; setup_id:Optional[str]=None
class ArduinoPinProvisioningRequest(StrictRequest):
    pin:Optional[str]=Field(default=None,min_length=6,max_length=12,pattern=r'^[0-9]+$')
class ArduinoPinProvisioningResponse(BaseModel): device_id:str; device_secret_hex:str; setup_id:str
class ArduinoPinCommitRequest(StrictRequest):
    setup_id:str=Field(...,min_length=36,max_length=36)
    pin_key_hex:Optional[str]=Field(default=None,min_length=64,max_length=64,pattern=r'^[0-9a-fA-F]{64}$')
class ArduinoPinCommitResponse(BaseModel): status:str; device_id:str
class ArduinoVerifyRequest(StrictRequest):
    challenge_id:str=Field(...,min_length=36,max_length=36); action:str=Field(...,min_length=3,max_length=64,pattern=r'^[a-z0-9_.-]+$'); response_hex:str=Field(...,min_length=64,max_length=64,pattern=r'^[0-9a-fA-F]{64}$')
class ArduinoVerifyResponse(BaseModel): verified:bool; challenge_id:str; grant_id:str; action:str; message:str
