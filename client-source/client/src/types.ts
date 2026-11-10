export interface LocalIdentity {
  identityPublicKey: string;
  devicePublicKey: string;
  deviceKeySignature: string;
  serverDeviceId: string | null;
}
export interface Session { userId:string; username:string; deviceId:string; token:string; }
export interface UserPublic { user_id:string; username:string; nickname:string|null; }
export interface ConversationMember extends UserPublic { role:"owner"|"admin"|"member"|string; }
export interface LastMessage { message_id:string; sender_device_id:string; message_type:string; created_at:string|null; }
export interface Conversation {
  conversation_id:string; type:"direct"|"group"|"channel"; peer:UserPublic|null; title:string|null;server_id:string|null;members:ConversationMember[];last_message:LastMessage|null;
  unread_count:number; pinned:boolean; muted:boolean; archived:boolean; peer_last_read_at:string|null;
  request_status:"pending"|"accepted"|"rejected"|"blocked"; incoming_request:boolean;
}
export interface Friendship { friendship_id:string;status:"pending"|"accepted"|"blocked";incoming:boolean;user:UserPublic; }
export interface CommunityServer { server_id:string;name:string;role:"owner"|"admin"|"member";member_count:number;channels:Conversation[];members:ConversationMember[]; }
export interface WireMessage {
  message_id:string; logical_message_id:string; conversation_id:string; sender_device_id:string; recipient_device_id:string|null;
  ciphertext:string; nonce:string; e2ee_version:number; signed_prekey_id:number|null; one_time_prekey_id:number|null;
  message_number:number|null; ratchet_session_id:string|null; ephemeral_public_key:string|null; message_type:"text"|"file"|string; created_at:string|null;
}
export interface ChatMessage extends WireMessage { plaintext:string; decryptError?:boolean; fileEnvelope?:FileMessageEnvelope; }
export interface PreKeyPublic { key_id:number; public_key:string; kind:"one_time"; }
export interface SignedPreKey { key_id:number; public_key:string; signature:string; created_at?:string|null; }
export interface OneTimePreKey { key_id:number; public_key:string; }
export interface DeviceKey {
  device_id:string; identity_public_key:string; device_public_key:string|null; device_key_signature:string|null;
  secret_gate_public_key?:string|null;
  secret_gate_key_signature?:string|null;
  signed_prekey:SignedPreKey|null; one_time_prekey:OneTimePreKey|null;
}
export interface DeviceInfo {
  device_id:string; device_name:string; identity_public_key:string; device_public_key:string|null; device_key_signature:string|null;
  status:"approved"|"pending"|"revoked"|string; key_fingerprint:string; created_at:string|null; approved_at:string|null;
  last_seen:string|null; key_changed_at:string|null; is_current:boolean; arduino_configured:boolean; approval_code:string|null;
}
export interface FileMessageEnvelope { kind:"file"; fileId:string; fileName:string; mimeType:string; size:number; sha256:string; fileKey:string; fileNonce:string; }
export interface PeerIdentityStatus { status:"unverified"|"verified"|"changed"; safetyNumber:string; pinnedIdentityPublicKey:string|null; }
export interface Profile { user_id:string;username:string;nickname:string;email:string|null;email_verified:boolean;phone_e164:string|null;phone_verified:boolean;bio:string;status_text:string;accent_color:string;profile_visibility:"public"|"friends"|"private";discoverable_by_username:boolean;share_read_receipts:boolean;share_typing_indicators:boolean;avatar_data_url:string|null;cover_data_url:string|null; }
export interface AdminStatus { is_admin:boolean;totp_enabled:boolean;passkey_count:number;rp_id:string;origin:string; }
export interface AdminUser { user_id:string;username:string;nickname:string;email_verified:boolean;phone_verified:boolean;active_devices:number;suspended:boolean;created_at:string|null; }
export interface AdminAudit { event_id:string;user_id:string|null;device_id:string|null;action:string;result:string;target_device_id:string|null;details:string|null;created_at:string|null; }
