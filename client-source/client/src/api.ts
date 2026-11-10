import type { AdminAudit, AdminStatus, AdminUser, CommunityServer, Conversation, DeviceInfo, DeviceKey, Friendship, Profile, Session, UserPublic, WireMessage } from "./types";

const ENV_API=(import.meta.env.VITE_AKFES_API_BASE as string|undefined)?.trim().replace(/\/+$/, "");
const ENV_AUTH=(import.meta.env.VITE_AKFES_AUTH_BASE as string|undefined)?.trim().replace(/\/+$/, "");
const ENV_WS=(import.meta.env.VITE_AKFES_WS_BASE as string|undefined)?.trim().replace(/\/+$/, "");
const LOCAL_TEST_BUILD=import.meta.env.VITE_AKFES_LOCAL_TEST_BUILD === "true";
const DEFAULT_DEV_API="http://127.0.0.1:8000";
const CUSTOM_SERVER=Boolean(import.meta.env.DEV && import.meta.env.VITE_AKFES_ALLOW_CUSTOM_SERVER === "true");
let devApi=CUSTOM_SERVER ? (ENV_API || DEFAULT_DEV_API) : (ENV_API || (import.meta.env.DEV ? DEFAULT_DEV_API : "https://api.invalid"));

function localRuntimeBase(value:string):string{
  if(!LOCAL_TEST_BUILD||typeof window==="undefined")return value;
  try{
    const page=new URL(window.location.origin),target=new URL(value);
    const isLocal=(host:string)=>host==="127.0.0.1"||host==="localhost";
    if(isLocal(page.hostname)&&isLocal(target.hostname)&&(page.protocol==="http:"||page.protocol==="https:"))return `${page.origin}${target.pathname.replace(/\/+$/,"")}`;
  }catch{}
  return value;
}

function validateApi(value:string):string {
  const parsed=new URL(value);
  const local=parsed.hostname==="127.0.0.1" || parsed.hostname==="localhost";
  if (parsed.protocol!=="https:" && !((import.meta.env.DEV || LOCAL_TEST_BUILD) && local && parsed.protocol==="http:")) throw new Error("운영 API는 HTTPS만 사용할 수 있습니다.");
  if (parsed.username || parsed.password || parsed.hash || parsed.search) throw new Error("API 주소에 자격증명·쿼리·fragment를 넣을 수 없습니다.");
  return `${parsed.protocol}//${parsed.host}${parsed.pathname.replace(/\/+$/, "")}`;
}
export function apiBase():string { return validateApi(localRuntimeBase(devApi)); }
export function apiIsConfigurable():boolean { return CUSTOM_SERVER; }
export function setApiBase(value:string):void { if(!CUSTOM_SERVER) throw new Error("Production API origin is fixed at build time."); devApi=validateApi(value); }
function authBase():string { return validateApi(localRuntimeBase(ENV_AUTH || devApi)); }
function websocketBase():string {
  const configured=ENV_WS || apiBase().replace(/^http:/,"ws:").replace(/^https:/,"wss:");
  const value=localRuntimeBase(configured).replace(/^http:/,"ws:").replace(/^https:/,"wss:");
  const parsed=new URL(value);const local=parsed.hostname==="127.0.0.1"||parsed.hostname==="localhost";
  if(parsed.protocol!=="wss:"&&!((import.meta.env.DEV||LOCAL_TEST_BUILD)&&local&&parsed.protocol==="ws:"))throw new Error("운영 WebSocket은 WSS만 사용할 수 있습니다.");
  if(parsed.username||parsed.password||parsed.hash||parsed.search)throw new Error("WebSocket 주소에 자격증명·쿼리·fragment를 넣을 수 없습니다.");
  return `${parsed.protocol}//${parsed.host}${parsed.pathname.replace(/\/+$/,"")}`;
}
export function productionApiConfigured():boolean { return import.meta.env.DEV || (Boolean(ENV_API) && apiBase()!=="https://api.invalid" && (!LOCAL_TEST_BUILD || Boolean(ENV_AUTH&&ENV_WS))); }

async function requestAt<T>(base:string,path:string,init:RequestInit={},token?:string):Promise<T>{
  const headers=new Headers(init.headers);if(init.body && !headers.has("Content-Type"))headers.set("Content-Type","application/json");if(token)headers.set("Authorization",`Bearer ${token}`);
  const response=await fetch(`${base}${path}`,{...init,headers,cache:"no-store",credentials:"omit",redirect:"error"});
  if(!response.ok){let detail=`${response.status} ${response.statusText}`;try{const body=await response.json();const value=body.detail??body.error?.message;if(typeof value==="string")detail=value;else if(Array.isArray(value))detail=value.slice(0,5).map(item=>{if(!item||typeof item!=="object")return String(item);const record=item as {loc?:unknown[];msg?:unknown;type?:unknown};const where=Array.isArray(record.loc)?record.loc.map(String).join("."):"request";return `${where}: ${String(record.msg??record.type??"invalid value")}`}).join("; ");else if(value&&typeof value==="object")detail=JSON.stringify(value)}catch{}if(detail.length>1000)detail=`${detail.slice(0,1000)}…`;if(response.status===401&&typeof window!=="undefined")window.dispatchEvent(new CustomEvent("akfes:session-expired",{detail:{path}}));throw new Error(detail)}
  if(response.status===204)return undefined as T;return response.json() as Promise<T>;
}
const request=<T>(path:string,init:RequestInit={},token?:string)=>requestAt<T>(apiBase(),path,init,token);
const authRequest=<T>(path:string,init:RequestInit={},token?:string)=>requestAt<T>(authBase(),path,init,token);
export interface AuthPayload { user_id:string;username:string;device_id:string;session_token:string;is_new_device?:boolean;requires_approval?:boolean;key_changed?:boolean;bootstrap_required?:boolean;registration_resumed?:boolean;arduino_setup_required?:boolean;approval_code?:string|null; }
export const register=(body:Record<string,unknown>)=>authRequest<AuthPayload>("/api/auth/register",{method:"POST",body:JSON.stringify(body)});
export const login=(body:Record<string,unknown>)=>authRequest<AuthPayload>("/api/auth/login",{method:"POST",body:JSON.stringify(body)});
export const refreshSession=(s:Session)=>authRequest<AuthPayload>("/api/auth/refresh",{method:"POST"},s.token);
export const createDeviceChallenge=(username:string,deviceId:string)=>authRequest<{challenge_id:string;nonce:string;expires_at:string}>("/api/auth/device-challenge",{method:"POST",body:JSON.stringify({username,device_id:deviceId})});
export async function logout(s:Session){await authRequest<void>("/api/auth/logout",{method:"POST"},s.token)}
export async function searchUsers(q:string,s:Session){return (await request<{users:UserPublic[]}>(`/api/users/search?q=${encodeURIComponent(q)}`,{},s.token)).users}
export async function listConversations(s:Session){return (await request<{conversations:Conversation[]}>("/api/conversations",{},s.token)).conversations}
export const openDirect=(peer:string,s:Session)=>request<Conversation>("/api/conversations/direct",{method:"POST",body:JSON.stringify({peer_user_id:peer})},s.token);
export const acceptConversation=(id:string,s:Session)=>request<Conversation>(`/api/conversations/${encodeURIComponent(id)}/accept`,{method:"POST"},s.token);
export const rejectConversation=(id:string,s:Session)=>request<void>(`/api/conversations/${encodeURIComponent(id)}/reject`,{method:"POST"},s.token);
export const listFriends=async(s:Session)=>(await request<{friends:Friendship[]}>("/api/social/friends",{},s.token)).friends;
export const requestFriend=(userId:string,s:Session)=>request<Friendship>("/api/social/friends/requests",{method:"POST",body:JSON.stringify({user_id:userId})},s.token);
export const acceptFriend=(id:string,s:Session)=>request<Friendship>(`/api/social/friends/${encodeURIComponent(id)}/accept`,{method:"POST"},s.token);
export const removeFriend=(id:string,s:Session)=>request<void>(`/api/social/friends/${encodeURIComponent(id)}`,{method:"DELETE"},s.token);
export const createGroup=(name:string,memberUserIds:string[],s:Session)=>request<Conversation>("/api/social/groups",{method:"POST",body:JSON.stringify({name,member_user_ids:memberUserIds})},s.token);
export const listServers=async(s:Session)=>(await request<{servers:CommunityServer[]}>("/api/social/servers",{},s.token)).servers;
export const createServer=(name:string,s:Session)=>request<CommunityServer>("/api/social/servers",{method:"POST",body:JSON.stringify({name})},s.token);
export const addServerMember=(serverId:string,userId:string,s:Session)=>request<CommunityServer>(`/api/social/servers/${encodeURIComponent(serverId)}/members`,{method:"POST",body:JSON.stringify({user_id:userId})},s.token);
export const updateServerMemberRole=(serverId:string,userId:string,role:"admin"|"member",s:Session)=>request<CommunityServer>(`/api/social/servers/${encodeURIComponent(serverId)}/members/${encodeURIComponent(userId)}/role`,{method:"PATCH",body:JSON.stringify({role})},s.token);
export const removeServerMember=(serverId:string,userId:string,s:Session)=>request<void>(`/api/social/servers/${encodeURIComponent(serverId)}/members/${encodeURIComponent(userId)}`,{method:"DELETE"},s.token);
export const createServerChannel=(serverId:string,name:string,s:Session)=>request<Conversation>(`/api/social/servers/${encodeURIComponent(serverId)}/channels`,{method:"POST",body:JSON.stringify({name})},s.token);
export async function updateConversationSettings(id:string,settings:Partial<Pick<Conversation,"pinned"|"muted"|"archived">>,s:Session){return request<{conversation_id:string;pinned:boolean;muted:boolean;archived:boolean;unread_count:number;last_read_at:string|null}>(`/api/conversations/${encodeURIComponent(id)}/settings`,{method:"PATCH",body:JSON.stringify(settings)},s.token)}
export async function markConversationRead(id:string,s:Session){return request<{conversation_id:string;pinned:boolean;muted:boolean;archived:boolean;unread_count:number;last_read_at:string|null}>(`/api/conversations/${encodeURIComponent(id)}/read`,{method:"POST"},s.token)}
export interface MessagePage { messages:WireMessage[];has_more:boolean; }
export async function getMessages(id:string,s:Session,options:{limit?:number;before?:string|null}={}):Promise<MessagePage>{
  const params=new URLSearchParams({limit:String(Math.min(100,Math.max(1,options.limit??50)))});
  if(options.before)params.set("before",options.before);
  return request<MessagePage>(`/api/conversations/${encodeURIComponent(id)}/messages?${params}`,{},s.token);
}
export type DeviceEnvelope={logical_message_id:string;recipient_device_id:string;ciphertext:string;nonce:string;message_type:"text"|"file"|"secret_text"|"secret_file";e2ee_version:4;signed_prekey_id:number|null;one_time_prekey_id:number|null;message_number:number;ratchet_session_id:string;ephemeral_public_key:string|null;encrypted_file_id:string|null};
export function sendMessage(conversationId:string,body:DeviceEnvelope,s:Session){return request<WireMessage>(`/api/conversations/${conversationId}/messages`,{method:"POST",body:JSON.stringify(body)},s.token)}
export async function sendMessageBatch(conversationId:string,messages:DeviceEnvelope[],s:Session){return (await request<{messages:WireMessage[]}>(`/api/conversations/${conversationId}/messages/batch`,{method:"POST",body:JSON.stringify({messages})},s.token)).messages}
export async function getUserKeys(userId:string,s:Session){return (await request<{devices:DeviceKey[]}>(`/api/keys/${userId}`,{},s.token)).devices}
export async function registerSecretGate(publicKey:string,signature:string,grant:string,s:Session){await request("/api/keys/secret-gate",{method:"POST",headers:{"X-Arduino-Grant":grant},body:JSON.stringify({public_key:publicKey,signature})},s.token)}
export const claimDevicePreKey=(userId:string,deviceId:string,s:Session)=>request<DeviceKey>(`/api/keys/${userId}/${deviceId}/claim`,{method:"POST"},s.token);
export async function uploadPreKeys(s:Session,deviceId:string,prekeys:Array<{key_id:number;public_key:string;signature?:string|null;kind:"signed"|"one_time"}>){await request("/api/keys/prekeys",{method:"POST",body:JSON.stringify({device_id:deviceId,prekeys})},s.token)}
export function websocketUrl(_s:Session){return `${websocketBase()}/ws`}
export async function uploadEncryptedFile(conversationId:string,bytes:Uint8Array,s:Session):Promise<{file_id:string;size_bytes:number;sha256:string}>{const form=new FormData();const uploadBuffer=Uint8Array.from(bytes).buffer;form.append("upload",new Blob([uploadBuffer],{type:"application/octet-stream"}),"encrypted.akfenc");const r=await fetch(`${apiBase()}/api/files?conversation_id=${encodeURIComponent(conversationId)}`,{method:"POST",headers:{Authorization:`Bearer ${s.token}`},body:form,cache:"no-store",credentials:"omit",redirect:"error"});if(!r.ok){let d=`${r.status}`;try{const value=(await r.json()).detail;if(typeof value==="string")d=value;else if(value!=null)d=JSON.stringify(value)}catch{}throw new Error(d)}return r.json()}
export async function discardEncryptedFile(fileId:string,s:Session){await request<void>(`/api/files/${encodeURIComponent(fileId)}/discard`,{method:"POST"},s.token)}
function hex(buf:ArrayBuffer){return Array.from(new Uint8Array(buf)).map(v=>v.toString(16).padStart(2,"0")).join("")}
export async function downloadEncryptedFile(fileId:string,s:Session):Promise<Uint8Array>{const r=await fetch(`${apiBase()}/api/files/${encodeURIComponent(fileId)}`,{headers:{Authorization:`Bearer ${s.token}`},cache:"no-store",credentials:"omit",redirect:"error"});if(!r.ok)throw new Error(`파일 다운로드 실패: ${r.status}`);const bytes=new Uint8Array(await r.arrayBuffer());const expected=(r.headers.get("X-AKFES-SHA256")||"").toLowerCase();if(expected){const actual=hex(await crypto.subtle.digest("SHA-256",bytes));if(actual!==expected)throw new Error("서버 저장 암호문의 SHA-256 무결성 검증에 실패했습니다.")}return bytes}
export async function listDevices(s:Session){return (await request<{devices:DeviceInfo[]}>("/api/devices",{},s.token)).devices}
export async function approveDevice(id:string,s:Session,g:string){await request(`/api/devices/${encodeURIComponent(id)}/approve`,{method:"POST",headers:{"X-Arduino-Grant":g}},s.token)}
export async function revokeDevice(id:string,s:Session,g:string){await request(`/api/devices/${encodeURIComponent(id)}/revoke`,{method:"POST",headers:{"X-Arduino-Grant":g}},s.token)}
export async function revokeAllOtherDevices(s:Session,g:string){await request("/api/devices/revoke-all-except-current",{method:"POST",headers:{"X-Arduino-Grant":g}},s.token)}
export const createArduinoChallenge=(s:Session,action:string)=>authRequest<{challenge_id:string;nonce:string;expires_at:string;action:string;pin_required:boolean}>("/api/arduino/challenge",{method:"POST",body:JSON.stringify({action})},s.token);
export const getArduinoBootstrapProvisioning=(s:Session)=>authRequest<{device_id:string;device_secret_hex:string;setup_id:string|null}>("/api/arduino/bootstrap-provisioning",{method:"POST",body:"{}"},s.token);
export const startArduinoPinProvisioning=(s:Session,g:string)=>authRequest<{device_id:string;device_secret_hex:string;setup_id:string}>("/api/arduino/pin-provisioning/start",{method:"POST",headers:{"X-Arduino-Grant":g},body:"{}"},s.token);
export const commitArduinoPinProvisioning=(s:Session,setupId:string,pinKeyHex:string)=>authRequest<{status:string;device_id:string}>("/api/arduino/pin-provisioning/commit",{method:"POST",body:JSON.stringify({setup_id:setupId,pin_key_hex:pinKeyHex})},s.token);
export const verifyArduinoChallenge=(challengeId:string,responseHex:string,s:Session,action:string)=>authRequest<{verified:boolean;grant_id:string;action:string;message:string}>("/api/arduino/verify",{method:"POST",body:JSON.stringify({challenge_id:challengeId,action,response_hex:responseHex})},s.token);
export const getProfile=(s:Session)=>request<Profile>("/api/profile/me",{},s.token);
export const getProfileAvatar=(s:Session,userId:string)=>request<{avatar_data_url:string|null;accent_color:string}>(`/api/profile/${encodeURIComponent(userId)}/avatar`,{},s.token);
export const updateProfile=(s:Session,profile:Pick<Profile,"nickname"|"bio"|"status_text"|"accent_color"|"profile_visibility"|"discoverable_by_username"|"share_read_receipts"|"share_typing_indicators"|"avatar_data_url"|"cover_data_url">)=>request<Profile>("/api/profile/me",{method:"PATCH",body:JSON.stringify(profile)},s.token);
export const startContactVerification=(s:Session,kind:"email"|"phone",target:string)=>request<{verification_id:string;expires_in:number}>("/api/profile/contact/start",{method:"POST",body:JSON.stringify({kind,target})},s.token);
export const confirmContactVerification=(s:Session,verificationId:string,code:string)=>request<Profile>("/api/profile/contact/confirm",{method:"POST",body:JSON.stringify({verification_id:verificationId,code})},s.token);
export const getAdminStatus=(s:Session)=>request<AdminStatus>("/api/admin/status",{},s.token);
export const setupAdminTotp=(s:Session,password:string)=>request<{setup_id:string;secret:string;otpauth_uri:string}>("/api/admin/totp/setup",{method:"POST",body:JSON.stringify({password})},s.token);
export const confirmAdminTotp=(s:Session,setupId:string,code:string)=>request<{configured:boolean}>("/api/admin/totp/confirm",{method:"POST",body:JSON.stringify({setup_id:setupId,code})},s.token);
export const stepUpAdminTotp=(s:Session,code:string,action:string,targetId:string)=>request<{grant_token:string;expires_in:number}>("/api/admin/step-up/totp",{method:"POST",body:JSON.stringify({code,action,target_id:targetId})},s.token);
export const adminPasskeyRegisterOptions=(s:Session)=>request<Record<string,any>>("/api/admin/passkeys/register/options",{method:"POST"},s.token);
export const adminPasskeyRegister=(s:Session,body:Record<string,unknown>,grant:string)=>request("/api/admin/passkeys/register",{method:"POST",headers:{"X-Admin-Step-Up":grant},body:JSON.stringify(body)},s.token);
export const adminPasskeyAuthOptions=(s:Session)=>request<Record<string,any>>("/api/admin/passkeys/auth/options",{method:"POST"},s.token);
export const stepUpAdminPasskey=(s:Session,body:Record<string,unknown>,action:string,targetId:string)=>request<{grant_token:string;expires_in:number}>("/api/admin/step-up/passkey",{method:"POST",body:JSON.stringify({...body,action,target_id:targetId})},s.token);
export const listAdminUsers=async(s:Session)=>(await request<{users:AdminUser[]}>("/api/admin/users",{},s.token)).users;
export const listAdminAudit=async(s:Session)=>(await request<{events:AdminAudit[]}>("/api/admin/audit",{},s.token)).events;
export const setAdminUserSuspension=(s:Session,userId:string,suspended:boolean,grant:string)=>request(`/api/admin/users/${encodeURIComponent(userId)}/suspension`,{method:"POST",headers:{"X-Admin-Step-Up":grant},body:JSON.stringify({suspended})},s.token);
export const revokeAdminUserDevices=(s:Session,userId:string,grant:string)=>request(`/api/admin/users/${encodeURIComponent(userId)}/revoke-devices`,{method:"POST",headers:{"X-Admin-Step-Up":grant}},s.token);
