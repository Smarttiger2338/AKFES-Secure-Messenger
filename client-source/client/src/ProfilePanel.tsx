import { useEffect, useRef, useState } from "react";
import { Camera, Check, ImageSquare, LockKey, ShieldCheck, UserCircle, X } from "./Icons";
import { confirmContactVerification, getProfile, startContactVerification, updateProfile } from "./api";
import type { Profile, Session } from "./types";

const DEFAULT_ACCENT="#7867f5";

async function prepareImage(file:File,kind:"avatar"|"cover"):Promise<string>{
  if(!/^image\/(png|jpeg|webp)$/.test(file.type))throw new Error("PNG, JPEG, WebP 이미지만 사용할 수 있습니다.");
  const maxBytes=kind==="avatar"?700_000:1_400_000,maxWidth=kind==="avatar"?640:1600,maxHeight=kind==="avatar"?640:720;
  const source=await createImageBitmap(file),scale=Math.min(1,maxWidth/source.width,maxHeight/source.height);
  const canvas=document.createElement("canvas");canvas.width=Math.max(1,Math.round(source.width*scale));canvas.height=Math.max(1,Math.round(source.height*scale));
  const context=canvas.getContext("2d");if(!context)throw new Error("이미지를 처리할 수 없습니다.");context.drawImage(source,0,0,canvas.width,canvas.height);source.close();
  for(const quality of [0.88,0.78,0.66,0.54]){const result=canvas.toDataURL("image/webp",quality);if(result.length*0.75<=maxBytes)return result}
  throw new Error("이미지가 너무 큽니다. 더 작은 사진을 선택하세요.");
}

export function ProfilePanel({session,onClose}:{session:Session;onClose:()=>void}){
  const [profile,setProfile]=useState<Profile|null>(null);const [nickname,setNickname]=useState("");const [bio,setBio]=useState("");const [status,setStatus]=useState("");const [accent,setAccent]=useState(DEFAULT_ACCENT);const [visibility,setVisibility]=useState<Profile["profile_visibility"]>("friends");const [discoverable,setDiscoverable]=useState(true);const [readReceipts,setReadReceipts]=useState(true);const [typingIndicators,setTypingIndicators]=useState(true);const [avatar,setAvatar]=useState<string|null>(null);const [cover,setCover]=useState<string|null>(null);
  const [email,setEmail]=useState("");const [phone,setPhone]=useState("");const [pending,setPending]=useState<{kind:"email"|"phone";id:string}|null>(null);const [code,setCode]=useState("");const [notice,setNotice]=useState("프로필을 불러오는 중입니다.");const [busy,setBusy]=useState(false);const avatarInput=useRef<HTMLInputElement>(null);const coverInput=useRef<HTMLInputElement>(null);
  useEffect(()=>{void getProfile(session).then(p=>{setProfile(p);setNickname(p.nickname);setBio(p.bio);setStatus(p.status_text);setAccent(p.accent_color||DEFAULT_ACCENT);setVisibility(p.profile_visibility);setDiscoverable(p.discoverable_by_username);setReadReceipts(p.share_read_receipts);setTypingIndicators(p.share_typing_indicators);setAvatar(p.avatar_data_url);setCover(p.cover_data_url);setEmail(p.email??"");setPhone(p.phone_e164??"");setNotice("")}).catch(e=>setNotice(String(e)))},[session]);
  async function chooseImage(file:File|undefined,kind:"avatar"|"cover"){if(!file)return;setBusy(true);try{const data=await prepareImage(file,kind);if(kind==="avatar")setAvatar(data);else setCover(data);setNotice("미리보기에 적용했습니다. 저장을 눌러 모든 장치에 반영하세요.")}catch(e){setNotice(String(e))}finally{setBusy(false)}}
  async function save(){setBusy(true);try{const p=await updateProfile(session,{nickname,bio,status_text:status,accent_color:accent,profile_visibility:visibility,discoverable_by_username:discoverable,share_read_receipts:readReceipts,share_typing_indicators:typingIndicators,avatar_data_url:avatar,cover_data_url:cover});setProfile(p);setNotice("프로필과 개인정보 설정을 저장했습니다.");window.dispatchEvent(new CustomEvent("akfes:profile-updated",{detail:p}))}catch(e){setNotice(String(e))}finally{setBusy(false)}}
  function enablePrivacyMode(){setVisibility("private");setDiscoverable(false);setReadReceipts(false);setTypingIndicators(false);setNotice("상대방 공개 최소화를 선택했습니다. 저장을 눌러 서버에 적용하세요.")}
  async function start(kind:"email"|"phone",target:string){setBusy(true);try{const r=await startContactVerification(session,kind,target);setPending({kind,id:r.verification_id});setCode("");setNotice("인증 코드를 발송했습니다.")}catch(e){setNotice(String(e))}finally{setBusy(false)}}
  async function confirm(){if(!pending)return;setBusy(true);try{const p=await confirmContactVerification(session,pending.id,code);setProfile(p);setPending(null);setCode("");setNotice("연락처 인증을 완료했습니다.")}catch(e){setNotice(String(e))}finally{setBusy(false)}}
  const initial=(nickname||profile?.username||session.username)[0]?.toUpperCase()||"A";
  return <div className="profile-screen" style={{"--profile-accent":accent} as React.CSSProperties}>
    <header className="profile-topbar"><button className="icon-button" onClick={onClose} aria-label="프로필 닫기"><X size={22}/></button><strong>프로필</strong><button className="profile-save" onClick={()=>void save()} disabled={busy||!nickname.trim()}><Check size={18}/><span>{busy?"저장 중":"저장"}</span></button></header>
    <div className="profile-scroll">
      <section className="profile-hero">
        <button className="profile-cover" onClick={()=>coverInput.current?.click()} aria-label="커버 사진 변경" style={cover?{backgroundImage:`linear-gradient(180deg,transparent,#080b14aa),url(${cover})`}:undefined}><span><ImageSquare size={19}/>커버 변경</span></button>
        <input ref={coverInput} hidden type="file" accept="image/png,image/jpeg,image/webp" onChange={e=>void chooseImage(e.target.files?.[0],"cover")}/>
        <button className="profile-avatar-editor" onClick={()=>avatarInput.current?.click()} aria-label="프로필 사진 변경">{avatar?<img src={avatar} alt="내 프로필"/>:<span>{initial}</span>}<i><Camera size={18}/></i></button>
        <input ref={avatarInput} hidden type="file" accept="image/png,image/jpeg,image/webp" onChange={e=>void chooseImage(e.target.files?.[0],"avatar")}/>
        <div className="profile-heading"><h1>{nickname||session.username}</h1><p>@{profile?.username??session.username}</p>{status&&<span>{status}</span>}</div>
      </section>
      <div className="profile-layout">
        <section className="profile-card profile-editor-card"><div className="profile-section-title"><UserCircle size={22}/><div><strong>나를 표현하기</strong><span>친구에게 보이는 이름과 소개입니다.</span></div></div>
          <label>공개 닉네임<input value={nickname} onChange={e=>setNickname(e.target.value)} maxLength={64}/></label>
          <label>한 줄 상태<input value={status} onChange={e=>setStatus(e.target.value)} maxLength={48} placeholder="오늘의 상태를 알려주세요"/><small>{status.length}/48</small></label>
          <label>소개<textarea value={bio} onChange={e=>setBio(e.target.value)} maxLength={160} rows={3} placeholder="좋아하는 것과 나를 소개해 보세요."/><small>{bio.length}/160</small></label>
          <div className="profile-inline"><label>포인트 색상<input type="color" value={accent} onChange={e=>setAccent(e.target.value)}/></label><label>프로필 공개<select value={visibility} onChange={e=>setVisibility(e.target.value as Profile["profile_visibility"])}><option value="public">모든 사용자</option><option value="friends">친구만</option><option value="private">나만</option></select></label></div>
          <div className="privacy-controls"><div className="profile-section-title"><LockKey size={20}/><div><strong>상대방에게 보이는 활동</strong><span>끄면 서버도 해당 실시간 신호를 상대에게 전달하지 않습니다.</span></div></div>
            <button type="button" onClick={enablePrivacyMode}>상대방 공개 최소화</button>
            <label><input type="checkbox" checked={discoverable} onChange={e=>setDiscoverable(e.target.checked)}/><span><b>아이디 검색 허용</b><small>끄면 새 사용자가 정확한 아이디를 입력해도 나를 찾을 수 없습니다.</small></span></label>
            <label><input type="checkbox" checked={readReceipts} onChange={e=>setReadReceipts(e.target.checked)}/><span><b>읽음 시각 공유</b><small>끄면 내 읽지 않은 메시지 계산만 갱신하고 상대에게 읽은 시각을 보내지 않습니다.</small></span></label>
            <label><input type="checkbox" checked={typingIndicators} onChange={e=>setTypingIndicators(e.target.checked)}/><span><b>입력 중 상태 공유</b><small>끄면 입력 중 이벤트 자체를 보내지 않습니다.</small></span></label>
            <p className="privacy-limit">이 설정은 다른 사용자에게 보이는 정보를 줄입니다. 서비스 서버에는 로그인 IP, 접속 시각과 대화 관계 메타데이터가 남을 수 있습니다.</p>
          </div>
        </section>
        <section className="profile-card"><div className="profile-section-title"><ShieldCheck size={22}/><div><strong>계정과 인증</strong><span>로그인 아이디는 변경할 수 없습니다.</span></div></div>
          <label>로그인 아이디<input value={profile?.username??session.username} disabled/></label>
          <div className="contact-row"><label>이메일<input type="email" value={email} onChange={e=>setEmail(e.target.value)}/></label><button onClick={()=>void start("email",email)} disabled={busy||!email}>{profile?.email_verified?<><Check size={17}/>인증됨</>:"인증"}</button></div>
          <div className="contact-row"><label>휴대전화<input value={phone} placeholder="+821012345678" onChange={e=>setPhone(e.target.value)}/></label><button onClick={()=>void start("phone",phone)} disabled={busy||!phone}>{profile?.phone_verified?<><Check size={17}/>인증됨</>:"인증"}</button></div>
          <div className="privacy-note"><LockKey size={20}/><span>연락처는 공개 프로필에 표시하지 않으며 계정 복구와 인증에만 사용합니다.</span></div>
          {pending&&<div className="pin-panel"><strong>{pending.kind==="email"?"이메일":"휴대전화"} 인증</strong><input inputMode="numeric" value={code} maxLength={6} onChange={e=>setCode(e.target.value.replace(/\D/g,""))} placeholder="6자리 인증 코드"/><button className="primary" onClick={()=>void confirm()} disabled={busy||code.length!==6}>인증 확인</button></div>}
        </section>
      </div>
      {notice&&<p className="profile-notice" role="status">{notice}</p>}
    </div>
  </div>
}
