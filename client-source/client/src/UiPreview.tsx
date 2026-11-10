import { useState } from "react";
import { ArrowLeft, ChatCircleDots, Check, DotsThree, ImageSquare, MagnifyingGlass, Paperclip, PaperPlane, Phone, ShieldCheck, Sliders, UserCircle, UsersThree, VideoCamera, X } from "./Icons";

export function UiPreview() {
  const [menuOpen, setMenuOpen] = useState(false);
  const [chatMenuOpen, setChatMenuOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [secret, setSecret] = useState(false);
  const [draft, setDraft] = useState("");
  const [composerOptions,setComposerOptions]=useState(false);
  const [profileOpen,setProfileOpen]=useState(()=>new URLSearchParams(window.location.search).has("profile-preview"));

  return <main className="messenger-shell chat-selected">
    <aside className="sidebar">
      <header className="sidebar-header">
        <div className="sidebar-identity"><span className="avatar">C</span><div><strong>chiwon1<span className="unread-total">2</span></strong><span className="status online">온라인</span></div></div>
        <button className="menu-trigger" onClick={() => setMenuOpen(v => !v)}>메뉴</button>
        {menuOpen && <div className="popover-menu sidebar-menu"><button>프로필</button><button>신뢰 장치</button><button>Arduino 보안</button><button>알림 설정</button><button className="menu-danger">로그아웃</button></div>}
      </header>
      <form className="search-box"><input placeholder="대화 검색 · Enter로 사용자 찾기" /></form>
      <div className="conversation-filter" role="tablist" aria-label="대화 필터"><button className="selected" role="tab" aria-selected="true">전체</button><button role="tab">안 읽음</button><button role="tab">보관함</button></div>
      <div className="conversation-list">
        <button className="selected"><span className="avatar">C</span><span className="conversation-copy"><strong>chiwon2</strong><small>@chiwon2</small><small>장치별 암호화</small></span><span className="conversation-meta"><time>오후 3:39</time><b className="unread-badge">2</b></span></button>
        <button><span className="avatar">T</span><span className="conversation-copy"><strong>test-user</strong><small>@test-user</small><small>장치별 암호화</small></span><span className="conversation-meta"><time>어제</time></span></button>
      </div>
      <nav className="app-navigation" aria-label="주요 메뉴"><button className="active"><ChatCircleDots size={22}/><span>대화</span></button><button><UsersThree size={22}/><span>커뮤니티</span></button><button onClick={()=>setProfileOpen(true)}><UserCircle size={22}/><span>프로필</span></button><button><ShieldCheck size={22}/><span>보안</span></button></nav>
    </aside>
    <section className="chat-panel">
      <header className="chat-header"><button className="mobile-back header-icon" aria-label="대화 목록"><ArrowLeft size={23}/></button><div className="avatar large">C</div><div className="chat-title"><strong>chiwon2</strong><span className="typing-label"><i className="presence-dot online"></i>입력 중…</span></div><div className="chat-actions"><button className="header-icon" aria-label="음성 통화"><Phone size={19}/></button><button className="header-icon" aria-label="영상 통화"><VideoCamera size={20}/></button><button className="header-icon" aria-label="검색" onClick={() => setSearchOpen(v => !v)}><MagnifyingGlass size={20}/></button><button className="header-icon" aria-label="대화 설정" onClick={() => setChatMenuOpen(v => !v)}><DotsThree size={22}/></button>{chatMenuOpen && <div className="popover-menu chat-menu"><button>상단에 고정</button><button>알림 끄기</button><button>대화 보관</button></div>}</div></header>
      <button className="security-summary verified"><ShieldCheck size={17}/><span>안전번호 확인 완료 · 비밀 메시지 사용 가능</span><b>보안 정보</b></button>
      {searchOpen && <div className="message-search"><input autoFocus placeholder="이 대화에서 검색"/><button onClick={() => setSearchOpen(false)}>닫기</button></div>}
      <div className="messages">
        <article className="bubble theirs"><p>와와</p><time>오후 3:38</time></article>
        <article className="bubble mine"><p>훨씬 보기 편해졌네.</p><time>오후 3:38</time></article>
        <article className="bubble theirs"><p>첨부 파일과 비밀 메시지도 같은 위치에서 보낼 수 있어.</p><time>오후 3:39</time></article>
        <article className="bubble mine"><p>모바일에서도 입력창이 가려지지 않게 바뀌었어.</p><footer className="message-meta"><time>오후 3:39</time><span className="read">읽음</span></footer></article>
        <div className="typing-indicator" aria-label="chiwon2님이 입력 중"><i></i><i></i><i></i></div>
      </div>
      <div className="composer-area">
        <div className={`composer-options ${composerOptions?"open":""}`}><button type="button" className="composer-options-trigger" aria-expanded={composerOptions} onClick={()=>setComposerOptions(v=>!v)}><Sliders size={18}/><span>보안 옵션</span>{secret&&<b>비밀</b>}</button>{composerOptions&&<div className="secret-toolbar"><label className="secret-toggle"><input type="checkbox" checked={secret} onChange={e => setSecret(e.target.checked)}/><span>비밀 메시지로 보내기</span></label><button className="secret-unlock">PIN으로 비밀 내용 열기</button></div>}</div>
        <form className="composer" onSubmit={e => { e.preventDefault(); setDraft(""); }}><label className="file-button" aria-label="파일 첨부"><Paperclip size={21}/><span>파일</span><input type="file" hidden/></label><div className="message-field"><textarea rows={1} maxLength={4000} aria-label="메시지" value={draft} onChange={e => setDraft(e.target.value)} onKeyDown={e=>{if(e.key!=="Enter"||e.shiftKey||e.nativeEvent.isComposing)return;e.preventDefault();e.currentTarget.form?.requestSubmit()}} placeholder="메시지를 입력하세요"/></div><button className="primary send-button" aria-label="메시지 전송" disabled={!draft.trim()}><PaperPlane size={20}/><span>{secret ? "비밀 전송" : "전송"}</span></button><small className="composer-help">Enter 전송 · Shift+Enter 줄바꿈</small></form>
      </div>
    </section>
    {profileOpen&&<div className="profile-screen" style={{"--profile-accent":"#7867f5"} as React.CSSProperties}><header className="profile-topbar"><button className="icon-button" onClick={()=>setProfileOpen(false)} aria-label="프로필 닫기"><X size={22}/></button><strong>프로필</strong><button className="profile-save"><Check size={18}/><span>저장</span></button></header><div className="profile-scroll"><section className="profile-hero"><button className="profile-cover"><span><ImageSquare size={19}/>커버 변경</span></button><button className="profile-avatar-editor"><span>C</span></button><div className="profile-heading"><h1>chiwon1</h1><p>@chiwon1</p><span>안전하게 대화 중</span></div></section><div className="profile-layout"><section className="profile-card"><div className="profile-section-title"><UserCircle size={22}/><div><strong>나를 표현하기</strong><span>친구에게 보이는 이름과 소개입니다.</span></div></div><label>공개 닉네임<input defaultValue="chiwon1"/></label><label>한 줄 상태<input defaultValue="안전하게 대화 중"/></label><label>소개<textarea rows={3} defaultValue="필요한 순간에는 가볍게, 중요한 대화는 안전하게."/></label><div className="profile-inline"><label>포인트 색상<input type="color" defaultValue="#7867f5"/></label><label>프로필 공개<select defaultValue="friends"><option value="friends">친구만</option></select></label></div></section><section className="profile-card"><div className="profile-section-title"><ShieldCheck size={22}/><div><strong>계정과 인증</strong><span>연락처는 공개되지 않습니다.</span></div></div><label>로그인 아이디<input value="chiwon1" disabled/></label><div className="contact-row"><label>이메일<input placeholder="me@example.com"/></label><button>인증</button></div><div className="privacy-note"><ShieldCheck size={20}/><span>계정 복구와 인증 정보는 프로필에 표시하지 않습니다.</span></div></section></div></div></div>}
  </main>;
}
