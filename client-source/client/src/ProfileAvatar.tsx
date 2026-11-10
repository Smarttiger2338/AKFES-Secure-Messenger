import { useEffect, useState } from "react";
import { getProfileAvatar } from "./api";
import type { Profile, Session } from "./types";

type CachedAvatar={data:string|null;accent:string};
const cache=new Map<string,CachedAvatar>();

export function ProfileAvatar({session,userId,label,className="avatar"}:{session:Session;userId:string;label:string;className?:string}){
  const [avatar,setAvatar]=useState<CachedAvatar|undefined>(()=>cache.get(userId));
  useEffect(()=>{let active=true;const load=()=>void getProfileAvatar(session,userId).then(result=>{const next={data:result.avatar_data_url,accent:result.accent_color};cache.set(userId,next);if(active)setAvatar(next)}).catch(()=>{const next={data:null,accent:"#4c6ef5"};cache.set(userId,next);if(active)setAvatar(next)});if(!cache.has(userId))load();const updated=(event:Event)=>{const detail=(event as CustomEvent<Profile>).detail;if(detail?.user_id===userId){const next={data:detail.avatar_data_url,accent:detail.accent_color};cache.set(userId,next);setAvatar(next)}};window.addEventListener("akfes:profile-updated",updated);return()=>{active=false;window.removeEventListener("akfes:profile-updated",updated)}},[session.token,userId]);
  const initial=label[0]?.toUpperCase()||"?";
  return <span className={`${className} profile-avatar`} style={{background:avatar?.accent||undefined}}>{avatar?.data?<img src={avatar.data} alt=""/>:<span>{initial}</span>}</span>
}
