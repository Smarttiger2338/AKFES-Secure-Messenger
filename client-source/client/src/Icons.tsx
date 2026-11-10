import type { ReactNode } from "react";

type IconProps={size?:number;className?:string};
function Icon({size=20,className,children}:{size?:number;className?:string;children:ReactNode}){return <svg aria-hidden="true" className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">{children}</svg>}
export const X=({size,className}:IconProps)=><Icon size={size} className={className}><path d="m6 6 12 12M18 6 6 18"/></Icon>;
export const Check=({size,className}:IconProps)=><Icon size={size} className={className}><path d="m5 12 4 4L19 6"/></Icon>;
export const Camera=({size,className}:IconProps)=><Icon size={size} className={className}><path d="M4 8h3l2-3h6l2 3h3v11H4z"/><circle cx="12" cy="13" r="3.5"/></Icon>;
export const ImageSquare=({size,className}:IconProps)=><Icon size={size} className={className}><rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="2"/><path d="m4 18 5-5 3 3 2-2 6 5"/></Icon>;
export const LockKey=({size,className}:IconProps)=><Icon size={size} className={className}><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/></Icon>;
export const ShieldCheck=({size,className}:IconProps)=><Icon size={size} className={className}><path d="M12 3 20 6v5c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6z"/><path d="m8.5 12 2.2 2.2 4.8-5"/></Icon>;
export const UserCircle=({size,className}:IconProps)=><Icon size={size} className={className}><circle cx="12" cy="12" r="9"/><circle cx="12" cy="9" r="3"/><path d="M6.5 19c.8-3 2.6-4.5 5.5-4.5s4.7 1.5 5.5 4.5"/></Icon>;
export const ChatCircleDots=({size,className}:IconProps)=><Icon size={size} className={className}><path d="M20 11a8 8 0 0 1-9 8l-5 2 1-4a8 8 0 1 1 13-6Z"/><path d="M9 11h.01M12 11h.01M15 11h.01"/></Icon>;
export const UsersThree=({size,className}:IconProps)=><Icon size={size} className={className}><circle cx="12" cy="8" r="3"/><circle cx="5" cy="10" r="2"/><circle cx="19" cy="10" r="2"/><path d="M6 19c.6-3.6 2.6-5.5 6-5.5s5.4 1.9 6 5.5M2 18c.3-2.4 1.4-3.7 3.5-4M22 18c-.3-2.4-1.4-3.7-3.5-4"/></Icon>;
export const Paperclip=({size,className}:IconProps)=><Icon size={size} className={className}><path d="m9 12 6-6a3 3 0 0 1 4 4l-8 8a5 5 0 0 1-7-7l8-8"/></Icon>;
export const PaperPlane=({size,className}:IconProps)=><Icon size={size} className={className}><path d="m21 3-7 18-4-7-7-4zM10 14 21 3"/></Icon>;
export const Sliders=({size,className}:IconProps)=><Icon size={size} className={className}><path d="M4 7h10M18 7h2M4 17h2M10 17h10"/><circle cx="16" cy="7" r="2"/><circle cx="8" cy="17" r="2"/></Icon>;
export const ArrowLeft=({size,className}:IconProps)=><Icon size={size} className={className}><path d="m15 18-6-6 6-6"/></Icon>;
export const MagnifyingGlass=({size,className}:IconProps)=><Icon size={size} className={className}><circle cx="11" cy="11" r="7"/><path d="m16.5 16.5 4 4"/></Icon>;
export const DotsThree=({size,className}:IconProps)=><Icon size={size} className={className}><circle cx="5" cy="12" r="1" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1" fill="currentColor" stroke="none"/><circle cx="19" cy="12" r="1" fill="currentColor" stroke="none"/></Icon>;
export const Phone=({size,className}:IconProps)=><Icon size={size} className={className}><path d="M7 4 4 6c0 7.7 6.3 14 14 14l2-3-4-3-2 2c-2.8-1-5-3.2-6-6l2-2z"/></Icon>;
export const VideoCamera=({size,className}:IconProps)=><Icon size={size} className={className}><rect x="3" y="6" width="13" height="12" rx="2"/><path d="m16 10 5-3v10l-5-3"/></Icon>;
