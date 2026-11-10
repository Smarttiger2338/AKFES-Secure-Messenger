export type RuntimeCapabilities={
  notifications:boolean;
  webRtc:boolean;
  webSerial:boolean;
  localStorage:boolean;
  fileSharing:boolean;
};

export type CompatibilityResult={
  blocking:string[];
  capabilities:RuntimeCapabilities;
};

function isDesktopRuntime(){return "__TAURI_INTERNALS__" in window}

export function runtimeCapabilities():RuntimeCapabilities{
  let storage=false;
  try{const probe="akfes.compatibility.probe";localStorage.setItem(probe,"1");localStorage.removeItem(probe);storage=true}catch{}
  return{
    notifications:"Notification" in window,
    webRtc:"RTCPeerConnection" in window&&Boolean(navigator.mediaDevices?.getUserMedia),
    webSerial:"serial" in navigator,
    localStorage:storage,
    fileSharing:"share" in navigator&&"canShare" in navigator&&typeof File!=="undefined",
  };
}

async function supportsCurve(name:"Ed25519"|"X25519",usages:KeyUsage[]){
  try{await crypto.subtle.generateKey({name},false,usages);return true}catch{return false}
}

function supportsIndexedDb(){
  if(!globalThis.indexedDB)return Promise.resolve(false);
  return new Promise<boolean>(resolve=>{
    const name=`akfes-compatibility-${Date.now()}`;let settled=false;
    const finish=(value:boolean)=>{if(settled)return;settled=true;resolve(value)};
    const timer=setTimeout(()=>finish(false),2500);
    try{
      const request=indexedDB.open(name,1);
      request.onerror=()=>{clearTimeout(timer);finish(false)};
      request.onupgradeneeded=()=>request.result.createObjectStore("probe");
      request.onsuccess=()=>{request.result.close();const removal=indexedDB.deleteDatabase(name);removal.onerror=removal.onblocked=()=>{clearTimeout(timer);finish(true)};removal.onsuccess=()=>{clearTimeout(timer);finish(true)}};
    }catch{clearTimeout(timer);finish(false)}
  });
}

export async function checkCompatibility():Promise<CompatibilityResult>{
  const blocking:string[]=[];
  if(typeof fetch!=="function")blocking.push("네트워크 요청 기능(fetch)");
  if(typeof WebSocket==="undefined")blocking.push("실시간 연결(WebSocket)");
  if(typeof TextEncoder==="undefined"||typeof TextDecoder==="undefined")blocking.push("문자 인코딩");
  if(!globalThis.crypto?.subtle||typeof globalThis.crypto.getRandomValues!=="function")blocking.push("Web Crypto");
  if(!isDesktopRuntime()&&!window.isSecureContext)blocking.push("HTTPS 보안 연결");
  if(!isDesktopRuntime()&&globalThis.crypto?.subtle){
    const [ed25519,x25519]=await Promise.all([
      supportsCurve("Ed25519",["sign","verify"]),
      supportsCurve("X25519",["deriveBits"]),
    ]);
    if(!ed25519)blocking.push("Ed25519 장치 서명");
    if(!x25519)blocking.push("X25519 종단간 암호화");
  }
  if(!isDesktopRuntime()&&!await supportsIndexedDb())blocking.push("IndexedDB 장치 키 저장소");
  return{blocking,capabilities:runtimeCapabilities()};
}
