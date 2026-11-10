function sleep(ms:number){return new Promise(resolve=>setTimeout(resolve,ms))}
type WebSerialPort={open:(options:{baudRate:number})=>Promise<void>;close:()=>Promise<void>;readable:any;writable:any};
let selectedPort:WebSerialPort|null=null;

function serialApi(){
  const serial=(navigator as Navigator & {serial?:{requestPort:()=>Promise<WebSerialPort>}}).serial;
  if(!serial)throw new Error("이 브라우저는 Web Serial을 지원하지 않습니다. Chrome/Edge 또는 Windows 앱을 사용하세요.");
  return serial;
}

// requestPort must run directly inside a user click. Network calls before it
// consume Chrome/Edge's transient user activation and make the picker fail.
export async function selectWebArduinoPort(){selectedPort=await serialApi().requestPort()}

// Chrome/Edge Web Serial bridge. The browser asks the user to select the USB
// device and never stores a serial-port identifier.
export async function webArduinoChallenge(nonce:string,keypad:boolean){
  serialApi();
  if(!selectedPort)throw new Error("먼저 상단 Arduino 메뉴에서 연결할 장치를 선택하세요.");
  const port=selectedPort;let opened=false;
  try{await port.open({baudRate:115200});opened=true;await sleep(2500);const writer=port.writable.getWriter();try{await writer.write(new TextEncoder().encode(`${keypad?"AUTH":"CHALLENGE"} ${nonce}\n`))}finally{writer.releaseLock()}
    const reader=port.readable.getReader(),decoder=new TextDecoder();let pending="";const deadline=Date.now()+(keypad?65000:7000);
    try{while(Date.now()<deadline){const remaining=Math.max(1,deadline-Date.now());const chunk=await Promise.race([reader.read().then((result:{value?:Uint8Array;done:boolean})=>({result})),new Promise<{timeout:true}>(resolve=>setTimeout(()=>resolve({timeout:true}),remaining))]);if("timeout" in chunk)break;const {value,done}=chunk.result;if(done)break;pending+=decoder.decode(value,{stream:true});let at;while((at=pending.indexOf("\n"))>=0){const line=pending.slice(0,at).trim();pending=pending.slice(at+1);if(line.startsWith("RESPONSE ")){const response=line.slice(9).trim().toLowerCase();if(/^[0-9a-f]{64}$/.test(response))return response;throw new Error("Arduino 응답 형식이 올바르지 않습니다.")}if(line.startsWith("ERROR "))throw new Error(`Arduino: ${line}`)}}}finally{try{await reader.cancel()}catch{/* response may already have closed the stream */}reader.releaseLock()}
    throw new Error("Arduino 승인 시간이 만료되었습니다. 키패드 PIN을 입력하고 확인 키를 누르세요.");
  }finally{if(opened){try{await port.close()}catch{/* the browser may have closed it after a USB reset */}}}
}
