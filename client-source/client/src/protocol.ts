import vectors from "./protocol-vectors.json";

const encoder=new TextEncoder();
const SAFE_FIELD=/^[A-Za-z0-9_-]+$/;

export interface MessageAadFields{
  conversationId:string;senderDeviceId:string;recipientDeviceId:string;logicalMessageId:string;
  ratchetSessionId:string;messageNumber:number;messageType:string;
}

function field(name:string,value:string,max:number){
  if(!value||value.length>max||!SAFE_FIELD.test(value))throw new Error(`Invalid ${name} for E2EE v4 AAD`);
  return value;
}

export function buildMessageAad(value:MessageAadFields):Uint8Array{
  const conversation=field("conversationId",value.conversationId,64);
  const sender=field("senderDeviceId",value.senderDeviceId,64);
  const recipient=field("recipientDeviceId",value.recipientDeviceId,64);
  const logical=field("logicalMessageId",value.logicalMessageId,64);
  const session=field("ratchetSessionId",value.ratchetSessionId,64);
  const kind=field("messageType",value.messageType,32);
  if(!Number.isSafeInteger(value.messageNumber)||value.messageNumber<0||value.messageNumber>0xffffffff)throw new Error("Invalid messageNumber for E2EE v4 AAD");
  return encoder.encode(`AKFES-E2EE-v4|${conversation}|${sender}|${recipient}|${logical}|${session}|${value.messageNumber}|${kind}`);
}

export function verifyProtocolVectors():true{
  for(const vector of vectors){
    const actual=new TextDecoder().decode(buildMessageAad(vector));
    if(actual!==vector.expectedAad)throw new Error("E2EE v4 protocol vector mismatch");
  }
  return true;
}
