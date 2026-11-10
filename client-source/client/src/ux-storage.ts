import { apiBase } from "./api";

function key(userId:string,conversationId:string){return `akfes.draft.v1:${apiBase()}:${userId}:${conversationId}`}
function contextKey(userId:string){return `akfes.context.v1:${apiBase()}:${userId}`}

export function loadDraft(userId:string,conversationId:string):string{
  try{return sessionStorage.getItem(key(userId,conversationId))??""}catch{return ""}
}

export function saveDraft(userId:string,conversationId:string,value:string):void{
  try{if(value.trim())sessionStorage.setItem(key(userId,conversationId),value.slice(0,20_000));else sessionStorage.removeItem(key(userId,conversationId))}catch{}
}

export function clearDraft(userId:string,conversationId:string):void{
  try{sessionStorage.removeItem(key(userId,conversationId))}catch{}
}

/** Preserve only the current conversation identifier for task resumption.
 * Message content and secret-chat state are never stored here. */
export function loadLastConversation(userId:string):string|null{
  try{return sessionStorage.getItem(contextKey(userId))}catch{return null}
}

export function saveLastConversation(userId:string,conversationId:string|null):void{
  try{if(conversationId)sessionStorage.setItem(contextKey(userId),conversationId);else sessionStorage.removeItem(contextKey(userId))}catch{}
}
