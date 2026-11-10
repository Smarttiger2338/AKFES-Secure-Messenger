import { apiBase } from "./api";

function key(userId:string,conversationId:string){return `akfes.draft.v1:${apiBase()}:${userId}:${conversationId}`}

export function loadDraft(userId:string,conversationId:string):string{
  try{return sessionStorage.getItem(key(userId,conversationId))??""}catch{return ""}
}

export function saveDraft(userId:string,conversationId:string,value:string):void{
  try{if(value.trim())sessionStorage.setItem(key(userId,conversationId),value.slice(0,20_000));else sessionStorage.removeItem(key(userId,conversationId))}catch{}
}

export function clearDraft(userId:string,conversationId:string):void{
  try{sessionStorage.removeItem(key(userId,conversationId))}catch{}
}
