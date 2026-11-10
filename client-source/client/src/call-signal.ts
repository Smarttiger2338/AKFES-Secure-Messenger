export type CallSignalValue = {
  type: string;
  conversation_id: string;
  call_id: string;
  sender_device_id?: string;
  media?: "audio" | "video";
  description?: { type?: string; sdp?: string };
  candidate?: { candidate?: string; sdpMid?: string | null; sdpMLineIndex?: number | null; usernameFragment?: string | null };
  signature?: string;
};

export function callSignalPayload(value: CallSignalValue, senderDeviceId: string): string {
  const description = value.description ? `${value.description.type}|${value.description.sdp || ""}` : "";
  const candidate = value.candidate ? JSON.stringify([
    value.candidate.candidate || "",
    value.candidate.sdpMid ?? null,
    value.candidate.sdpMLineIndex ?? null,
    value.candidate.usernameFragment ?? null,
  ]) : "";
  return `${value.call_id}|${value.conversation_id}|${value.type}|${senderDeviceId}|${description || candidate}|${value.media || ""}`;
}

export async function verifyPeerCallSignal(
  identityPublicKey: string,
  signal: CallSignalValue,
  verify: (identityPublicKey: string, payload: string, signature: string) => Promise<boolean>,
): Promise<void> {
  if (!signal.sender_device_id || !signal.signature) throw new Error("서명되지 않은 통화 신호입니다.");
  const verified = await verify(identityPublicKey, callSignalPayload(signal, signal.sender_device_id), signal.signature);
  if (!verified) throw new Error("통화 신호의 장치 서명이 올바르지 않습니다.");
}
