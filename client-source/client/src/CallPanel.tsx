import { useEffect, useRef, useState } from "react";
import { getUserKeys } from "./api";
import { peerIdentityStatus, signCallSignal, verifyCallSignal } from "./crypto";
import { callSignalPayload, verifyPeerCallSignal } from "./call-signal";
import { secureRandomId } from "./secure-id";
import type { Conversation, Session } from "./types";

type MediaKind = "audio" | "video";
type Signal = {
  type: string;
  conversation_id: string;
  call_id: string;
  caller_user_id: string;
  sender_device_id: string;
  description?: RTCSessionDescriptionInit;
  candidate?: RTCIceCandidateInit;
  media?: MediaKind;
  signature?: string;
};
type ActiveCall = {
  callId: string;
  conversation: Conversation;
  media: MediaKind;
  direction: "incoming" | "outgoing";
  status: "ringing" | "connecting" | "connected";
  remoteDeviceId: string | null;
  offer?: RTCSessionDescriptionInit;
};
type QueuedIce = { candidate: RTCIceCandidateInit; senderDeviceId: string };

const RING_TIMEOUT_MS = 45_000;
const CONNECT_TIMEOUT_MS = 20_000;
const rtcConfig: RTCConfiguration = {
  iceServers: [{ urls: "stun:stun.cloudflare.com:3478" }],
  iceCandidatePoolSize: 4,
};

export function CallPanel({ session, conversations, socket, notify }: {
  session: Session;
  conversations: Conversation[];
  socket: () => WebSocket | null;
  notify: (value: string) => void;
}) {
  const [call, setCall] = useState<ActiveCall | null>(null);
  const [muted, setMuted] = useState(false);
  const [cameraOff, setCameraOff] = useState(false);
  const peer = useRef<RTCPeerConnection | null>(null);
  const local = useRef<MediaStream | null>(null);
  const remote = useRef<MediaStream | null>(null);
  const queuedIce = useRef<QueuedIce[]>([]);
  const localVideo = useRef<HTMLVideoElement | null>(null);
  const remoteVideo = useRef<HTMLVideoElement | null>(null);
  const callRef = useRef<ActiveCall | null>(null);
  const timeoutRef = useRef<number | undefined>();
  const signalQueue = useRef<Promise<void>>(Promise.resolve());
  const mountedRef = useRef(true);
  const expectedRemoteDevices = useRef<Set<string>>(new Set());
  const rejectedRemoteDevices = useRef<Set<string>>(new Set());

  useEffect(() => { callRef.current = call; }, [call]);
  useEffect(() => {
    if (localVideo.current) localVideo.current.srcObject = local.current;
    if (remoteVideo.current) remoteVideo.current.srcObject = remote.current;
  }, [call?.status, cameraOff]);

  const send = async (value: Record<string, unknown>) => {
    const ws = socket();
    if (ws?.readyState !== WebSocket.OPEN) throw new Error("실시간 서버 연결이 필요합니다.");
    const signature = await signCallSignal(session.username, callSignalPayload(value as any, session.deviceId));
    ws.send(JSON.stringify({ ...value, signature }));
  };

  const clearCallTimeout = () => {
    if (timeoutRef.current) window.clearTimeout(timeoutRef.current);
    timeoutRef.current = undefined;
  };
  const armCallTimeout = (delay: number, message: string) => {
    clearCallTimeout();
    timeoutRef.current = window.setTimeout(() => {
      notify(message);
      end(true);
    }, delay);
  };
  const closeMedia = () => {
    clearCallTimeout();
    peer.current?.close();
    peer.current = null;
    for (const track of local.current?.getTracks() || []) track.stop();
    for (const track of remote.current?.getTracks() || []) track.stop();
    local.current = null;
    remote.current = null;
    queuedIce.current = [];
    expectedRemoteDevices.current.clear();
    rejectedRemoteDevices.current.clear();
    setMuted(false);
    setCameraOff(false);
  };
  const end = (signal = true) => {
    const active = callRef.current;
    if (signal && active) void send({
      type: "call_end",
      conversation_id: active.conversation.conversation_id,
      call_id: active.callId,
      target_device_id: active.remoteDeviceId || undefined,
    }).catch(() => {});
    closeMedia();
    callRef.current = null;
    setCall(null);
  };
  useEffect(() => { mountedRef.current = true; return () => { mountedRef.current = false; end(false); }; }, []);

  async function assertTrusted(conversation: Conversation, deviceId?: string, signal?: Signal) {
    const peerUser = conversation.peer;
    if (!peerUser) throw new Error("1:1 대화에서만 통화할 수 있습니다.");
    const keys = await getUserKeys(peerUser.user_id, session);
    const relevant = deviceId ? keys.filter(key => key.device_id === deviceId) : keys;
    if (!relevant.length) throw new Error("상대 승인 장치를 확인할 수 없습니다.");
    for (const key of relevant) {
      const trust = await peerIdentityStatus(session.username, peerUser.user_id, key);
      if (trust.status !== "verified") throw new Error("안전번호가 확인된 상대 장치만 통화할 수 있습니다.");
      if (signal) {
        await verifyPeerCallSignal(key.identity_public_key, signal, verifyCallSignal);
      }
    }
    return relevant.map(key => key.device_id);
  }

  async function verifyOwnCallClaim(signal: Signal) {
    if (!signal.description || signal.description.type !== "answer") throw new Error("통화 수락 증명이 없습니다.");
    const ownKeys = await getUserKeys(session.userId, session);
    const key = ownKeys.find(value => value.device_id === signal.sender_device_id);
    if (!key) throw new Error("승인되지 않은 내 장치의 통화 수락입니다.");
    await verifyPeerCallSignal(key.identity_public_key, { ...signal, type: "call_answer" }, verifyCallSignal);
  }

  async function media(kind: MediaKind) {
    if (!navigator.mediaDevices?.getUserMedia) throw new Error("이 환경은 마이크/카메라 통화를 지원하지 않습니다.");
    return navigator.mediaDevices.getUserMedia({
      audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
      video: kind === "video" ? { width: { ideal: 1280 }, height: { ideal: 720 }, facingMode: "user" } : false,
    });
  }

  function createPeer(active: ActiveCall) {
    const pc = new RTCPeerConnection(rtcConfig);
    peer.current = pc;
    remote.current = new MediaStream();
    pc.ontrack = event => {
      for (const track of event.streams[0]?.getTracks() || [event.track]) {
        if (!remote.current!.getTracks().some(value => value.id === track.id)) remote.current!.addTrack(track);
      }
      if (remoteVideo.current) remoteVideo.current.srcObject = remote.current;
    };
    pc.onicecandidate = event => {
      if (event.candidate) void send({
        type: "call_ice",
        conversation_id: active.conversation.conversation_id,
        call_id: active.callId,
        candidate: event.candidate.toJSON(),
        target_device_id: callRef.current?.remoteDeviceId || undefined,
      }).catch(error => notify(`통화 네트워크 정보 전송 실패: ${String(error)}`));
    };
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === "connected") {
        clearCallTimeout();
        setCall(current => current ? { ...current, status: "connected" } : current);
      }
      if (["failed", "closed", "disconnected"].includes(pc.connectionState)) end(false);
    };
    return pc;
  }

  async function start(conversation: Conversation, kind: MediaKind) {
    if (callRef.current) throw new Error("이미 통화 중입니다.");
    if (conversation.type !== "direct" || conversation.request_status !== "accepted") throw new Error("수락된 1:1 대화에서만 통화할 수 있습니다.");
    const trustedDeviceIds = await assertTrusted(conversation);
    expectedRemoteDevices.current = new Set(trustedDeviceIds);
    rejectedRemoteDevices.current.clear();
    const active: ActiveCall = {
      callId: secureRandomId(), conversation, media: kind, direction: "outgoing", status: "ringing", remoteDeviceId: null,
    };
    setCall(active);
    callRef.current = active;
    armCallTimeout(RING_TIMEOUT_MS, "상대방이 통화에 응답하지 않았습니다.");
    try {
      local.current = await media(kind);
      const pc = createPeer(active);
      for (const track of local.current.getTracks()) pc.addTrack(track, local.current);
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await send({ type: "call_offer", conversation_id: conversation.conversation_id, call_id: active.callId, description: pc.localDescription, media: kind });
    } catch (error) {
      end(false);
      throw error;
    }
  }

  async function accept() {
    const active = callRef.current;
    if (!active?.offer) return;
    const connecting = { ...active, status: "connecting" as const };
    setCall(connecting);
    callRef.current = connecting;
    armCallTimeout(CONNECT_TIMEOUT_MS, "통화 연결 시간이 초과되었습니다.");
    try {
      local.current = await media(active.media);
      const pc = createPeer(connecting);
      for (const track of local.current.getTracks()) pc.addTrack(track, local.current);
      await pc.setRemoteDescription(active.offer);
      for (const item of queuedIce.current.splice(0)) {
        if (item.senderDeviceId === active.remoteDeviceId) await pc.addIceCandidate(item.candidate);
      }
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      await send({
        type: "call_answer", conversation_id: active.conversation.conversation_id, call_id: active.callId,
        description: pc.localDescription, media: active.media, target_device_id: active.remoteDeviceId,
      });
    } catch (error) {
      notify(`통화 연결 실패: ${String(error)}`);
      end(true);
    }
  }

  async function handleSignal(signal: Signal) {
    if (!signal?.type?.startsWith("call_")) return;
    const active = callRef.current;
    if (signal.type === "call_offer") {
      const conversation = conversations.find(value => value.conversation_id === signal.conversation_id);
      if (!conversation || conversation.type !== "direct" || conversation.request_status !== "accepted" || active || !signal.description) {
        if (conversation && signal.sender_device_id) void send({
          type: "call_reject", conversation_id: signal.conversation_id, call_id: signal.call_id, target_device_id: signal.sender_device_id,
        }).catch(() => {});
        return;
      }
      try {
        await assertTrusted(conversation, signal.sender_device_id, signal);
        if (callRef.current) return;
        const next: ActiveCall = {
          callId: signal.call_id, conversation, media: signal.media === "video" ? "video" : "audio",
          direction: "incoming", status: "ringing", remoteDeviceId: signal.sender_device_id, offer: signal.description,
        };
        setCall(next);
        callRef.current = next;
        armCallTimeout(RING_TIMEOUT_MS, "받지 않은 통화가 종료되었습니다.");
      } catch {
        void send({
          type: "call_reject", conversation_id: signal.conversation_id, call_id: signal.call_id, target_device_id: signal.sender_device_id,
        }).catch(() => {});
      }
      return;
    }
    if (!active || active.callId !== signal.call_id || active.conversation.conversation_id !== signal.conversation_id) return;

    // call_claimed is a server-generated same-account coordination event. All peer-originated
    // state and WebRTC data below must carry a valid signature from the exact peer device.
    if (signal.type === "call_claimed") {
      try {
        await verifyOwnCallClaim(signal);
        const current = callRef.current;
        if (!mountedRef.current || !current || current.callId !== signal.call_id || current.conversation.conversation_id !== signal.conversation_id) return;
        if (current.direction === "incoming" && signal.sender_device_id !== session.deviceId) {
          notify("다른 장치에서 통화를 받았습니다.");
          end(false);
        }
      } catch (error) { notify(`검증되지 않은 통화 수락 알림을 차단했습니다: ${String(error)}`); }
      return;
    }

    try {
      await assertTrusted(active.conversation, signal.sender_device_id, signal);
    } catch (error) {
      notify(`검증되지 않은 통화 신호를 차단했습니다: ${String(error)}`);
      return;
    }
    const current = callRef.current;
    if (!mountedRef.current || !current || current.callId !== signal.call_id || current.conversation.conversation_id !== signal.conversation_id) return;

    if (signal.type === "call_answer" && signal.description && current.direction === "outgoing") {
      if (current.remoteDeviceId && current.remoteDeviceId !== signal.sender_device_id) return;
      const next = { ...current, status: "connecting" as const, remoteDeviceId: signal.sender_device_id };
      setCall(next);
      callRef.current = next;
      armCallTimeout(CONNECT_TIMEOUT_MS, "통화 연결 시간이 초과되었습니다.");
      try {
        await peer.current?.setRemoteDescription(signal.description);
        for (const item of queuedIce.current.splice(0)) {
          if (item.senderDeviceId === signal.sender_device_id) await peer.current?.addIceCandidate(item.candidate);
        }
      } catch (error) {
        notify(`통화 응답 적용 실패: ${String(error)}`);
        end(true);
      }
    } else if (signal.type === "call_ice" && signal.candidate) {
      if (current.remoteDeviceId && current.remoteDeviceId !== signal.sender_device_id) return;
      if (peer.current?.remoteDescription) await peer.current.addIceCandidate(signal.candidate).catch(() => {});
      else queuedIce.current.push({ candidate: signal.candidate, senderDeviceId: signal.sender_device_id });
    } else if (signal.type === "call_end") {
      if (!current.remoteDeviceId || current.remoteDeviceId === signal.sender_device_id) {
        notify("통화가 종료되었습니다.");
        end(false);
      }
    } else if (signal.type === "call_reject") {
      // Before an answer there may be several peer devices ringing. A rejection from one
      // device must not cancel a call that another device can still accept.
      rejectedRemoteDevices.current.add(signal.sender_device_id);
      const allKnownDevicesRejected=expectedRemoteDevices.current.size>0&&[...expectedRemoteDevices.current].every(deviceId=>rejectedRemoteDevices.current.has(deviceId));
      if (current.remoteDeviceId === signal.sender_device_id || allKnownDevicesRejected) {
        notify("상대방이 통화를 거절했습니다.");
        end(false);
      }
    }
  }

  useEffect(() => {
    const startHandler = (event: Event) => {
      const detail = (event as CustomEvent<{ conversation: Conversation; media: MediaKind }>).detail;
      void start(detail.conversation, detail.media).catch(error => notify(`통화 시작 실패: ${String(error)}`));
    };
    const signalHandler = (event: Event) => {
      const signal = (event as CustomEvent<Signal>).detail;
      // Signature checks and WebRTC mutations must preserve WebSocket arrival order.
      signalQueue.current = signalQueue.current.then(() => handleSignal(signal)).catch(error => {
        notify(`통화 신호 처리 실패: ${String(error)}`);
      });
    };
    window.addEventListener("akfes:start-call", startHandler);
    window.addEventListener("akfes:call-signal", signalHandler);
    return () => {
      window.removeEventListener("akfes:start-call", startHandler);
      window.removeEventListener("akfes:call-signal", signalHandler);
    };
  }, [conversations, session.token]);

  if (!call) return null;
  const label = call.conversation.peer?.nickname || call.conversation.peer?.username || "상대방";
  return <div className="call-overlay"><section className="call-card">
    <strong>{label}</strong>
    <span>{call.direction === "incoming" ? `${call.media === "video" ? "영상" : "음성"} 통화가 왔습니다` : call.status === "ringing" ? "연결 요청 중…" : call.status === "connected" ? "통화 연결됨" : "연결 중…"}</span>
    <div className="call-videos"><video ref={remoteVideo} autoPlay playsInline/><video ref={localVideo} autoPlay playsInline muted className={call.media === "video" ? "" : "audio-only"}/></div>
    <div className="call-actions">{call.direction === "incoming" && call.status === "ringing" ? <>
      <button className="primary" onClick={() => void accept()}>받기</button><button className="danger-button" onClick={() => end(true)}>거절</button>
    </> : <>
      <button onClick={() => { const next = !muted; setMuted(next); for (const track of local.current?.getAudioTracks() || []) track.enabled = !next; }}>{muted ? "음소거 해제" : "음소거"}</button>
      {call.media === "video" && <button onClick={() => { const next = !cameraOff; setCameraOff(next); for (const track of local.current?.getVideoTracks() || []) track.enabled = !next; }}>{cameraOff ? "카메라 켜기" : "카메라 끄기"}</button>}
      <button className="danger-button" onClick={() => end(true)}>통화 종료</button>
    </>}</div>
  </section></div>;
}
