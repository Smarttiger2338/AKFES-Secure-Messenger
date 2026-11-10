import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign, verify } from "node:crypto";
import { callSignalPayload, verifyPeerCallSignal } from "../src/call-signal.ts";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const identity = publicKey.export({ type: "spki", format: "der" }).toString("base64");
const base = {
  type: "call_answer",
  conversation_id: "11111111-1111-1111-1111-111111111111",
  call_id: "22222222-2222-2222-2222-222222222222",
  sender_device_id: "33333333-3333-3333-3333-333333333333",
  media: "audio",
  description: { type: "answer", sdp: "v=0\r\na=fingerprint:sha-256 trusted" },
};
const domainPayload = value => Buffer.from(`AKFES-CALL-SIGNAL-v1|${callSignalPayload(value, value.sender_device_id)}`);
const verifier = async (_identity, payload, signature) => verify(null, Buffer.from(`AKFES-CALL-SIGNAL-v1|${payload}`), publicKey, Buffer.from(signature, "base64"));

test("valid peer call signal is accepted", async () => {
  const signal = { ...base, signature: sign(null, domainPayload(base), privateKey).toString("base64") };
  await assert.doesNotReject(() => verifyPeerCallSignal(identity, signal, verifier));
});

test("tampered SDP is rejected before it can reach WebRTC", async () => {
  const signal = { ...base, signature: sign(null, domainPayload(base), privateKey).toString("base64") };
  const tampered = { ...signal, description: { ...signal.description, sdp: "v=0\r\na=fingerprint:sha-256 attacker" } };
  await assert.rejects(() => verifyPeerCallSignal(identity, tampered, verifier), /올바르지 않습니다/);
});

test("tampered media kind is rejected before camera acquisition", async () => {
  const signal = { ...base, signature: sign(null, domainPayload(base), privateKey).toString("base64") };
  await assert.rejects(() => verifyPeerCallSignal(identity, { ...signal, media: "video" }, verifier), /올바르지 않습니다/);
});

test("unsigned ICE is rejected", async () => {
  const ice = { ...base, type: "call_ice", description: undefined, candidate: { candidate: "candidate:1", sdpMid: "0", sdpMLineIndex: 0 } };
  await assert.rejects(() => verifyPeerCallSignal(identity, ice, verifier), /서명되지 않은/);
});
