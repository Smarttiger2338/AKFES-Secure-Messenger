# AKFES E2EE v4 compatibility contract

This document records the behavior that the browser and native clients must share. The executable seed corpus is `client/src/protocol-vectors.json`.

## Authenticated metadata

Message metadata is UTF-8 encoded exactly as:

```text
AKFES-E2EE-v4|conversation_id|sender_device_id|recipient_device_id|logical_message_id|ratchet_session_id|message_number|message_type
```

All string fields are non-empty ASCII alphanumeric, underscore or hyphen. Identifiers/session fields are at most 64 bytes, `message_type` is at most 32 bytes, and `message_number` is an unsigned 32-bit integer. The delimiter is therefore never ambiguous.

The complete byte string is AES-256-GCM additional authenticated data. Changing any field must make decryption fail.

## Compatibility gate

- Web and native clients must pass the same vector corpus.
- Unsupported versions fail closed; they are not interpreted as v4.
- Replay, duplicate ratchet number with different ciphertext, excessive skip distance, changed identity and malformed fields must be rejected.
- A future protocol version receives a new domain prefix and a separate corpus; v4 behavior is never silently changed in place.

This initial corpus covers canonical AAD encoding. Session, ratchet, replay and negative ciphertext vectors remain required before declaring the full cross-runtime conformance gate complete.
