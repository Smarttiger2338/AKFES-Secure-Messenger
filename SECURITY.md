# AKFES security policy

## Supported releases

Only the current signed production release and the immediately previous signed release are supported. Protocol or database versions outside that window must fail closed rather than attempt an undocumented downgrade.

## Reporting

Do not include passwords, access tokens, private keys, Arduino PIN material, invite codes, message plaintext, or production database contents in a report. Record the affected component, release/source identity, reproduction prerequisites, impact, and the smallest safe reproduction. Establish a private reporting address before public distribution of this project.

## Security invariants

- The server is an untrusted relay for message confidentiality and never receives message plaintext or client private message keys.
- Every E2EE envelope is bound to conversation, sender device, recipient device, logical message, ratchet session, message number, and message type.
- A conversation must be accepted before keys, messages, files, typing, or read receipts are authorized.
- Friend requests grant no key or conversation access until accepted. Group and server membership never bypasses conversation membership checks.
- Group and server-channel messages are fanned out as a separate E2EE envelope for every approved recipient device; the server never receives a shared plaintext group key.
- Server management operations require an explicit `owner` or `admin` membership role, and only accepted friends can be added to groups or servers.
- Calls are limited to accepted direct conversations. Signaling frames are device-identity signed and media uses WebRTC DTLS-SRTP; call media is never persisted by AKFES.
- Revoked devices and sessions cannot regain authority through refresh, WebSocket reconnect, cached grants, or another API role.
- Administrator and Arduino grants are one-time, short-lived, actor/device/action bound, and fail closed when their security dependency is unavailable.
- Identity-key changes block sending until the user explicitly re-establishes trust.
- Release artifacts are hash verified. Production distribution must additionally require the intended Windows publisher signature and a release manifest from a protected release process.
- Logs, audit events, crash output, metrics, and test fixtures contain no credentials, private keys, PIN material, plaintext messages, or decrypted files.

## Verification requirements

Security-sensitive changes require relevant negative tests in addition to successful-path tests. E2EE changes must pass the shared protocol corpus in both web and native runtimes. Authorization changes must test every affected state and actor. Release changes must demonstrate tamper rejection and rollback. Backup changes must demonstrate an isolated restore.

## Generated and third-party content

Build output, caches, generated Tauri schemas, vendored toolchains, dependency trees, encrypted test files, and visual snapshots are not primary policy owners. Review their generation and integrity inputs instead of editing them as source. Never place production secrets in a client package, source archive, test fixture, report, or generated artifact.

## Capture-protection limitation

Windows capture exclusion and browser privacy controls are defense in depth. They cannot prevent an external camera, hardware capture, kernel/administrator compromise, or every remote-desktop implementation. Product text must not describe them as absolute DRM or guaranteed screenshot prevention.
