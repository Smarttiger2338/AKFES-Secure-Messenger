# Client customization boundary

## Supported customization

The supported extension point is declarative UI presentation: color tokens,
spacing, typography, product-neutral display text, accessibility, responsive
layout, and presentational components. `src/customization/theme.ts` is applied
through a strict runtime validator and cannot declare URLs, HTML, JavaScript,
API origins, storage keys, crypto choices, or protocol versions.

## Fixed security core

These modules are not theme APIs:

- `api.ts`: origin policy, credentials, redirect behavior, and wire contracts;
- `crypto.ts`, `web-crypto.ts`, `protocol.ts`: identity, ratchet, AAD, and E2EE;
- Tauri commands and capability ACLs;
- server schemas, authorization policies, route profiles, and migrations;
- release hashing, signatures, deployment secrets, and production manifests.

A pull request touching those paths is reviewed as a security-core change.

## Isolation guarantee

The server never accepts executable client extensions. It accepts only bounded
protocol data validated with strict schemas (`extra='forbid'`) and then repeats
authorization using server-owned state. Messages and files are opaque ciphertext;
their metadata is bound to authenticated users, devices, conversations, quotas,
and the supported protocol version. Realtime frames cannot perform durable DB
writes. Therefore a modified client can break or restyle itself, but it cannot
install code into other clients or mutate the official server implementation.

No architecture can prevent an open-source fork from changing its own source.
The official guarantee comes from server-side distrust, protected deployment
credentials, signed releases, branch review, and separate official branding.
