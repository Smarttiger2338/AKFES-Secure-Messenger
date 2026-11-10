# AKFES Secure Messenger

AKFES is a device-oriented end-to-end encrypted messenger with web and Windows
clients. This repository is the public source of the original AKFES project;
security protocol, authorization, and deployment boundaries remain owned by the
canonical implementation in this repository.

## What contributors may customize

- visual tokens, layout, accessibility, and localization;
- presentation-only React components;
- tests, documentation, performance, and bug fixes that preserve the protocol;
- security improvements accompanied by negative tests.

Changes to authentication, E2EE, device trust, message envelopes, server roles,
database migrations, Arduino grants, or release signing are **security-boundary
changes**, not ordinary UI customization. They require maintainer review and the
verification rules in [SECURITY.md](SECURITY.md).

Read [the customization boundary](docs/CUSTOMIZATION_BOUNDARY.md),
[protocol governance](docs/PROTOCOL_GOVERNANCE.md), and
[architecture](ARCHITECTURE.md) before contributing. UI work should also follow
the research-backed [interaction design foundations](docs/DESIGN_FOUNDATIONS.md).

## Local development

On Windows PowerShell:

```powershell
.\START_LOCAL_TEST_NO_DOCKER.ps1
```

For client-only development:

```powershell
cd .\client-source\client
npm ci
npm run dev
```

Build output, local databases, bundled Arduino toolchains, secrets, and release
archives are intentionally excluded from Git. The release scripts regenerate
them from reviewed source.

## Security model

The official server treats every client—including modified clients—as hostile.
It validates schemas, authorization, conversation state, device identity,
ratchet metadata, quotas, and rate limits server-side. A custom client can alter
its own interface; it cannot grant itself authority, upload executable UI to the
server, change another client's code, or make the server decrypt messages.

## License and official identity

Source code is available under the [MIT License](LICENSE). “AKFES”, official
logos, official hosted services, and signed official releases are not granted by
that license; see [TRADEMARKS.md](TRADEMARKS.md). Forks must not represent
themselves as an official AKFES release.
