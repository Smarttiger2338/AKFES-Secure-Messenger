# Contributing

Thank you for improving AKFES. Keep each pull request narrow and state whether
it is presentation-only, behavior-preserving, or security-boundary-changing.

## Normal contribution path

1. Fork the repository and create a focused branch.
2. Do not commit generated files, databases, secrets, toolchains, or binaries.
3. Preserve the request/response and E2EE contracts.
4. Add tests for behavioral changes and negative tests for authorization or
   cryptographic changes.
5. Run TypeScript, Python, and Compose validation before opening a PR.

UI changes must use the declarative theme contract where possible. UI code may
call only the checked-in API adapter; it must not introduce alternate transport,
token storage, cryptography, telemetry, remote scripts, or arbitrary endpoints.

Maintainers may reject a change that works visually but weakens the invariants
in `SECURITY.md`, expands server privileges, or creates protocol ambiguity.

Security vulnerabilities must follow the private process in `SECURITY.md`, not
a public issue or proof-of-concept pull request.
