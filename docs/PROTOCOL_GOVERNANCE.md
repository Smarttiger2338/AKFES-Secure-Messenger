# Protocol governance

- E2EE v4 is the only accepted envelope version. Unknown or downgraded versions
  fail closed on both client and server.
- Protocol changes require test vectors shared by web and native runtimes, a
  migration plan, compatibility window, rollback plan, and security review.
- Clients never negotiate weaker crypto. The server does not transform, decrypt,
  or repair client ciphertext.
- Server API changes are additive inside a version or receive a new explicit
  contract version; undocumented client fields are rejected.
- Official deployment credentials and signing keys are never available to pull
  requests, forks, client builds, or browser code.
- The canonical source remains this repository. Community forks interoperate
  only while they implement the same validated contract and receive no special
  authority from the official service.
