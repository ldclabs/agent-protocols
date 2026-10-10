# Changelog

Notable changes to the Agent Protocols draft specifications and SDKs. The Rust crate, the TypeScript package, and the Python package share one version number.

## 0.11.4 — 2026-10-10

### Specifications

- Agent Identity: state the request-JWT replay model, make `200` the default success status, centralize the outbound-fetch rules (HTTPS at every hop, public destinations only, bounded size and time), and note that key rotation and succession are out of scope.
- Agent Delegation: list every allowed change to a published Controller, explain what a guessable credential ID reveals, send profile-hint lookups as public existence queries with `principal_id`, and apply the outbound-fetch rules to principal resolution.
- Agent Discourse: forbid request JWTs in URLs and close SSE streams by the JWT's `exp`, apply the outbound-fetch rules to external packs, align the `room.create` response and the room resource table with Section 8, and fix the mentions limit.
- Agent Profile: name `profiles` as the base URL of reads, history, and submission, and cap the events `limit`.

### SDKs

- `DelegationClient` principal resolution gives each request 30 seconds and rejects a document over 1 MiB with `payload_too_large`, reading the body as a stream. In Python the 30 seconds bound the whole download, not only each socket read.
- `ProfileClient` and `DiscourseClient` accept discovered endpoints and gain `discover(origin)`, which reads the service's discovery document and falls back to the RECOMMENDED paths. `profiles` is the base of profile reads, history, and submission, and `profile_batch` defaults to `{profiles}/batch`; `rooms` is the base of room creation, public discovery, every room URL, and the SSE stream, and `my_rooms` serves `GET /v1/me/rooms`.

### Local connector (Rust and TypeScript)

- Reads each Discourse host's discovery document once per session, and each profile service's before a profile update. The host must be allowed before discovery, and every call refuses a discovered `rooms` or `profiles` endpoint whose origin the operator has not allowed.
- `snapshot()` and `fromSnapshot(signer, snapshot)` / `from_snapshot(signer, &snapshot)` persist and restore the next nonce and all local state in one versioned JSON layout shared by both SDKs. Restoring checks the version and the Agent ID.
