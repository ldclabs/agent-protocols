# Changelog

Notable changes to the Agent Protocols draft specifications and SDKs. The Rust crate, the TypeScript package, and the Python package share one version number.

## 0.12.1 — 2026-10-17

### Specifications

- Local connector: a connector may bound the local history it keeps — the most recent records and timeline items of each room, and not every acknowledged inbox item — as long as it keeps the latest verified record and the current Room Head. A held draft's `changes` start at the oldest kept item.

### Local connector (Rust and TypeScript)

- Each room keeps its latest `ROOM_HISTORY_LIMIT` (1000) records and timeline items, and the inbox keeps `INBOX_LIMIT` (1000) entries, forgetting acknowledged ones first; restoring a larger snapshot trims it. A replayed record older than the kept history is treated as already applied. Snapshots stay at version 2.
- `DiscoveryCache` holds the Discourse and Knowledge clients built from discovery documents. Connectors share one through `with_discovery_cache(cache)` / the `discoveryCache` option, so a host that restores a connector for every call reads each origin's document once. A Discourse discovery that fails with a network error, `rate_limited`, or a 5xx status is no longer kept: the default paths serve that call and the next call reads the document again. A host that answers without a document still uses the default paths for the cache's lifetime.
- `set_mail_blocked_senders` / `setMailBlockedSenders` replaces the operator's blocked senders as a whole.

## 0.12.0 — 2026-10-12

### Specifications

- Local connector: add Agent Mail and Agent Knowledge tools. Five Mail tools list and publish the agent's mailboxes, send letters with pinned, refreshed cards and byte-identical retries, sync new mail into the inbox as `mail.received` items, and read stored messages. Five Knowledge tools sign and submit events, read verified query, batch, and search pages, and check an event's lifecycle status after a complete reverse-link query. Mail relays and Knowledge services fall under the host allowlist, mail decryption keys stay in the key store, and a relay copy is deleted only after its message is persisted.
- Agent Mail and Agent Knowledge point to the local connector for their MCP tools.

### SDKs

- `MailCardCache.get(owner, mailbox_id)` reads a pin in all three SDKs.

### Local connector (Rust and TypeScript)

- 33 tools. Snapshot version 2 adds a `mail` section: the agent's mailboxes with every retained card, card pins, blocked senders, and stored messages. Mail decryption keys are kept apart, through `mail_keys_snapshot()` / `mailKeysSnapshot()` and `restore_mail_keys` / `restoreMailKeys`; `set_mail_sender_blocked` / `setMailSenderBlocked` is the operator's sender policy. The Rust connector's `with_http_client` now also carries Mail and Knowledge requests; that client, like the default one, must not follow redirects.

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
