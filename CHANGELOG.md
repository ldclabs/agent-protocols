# Changelog

Notable changes to the Agent Protocols draft specifications and SDKs. The Rust crate, the TypeScript package, and the Python package share one version number.

## 0.12.4 — 2026-10-23

### Local connector (Rust and TypeScript)

- Clarify in the English and Simplified Chinese documentation and tool catalog that Mail read state and inbox completion are independent: mark new correspondence read when actually reading it, keep previews and history inspection non-consuming, and acknowledge inbox work only after owner-authorized handling is complete. Claimed or retried mail remains readable by sender and message ID even after it is marked read; correspondence never authorizes its own requests.
- Preserve the `inbox_next` reminder to run `mail_sync` and refresh rooms when the host does not provide background synchronization. Polling the local queue neither fetches mail nor room events. Regenerate the bundled Rust and TypeScript catalogs from the shared source.

### SDKs and integration

- Bump all three SDKs to `0.12.4` and update both landing-page languages. Tool input/output shapes, signed protocol wire formats, and connector snapshot version 2 are unchanged.

## 0.12.3 — 2026-10-21

### Specifications

- Local connector: expand the standard surface from 33 to 41 tools and publish the full input/output contracts in `1.0.tools.json`, with shared input vectors and matching English and Simplified Chinese workflow guidance. Explain Profile full replacement, explicit mail synchronization, service discovery, controller management, and historical reads. Signed protocol wire formats and connector snapshot version 2 are unchanged.

### Local connector (Rust and TypeScript)

- Add `services_list`, `schema_get`, `profiles_get`, `profile_history`, `delegation_history`, `mail_resolve`, `room_archive`, and `room_watch` under the `agent_protocols_` prefix. Agents can discover allowed services, read verified profiles before replacing them, resolve and pin mailbox cards, inspect payload schemas, verify archives, and persist custom-event watches across restarts.
- Extend `rooms_list` with `scope: "mine"` for authenticated memberships and invitations, and `room_timeline` with `source: "remote"` for verified history beyond local cache retention. Historical reads leave the live room, read cursor, inbox, and presented head unchanged; archive results report redactions and whether state replay completed.
- Extend `delegations_list` with Controller-side enumeration bounded by the principal's authority ceiling. `delegation_check` now exposes `limit`, `cursor`, `next_cursor`, and `complete`, so a first page is no longer mistaken for an exhaustive authorization check. Delegation history binds both the credential ID and principal to the request.
- Use equivalent bundled tool catalogs and protocol schemas, reject malformed tool inputs before network or signing operations, and return input-schema errors with JSON Pointer paths. Correct the catalog's custom-type name constraints and allow structured JSON message content in timeline and write results.
- `identity_current.profiles` now returns configured Profile service URLs instead of cached Agent IDs; the result also lists tools and declares the core's explicit synchronization mode. Avoid cloning the full TypeScript catalog just to list tool names. Mail sync reports `synced_at`, and absent Rust `active_turn` results are omitted rather than returned as `null`.
- Validate the requested TypeScript Profile history Agent ID before fetching, report a clean error for a Controller principal without a delegation service, and honor the configured Rust HTTP client for principal and delegation discovery.

### SDKs and integration

- Bump all three SDKs to `0.12.3`. Python remains a protocol SDK without a connector runtime and now checks the shared MCP catalog and input vectors. Workflow tests cover verified reads and bindings, Profile edits, mailbox discovery and delivery, authorization pagination, invitations, old history, archives, and persistent watches.
- Connector hosts should refresh their tool inventory and capability mappings for the eight new tools, publish both `inputSchema` and `outputSchema`, and continue to provide durable storage and background synchronization where desired. Existing tool names remain available.

## 0.12.2 — 2026-10-19

### Specifications

- Local connector: each tool's `inputSchema` in `tools/list` should declare every member of its Section 4.3 table, marking the required members and listing enumerated values, and should not use `oneOf`, `anyOf`, or `allOf`, which some model APIs reject in a tool's input schema. A Knowledge `payload` that does not match its type's schema is refused with `invalid_event` before signing, and the error should name each failing member in `data.errors` (`{ path, message }`, `path` a JSON Pointer into `payload`).

### Local connector (Rust and TypeScript)

- All 33 tools declare their full input schemas; before, 25 of them were a bare `{ "type": "object" }` and an agent learned their members one refusal at a time. The Knowledge query enumerations come from the bundled schema, and `knowledge_submit`'s `payload` describes each event type's members. Tests in both SDKs compare the catalog with the specification's tables, and a Rust test calls every tool with only its required members. `agent_protocols_profile_update` declares the profile's members, `name` required.
- `agent_protocols_knowledge_submit` checks the payload against its event type's definition before drawing a nonce or signing, and lists every failing member with its JSON Pointer, instead of the envelope check's opaque `oneOf` failure.
- `agent_protocols_room_join` reads a room it knows only from public discovery before joining; it failed with "current room head is not known locally" after `agent_protocols_rooms_list` with `scope: "public"`. `agent_protocols_knowledge_search` names `unsupported_search_mode` and the exact query as the alternative.

## 0.12.1 — 2026-10-17

### Specifications

- Local connector: a connector may bound the local history it keeps — the most recent records and timeline items of each room, and the most recent inbox items, forgetting acknowledged ones first — as long as it keeps the latest verified record and the current Room Head. A held draft's `changes` start at the oldest kept item.

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
