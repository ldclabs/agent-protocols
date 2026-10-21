# agent-protocols TypeScript SDK

TypeScript SDK for the draft Agent Identity, Agent Profile, Agent Delegation, Agent Discourse, Agent Knowledge, and Agent Mail protocols.

## Modules

- `identity`: `did:agent:` encoding, strict JSON parsing (`parseStrictJson`, `parseEnvelopeJson`), JCS canonicalization, event hashes, Ed25519 signing and strict verification (`verifyEd25519Strict`), closed event objects (`validateEventFields`), clock-derived nonces with bounded `Max-Seen-Nonce` resynchronization, live-write and exact-resubmission checks (`verifySubmission`), request JWT helpers, and the shared HTTP shapes (`ErrorResponse`, `ListResponse`, `AcceptedRecord`, `DiscoveryDocument`).
- `profile`: `profile.update` payloads, Profile documents, delegation discovery hints, validation, succession checks, materialization.
- `delegation`: principal documents and resolution, Controller records, grant/revoke payloads, credentials, query shapes, authority, acceptance, historical, and use checks, `verifyDelegationCredential` over the latest grant record, and `auditDelegationHistory` for auditors.
- `discourse`: the ADP kernel — twelve built-in event types, freshness classes, room policy (`invites`, `open_roles`), signed join requests and reviews, the type system with the portable type schema profile, redacted records, server records, and archive verification.
- `knowledge`: signed research contributions, validation, in-memory retrieval and state.
- `mail`: signed mailbox cards, sender-signed HPKE packets, card pins, key retention, inbox deduplication, and relay state.
- `mail-client`: sender-signed Mail delivery and owner-authenticated retrieval with strict HTTP response checks.
- `http-client`: fetch-based Profile, Delegation, Discourse, and Knowledge clients. Lists use `{ result, next_cursor }`; non-2xx responses throw `HttpResponseError` with the protocol `code`, `data`, and `Max-Seen-Nonce`. `ProfileClient.discover(origin)`, `DelegationClient.discover(origin)`, and `DiscourseClient.discover(origin)` use the endpoints in the service's discovery document, falling back to the RECOMMENDED paths.
- `local-connector`: the Local Agent Protocols MCP connector: 41 standard tools, each with the full input schema of its local connector Section 4.3 table (required members and enumerated values, no `oneOf`, `anyOf`, or `allOf`), resource URIs, structured views, and the connector engine. It reads each Discourse host's and Knowledge service's discovery document on first use and keeps the client in its `DiscoveryCache` (after a network error, 429, or 5xx the next call reads it again), reads each profile service's before a profile update, and refuses discovered endpoints whose origin the operator has not allowed. A host that restores a connector for every call shares one cache through the `discoveryCache` option, only among connectors with the same `fetchImpl`. The Mail tools create and rotate mailboxes, send with pinned cards, retry queued packets byte-for-byte, and sync new mail into the inbox, deleting a relay copy only in a later call; the Knowledge tools sign and submit contributions (a payload that does not match its type is refused before signing, with each failing member in `data.errors`), read verified pages, and check lifecycle status. Mail relays and Knowledge services must be allowed hosts; `setMailSenderBlocked` is the operator's sender policy, and `setMailBlockedSenders` replaces the whole list. `connector.snapshot()` returns a versioned JSON document with the next nonce and all the local state that local connector Section 4.1 requires a host to persist, including mail state; each room keeps its latest `ROOM_HISTORY_LIMIT` (1000) records and timeline items and the inbox `INBOX_LIMIT` (1000) entries, forgetting acknowledged ones first, and a restore trims a larger snapshot. Save it after every tool call and restore it with `LocalConnector.fromSnapshot(signer, snapshot)` for the same Agent ID. The Rust connector uses the same layout. Mail decryption keys stay out of the snapshot: keep `mailKeysSnapshot()` in the key store and load it with `restoreMailKeys(keys)`.

## Example

```ts
import { AgentSigner, ClientNonceManager, materializeProfile, profileUpdateEvent } from "agent-protocols";

const signer = AgentSigner.generate();
const nonces = new ClientNonceManager();
const createdAt = Date.now();
const event = profileUpdateEvent(signer.agentId(), createdAt, nonces.nextNonce(createdAt), {
  id: signer.agentId(),
  name: "ResearchAgent-v3",
});
const envelope = signer.signEvent(event);
const profile = materializeProfile(envelope);
```

`nextNonce(createdAt)` derives `max(last + 1, created_at)`, so nonces stay monotonic across restarts and devices. Agent Profile has no `username` field: the Agent ID is the identity key, and the latest profile is the accepted `profile.update` with the greatest `nonce`.

ADP room writes carry a signed `base_seq` / `base_hash`. Message and control writes — `message.create` and custom `message` or `control` kinds — must be based at or after the room head, the latest `genesis`, `contract`, or `control` record, so messages never conflict with each other; contract writes (`room.update`, `room.close`, `room.cancel`, `type.define`) and signal writes, including the membership events, only anchor to an accepted record. Use `eventRequiresRoomHead` and `eventAdvancesRoomHead` to tell them apart, `validateRoomBase` for the host-side base check, `discourseEvent` to build them, and `roomJoinRequestEvent` for a join request, which carries `room_id` but no base. Mentions are represented by the event-level `mentions` field, not by `payload.extra`.

The conformance vectors in `docs/protocols/*/1.0.vectors.json` are part of the test suite.

## Delegation

Controllers are records shared by `controllers` and `retired_controllers`: `id` is the Agent ID, `source` is an HTTPS origin or `local`, and `valid_from` starts the binding. Omit `delegation` for a signing-only key, use `"*"` for full authority, or supply `{ "scopes": [...], "audiences": [...] }` for restricted authority. A restricted key manages (replaces, revokes, enumerates) only credentials whose scopes and audiences fall within its own ceiling. Retirement adds `retired_at`; compromise additionally sets `invalid_from`. A principal that grants delegations publishes its `delegation_service` origin.

Controller registration (Section 4.3) proves key possession with a fixed-shape challenge: `signer.signControllerChallenge(challenge)` signs its exact UTF-8 bytes and refuses any other string, and `verifyControllerChallenge(id, challenge, signature)` applies the strict Ed25519 rules. Issuing challenges, binding them to the owner-approved fields, and expiry stay with the provider.

Grants name the canonical `principal_id`. Credentials carry `principal_id`, an immutable `subject`, the latest `grant_event_id`, the service `accepted_at`, and `checked_at`. Materialization requires an explicit acceptance time and trusted previous state; it never derives acceptance time from `created_at`.

The validation layers have different responsibilities:

- Envelope validation checks cryptography, the closed event object, and payload shape, not principal authority.
- Event-authority validation checks the controller policy before signing. Acceptance validation also checks the envelope and the authoritative-resolution URL.
- Historical validation checks an accepted record `{ envelope, accepted_at }` against the original controller interval and ceiling. It does not authenticate a service receipt or prove offline revocation status.
- Use validation checks audience, status, and validity. Applications still authenticate the subject and enforce the requested scopes and every constraint.

```ts
// principal was freshly resolved over HTTPS; previous is trusted service state.
validateDelegationAcceptance(envelope, principal, resolvedUrl, acceptedAt, previous);
const credential = materializeDelegationCredential(envelope, { acceptedAt, previous });

// A relying party checks the credential's latest grant record.
const verdict = verifyDelegationCredential(credential, records, principal, principal.id, "https://dmsg.net", Date.now());
```

`DelegationClient.principal()` follows at most five HTTPS redirects, gives each request 30 seconds, and rejects a document over 1 MiB with `payload_too_large`. Principal URLs come from signed events that anyone can submit, so a delegation service must also refuse loopback, private, and other non-public destinations (Agent Identity Section 10). The SDK cannot see the address a request connects to, so pass a `fetch` whose egress policy enforces this.

Services remain responsible for fresh HTTPS resolution, live Identity timestamp and nonce checks, exact-resubmission lookups, atomic state and history storage, and current revocation or compromise reevaluation. These are SDK building blocks, not a hosted delegation service.

The local connector derives the delegation service from the principal's `delegation_service` origin and its discovery document, and checks policy and the controller's ceiling before signing a grant or revocation.

## Agent Knowledge

The `agent-protocols/knowledge` entry point implements Agent Knowledge 1.0
objects, dependency validation, deterministic views, evidence verification,
discovery and retrieval contracts, and an in-memory service engine.
`KnowledgeClient` is exported from the main and `http-client` entry points.

```ts
import { AgentSigner, KnowledgeClient, knowledgePublishEvent } from "agent-protocols";

const signer = AgentSigner.generate();
const now = Date.now();
const envelope = signer.signEvent(knowledgePublishEvent(signer.agentId(), now, now, {
  license: "https://creativecommons.org/licenses/by/4.0/",
  kind: "observation",
  title: "Cache keys must include language",
  statement: "This fixture returns the first language when keyed by user alone.",
  language: "en",
  context: { scope: "Two-language greeting fixture", conditions: [], limitations: [] },
  basis: "Two requests with the same user and different languages shared a cache entry.",
}));
const client = await KnowledgeClient.discover("https://knowledge.example.com");
await client.submit(envelope);

// Reads require no signer, JWT, or publication.
let checkpoint = 0;
for await (const page of client.queryPages({ kind: "observation", language: "en" })) {
  console.log(page.service, page.checkpoint, page.result);
  checkpoint = page.checkpoint;
}
// Later: poll for newly accepted records with { after_seq: checkpoint }.
```

`KnowledgeStore({ service, clock?, futureSkewMs?, maxEnvelopeBytes?, admit? })`
provides `submit`, `event`, `batch`, `query`, and `search`. Knowledge events are
portable objects: acceptance rejects only `created_at` beyond the future-skew
allowance (300 s by default), never consults an Identity nonce cache, and resolves
dependencies against every retained envelope, including hidden ones. Exact retries
return the original acceptance record, including when hidden. `hide` / `unhide`
preserve history; `prune` removes the record while retaining the sequence
high-water mark. Input and output objects are copied. Query cursors are stateless:
they encode the checkpoint, snapshot time, last returned `seq`, and a digest of the
effective request, so a mismatched or foreign cursor fails with `invalid_cursor`
and no read state is retained. This synchronous engine is an application building
block; it does not provide durable storage, an HTTP server, or deployment policy.

Ranked `search` returns one page of application-selected candidate IDs with a
ranking configuration and honest coverage metadata; it verifies exact filters and
lexical matches and refuses false exhaustive coverage. Embedding models and ranking
algorithms are application choices. The HTTP client requires discovery to
advertise ranked search; it rejects mode substitution, mismatched scopes,
malformed batches, invalid signatures, and cross-page drift (`KnowledgePageTracker`).
Redirects are disabled and ambient credentials omitted. Submission JWTs are
optional and must be bound to the receiving origin; they identify the caller,
which can differ from the signed publisher.

`materializeKnowledge` requires a validated, dependency-closed known set, and its
active/retracted facts are local to that set. `verifyKnowledgeEvidence(digest,
bytes)` compares complete decoded representation bytes; pass `null` when they
could not be obtained. It never fetches artifacts or executes methods. Signature
validity, artifact identity, profile conformance, retrieval relevance, and
scientific correctness remain separate judgments. The native TypeScript
conformance suite executes every signed fixture and layered protocol case, with
additional HTTP, isolation, pruning, and pagination regressions.

## Agent Mail

Messages have no inner signature. A packet is the sender-signed `mail.submit`
envelope around the HPKE ciphertext. HPKE AAD binds its protocol, type, actor,
creation time, nonce and header. Relays can verify the sender without reading
the subject or body; this format does not hide the communication graph. A
plaintext message alone is not a transferable author-signed artifact.

`message_id` is a random `id16` (16 bytes, base64url) retained across retries;
`from`, original `created_at`, recipient, expiration, thread and parts are also
immutable. The outer hash is the packet ID, not the logical message ID. Retries
reuse the same packet on every route until it expires; only a card change needs
a fresh packet (new HPKE randomness, time and nonce) around the same message. Replies refer to the parent's `message_id` and must
bind both participants and the thread. Content is inert and never executes tools.

Packets are asynchronous signed objects, not live writes: relays and recipients
reject only future-dated packets and apply no nonce maximum, so offline and
out-of-order messages remain usable. Relays deduplicate packet IDs with
tombstones; only card publishes use the live-write nonce store. Inbox
deduplication is scoped to the recipient, sender and message ID; different
content under an accepted identity is rejected, not overwritten. Sender policy
is checked before decryption.

The state helpers are **in memory**, not hosted or durable services. Persist
snapshots atomically before acknowledging storage/deletion or acting. Relay
snapshots include sender policies but not the short-lived nonce cache.
Keyring snapshots contain raw private keys and need protected storage. Pruning
keys cannot erase copies in backups. Production HPKE always uses fresh randomness.

Mailbox addressing uses `did:agent:<key>/mail/<mailbox_id>` and optional
`?route=<origin>` hints. Parse/format helpers reuse Agent Identity's Agent URLs.
Hints do not authorize a route; verified, pinned cards supply current routes,
and `MailCardCache.get` reads a pin. The local connector's Mail tools build on
these helpers.

```ts
import {
  AgentSigner, ClientNonceManager, MailEncryptionKey, MailCardCache,
  MailKeyring, MailInbox, createMailMessage, mailboxPublishEvent,
  mailTextPart, newMailId,
} from "agent-protocols";

const sender = AgentSigner.generate(), owner = AgentSigner.generate();
const key = MailEncryptionKey.generate(), nonces = new ClientNonceManager();
const now = Date.now();
const card = owner.signEvent(mailboxPublishEvent(owner.agentId(), now, now, {
  mailbox_id: newMailId(), expires_at: now + 86400000,
  receive_until: now + 172800000, public_key: key.publicKey(),
  routes: ["https://relay.example"], max_packet_bytes: 65536,
}));
const message = createMailMessage(sender.agentId(), now, {
  to: owner.agentId(), expires_at: now + 86400000, thread_id: newMailId(),
  parts: [mailTextPart("A private question")],
});
const pins = new MailCardCache();
const packet = await pins.seal(message, card, sender, nonces.nextNonce(now), now);
const keys = new MailKeyring(owner.agentId());
keys.add(card, key);
const inbox = new MailInbox(keys);
const { kind, message: received } = await inbox.accept(packet, now);
// Persist pins.snapshot(), keys.exportSnapshot() and inbox.snapshot() before ack.
```

`agent-protocols/mail` exports `MailMessagePayload` for plaintext and
`MailPacket = Envelope<MailPacketPayload>` for the signed wire object.
`sealMailPacket(message, card, signer, nonce, now)` returns a packet;
`openMailPacket` verifies and decrypts it. `validateMailMessage` checks
plaintext, `validateMailPacket` checks the packet, and `mailPacketId` returns its
event hash. `validateMailReply` checks parent bindings. `MailInbox.accept`
returns `{ kind, message }`. `MailInbox.setSenderBlocked(sender, blocked)`
controls local pre-decryption policy. `MailRelayStore.setSenderBlocked(mailboxId,
sender, blocked)` is relay-side policy: Mail defines no management endpoint, so
the host authenticates the mailbox owner first. Exact retries return historical
status without new admission. The injected `nonceStore` applies to card publishes.

`MailClient` is exported from the root and `agent-protocols/mail-client`.
It uses fixed HTTPS paths for `publish`, `card`, `deliver`, `list`, `pages` and
`delete`. Pass a shared `cardCache` and persist it even when a read reports an
unusable newer card. Delivery exposes the signed actor but never sends ambient
credentials. Fetch uses `credentials: "omit"` and `redirect: "error"`; owner
reads/deletes validate their JWT first. Responses have size, strict JSON and
binding checks. Supply `allowUrl` and transport-level DNS/egress policy for the
deployment. Production code runs in Node, browsers and Workers, with no Node-only
crypto or Buffer. JS cannot guarantee erasure of provider-owned or GC copies.

### Complete MCP workflows

The local connector exposes 41 tools with shared input/output contracts from
[`1.0.tools.json`](../../docs/mcp/local-connector/1.0.tools.json). Run
`python3 scripts/sync_connector_catalog.py --check` from the repository root to
check bundled contracts and protocol schemas. The signed wire protocols and SDK
version are unchanged.

Start with `agent_protocols_identity_current` and `agent_protocols_services_list`.
Use `agent_protocols_profiles_get` before editing: `profile_update` replaces the
whole profile, so preserve desired optional fields and remove `updated_at` and
`event_id`. Omit `mailbox_id` in `mail_mailbox_publish` to create a mailbox; use
`mail_resolve` with an expected Agent ID and a profile service, card URL, or
contact address to discover verified candidates. Explicitly choose a reply
mailbox when sending.

`rooms_list` with `scope: "mine"` discovers invitations and memberships on the
host. `schema_get` supplies exact built-in payloads, registered packs, and
installed custom schemas; `room_watch` persists custom event interests.
`room_timeline` with `source: "remote"` reads older verified history independently
of the live read/presented heads. `room_archive` verifies an archive and reports
redactions and incomplete state replay. `profile_history` and
`delegation_history` expose signed histories. `delegations_list` with
`principal_id` enumerates the active Controller's management scope;
`delegation_check` exposes `next_cursor` and `complete`, so callers must finish
pagination before concluding no usable grant exists.

The transport-neutral core reports `sync_mode: "explicit"`: inbox reads do not
poll relays or open SSE connections. Hosts drive SSE/background polling and
persist state and mail keys after calls; otherwise call `mail_sync` and refresh
rooms before reading the inbox. Input-schema validation errors include field paths in `data.errors`.
Transport adapters should publish both `inputSchema` and `outputSchema`, refresh
their tool inventory, and extend their own capability mappings for the new read
and local watch tools. Consumers pinned to an older SDK must update their
integration before the new surface is available.
