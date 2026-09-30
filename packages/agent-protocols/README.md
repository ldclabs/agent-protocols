# agent-protocols TypeScript SDK

TypeScript SDK for the draft Agent Identity, Agent Profile, Agent Delegation, Agent Discourse, Agent Knowledge, and Agent Mail protocols.

## Modules

- `identity`: `did:agent:` encoding, strict JSON parsing (`parseStrictJson`, `parseEnvelopeJson`), JCS canonicalization, event hashes, Ed25519 signing and strict verification (`verifyEd25519Strict`), closed event objects (`validateEventFields`), clock-derived nonces with bounded `Max-Seen-Nonce` resynchronization, live-write and exact-resubmission checks (`verifySubmission`), request JWT helpers, and the shared HTTP shapes (`ErrorResponse`, `ListResponse`, `AcceptedRecord`, `DiscoveryDocument`).
- `profile`: `profile.update` payloads, Profile documents, delegation discovery hints, validation, succession checks, materialization.
- `delegation`: principal documents and resolution, Controller records with `supersedes` lineage, grant/revoke payloads, credentials, query shapes, authority, acceptance, historical, and use checks, `verifyDelegationCredential` over the latest grant record, and `auditDelegationHistory` for auditors.
- `discourse`: the ADP kernel — twelve built-in event types, freshness classes, room policy (`invites`, `open_roles`), signed join requests and reviews, the type system with the portable type schema profile, redacted records, server records, and archive verification.
- `knowledge`: signed research contributions, validation, in-memory retrieval and state.
- `mail`: signed mailbox cards and private letters, HPKE packets, card pins, key retention, inbox deduplication, and relay state.
- `mail-client`: anonymous Mail delivery and owner-authenticated retrieval with strict HTTP response checks.
- `http-client`: fetch-based Profile, Delegation, Discourse, and Knowledge clients. Lists use `{ result, next_cursor }`; non-2xx responses throw `HttpResponseError` with the protocol `code`, `data`, and `Max-Seen-Nonce`.
- `local-connector`: the Local Agent Protocols MCP connector: 23 standard tools, resource URIs, structured views, and the connector engine.

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

Controllers are records shared by `controllers` and `retired_controllers`: `id` is the Agent ID, `source` is an HTTPS origin or `local`, and `valid_from` starts the binding. Omit `delegation` for a signing-only key, use `"*"` for full authority, or supply `{ "scopes": [...], "audiences": [...] }` for restricted authority. `supersedes` lets a successor key manage its predecessors' credentials. Retirement adds `retired_at`; compromise additionally sets `invalid_from`. A principal that grants delegations publishes `delegation_query_url`.

Controller registration (Section 4.3) proves key possession with a fixed-shape challenge: `signer.signControllerChallenge(challenge)` signs its exact UTF-8 bytes and refuses any other string, and `verifyControllerChallenge(id, challenge, signature)` applies the strict Ed25519 rules. Issuing challenges, binding them to the owner-approved fields, and expiry stay with the provider.

Grants name the canonical `principal_id`. Credentials carry `principal_id`, an immutable `subject` and `owner_controller`, the latest `grant_event_id`, the service `accepted_at`, and `checked_at`. Materialization requires an explicit acceptance time and trusted previous state; it never derives acceptance time from `created_at`.

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

Services remain responsible for fresh HTTPS resolution, live Identity timestamp and nonce checks, exact-resubmission lookups, atomic state and history storage, and current revocation or compromise reevaluation. These are SDK building blocks, not a hosted delegation service.

The local connector derives the delegation service from the principal's `delegation_query_url` and its discovery document, and checks policy and credential ownership before signing a grant or revocation.

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
for await (const page of client.queryPages({ q: "cache language", kind: "observation" })) {
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

`agent-protocols/mail` implements Agent Mail 1.0 cards, signed letters, packets,
semantic validation, HPKE encryption, and process-local reference state.
`MailClient` is available from the main and `agent-protocols/mail-client` entry
points. The local MCP connector does not yet expose Mail tools.

```ts
import {
  AgentSigner, ClientNonceManager, MailEncryptionKey, MailCardCache,
  MailKeyring, MailInbox, mailboxPublishEvent, mailMessageEvent,
  mailTextPart, newMailId,
} from "agent-protocols";

const alice = AgentSigner.generate();
const bob = AgentSigner.generate();
const bobEncryption = MailEncryptionKey.generate(); // Independent X25519 key.
const aliceNonces = new ClientNonceManager();
const bobNonces = new ClientNonceManager();
const now = Date.now();
const card = bob.signEvent(mailboxPublishEvent(
  bob.agentId(), now, bobNonces.nextNonce(now), {
    mailbox_id: newMailId(),
    expires_at: now + 86400000, receive_until: now + 2 * 86400000,
    public_key: bobEncryption.publicKey(),
    routes: ["https://relay.example"], max_packet_bytes: 65536,
  },
));
const letter = alice.signEvent(mailMessageEvent(
  alice.agentId(), now, aliceNonces.nextNonce(now), {
    to: bob.agentId(), expires_at: now + 86400000, thread_id: newMailId(),
    subject: "A private question", parts: [mailTextPart("Can we compare results?")],
  },
));
const cards = new MailCardCache();
const packet = await cards.seal(letter, card, now);
// Persist cards.snapshot() and the original outgoing letter before delivery.

const keys = new MailKeyring(bob.agentId());
keys.add(card, bobEncryption);
const inbox = new MailInbox(keys);
const result = await inbox.accept(packet, now);
// Store result.letter and persist inbox.snapshot() before deleting the relay copy.
// result.kind is "accepted" or "duplicate"; no reply or action is automatic.
```

For HTTP, `new MailClient(route, options)` talks to one relay origin taken from
a card's `routes`; paths are fixed at `/v1/mailboxes`, and `protocol()` reads the
informational discovery document. Pass a shared `cardCache` in options and
persist `client.cardCache.snapshot()` across requests and restarts. Card reads
pin authentic closed, moved, or expired cards as well as usable ones; use that
same cache for sending. `publish(card)` and `card(mailboxId, expectedOwner)`
verify signed responses. `deliver(packet)` always omits credentials and never
accepts a sender JWT. Owner operations `list(mailboxId, owner, jwt, { limit?,
cursor? })`, `pages(mailboxId, owner, tokenProvider, limit?)`, and
`delete(mailboxId, packetId, owner, jwt)` validate the token's owner and
audience before sending it. All requests disable redirects, cookies, and
referrers. Responses undergo strict JSON, signature, shape, binding, ordering,
and size checks. Supply `allowUrl` and a `fetch` transport that enforces your
DNS/private-network policy; a signed URL alone never authorizes network access.
`clock` supports an explicit trusted clock; `maxResponseBytes` bounds streamed
responses (default 128 MiB).

The main building blocks are:

| API | Purpose |
| --- | --- |
| `validateMailboxCard`, `validateMailSenderCard`, `validateMailLetter`, `validateMailPacket` | Structural, signature, origin, lifetime, media, and encryption-key checks. A sender card must be unexpired and have routes. Historical letters never advance live nonce state. |
| `mailboxPublishEvent`, `mailMessageEvent` | Build Identity events for signing with an `AgentSigner`. |
| `parseMailAddress`, `formatMailAddress` | The stable address `did:agent:<key>/mail/<mailbox_id>` and the contact address with `?route=<origin>` hints (Mail Section 3.3), built on Identity's `parseAgentUrl` / `formatAgentUrl`. Routes in an address are unauthenticated hints; the pinned card's routes win. |
| `MailEncryptionKey.generate/fromBytes/publicKey/exportSecret/destroy` | Independently generate or restore X25519 keys, export explicit sensitive backups, and clear owned secret bytes. |
| `sealMailPacket`, `openMailPacket` | Stateless, fixed-suite HPKE with canonical framing and authenticated recipient/card/header binding. Use a `MailCardCache` for rollback protection and `MailInbox` for acceptance/deduplication. |
| `MailCardCache.observe/seal/prune/snapshot` | Pins the greatest-nonce card per mailbox; an older or conflicting card fails with `stale_card`. A newer closed/expired card still updates the pin although sending fails, so persist the snapshot on these outcomes. `prune` drops pins once every earlier card has expired. |
| `MailKeyring.add/open/prune/exportSnapshot/restore` | Retain old verified cards and secrets through their `receive_until`. Snapshots include secrets and require protected storage. |
| `MailInbox.accept/has/prune/snapshot` | Cross-route, cross-encryption deduplication by letter ID, with concurrent receive protection. The application stores accepted letters. Restore with `new MailInbox(keyring, snapshot)`. |
| `MailRelayStore` | Live card publication, injectable Identity nonce store, route checks, opaque packets, per-mailbox quotas, tombstones, owner JWT authorization, and `seq` cursors. `prune` drops expired packets and tombstones and forgets mailboxes whose current card's `receive_until` passed. |
| `validateMailReply`, `mailTextPart`, `mailPartText` | Bind a reply to its parent's participants, letter ID, and thread; encode/decode inert UTF-8 content without rendering or executing it. |

`MailRelayStore(origin, { clock?, nonceStore?, maxPackets?, maxBytes?, snapshot? })`
provides `publish`, `card`, `deliver`, `list`, `delete`, `prune`, `discovery`, and
`snapshot`. `publishJson` and `deliverJson` enforce a raw UTF-8 body bound before
strict parsing. Default per-mailbox quotas are 10,000 packets and 64 MiB and
fail with `rate_limited`; a real HTTP server must also bound raw request
streams, registration, concurrency, and rate. Delivery results never include the
mailbox `seq`. An injected nonce store can be shared with other protocol services
at the same origin; the short-lived nonce cache is not part of the Mail snapshot.

These stores are in-memory building blocks, not durable services. Persist relay
state before acknowledging a write, and persist recipient acceptance before
transport deletion or executing anything. Snapshots and returned objects are
detached copies; restore assumes an authenticated, current local backup and
checks only its version and shape. No API automatically authorizes actions,
sends replies, fetches attachments, or renders active content.

Encryption uses the maintained [hpke-js](https://github.com/dajiaji/hpke-js)
packages `@hpke/core`, `@hpke/dhkem-x25519`, and `@hpke/chacha20poly1305` with
RFC 9180 Base mode, X25519/HKDF-SHA256/ChaCha20Poly1305. Production sealing always
uses fresh randomness and a new context for one message; deterministic material
is confined to tests. The portable build uses Web Crypto-compatible runtimes
(Node.js, secure browser contexts, and Workers), without Node `Buffer` APIs in
production code. The SDK clears its owned temporary plaintext/raw key buffers;
JavaScript garbage collection and library-owned `CryptoKey` copies prevent a
guarantee that every secret copy is immediately erased. Base HPKE supplies no
ratchet, recipient-compromise forward secrecy, post-quantum security, or network
anonymity.

Mail tests execute all shared structural/rejection/lifecycle cases, exact signing
and encryption fixtures, and an independent RFC 9180 known-answer vector.
Additional tests cover random round trips, concurrent delivery, snapshots,
rollback, route changes and key rotation, JWT boundaries, HTTP redirects,
credentials, malformed responses, authorization, pagination, and quotas.
