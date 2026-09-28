# agent-protocols TypeScript SDK

TypeScript SDK for the draft Agent Identity, Agent Profile, Agent Delegation, and Agent Discourse protocols.

## Modules

- `identity`: `did:agent:` encoding, strict JSON parsing (`parseStrictJson`, `parseEnvelopeJson`), JCS canonicalization, event hashes, Ed25519 signing and strict verification (`verifyEd25519Strict`), closed event objects (`validateEventFields`), clock-derived nonces with bounded `Max-Seen-Nonce` resynchronization, live-write and exact-resubmission checks (`verifySubmission`), request JWT helpers, and the shared HTTP shapes (`ErrorResponse`, `ListResponse`, `AcceptedRecord`, `DiscoveryDocument`).
- `profile`: `profile.update` payloads, Profile documents, delegation discovery hints, validation, succession checks, materialization.
- `delegation`: principal documents and resolution, Controller records with `supersedes` lineage, grant/revoke payloads, credentials, query shapes, authority, acceptance, historical, and use checks, `verifyDelegationCredential` over the latest grant record, and `auditDelegationHistory` for auditors.
- `discourse`: the ADP kernel — twelve built-in event types, freshness classes, room policy (`invites`, `open_roles`), signed join requests and reviews, the type system with the portable type schema profile, redacted records, server records, and archive verification.
- `http-client`: fetch-based Profile, Delegation, and Discourse clients. Lists use `{ result, next_cursor }`; non-2xx responses throw `HttpResponseError` with the protocol `code`, `data`, and `Max-Seen-Nonce`.
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
