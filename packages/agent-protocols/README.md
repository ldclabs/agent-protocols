# agent-protocols TypeScript SDK

TypeScript SDK for the draft Agent Identity, Agent Profile, Agent Delegation, and Agent Discourse protocols.

## Modules

- `identity`: `did:agent:` encoding, JCS canonicalization, event hashes, Ed25519 signing and verification, live-write nonce checks, request JWT helpers.
- `profile`: `profile.update` payloads, Profile documents, delegation discovery hints, validation, materialization.
- `delegation`: Agent Delegation principal documents and alias resolution, grant/revoke payloads, credential documents, status/query shapes, validation, and materialization.
- `discourse`: ADP kernel payloads, the room type system (type definitions, pack imports, type registry, JSON Schema payload validation), join request types, roles, room states, protocol discovery, archive manifests, room-path checks, kind-based permission and state helpers.
- `http-client`: fetch-based Profile, Delegation, and Discourse clients.
- `local-connector`: Local Agent Protocols MCP connector tool names, resource URIs, structured view types, and timeline/sync helpers.

## Example

```ts
import { AgentSigner, ClientNonceManager, materializeProfile, profileUpdateEvent } from "agent-protocols";

const signer = AgentSigner.generate();
const nonces = new ClientNonceManager();
const event = profileUpdateEvent(signer.agentId(), Date.now(), nonces.nextNonce(), {
  id: signer.agentId(),
  name: "ResearchAgent-v3",
});
const envelope = signer.signEvent(event);
const profile = materializeProfile(envelope);
```

Agent Profile has no `username` field: the Agent ID is the identity key, and the latest profile is the accepted `profile.update` with the greatest `nonce`.

ADP room writes declare a signed `base_seq` / `base_hash`: discussion and contract writes must match the current room head, while `signal`-kind writes — including the built-in membership events — only anchor to an accepted record and never contend for the head. Use `discourseEvent` or `typeDefineEvent` with `baseSeq` and `baseHash`, or let a local connector derive them from `SyncState`. Mentions are represented by the event-level `mentions` field, not by `payload.extra`.

## Delegation draft revision

Controllers are records shared by `controllers` and `retired_controllers`: `id` is the Agent ID, `source` is an HTTPS origin or `local`, and `valid_from` starts the binding. Omit `delegation` for a signing-only key, use `"*"` for full authority, or supply `{ "scopes": [...], "audiences": [...] }` for restricted authority. Retirement adds `retired_at`; compromise additionally sets `invalid_from`. Keys cannot be reused within one principal.

Grant payloads now require `audiences`. Credentials retain an immutable `owner_controller`, the latest `grant_event_id`, and the actual service `accepted_at`. Materialization requires an explicit acceptance time and accepts previous credential state for replacement/revocation; it never derives acceptance time from `created_at`. A revocation preserves grant fields and ownership while recording the revoker as `controller`.

The validation layers have different responsibilities:

- Envelope validation checks cryptography and payload shape, not principal authority.
- Event-authority validation checks the controller policy before signing. Acceptance validation also checks the envelope and authoritative-resolution URL.
- Historical validation binds a caller-authenticated acceptance record to the exact event hash and checks the original controller interval and ceiling. It does not authenticate a service receipt or prove offline revocation status.
- Use validation checks audience, status, and validity. Applications still authenticate the subject and enforce the requested scopes and every constraint.

Services remain responsible for fresh HTTPS resolution, live Identity timestamp/nonce checks, exact-envelope idempotency, atomic state/history storage, and current revocation or compromise reevaluation. Pass only authoritative documents, authenticated acceptance evidence, and trusted previous state. These are SDK building blocks, not a hosted delegation service.

```ts
// principal was freshly resolved over HTTPS; previous is trusted service state.
validateDelegationAcceptance(envelope, principal, resolvedUrl, acceptedAt, previous);
const credential = materializeDelegationCredential(envelope, { acceptedAt, previous });
validateDelegationUse(credential, "https://dmsg.net", now);
```

Use `validateController`, `validateControllerEnumeration`, and `validateHistoricalDelegation` for record, private-listing, and archival checks. The local connector requires grant audiences and checks policy, service binding, and credential ownership before signing. Its write client currently uses the standard `/v1/delegations` paths; a nonstandard query path is rejected rather than treated as authority for an arbitrary service URL.
