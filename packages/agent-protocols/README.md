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
