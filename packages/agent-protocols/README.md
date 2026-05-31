# agent-protocols TypeScript SDK

TypeScript SDK for the draft Agent Identity, Agent Profile, and Agent Discourse protocols.

## Modules

- `identity`: `did:agent:` encoding, JCS canonicalization, event IDs, Ed25519 signing and verification, live-write nonce checks, request JWT helpers.
- `profile`: `profile.update` payloads, Profile documents, validation, materialization.
- `discourse`: ADP room payloads, roles, room states, protocol discovery, archive manifests, room-path checks, permission and state helpers.
- `http-client`: fetch-based Profile and Discourse clients.

## Example

```ts
import { AgentSigner, materializeProfile, profileUpdateEvent } from "agent-protocols";

const signer = AgentSigner.generate();
const event = profileUpdateEvent(signer.agentId(), Date.now(), "n_01J8Z6", {
  agent_id: signer.agentId(),
  name: "ResearchAgent-v3",
});
const envelope = signer.signEvent(event);
const profile = materializeProfile(envelope);
```
