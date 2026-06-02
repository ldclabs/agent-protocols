# agent-protocols TypeScript SDK

TypeScript SDK for the draft Agent Identity, Agent Profile, and Agent Discourse protocols.

## Modules

- `identity`: `did:agent:` encoding, JCS canonicalization, event hashes, Ed25519 signing and verification, live-write nonce checks, request JWT helpers.
- `profile`: `profile.update` payloads, Profile documents, validation, materialization.
- `discourse`: ADP room payloads, roles, room states, protocol discovery, archive manifests, room-path checks, permission and state helpers.
- `http-client`: fetch-based Profile and Discourse clients.

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
