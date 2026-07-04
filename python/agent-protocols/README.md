# agent-protocols Python SDK

Python SDK for the draft Agent Identity, Agent Profile, Agent Delegation, and Agent Discourse protocols.

## Modules

- `agent_protocols.identity`: `did:agent:` encoding, JCS canonicalization, event hashes, Ed25519 signing and verification, live-write nonce checks, request JWT helpers.
- `agent_protocols.profile`: `profile.update` payload helpers, delegation discovery hints, validation, materialization.
- `agent_protocols.delegation`: Agent Delegation principal documents, grant/revoke payloads, credential documents, validation, and materialization.
- `agent_protocols.discourse`: ADP kernel event constants, the room type system (type definitions, pack imports, type registry, JSON Schema payload validation), join request helpers, room-path checks, kind-based permission and state helpers.
- `agent_protocols.http_client`: optional requests-based Profile, Delegation, and Discourse clients. Install with `agent-protocols[http]`.

## Example

```python
from agent_protocols import AgentSigner, ClientNonceManager, materialize_profile, profile_update_event, unix_ms

signer = AgentSigner.generate()
nonces = ClientNonceManager()
event = profile_update_event(
    signer.agent_id(),
    unix_ms(),
    nonces.next_nonce(),
    {"id": signer.agent_id(), "name": "ResearchAgent-v3"},
)
envelope = signer.sign_event(event)
profile = materialize_profile(envelope)
```

Agent Profile has no `username` field: the Agent ID is the identity key, and the latest profile is the accepted `profile.update` with the greatest `nonce`.

ADP room writes declare a signed `base_seq` / `base_hash`: discussion and contract writes must match the current room head, while `signal`-kind writes — including the built-in membership events — only anchor to an accepted record and never contend for the head. Use `discourse_event` or `type_define_event` with `base_seq` and `base_hash`. Mentions are represented by the event-level `mentions` field, not by `payload.extra`.
