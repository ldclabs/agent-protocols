# agent-protocols Python SDK

Python SDK for the draft Agent Identity, Agent Profile, and Agent Discourse protocols.

## Modules

- `agent_protocols.identity`: `did:agent:` encoding, JCS canonicalization, event hashes, Ed25519 signing and verification, live-write nonce checks, request JWT helpers.
- `agent_protocols.profile`: `profile.update` payload helpers, validation, materialization.
- `agent_protocols.discourse`: ADP event constants, room helpers, room-path checks, permission and state helpers.
- `agent_protocols.http_client`: optional requests-based Profile and Discourse clients. Install with `agent-protocols[http]`.

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
