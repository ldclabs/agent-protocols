# agent-protocols Python SDK

Python SDK for the draft Agent Identity, Agent Profile, Agent Delegation, and Agent Discourse protocols.

## Modules

- `agent_protocols.identity`: `did:agent:` encoding, JCS canonicalization, event hashes, Ed25519 signing and verification, live-write nonce checks, request JWT helpers.
- `agent_protocols.profile`: `profile.update` payload helpers, delegation discovery hints, validation, materialization.
- `agent_protocols.delegation`: Agent Delegation principal documents and alias resolution, grant/revoke payloads, credential documents, validation, and materialization.
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

## Delegation draft revision

Controllers are records shared by `controllers` and `retired_controllers`: `id` is the Agent ID, `source` is an HTTPS origin or `local`, and `valid_from` starts the binding. Omit `delegation` for a signing-only key, use `"*"` for full authority, or supply `{ "scopes": [...], "audiences": [...] }` for restricted authority. Retirement adds `retired_at`; compromise additionally sets `invalid_from`. Keys cannot be reused within one principal.

Grant payloads now require `audiences`. Credentials retain an immutable `owner_controller`, the latest `grant_event_id`, and the actual service `accepted_at`. Materialization requires an explicit acceptance time and accepts previous credential state for replacement/revocation; it never derives acceptance time from `created_at`. A revocation preserves grant fields and ownership while recording the revoker as `controller`.

The validation layers have different responsibilities:

- Envelope validation checks cryptography and payload shape, not principal authority.
- Event-authority validation checks the controller policy before signing. Acceptance validation also checks the envelope and authoritative-resolution URL.
- Historical validation binds a caller-authenticated acceptance record to the exact event hash and checks the original controller interval and ceiling. It does not authenticate a service receipt or prove offline revocation status.
- Use validation checks audience, status, and validity. Applications still authenticate the subject and enforce the requested scopes and every constraint.

Services remain responsible for fresh HTTPS resolution, live Identity timestamp/nonce checks, exact-envelope idempotency, atomic state/history storage, and current revocation or compromise reevaluation. Pass only authoritative documents, authenticated acceptance evidence, and trusted previous state. These are SDK building blocks, not a hosted delegation service.

```python
# principal was freshly resolved over HTTPS; previous is trusted service state.
validate_delegation_acceptance(envelope, principal, resolved_url, accepted_at, previous)
credential = materialize_delegation_credential(
    envelope, accepted_at=accepted_at, previous=previous,
)
validate_delegation_use(credential, "https://dmsg.net", now)
```

The same module exports `Controller`, `DelegationPolicy`, `DelegationAcceptance`, `validate_controller`, `validate_controller_enumeration`, and `validate_historical_delegation`. Transport implementations injected into the HTTP client must honor `allow_redirects=False`.
