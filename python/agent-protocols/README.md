# agent-protocols Python SDK

Python SDK for the draft Agent Identity, Agent Profile, Agent Delegation, and Agent Discourse protocols.

## Modules

- `agent_protocols.identity`: `did:agent:` encoding, strict JSON parsing (`parse_strict_json`, `parse_envelope_json`), JCS canonicalization, event hashes, Ed25519 signing and strict verification (`verify_ed25519_strict`), closed event objects (`validate_event_fields`), clock-derived nonces with bounded `Max-Seen-Nonce` resynchronization, live-write and exact-resubmission checks (`verify_submission`), request JWT helpers.
- `agent_protocols.profile`: `profile.update` payload helpers, delegation discovery hints, validation, succession checks, materialization.
- `agent_protocols.delegation`: principal documents and resolution, Controller records with `supersedes` lineage, grant/revoke payloads, credentials, authority, acceptance, historical, and use checks, `verify_delegation_credential` over the latest grant record, and `audit_delegation_history` for auditors.
- `agent_protocols.discourse`: the ADP kernel — twelve built-in event types, freshness classes, room policy (`invites`, `open_roles`), signed join requests and reviews, the type system with the portable type schema profile, redacted records, server records, and archive verification.
- `agent_protocols.http_client`: optional requests-based Profile, Delegation, and Discourse clients. Install with `agent-protocols[http]`. Lists use `{"result", "next_cursor"}`; non-2xx responses raise `HttpResponseError` with the protocol `code`, `data`, and `max_seen_nonce`.

## Example

```python
from agent_protocols import AgentSigner, ClientNonceManager, materialize_profile, profile_update_event, unix_ms

signer = AgentSigner.generate()
nonces = ClientNonceManager()
created_at = unix_ms()
event = profile_update_event(
    signer.agent_id(),
    created_at,
    nonces.next_nonce(created_at),
    {"id": signer.agent_id(), "name": "ResearchAgent-v3"},
)
envelope = signer.sign_event(event)
profile = materialize_profile(envelope)
```

`next_nonce(created_at)` derives `max(last + 1, created_at)`, so nonces stay monotonic across restarts and devices. Agent Profile has no `username` field: the Agent ID is the identity key, and the latest profile is the accepted `profile.update` with the greatest `nonce`.

ADP room writes carry a signed `base_seq` / `base_hash`. Message and control writes — `message.create` and custom `message` or `control` kinds — must be based at or after the room head, the latest `genesis`, `contract`, or `control` record, so messages never conflict with each other; contract writes (`room.update`, `room.close`, `room.cancel`, `type.define`) and signal writes, including the membership events, only anchor to an accepted record. Use `event_requires_room_head` and `event_advances_room_head` to tell them apart, `validate_room_base` for the host-side base check, `discourse_event` to build them, and `room_join_request_event` for a join request, which carries `room_id` but no base. Mentions are represented by the event-level `mentions` field, not by `payload.extra`.

## Delegation

Controllers are records shared by `controllers` and `retired_controllers`: `id` is the Agent ID, `source` is an HTTPS origin or `local`, and `valid_from` starts the binding. Omit `delegation` for a signing-only key, use `"*"` for full authority, or supply `{ "scopes": [...], "audiences": [...] }` for restricted authority. `supersedes` lets a successor key manage its predecessors' credentials. Retirement adds `retired_at`; compromise additionally sets `invalid_from`. A principal that grants delegations publishes `delegation_query_url`.

Grants name the canonical `principal_id`. Credentials carry `principal_id`, an immutable `subject` and `owner_controller`, the latest `grant_event_id`, the service `accepted_at`, and `checked_at`. Materialization requires an explicit acceptance time and trusted previous state; it never derives acceptance time from `created_at`.

The validation layers have different responsibilities:

- Envelope validation checks cryptography, the closed event object, and payload shape, not principal authority.
- Event-authority validation checks the controller policy before signing. Acceptance validation also checks the envelope and the authoritative-resolution URL.
- Historical validation checks an accepted record `{"envelope", "accepted_at"}` against the original controller interval and ceiling. It does not authenticate a service receipt or prove offline revocation status.
- Use validation checks audience, status, and validity. Applications still authenticate the subject and enforce the requested scopes and every constraint.

```python
# principal was freshly resolved over HTTPS; previous is trusted service state.
validate_delegation_acceptance(envelope, principal, resolved_url, accepted_at, previous)
credential = materialize_delegation_credential(
    envelope, accepted_at=accepted_at, previous=previous,
)

# A relying party checks the credential's latest grant record.
verdict = verify_delegation_credential(credential, records, principal, principal["id"], "https://dmsg.net", now)
```

Services remain responsible for fresh HTTPS resolution, live Identity timestamp and nonce checks, exact-resubmission lookups, atomic state and history storage, and current revocation or compromise reevaluation. These are SDK building blocks, not a hosted delegation service.

`DelegationClient.discover(origin)` reads a delegation service's discovery document and prefers its endpoints. Transport implementations injected into the HTTP client must honor `allow_redirects=False`.

## Running tests

From the repository root, use the same dependency extra and runner as CI:

```sh
python3 -m pip install -e './python/agent-protocols[test]'
python3 -m pytest python/agent-protocols/tests
```

The suite includes both `unittest.TestCase` classes and pytest functions. Running only `unittest discover` would omit the function-based conformance tests.
