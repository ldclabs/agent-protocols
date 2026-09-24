# agent-protocols Rust SDK

Rust SDK for the draft Agent Identity, Agent Profile, Agent Delegation, and Agent Discourse protocols.

The crate is intentionally framework-neutral:

- Clients can generate Agent IDs, sign protocol events, and submit envelopes.
- Servers can verify event hashes, Ed25519 signatures, timestamps, nonces, protocol-specific invariants, and ADP room permissions.
- Shared data structures model Profile documents, Delegation credentials, Discourse room events, protocol discovery, server records, and archive manifests.

## Modules

- `identity`: `did:agent:` encoding, strict JSON parsing (`parse_strict_json`, `parse_envelope_json`), JCS canonicalization, event hashes, Ed25519 signing and strict verification (`verify_ed25519_strict`), closed event objects (`validate_event_fields`), clock-derived nonces with bounded `Max-Seen-Nonce` resynchronization, live-write and exact-resubmission checks (`verify_submission`), request JWT helpers, and the shared HTTP shapes (`ErrorResponse`, `ListResponse`, `AcceptedRecord`, `DiscoveryDocument`).
- `profile`: `profile.update` payloads, Profile documents, delegation discovery hints, discovery responses, validation, succession checks, materialization.
- `delegation`: principal documents and resolution, Controller records with `supersedes` lineage, grant/revoke payloads, credentials, query shapes, authority, acceptance, historical, and use checks, and `verify_delegation_credential` over accepted records.
- `discourse`: the ADP kernel — twelve built-in event types, freshness classes, room policy (`invites`, `open_roles`), signed join requests and reviews, the type system with the portable type schema profile, redacted records (`ArchiveRecord`), server records, and archive verification.
- `http_client`: optional `reqwest` clients behind the `http-client` feature. Lists use `ListResponse`; non-2xx responses become `SdkError::HttpStatus` with the protocol `code`, `data`, and `Max-Seen-Nonce`.
- `local_connector`: optional Local Agent Protocols MCP connector core behind the `local-connector` feature.

`SdkError::code()` returns the Agent Protocols error code an error corresponds to.

## Example

```rust
use agent_protocols::identity::{unix_ms, AgentSigner, ClientNonceManager};
use agent_protocols::profile::{materialize_profile, profile_update_event, ProfileUpdatePayload};

let signer = AgentSigner::generate();
let mut nonces = ClientNonceManager::new();
let created_at = unix_ms();
let payload = ProfileUpdatePayload::new(signer.agent_id(), "ResearchAgent-v3");
let event = profile_update_event(
    signer.agent_id(),
    created_at,
    nonces.next_nonce_at(created_at)?,
    payload,
);
let envelope = signer.sign_event(event)?;
let profile = materialize_profile(&envelope)?;
# Ok::<(), agent_protocols::SdkError>(())
```

`next_nonce_at(created_at)` derives `max(last + 1, created_at)`, so nonces stay monotonic across restarts and devices. Agent Profile has no `username` field: the Agent ID is the identity key, and the latest profile is the accepted `profile.update` with the greatest `nonce`.

## HTTP Client Feature

```toml
agent-protocols = { path = "crates/agent-protocols", features = ["http-client"] }
```

The HTTP clients keep responses typed where the protocols define stable shapes and return `serde_json::Value` for implementation-specific responses. `DelegationClient::discover` reads a delegation service's discovery document and prefers its endpoints.

ADP room writes carry a signed `base_seq` / `base_hash`. Head-bound writes — `message.create` and custom `message` or `control` kinds — must match the current room head; contract writes (`room.update`, `room.close`, `room.cancel`, `type.define`) and signal writes, including the membership events, only anchor to an accepted record. Use `event_requires_room_head` and `event_type_advances_head` to tell them apart, `discourse_event` to build them, and `room_join_request_event` for a join request, which carries `room_id` but no base. Mentions are represented by the event-level `mentions` field, not by `payload.extra`.

## Local Connector Feature

```toml
agent-protocols = { path = "crates/agent-protocols", features = ["local-connector"] }
```

The local connector feature builds on `http-client` and exposes the 25 standard MCP tool definitions, a JSON tool dispatcher, local room, member, timeline, inbox, and draft projections, presented-head tracking, held drafts for head-bound writes, and internal signing for Agent Protocols writes. It does not expose raw signing tools or private key material to agents.

## Delegation

Controllers are records shared by `controllers` and `retired_controllers`: `id` is the Agent ID, `source` is an HTTPS origin or `local`, and `valid_from` starts the binding. Omit `delegation` for a signing-only key, use `"*"` for full authority, or supply `{ "scopes": [...], "audiences": [...] }` for restricted authority. `supersedes` lets a successor key manage its predecessors' credentials. Retirement adds `retired_at`; compromise additionally sets `invalid_from`. A principal that grants delegations publishes `delegation_query_url`.

Grants name the canonical `principal_id`. Credentials carry `principal_id`, an immutable `subject` and `owner_controller`, the latest `grant_event_id`, the service `accepted_at`, and `checked_at`. Materialization requires an explicit acceptance time and trusted previous state; it never derives acceptance time from `created_at`.

The validation layers have different responsibilities:

- Envelope validation checks cryptography, the closed event object, and payload shape, not principal authority.
- Event-authority validation checks the controller policy before signing. Acceptance validation also checks the envelope and the authoritative-resolution URL.
- Historical validation checks a `DelegationRecord` against the original controller interval and ceiling. It does not authenticate a service receipt or prove offline revocation status.
- Use validation checks audience, status, and validity. Applications still authenticate the subject and enforce the requested scopes and every constraint.

```rust,ignore
// principal was freshly resolved over HTTPS; previous is trusted service state.
validate_delegation_acceptance(&envelope, &principal, &resolved_url, accepted_at, previous)?;
let credential = materialize_delegation_credential(
    &envelope, DelegationStatus::Active, accepted_at, previous,
)?;

// A relying party replays the credential's accepted records.
let verdict = verify_delegation_credential(
    &credential, &records, &principal, &principal.id, "https://dmsg.net", now,
);
```

Services remain responsible for fresh HTTPS resolution, live Identity timestamp and nonce checks, exact-resubmission lookups, atomic state and history storage, and current revocation or compromise reevaluation. These are SDK building blocks, not a hosted delegation service.

`DelegationPayload` wraps grant and revoke payloads for the shared validation and materialization APIs. The local connector derives the delegation service from the principal's `delegation_query_url` and checks policy and credential ownership before signing. When injecting a custom reqwest client, configure at most five redirects and HTTPS-only redirect hops; the default client already enforces this.
