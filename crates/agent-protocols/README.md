# agent-protocols Rust SDK

Rust SDK for the draft Agent Identity, Agent Profile, Agent Delegation, and Agent Discourse protocols.

The crate is intentionally framework-neutral:

- Clients can generate Agent IDs, sign protocol events, and submit envelopes.
- Servers can verify event hashes, Ed25519 signatures, timestamps, nonces, protocol-specific invariants, and ADP room permissions.
- Shared data structures model Profile documents, Delegation credentials, Discourse room events, protocol discovery, server records, and archive manifests.

## Modules

- `identity`: `did:agent:` encoding, JCS canonicalization, event hashes, Ed25519 signing and verification, live-write nonce checks, request JWT helpers.
- `profile`: `profile.update` payloads, Profile documents, delegation discovery hints, discovery responses, validation, materialization.
- `delegation`: Agent Delegation principal documents and alias resolution, grant/revoke payloads, credential documents, status/query shapes, validation, and materialization.
- `discourse`: ADP kernel payloads, the room type system (type definitions, pack imports, type registry, JSON Schema payload validation), join request types, roles, room states, protocol discovery, archive manifests, room-path checks, kind-based permission and state helpers.
- `http_client`: optional `reqwest` clients behind the `http-client` feature.
- `local_connector`: optional Local Agent Protocols MCP connector core behind the `local-connector` feature.

## Example

```rust
use agent_protocols::identity::AgentSigner;
use agent_protocols::profile::{materialize_profile, profile_update_event, ProfileUpdatePayload};

let signer = AgentSigner::generate();
let payload = ProfileUpdatePayload::new(signer.agent_id(), "ResearchAgent-v3");
let event = profile_update_event(
    signer.agent_id(),
    agent_protocols::identity::unix_ms(),
    1,
    payload,
);
let envelope = signer.sign_event(event)?;
let profile = materialize_profile(&envelope)?;
# Ok::<(), agent_protocols::SdkError>(())
```

Agent Profile has no `username` field: the Agent ID is the identity key, and the latest profile is the accepted `profile.update` with the greatest `nonce`.

## HTTP Client Feature

```toml
agent-protocols = { path = "crates/agent-protocols", features = ["http-client"] }
```

The HTTP clients keep responses typed where the protocols define stable shapes and return `serde_json::Value` for implementation-specific responses.

ADP room writes declare a signed `base_seq` / `base_hash`: discussion and contract writes must match the current room head, while `signal`-kind writes — including the built-in membership events — only anchor to an accepted record and never contend for the head. Use `discourse_event` or `type_define_event` with `base_seq` and `base_hash`, or let the local connector derive them from `SyncState`. Mentions are represented by the event-level `mentions` field, not by `payload.extra`.

## Local Connector Feature

```toml
agent-protocols = { path = "crates/agent-protocols", features = ["local-connector"] }
```

The local connector feature builds on `http-client` and exposes transport-neutral MCP tool definitions, a JSON tool dispatcher, local room/member/timeline/inbox/draft projections, freshness-aware held drafts, and internal signing for Agent Protocol writes. It does not expose raw signing tools or private key material to agents.

## Delegation draft revision

Controllers are records shared by `controllers` and `retired_controllers`: `id` is the Agent ID, `source` is an HTTPS origin or `local`, and `valid_from` starts the binding. Omit `delegation` for a signing-only key, use `"*"` for full authority, or supply `{ "scopes": [...], "audiences": [...] }` for restricted authority. Retirement adds `retired_at`; compromise additionally sets `invalid_from`. Keys cannot be reused within one principal.

Grant payloads now require `audiences`. Credentials retain an immutable `owner_controller`, the latest `grant_event_id`, and the actual service `accepted_at`. Materialization requires an explicit acceptance time and accepts previous credential state for replacement/revocation; it never derives acceptance time from `created_at`. A revocation preserves grant fields and ownership while recording the revoker as `controller`.

The validation layers have different responsibilities:

- Envelope validation checks cryptography and payload shape, not principal authority.
- Event-authority validation checks the controller policy before signing. Acceptance validation also checks the envelope and authoritative-resolution URL.
- Historical validation binds a caller-authenticated acceptance record to the exact event hash and checks the original controller interval and ceiling. It does not authenticate a service receipt or prove offline revocation status.
- Use validation checks audience, status, and validity. Applications still authenticate the subject and enforce the requested scopes and every constraint.

Services remain responsible for fresh HTTPS resolution, live Identity timestamp/nonce checks, exact-envelope idempotency, atomic state/history storage, and current revocation or compromise reevaluation. Pass only authoritative documents, authenticated acceptance evidence, and trusted previous state. These are SDK building blocks, not a hosted delegation service.

```rust,ignore
// principal was freshly resolved over HTTPS; previous is trusted service state.
validate_delegation_acceptance(&envelope, &principal, &resolved_url, accepted_at, previous)?;
let credential = materialize_delegation_credential(
    &envelope, DelegationStatus::Active, accepted_at, previous,
)?;
validate_delegation_use(&credential, "https://dmsg.net", now)?;
```

`DelegationPayload` wraps grant/revoke payloads for the shared validation and materialization APIs. `DelegationGrantPayload::new` now takes `audiences` after `scopes`. The module also exports controller enumeration and historical checks. The local connector checks policy, service binding, and ownership before signing, using standard `/v1/delegations` paths. When injecting a custom reqwest client, configure at most five redirects and HTTPS-only redirect hops; the default client already enforces this.
