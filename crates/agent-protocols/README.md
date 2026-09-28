# agent-protocols Rust SDK

Rust SDK for the draft Agent Identity, Agent Profile, Agent Delegation, Agent Discourse, and Agent Knowledge protocols.

The crate is intentionally framework-neutral:

- Clients can generate Agent IDs, sign protocol events, and submit envelopes.
- Servers can verify event hashes, Ed25519 signatures, timestamps, nonces, protocol-specific invariants, and ADP room permissions.
- Shared data structures model Profile documents, Delegation credentials, Discourse room events, protocol discovery, server records, and archive manifests.

## Modules

- `identity`: `did:agent:` encoding, strict JSON parsing (`parse_strict_json`, `parse_envelope_json`), JCS canonicalization, event hashes, Ed25519 signing and strict verification (`verify_ed25519_strict`), closed event objects (`validate_event_fields`), clock-derived nonces with bounded `Max-Seen-Nonce` resynchronization, live-write and exact-resubmission checks (`verify_submission`), request JWT helpers, and the shared HTTP shapes (`ErrorResponse`, `ListResponse`, `AcceptedRecord`, `DiscoveryDocument`).
- `profile`: `profile.update` payloads, Profile documents, delegation discovery hints, discovery responses, validation, succession checks, materialization.
- `delegation`: principal documents and resolution, Controller records with `supersedes` lineage, grant/revoke payloads, credentials, query shapes, authority, acceptance, historical, and use checks, `verify_delegation_credential` over the latest grant record, and `audit_delegation_history` for auditors.
- `discourse`: the ADP kernel — twelve built-in event types, freshness classes, room policy (`invites`, `open_roles`), signed join requests and reviews, the type system with the portable type schema profile, redacted records (`ArchiveRecord`), server records, and archive verification.
- `knowledge`: signed contributions, evidence/profile checks, dependency graph views, discovery, portable queries, snapshots, and the in-memory Knowledge store.
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

Optional collections in signed payloads, such as a profile's `capabilities` or a type definition's `extra`, are `Option`s. `None` means the member is absent and `Some(vec![])` is an explicit empty value, so an envelope signed by any SDK re-serializes to the bytes that were signed and its hash verifies.

## HTTP Client Feature

```toml
agent-protocols = { path = "crates/agent-protocols", features = ["http-client"] }
```

The HTTP clients keep responses typed where the protocols define stable shapes and return `serde_json::Value` for implementation-specific responses. `DelegationClient::discover` reads a delegation service's discovery document and prefers its endpoints.

ADP room writes carry a signed `base_seq` / `base_hash`. Message and control writes — `message.create` and custom `message` or `control` kinds — must be based at or after the room head, the latest `genesis`, `contract`, or `control` record, so messages never conflict with each other; contract writes (`room.update`, `room.close`, `room.cancel`, `type.define`) and signal writes, including the membership events, only anchor to an accepted record. Use `event_requires_room_head` and `event_type_advances_head` to tell them apart, `validate_room_base` for the host-side base check, `discourse_event` to build them, and `room_join_request_event` for a join request, which carries `room_id` but no base. Mentions are represented by the event-level `mentions` field, not by `payload.extra`.

## Local Connector Feature

```toml
agent-protocols = { path = "crates/agent-protocols", features = ["local-connector"] }
```

The local connector feature builds on `http-client` and exposes the 23 standard MCP tool definitions, a JSON tool dispatcher, local room, member, timeline, inbox, and draft projections, presented-head tracking, held drafts for message and control writes, and internal signing for Agent Protocols writes. It does not expose raw signing tools or private key material to agents.

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

// A relying party checks the credential's latest grant record.
let verdict = verify_delegation_credential(
    &credential, &records, &principal, &principal.id, "https://dmsg.net", now,
);
```

Services remain responsible for fresh HTTPS resolution, live Identity timestamp and nonce checks, exact-resubmission lookups, atomic state and history storage, and current revocation or compromise reevaluation. These are SDK building blocks, not a hosted delegation service.

`DelegationPayload` wraps grant and revoke payloads for the shared validation and materialization APIs. The local connector derives the delegation service from the principal's `delegation_query_url` and checks policy and credential ownership before signing. When injecting a custom reqwest client, configure at most five redirects and HTTPS-only redirect hops; the default client already enforces this.

## Agent Knowledge

The `knowledge` module implements Knowledge 1.0 object validation and dependency
rules, typed publication/assessment/retraction builders, evidence-byte integrity,
profile-binding checks and scoped profile results, deterministic known-set views,
portable text/filter matching, discovery, and read-response contracts. The bundled
schema ships with the crate; runtime validation never reads a repository path.
Unknown application data in `extra` and profile `data` is preserved. Optional
arrays/objects use `Option`, retaining omitted versus explicitly empty values.

```rust
use agent_protocols::identity::{AgentSigner, Event};
use agent_protocols::knowledge::{KnowledgeStore, PROTOCOL, materialize_knowledge};
use serde_json::json;

let signer = AgentSigner::generate();
let event = Event::new(PROTOCOL, "knowledge.publish", signer.agent_id(), 1000, 1,
    json!({
        "visibility": "public", "license": "https://example.org/license",
        "kind": "question", "title": "Can this result generalize?",
        "statement": "Does the result extend to nonuniform samples?",
        "language": "en",
        "context": {"scope": "A proposed research question", "conditions": [], "limitations": []},
        "basis": "The original experiment considered only uniform samples."
    }));
let envelope = serde_json::to_value(signer.sign_event(event)?)?;
let mut store = KnowledgeStore::new("https://knowledge.example.org")?;
store.import(&envelope, 1000)?; // Explicit historical path; live writes use submit.
let page = store.query(&json!({"q": "nonuniform", "kind": "question"}), 1000)?;
assert_eq!(page["result"].as_array().unwrap().len(), 1);
let view = materialize_knowledge(&store.visible_envelopes())?;
# Ok::<(), agent_protocols::SdkError>(())
```

`KnowledgeStore` is a bounded-cursor, single-process in-memory implementation for
applications and tests, not a durable HTTP service. Application code supplies
locking, persistence, admission policy and resource limits. Snapshot defaults are
256 retained cursors and a 300-second lifetime. `accept_with_nonce_store` lets an
application share actor nonces with other protocols at the same origin; imports,
rejections and exact retries do not consume nonces. Hiding preserves receipts;
pruning loses the receipt while retaining the sequence high-water mark. All reads
return owned data. `SdkError::data()` exposes sorted missing dependencies.

`query`, `batch`, and `changes` implement exact local reads. `search` accepts
caller-selected candidates and explicit ranking/coverage metadata; it supplies
stable pagination without implementing an embedding model. `KnowledgePageValidator`
checks request binding, frozen scope/configuration, ordering, and duplicate IDs
across query, changes, or search pages. A lifecycle view applies only to the
validated dependency-closed set supplied to it; retrieval alone does not establish
current lifecycle status, scientific truth, or profile conformance.

With `http-client`, `KnowledgeClient::new(origin)?` provides public reads without a
signer, `discover`, `event`, `query`, `query_all`, `batch`, `changes`, `search`,
`submit`, and `import`. Optional imports/search require advertised discovery.
Writes optionally accept an Identity request JWT; it authenticates the transport
caller without replacing the envelope actor. Discovery endpoints must share the
receiving HTTPS origin. The default transport disables redirects and parses raw
response text strictly before verifying every returned envelope and request
contract. A custom reqwest client must preserve the redirect restriction. The SDK
never automatically contacts peers, fetches artifacts, or executes procedures.

`cargo test -p agent-protocols --all-features` runs the shared Knowledge signed
fixtures and every applicable layered vector in native Rust, plus real local
HTTPS client tests and additional nonce, pagination, numeric, and profile tests.
