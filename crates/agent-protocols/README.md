# agent-protocols Rust SDK

Rust SDK for the draft Agent Identity, Agent Profile, Agent Delegation, Agent Discourse, Agent Knowledge, and Agent Mail protocols.

The crate is intentionally framework-neutral:

- Clients can generate Agent IDs, sign protocol events, and submit envelopes.
- Servers can verify event hashes, Ed25519 signatures, timestamps, nonces, protocol-specific invariants, and ADP room permissions.
- Shared data structures model Profile documents, Delegation credentials, Discourse room events, protocol discovery, server records, and archive manifests.

## Modules

- `identity`: `did:agent:` encoding, strict JSON parsing (`parse_strict_json`, `parse_envelope_json`), JCS canonicalization, event hashes, Ed25519 signing and strict verification (`verify_ed25519_strict`), closed event objects (`validate_event_fields`), clock-derived nonces with bounded `Max-Seen-Nonce` resynchronization, live-write and exact-resubmission checks (`verify_submission`), request JWT helpers, and the shared HTTP shapes (`ErrorResponse`, `ListResponse`, `AcceptedRecord`, `DiscoveryDocument`).
- `profile`: `profile.update` payloads, Profile documents, delegation discovery hints, discovery responses, validation, succession checks, materialization.
- `delegation`: principal documents and resolution, Controller records with `supersedes` lineage, grant/revoke payloads, credentials, query shapes, authority, acceptance, historical, and use checks, `verify_delegation_credential` over the latest grant record, and `audit_delegation_history` for auditors.
- `discourse`: the ADP kernel — twelve built-in event types, freshness classes, room policy (`invites`, `open_roles`), signed join requests and reviews, the type system with the portable type schema profile, redacted records (`ArchiveRecord`), server records, and archive verification.
- `knowledge`: signed contributions, evidence/profile checks, dependency graph views, discovery, portable queries, checkpoint-bound pagination, and the in-memory Knowledge store.
- `mail`: signed mailbox cards and encrypted submissions, HPKE packets, card pins, key retention, inbox deduplication, and an in-memory relay with snapshot persistence boundaries.
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

Controller registration (Section 4.3) proves key possession with a fixed-shape challenge: `signer.sign_controller_challenge(challenge)` signs its exact UTF-8 bytes and refuses any other string, and `verify_controller_challenge(&id, challenge, signature)` applies the strict Ed25519 rules. Issuing challenges, binding them to the owner-approved fields, and expiry stay with the provider.

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
profile-binding checks, deterministic known-set views, portable text/filter
matching, discovery, and read-response contracts. The bundled schema ships with
the crate; runtime validation never reads a repository path. Unknown application
data in `extra` and profile `data` is preserved. Optional arrays/objects use
`Option`, retaining omitted versus explicitly empty values.

```rust
use agent_protocols::identity::{AgentSigner, Event};
use agent_protocols::knowledge::{KnowledgeStore, PROTOCOL, materialize_knowledge};
use serde_json::json;

let signer = AgentSigner::generate();
let event = Event::new(PROTOCOL, "knowledge.publish", signer.agent_id(), 1000, 1,
    json!({
        "license": "https://example.org/license",
        "kind": "question", "title": "Can this result generalize?",
        "statement": "Does the result extend to nonuniform samples?",
        "language": "en",
        "context": {"scope": "A proposed research question", "conditions": [], "limitations": []},
        "basis": "The original experiment considered only uniform samples."
    }));
let envelope = serde_json::to_value(signer.sign_event(event)?)?;
let mut store = KnowledgeStore::new("https://knowledge.example.org")?;
store.submit(&envelope, 1000)?; // Old events are accepted too; no nonce cache.
let page = store.query(&json!({"q": "nonuniform", "kind": "question"}), 1000)?;
assert_eq!(page["result"].as_array().unwrap().len(), 1);
let view = materialize_knowledge(&store.known_envelopes())?;
# Ok::<(), agent_protocols::SdkError>(())
```

`KnowledgeStore` is a single-process in-memory reference implementation for
applications and tests, not a durable HTTP service. Acceptance verifies the
envelope, rejects `created_at` beyond `future_skew_ms` (300 s by default), resolves
dependencies against every retained envelope (including hidden ones), and applies
`max_envelope_bytes` and an optional `set_admission` hook; it never reads or
advances an Identity nonce cache. Hiding preserves receipts; pruning loses the
receipt while retaining the sequence high-water mark. All reads return owned data.
`SdkError::data()` exposes sorted missing dependencies.

`query` and `batch` implement exact local reads. Query cursors are stateless: they
encode the checkpoint, snapshot time, last returned `seq`, and a request digest,
so no read state is retained. Poll for new records with `after_seq` set to a
completed checkpoint. `search` returns one page of caller-selected candidates with
explicit ranking/coverage metadata; it does not implement an embedding model.
`KnowledgePageTracker` checks request binding, checkpoint scope, ordering, and
duplicate IDs across query pages and exposes the persistable checkpoint only after
the last page. A lifecycle view applies only to the validated dependency-closed
set supplied to it; retrieval alone does not establish current lifecycle status,
scientific truth, or profile conformance.

With `http-client`, `KnowledgeClient::new(origin)?` provides public reads without a
signer, `protocol`, `discover`, `event`, `query`, `query_all`, `batch`, `search`, and `submit`.
Search requires advertised discovery. `query_all` returns the records and the
checkpoint, or `SdkError::PageLimitExceeded` when its page budget ends first.
Submissions optionally accept an Identity request JWT; it authenticates the
transport caller, who need not be the envelope actor. Discovery endpoints must
share the receiving HTTPS origin. The default transport disables redirects and
parses raw response text strictly before verifying every returned envelope and
request contract. A custom reqwest client must preserve the redirect restriction.
The SDK never automatically contacts peers, fetches artifacts, or executes
procedures.

`cargo test -p agent-protocols --all-features` runs the shared Knowledge signed
fixtures and every applicable layered vector in native Rust, plus real local
HTTPS client tests and additional pagination, numeric, and store-limit tests.

## Agent Mail

Messages have no inner signature. The signed `mail.submit` envelope covers the
complete encrypted packet. HPKE AAD binds its protocol, type, actor, submission
creation time, nonce and packet header. Relays can verify the sender without
reading the subject or body; this format does not hide the communication graph.
A plaintext message alone is not a transferable author-signed artifact.

`message_id` is a random 32-byte base64url identifier retained across retries;
`from`, original `created_at`, recipient, expiration, thread and parts are also
immutable. The outer hash is the packet ID, not the logical message ID. A retry
may use a new card, HPKE randomness, submission time and nonce while keeping the
original message exactly. Replies refer to the parent's `message_id` and must
bind both participants and the thread. Content is inert and never executes tools.

Relay admission uses Identity's live timestamp window and origin-wide nonce
store. Recipient processing verifies queued submissions historically, so offline
and out-of-order messages remain usable. Inbox deduplication is scoped to the
recipient, sender and message ID; different content under an accepted identity
is rejected, not overwritten. Sender policy is checked before decryption.

The state helpers are **in memory**, not hosted or durable services. Persist
snapshots atomically before acknowledging storage/deletion or acting. Relay
snapshots preserve accepted Mail nonce maxima and sender policies; an injected
nonce store shared with other protocols must also be persisted by the host.
Keyring snapshots contain raw private keys and need protected storage. Pruning
keys cannot erase copies in backups. Production HPKE always uses fresh randomness.

Mailbox addressing uses `did:agent:<key>/mail/<mailbox_id>` and optional
`?route=<origin>` hints. Parse/format helpers reuse Agent Identity's Agent URLs.
Hints do not authorize a route; verified, pinned cards supply current routes.
The local MCP connector does not yet expose Mail tools.

```rust
use agent_protocols::{identity::{AgentSigner, ClientNonceManager}, mail::*};
use serde_json::json;

# fn main() -> agent_protocols::Result<()> {
let now = agent_protocols::identity::unix_ms();
let owner = AgentSigner::generate();
let sender = AgentSigner::generate();
let key = MailEncryptionKey::generate()?;
let mut nonces = ClientNonceManager::new();
let card = sign_card(&owner, MailboxCardPayload {
    mailbox_id: random_id()?, expires_at: now + 86_400_000,
    receive_until: now + 172_800_000, public_key: key.public_key(),
    routes: vec!["https://relay.example".into()], max_packet_bytes: 65536,
}, now, now as u64)?;
let message = create_mail_message(&sender.agent_id(), now, json!({
    "to": owner.agent_id(), "expires_at": now + 86_400_000,
    "thread_id": random_id()?, "parts": [MailPart::text("A private question")],
}))?;
let mut pins = MailCardCache::new();
let submission = pins.seal(&message, &serde_json::to_value(&card)?, &sender,
    nonces.next_nonce_at(now)?, now)?;
let mut keys = MailKeyring::new(owner.agent_id());
keys.add(&card, key)?;
let mut inbox = MailInbox::new(keys);
assert!(matches!(inbox.accept(&submission, Some(&packet_id(&submission)?), now)?,
    InboxAcceptance::Accepted(_)));
# Ok(())
# }
```

`Letter = MessagePayload` is immutable plaintext; its Rust `sender` member
serializes as `from`. `Submission = Envelope<Packet>` is the signed wire object.
`encrypt_letter(message, card, signer, nonce, now)` produces a fresh submission;
`decrypt_packet` verifies and opens it. Use `validate_letter` for plaintext and
`parse_packet`/`validate_packet` for wire data. Typed deserialization alone is not
wire validation. `packet_id` returns the verified outer event hash.
`MailInbox::set_sender_blocked(sender, blocked)` controls local admission.
`MailRelayStore::set_sender_blocked(mailbox, sender, blocked, owner_jwt, now)`
authenticates policy changes. `publish_with_nonce_store` and
`deliver_with_nonce_store` accept the same origin-wide Identity nonce store.
Snapshots preserve Mail nonce maxima and local policy. Secret keys and temporary
frames are zeroized on drop; exported secrets and plaintext still require
protected storage. Returned objects are owned copies.

With `http-client`, `mail::MailClient` (also exported from `http_client`) provides
`protocol`, `card`, `publish`, sender-signed `deliver`, and owner-JWT `list` and
`delete`. The client constructs its own HTTPS transport, disables redirects and
ambient credentials, and accepts explicit private CA roots through
`with_tls_roots`. Card reads pin even closed or expired cards; clones share the
cache. Use `card_at` for an explicit clock, `card_cache_snapshot` for persistence,
and `with_card_cache` for a shared restored cache. Applications enforce local
network/DNS policy. No Mail MCP tools or hosted relay are supplied.
