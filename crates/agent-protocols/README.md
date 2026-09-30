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
- `mail`: signed mailbox cards and letters, HPKE packets, card pins, key retention, inbox deduplication, and an in-memory relay with snapshot persistence boundaries.
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

`mail` implements `agent-mail/1.0`: signed mailbox cards and letters, strict
wire validation, independent X25519 keys, RFC 9180 HPKE Base encryption, padded
packets, private attachments, reply bindings, and lifecycle state.
The fixed suite uses the maintained [`hpke`](https://docs.rs/hpke/0.14.1/hpke/)
crate with X25519/HKDF-SHA256/ChaCha20Poly1305. Secret keys and temporary
plaintext frames are zeroized on drop; deliberately exported secrets, decoded
letters, and application backups still need protected storage.

```rust
use agent_protocols::{identity::AgentSigner, mail::*};

# fn main() -> agent_protocols::Result<()> {
let now = agent_protocols::identity::unix_ms();
let owner = AgentSigner::generate();
let sender = AgentSigner::generate();
let key = MailEncryptionKey::generate()?;
let card = sign_card(&owner, MailboxCardPayload {
    mailbox_id: random_id()?,
    expires_at: now + 86_400_000, receive_until: now + 172_800_000,
    public_key: key.public_key(),
    routes: vec!["https://relay.example".into()], max_packet_bytes: 65536,
}, now, now as u64)?;
let letter = sign_message(&sender, MessagePayload {
    to: owner.agent_id(), expires_at: now + 86_400_000,
    thread_id: random_id()?, parts: vec![MailPart::text("A private question")],
    subject: None, in_reply_to: None, reply_card: None,
}, now, now as u64)?;
let mut pins = MailCardCache::new();
let packet = pins.seal(&letter, &serde_json::to_value(&card)?, now)?;
let mut keys = MailKeyring::new(owner.agent_id());
keys.add(&card, key)?;
let mut inbox = MailInbox::new(keys);
let accepted = inbox.accept(&packet, Some(&packet_id(&packet)?), now)?;
assert!(matches!(accepted, InboxAcceptance::Accepted(_)));
# Ok(())
# }
```

- `validate_card`, `validate_letter`, `validate_packet` validate raw JSON values;
  `parse_card`, `parse_letter`, `parse_packet` also reject duplicate JSON names.
  Typed deserialization alone is not a wire validation boundary.
- `MailCardCache::observe` pins the greatest-nonce card per mailbox; an older
  or conflicting card fails with `stale_card`. Persist its snapshot **even when
  observation returns a closed or expired card**. `prune` drops pins once every
  earlier card has expired, and `seal` pins a card before encrypting.
- `MailKeyring` retains old card/key pairs through `receive_until`, and
  `MailInbox` deduplicates letters across re-encryption, routes and mailboxes;
  the application stores accepted letters. Lower nonces arriving later are
  accepted. An acknowledgement is an ordinary reply checked with `validate_reply`.
- `MailRelayStore` models live card publication, ownership, route checks,
  per-mailbox packet quotas (`rate_limited`), stable sequence numbers, `seq`
  cursors and deletion tombstones. Delivery results never include `seq`. `list`
  and `delete` require the owner's signed JWT. `prune` drops expired packets and
  tombstones and forgets mailboxes whose current card's `receive_until` passed. `publish_with_nonce_store` accepts
  the shared origin-wide Identity `NonceStore`; invalid writes do not consume
  its nonce, and the short-lived nonce cache is not part of the snapshot.
- All state helpers are **in-memory**, not durable or hosted services. Their
  `snapshot` / `from_snapshot` APIs support application-managed persistence of
  trusted local state; restoring checks only version and shape. Persist inbox
  state before transport deletion and relay state before success. Keyring
  snapshots contain **private decryption keys**. Every returned object is an
  owned copy, so modifying it cannot mutate retained state.

With `http-client`, `mail::MailClient` (also exported from `http_client`) talks
to one relay origin from a card's `routes`; paths are fixed at `/v1/mailboxes`.
It provides informational `protocol`, `card`, `publish`, anonymous `deliver`,
and owner-authenticated `list` / `delete`. It constructs a separate HTTPS
transport with redirects permanently disabled; callers cannot supply a
credential-bearing HTTP client or builder. `with_tls_roots` supports explicitly
trusted private relay CAs. Card reads automatically pin cards, including closed,
moved or expired ones; cloned clients share the same cache. `card_at` accepts an
explicit verification clock. Use `card_cache_snapshot` for persistence and
`with_card_cache(Arc<Mutex<MailCardCache>>)` to restore/share pins across
independent clients and relay origins. Responses are bounded (default 128 MiB),
parsed as strict JSON, and checked for shape, signatures, expected IDs, mailbox
bindings and list ordering. Applications remain responsible for
private-network/DNS access policy, persistent retry state, quarantine, and
authorization of any action described by a letter. A relay acknowledgment is not
a recipient reply. This implementation supplies neither forward secrecy against
retained-recipient-key compromise nor a ratchet.

`tests/mail_vectors.rs` executes shared Mail vectors directly through this SDK,
including the RFC known answer, signed messages, rejection cases, lifecycle and
snapshot restoration; `tests/mail_http.rs` uses a local authenticated TLS fixture.
`examples/mail_interop.rs` is a public-fixture-only cross-language test adapter,
not an application key-management example.
