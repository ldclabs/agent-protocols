# agent-protocols Python SDK

Python SDK for the draft Agent Identity, Agent Profile, Agent Delegation, Agent Discourse, Agent Knowledge, and Agent Mail protocols.

## Modules

- `agent_protocols.identity`: `did:agent:` encoding, strict JSON parsing (`parse_strict_json`, `parse_envelope_json`), JCS canonicalization, event hashes, Ed25519 signing and strict verification (`verify_ed25519_strict`), closed event objects (`validate_event_fields`), clock-derived nonces with bounded `Max-Seen-Nonce` resynchronization, live-write and exact-resubmission checks (`verify_submission`), request JWT helpers.
- `agent_protocols.profile`: `profile.update` payload helpers, delegation discovery hints, validation, succession checks, materialization.
- `agent_protocols.delegation`: principal documents and resolution, Controller records with `supersedes` lineage, grant/revoke payloads, credentials, authority, acceptance, historical, and use checks, `verify_delegation_credential` over the latest grant record, and `audit_delegation_history` for auditors.
- `agent_protocols.discourse`: the ADP kernel — twelve built-in event types, freshness classes, room policy (`invites`, `open_roles`), signed join requests and reviews, the type system with the portable type schema profile, redacted records, server records, and archive verification.
- `agent_protocols.knowledge`: signed research contributions, known-set lifecycle views, evidence and profile bindings, in-memory storage, exact queries with checkpoint-bound pagination, single-page ranked search, discovery, and response validation.
- `agent_protocols.mail` and `agent_protocols.mail_state`: signed mailbox cards, sender-signed PyHPKE packets, historical key retention, card pins, inbox deduplication, and synchronized relay state with snapshots.
- `agent_protocols.http_client`: optional requests-based Profile, Delegation, Discourse, Knowledge, and Mail clients. Install with `agent-protocols[http]`. Lists use `{"result", "next_cursor"}`; non-2xx responses raise `HttpResponseError` with the protocol `code`, `data`, and `max_seen_nonce`.

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

Controller registration (Section 4.3) proves key possession with a fixed-shape challenge: `signer.sign_controller_challenge(challenge)` signs its exact UTF-8 bytes and refuses any other string, and `verify_controller_challenge(agent_id, challenge, signature)` applies the strict Ed25519 rules. Issuing challenges, binding them to the owner-approved fields, and expiry stay with the provider.

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

## Knowledge

`agent_protocols.knowledge` implements Agent Knowledge 1.0: signed publications,
assessments and retractions; strict payload and dependency validation; deterministic
known-set lifecycle views; evidence byte verification; and exact query, batch,
ranked-search and discovery contracts. The JSON Schema ships inside the installed
package; no repository files are needed at runtime.

```python
from agent_protocols import (
    AgentSigner, ClientNonceManager, KnowledgeStore,
    knowledge_publish_event, materialize_knowledge, unix_ms,
)

signer = AgentSigner.generate()
now = unix_ms()
nonces = ClientNonceManager()
event = knowledge_publish_event(signer.agent_id(), now, nonces.next_nonce(now), {
    "license": "https://creativecommons.org/licenses/by/4.0/",
    "kind": "observation",
    "title": "Cache keys must preserve language",
    "statement": "Caching a greeting by user alone can return the wrong language.",
    "language": "en",
    "context": {
        "scope": "A two-language in-memory greeting renderer",
        "conditions": ["A user switches languages"],
        "limitations": ["Only this fixture was tested"],
    },
    "basis": "A two-request fixture returned the first cached greeting.",
    "tags": ["caching"],
})
envelope = signer.sign_event(event)
store = KnowledgeStore("https://knowledge.example.com")
record = store.submit(envelope)
page = store.query({"q": "cache language", "kind": "observation"})
assert page["result"][0]["envelope"]["hash"] == envelope["hash"]
assert materialize_knowledge(store.known_envelopes())[envelope["hash"]]["status"] == "active"
```

`validate_knowledge_envelope` checks signatures and core object rules;
`validate_knowledge_dependencies` checks target rules against already validated
envelopes. `materialize_knowledge` verifies its map and requires dependency
closure before reporting facts within that known set.
`verify_knowledge_evidence(digest, representation)` compares complete decoded
representation bytes without fetching resources; pass `None` when they could not
be obtained. Profile bindings are checked and preserved; profile conformance and
scientific validity need the application's discipline-specific checks. Nothing is
automatically fetched or run.

`KnowledgeStore` is a synchronized **in-memory** reference component. Knowledge
events are portable objects: `submit` rejects only `created_at` beyond
`future_skew_ms` (300 s by default), never consults an Identity nonce cache, and
resolves dependencies against every retained envelope, including hidden ones. It
preserves exact retry receipts, applies `max_envelope_bytes` and an optional
`admit` hook, and distinguishes hiding from pruning. Query cursors are stateless:
they encode the checkpoint, snapshot time, last returned `seq`, and a request
digest, and incompatible cursors fail with `invalid_cursor`. Poll for new records
with `after_seq` set to a completed checkpoint. Applications supply durable
storage, restoration of the sequence high-water mark, and hosting.

`search` returns one page of application-ranked `candidates` with a versioned
`ranking`, honest `coverage`, and optional `explanations`; it refuses candidates
that violate the exact filters and false exhaustive coverage.

Install `agent-protocols[http]` to use `agent_protocols.http_client.KnowledgeClient`.
`KnowledgeClient.discover(origin)` validates discovery and honors same-origin
endpoint overrides. `event`, `query`, `batch`, and `search` are public reads
without a signer. `submit` accepts an optional origin-bound request JWT; the
caller may differ from the event's author. All returned envelopes, exact IDs,
filters, scope and ranking mode are verified. Raw response JSON is parsed strictly
and redirects are disabled. Use a dedicated session without default credentials
for public discovery; any session-level auth, cookies or transport adapters remain
caller-controlled.

Use `client.query_pages(request)` to reject cross-page scope drift, repeated IDs,
and ordering regressions. Persist the checkpoint only after consuming every page;
`KnowledgePageTracker` exposes that completed checkpoint for callers implementing
their own transport. Peers are hints; the SDK does not send queries or credentials
to them automatically.

## Mail

Messages have no inner signature. A packet is the sender-signed `mail.submit`
envelope around the HPKE ciphertext. HPKE AAD binds its protocol, type, actor,
creation time, nonce and header. Relays can verify the sender without reading
the subject or body; this format does not hide the communication graph. A
plaintext message alone is not a transferable author-signed artifact.

`message_id` is a random `id16` (16 bytes, base64url) retained across retries;
`from`, original `created_at`, recipient, expiration, thread and parts are also
immutable. The outer hash is the packet ID, not the logical message ID. Retries
reuse the same packet on every route until it expires; only a card change needs
a fresh packet (new HPKE randomness, time and nonce) around the same message. Replies refer to the parent's `message_id` and must
bind both participants and the thread. Content is inert and never executes tools.

Packets are asynchronous signed objects, not live writes: relays and recipients
reject only future-dated packets and apply no nonce maximum, so offline and
out-of-order messages remain usable. Relays deduplicate packet IDs with
tombstones; only card publishes use the live-write nonce store. Inbox
deduplication is scoped to the recipient, sender and message ID; different
content under an accepted identity is rejected, not overwritten. Sender policy
is checked before decryption.

The state helpers are **in memory**, not hosted or durable services. Persist
snapshots atomically before acknowledging storage/deletion or acting. Relay
snapshots include sender policies but not the short-lived nonce cache.
Keyring snapshots contain raw private keys and need protected storage. Pruning
keys cannot erase copies in backups. Production HPKE always uses fresh randomness.

Mailbox addressing uses `did:agent:<key>/mail/<mailbox_id>` and optional
`?route=<origin>` hints. Parse/format helpers reuse Agent Identity's Agent URLs.
Hints do not authorize a route; verified, pinned cards supply current routes.
The local MCP connector does not yet expose Mail tools.

```python
from agent_protocols import (
    AgentSigner, ClientNonceManager, MailCardCache, MailEncryptionKey,
    MailKeyring, MailInbox, create_mail_message, mailbox_publish_event,
    sign_mail_event, mail_part, new_mail_id, unix_ms,
)

sender, owner = AgentSigner.generate(), AgentSigner.generate()
key, nonces = MailEncryptionKey.generate(), ClientNonceManager()
now = unix_ms()
card = sign_mail_event(owner, mailbox_publish_event(owner.agent_id(), now, now, {
    'mailbox_id': new_mail_id(), 'expires_at': now + 86400000,
    'receive_until': now + 172800000, 'public_key': key.public_key(),
    'routes': ['https://relay.example'], 'max_packet_bytes': 65536,
}))
message = create_mail_message(sender.agent_id(), now, {
    'to': owner.agent_id(), 'expires_at': now + 86400000,
    'thread_id': new_mail_id(), 'parts': [mail_part('text/plain', 'A private question')],
})
pins = MailCardCache()
packet = pins.seal(message, card, sender, nonces.next_nonce(now), now_ms=now)
keys = MailKeyring(owner.agent_id())
keys.add(card, key)
inbox = MailInbox(keys)
result = inbox.accept(packet, now_ms=now)
assert result['kind'] == 'accepted' and result['message'] == message
# Persist the pin, keyring and inbox state before confirming receipt.
```

`encrypt_mail(message, card, signer, nonce, now_ms=...)` and `decrypt_mail`
are stateless primitives. `validate_mail_message` validates plaintext;
`validate_mail_packet` verifies a signed packet before decryption.
`mail_packet_id(packet)` returns the verified outer event hash.
`validate_mail_reply` validates the known parent's message ID and participants.
`MailInbox.accept` returns `{'kind', 'message'}`.
`MailInbox.set_sender_blocked(sender, blocked=True)` applies local policy.
`MailRelayStore.set_sender_blocked(mailbox_id, sender, blocked)` is relay-side
policy: Mail defines no management endpoint, so the host authenticates the
mailbox owner first. It blocks new acceptance, preserves queued packets, and
does not recreate deleted packets on exact retries. The injectable Identity
nonce store applies to card publishes.

Install `agent-protocols[http]` for `agent_protocols.http_client.MailClient`.
`publish`, `card`, `deliver`, `packets`, `packet_pages` and `delete` use fixed
HTTPS paths. Card reads update the shared pin cache even for closed/expired
cards. Delivery carries the sender signature, with no ambient cookies, auth,
netrc or client certificate. Read/delete use an owner-bound JWT. Redirects are
disabled and responses are bounded, strictly parsed and binding-checked. A
network policy runs before every request; private relays need an explicit local
policy. Test fixtures and `tests/mail_interop.py` use public test material only.
