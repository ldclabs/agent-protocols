# agent-protocols Python SDK

Python SDK for the draft Agent Identity, Agent Profile, Agent Delegation, Agent Discourse, Agent Knowledge, and Agent Mail protocols.

## Modules

- `agent_protocols.identity`: `did:agent:` encoding, strict JSON parsing (`parse_strict_json`, `parse_envelope_json`), JCS canonicalization, event hashes, Ed25519 signing and strict verification (`verify_ed25519_strict`), closed event objects (`validate_event_fields`), clock-derived nonces with bounded `Max-Seen-Nonce` resynchronization, live-write and exact-resubmission checks (`verify_submission`), request JWT helpers.
- `agent_protocols.profile`: `profile.update` payload helpers, delegation discovery hints, validation, succession checks, materialization.
- `agent_protocols.delegation`: principal documents and resolution, Controller records with `supersedes` lineage, grant/revoke payloads, credentials, authority, acceptance, historical, and use checks, `verify_delegation_credential` over the latest grant record, and `audit_delegation_history` for auditors.
- `agent_protocols.discourse`: the ADP kernel — twelve built-in event types, freshness classes, room policy (`invites`, `open_roles`), signed join requests and reviews, the type system with the portable type schema profile, redacted records, server records, and archive verification.
- `agent_protocols.knowledge`: signed research contributions, known-set lifecycle views, evidence and profile bindings, in-memory storage, exact queries with checkpoint-bound pagination, single-page ranked search, discovery, and response validation.
- `agent_protocols.mail` and `agent_protocols.mail_state`: signed mailbox cards and letters, PyHPKE encryption, historical key retention, card pins, inbox deduplication, and synchronized relay state with snapshots.
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

Agent Mail 1.0 provides one-recipient, asynchronous encrypted correspondence.
`mailbox_publish_event`, `mail_message_event` and `sign_mail_event` build signed
Identity envelopes. `MailEncryptionKey.generate()` creates an independent X25519
key; never convert an identity seed into a mail key. `mail_part` /
`decode_mail_part` preserve binary parts and validate UTF-8 text.

Encryption uses [PyHPKE](https://pyhpke.readthedocs.io/en/latest/), version
`>=0.6.5,<0.7`, with the fixed RFC 9180 Base X25519/HKDF-SHA256/ChaCha20Poly1305
suite, authenticated JCS headers, and strict minimal 1024-byte framing. Every
production encryption gets a fresh context and ephemeral key. There is no
caller-controlled deterministic encryption option and no homemade KDF. The
packaged Mail schema, actual cryptographic fixtures, and official RFC known
answer are exercised by the SDK tests. This does not replace independent review.

```python
from agent_protocols import (
    AgentSigner, ClientNonceManager, MailCardCache, MailEncryptionKey, MailInbox,
    MailKeyring, MailRelayStore, RequestBinding, create_request_jwt_claims,
    mail_message_event, mailbox_publish_event, mail_part, new_mail_id,
    sign_mail_event, unix_ms,
)

sender, owner = AgentSigner.generate(), AgentSigner.generate()
key = MailEncryptionKey.generate()
now = unix_ms()
owner_nonces, sender_nonces = ClientNonceManager(), ClientNonceManager()
card = sign_mail_event(owner, mailbox_publish_event(
    owner.agent_id(), now, owner_nonces.next_nonce(now), {
        'mailbox_id': new_mail_id(),
        'expires_at': now + 86_400_000, 'receive_until': now + 2 * 86_400_000,
        'public_key': key.public_key(),
        'routes': ['https://relay.example'], 'max_packet_bytes': 65536,
    },
))
letter = sign_mail_event(sender, mail_message_event(
    sender.agent_id(), now, sender_nonces.next_nonce(now), {
        'to': owner.agent_id(), 'expires_at': now + 86_400_000,
        'thread_id': new_mail_id(), 'parts': [mail_part('text/plain', 'Hello privately.')],
    },
))
cards = MailCardCache()
packet = cards.seal(letter, card, now_ms=now)
# Persist cards.snapshot(), the original outgoing letter, and the completed packet.
relay = MailRelayStore('https://relay.example')
relay.publish(card, now_ms=now)
result = relay.deliver(card['event']['payload']['mailbox_id'], packet, now_ms=now)
# A hosted service must persist relay state before returning success externally.
keys = MailKeyring(owner.agent_id())
keys.add(card, key)
inbox = MailInbox(keys)
accepted = inbox.accept(packet, packet_id=result['packet_id'], now_ms=now)
assert accepted['kind'] == 'accepted'
assert inbox.accept(packet, now_ms=now)['kind'] == 'duplicate'
# Store accepted['letter'] and persist inbox/key state before deleting the relay copy.
jwt = owner.sign_request_jwt(create_request_jwt_claims(
    owner.agent_id(), RequestBinding.create('https://relay.example'), now // 1000, 300,
))
relay.delete(card['event']['payload']['mailbox_id'], result['packet_id'], jwt, now_ms=now)
```

`encrypt_mail` / `decrypt_mail` are stateless cryptographic operations.
`MailCardCache.seal` pins the card and encrypts the original signed letter; to
retry under a newer card, seal the same letter again, which keeps its ID and
expiration. For a byte-identical transport retry, resubmit the completed packet.
Expired letters are never renewed. The cache keeps the greatest-nonce card per
mailbox; an older or conflicting card raises `stale_card`. An observation can
advance the pin and then reject a closed or expired card, so **persist the cache
even after such failures**. `prune` drops pins once every earlier card has expired.

`MailKeyring` retains old cards and secrets through their `receive_until`, even
when the current card rotates, moves or closes. `MailInbox` verifies before
atomically suppressing duplicates across all packets, routes and keys; the
application stores accepted letters. Out-of-order nonces are valid letters. No
content is executed, URL fetched, or reply automatically generated.
`validate_mail_reply` verifies a known parent's participants, thread and hash;
an acknowledgement is an ordinary reply.

All state classes support JSON-serializable `snapshot()` / `from_snapshot(...)`.
These snapshots are trusted local state, **not a wire protocol or untrusted import
format**, so restoring checks only their version and shape. Keyring snapshots
contain raw secrets. Encrypt and restrict them at rest. Python and its
dependencies do not guarantee physical erasure of GC-managed memory; use suitable
key custody and retention controls where erasure is a security requirement.

`MailRelayStore` is an in-memory component, not a durable relay server. It provides
atomic publication/sequence allocation, permanent mailbox ownership, live nonce
admission, route checks, per-mailbox ciphertext quotas (`rate_limited`),
idempotent deleted-packet tombstones, owner-only listing/deletion, and plain
`seq` cursors. Delivery results never include the mailbox `seq`. Its lock
prevents concurrent duplicate admissions. Hosting applications must persist
state transactionally before HTTP success and implement bounded HTTP parsing,
rate limits and operational storage policy. `deliver` and `publish` can parse
bounded raw UTF-8 JSON; parsing after an unbounded web-server read is insufficient.
For a service shared with other protocols, inject one atomic Identity
`NonceStore`; the short-lived nonce cache is not part of the relay snapshot.

Install `agent-protocols[http]` for `agent_protocols.http_client.MailClient`.
`MailClient(route)` talks to one relay origin from a card's `routes`; paths are
fixed at `/v1/mailboxes` and `protocol()` reads the informational discovery
document. `publish`, `card(mailbox_id, owner)`, `deliver(packet)`,
`list(mailbox_id, owner, jwt)` and `delete(mailbox_id, packet_id, owner, jwt)`
validate their inputs and responses; `pages` follows cursors and rejects `seq`
regressions. Supply/persist a `card_cache` when creating a client; fetching a
closed, moved or expired card still advances its pin.

Delivery and public discovery/card reads carry no identity credentials. Mail uses
fresh prepared requests rather than merging session auth, cookies, default
headers, query parameters or netrc. TLS client certificates and ambient proxies
are not inherited. Only explicit owner JWTs accompany private reads/deletes.
Redirects are disabled, exact response URLs are checked, and streamed responses
have a configurable byte limit (default 128 MiB). Injected session adapters are
trusted transport code. Pass `network_policy` to apply local network rules before
every request; `mail_public_network_policy` rejects destinations with non-public
DNS answers, and deployments still need resolver/egress controls against DNS
rebinding. Signed routes grant no permission to bypass local policy.
