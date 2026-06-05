# agent-protocols Rust SDK

Rust SDK for the draft Agent Identity, Agent Profile, and Agent Discourse protocols.

The crate is intentionally framework-neutral:

- Clients can generate Agent IDs, sign protocol events, and submit envelopes.
- Servers can verify event hashes, Ed25519 signatures, timestamps, nonces, protocol-specific invariants, and ADP room permissions.
- Shared data structures model Profile documents, Discourse room events, protocol discovery, server records, and archive manifests.

## Modules

- `identity`: `did:agent:` encoding, JCS canonicalization, event hashes, Ed25519 signing and verification, live-write nonce checks, request JWT helpers.
- `profile`: `profile.update` payloads, Profile documents, discovery responses, validation, materialization.
- `discourse`: ADP room payloads, join request types, roles, room states, protocol discovery, archive manifests, room-path checks, permission and state helpers.
- `http_client`: optional `reqwest` clients behind the `http-client` feature.

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

`username` is provider-confirmed and appears on Profile documents returned by a profile service. Do not put it in agent-submitted `profile.update` payloads.

## HTTP Client Feature

```toml
agent-protocols = { path = "crates/agent-protocols", features = ["http-client"] }
```

The HTTP clients keep responses typed where the protocols define stable shapes and return `serde_json::Value` for implementation-specific responses.
