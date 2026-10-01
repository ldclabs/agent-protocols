# Agent Protocols

[English](README.md) | [简体中文](README.zh-CN.md)

Agent Protocols is an open specification repository for interoperable autonomous agents. The repository currently defines six draft protocols:

1. **Agent Identity Protocol**: Ed25519-based agent identity, signed event envelopes, canonical encoding, and verification rules.
2. **Agent Profile Protocol**: portable agent profiles that describe names, capabilities, service endpoints, and provider metadata without replacing cryptographic identity.
3. **Agent Delegation Protocol**: portable, verifiable delegation credentials that state on whose behalf an agent may act — grants signed by principal controller keys, with scopes, constraints, validity windows, and revocation status.
4. **Agent Discourse Protocol**: lifecycle-bounded rooms for multi-agent discussion, built as a small kernel — membership, signed messages, ordered records, verifiable archives — plus a type system through which each room declares schema-validated custom event types, inline or from reusable type packs.
5. **Agent Knowledge Protocol**: an open network for discovering, sharing, and collaboratively evolving knowledge across disciplines. Signed research capsules connect through provenance, assessments, and reuse reports. Public text and structured queries, batch reads, relationship exploration, and optional ranked search help agents find and examine contributions; disciplinary application profiles define more precise interpretation and validation.
6. **Agent Mail Protocol**: decentralized, asynchronous, end-to-end encrypted private correspondence. Recipient-signed Mailbox Cards bind independent encryption keys to replaceable delivery routes; immutable Messages are encrypted locally, then their Packets are signed for offline delivery, replies, and attachments.

English and Simplified Chinese versions are maintained side by side. The English version is the default working language for cross-implementation review. The Chinese version should preserve the same normative requirements.

## Specifications

| Protocol                  | English                                                                          | 简体中文                                                                                     | Status |
| ------------------------- | -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ------ |
| Agent Identity Protocol   | [docs/protocols/agent-identity/1.0.md](docs/protocols/agent-identity/1.0.md)     | [docs/protocols/agent-identity/1.0.zh-CN.md](docs/protocols/agent-identity/1.0.zh-CN.md)     | Draft  |
| Agent Profile Protocol    | [docs/protocols/agent-profile/1.0.md](docs/protocols/agent-profile/1.0.md)       | [docs/protocols/agent-profile/1.0.zh-CN.md](docs/protocols/agent-profile/1.0.zh-CN.md)       | Draft  |
| Agent Delegation Protocol | [docs/protocols/agent-delegation/1.0.md](docs/protocols/agent-delegation/1.0.md) | [docs/protocols/agent-delegation/1.0.zh-CN.md](docs/protocols/agent-delegation/1.0.zh-CN.md) | Draft  |
| Agent Discourse Protocol  | [docs/protocols/agent-discourse/1.0.md](docs/protocols/agent-discourse/1.0.md)   | [docs/protocols/agent-discourse/1.0.zh-CN.md](docs/protocols/agent-discourse/1.0.zh-CN.md)   | Draft  |
| Agent Knowledge Protocol | [docs/protocols/agent-knowledge/1.0.md](docs/protocols/agent-knowledge/1.0.md) | [docs/protocols/agent-knowledge/1.0.zh-CN.md](docs/protocols/agent-knowledge/1.0.zh-CN.md) | Draft |
| Agent Mail Protocol | [docs/protocols/agent-mail/1.0.md](docs/protocols/agent-mail/1.0.md) | [docs/protocols/agent-mail/1.0.zh-CN.md](docs/protocols/agent-mail/1.0.zh-CN.md) | Draft |

Each specification links its machine-readable files — JSON Schemas, the ADP type packs, and normative test vectors — from [docs/protocols](docs/protocols/README.md). The Rust, TypeScript, and Python SDKs run shared protocol vectors, including Agent Knowledge's object, acceptance, retrieval, and discovery cases.

## Protocol Relationship

The protocols are designed to compose without forcing one service to own everything:

- Agent Identity defines `did:agent:` identifiers and the signed event envelope shared by the other protocols.
- Agent Profile uses Agent Identity signatures to publish mutable descriptive metadata for an agent.
- Agent Delegation states on whose behalf an agent may act. Grants and revocations are ordinary Agent Identity signed events whose `actor` must be a controller key published by the principal's HTTPS URL; Agent Profile can carry delegation discovery hints.
- Agent Discourse uses Agent Identity for all write operations and may resolve profiles from a local profile store or any compatible third-party Agent Profile service.
- Agent Knowledge uses Agent Identity for portable public research contributions and their continuing evaluation, reuse, and evolution. Profile can advertise knowledge services, and Discourse can discuss or supply public evidence for capsules; neither is required for the knowledge graph. Disciplinary application profiles add structured interpretation and validation without changing core identity or authority.
- Agent Mail uses Agent Identity to sign mailbox configuration and HPKE-encrypted submissions. Profile may advertise Mailbox Cards; independent relays store ciphertext while recipients decrypt and verify locally. Receiving a letter does not authorize action.

```text
Agent Identity
      |
      +--> Agent Profile -- delegation hints --> Agent Delegation
      |
      +--> Agent Delegation (principal-signed credentials)
      |
      +--> Agent Discourse -- may resolve --> third-party Agent Profile service
      |
      +--> Agent Knowledge -- derivation, assessments, corrections --> knowledge graph
      |
      +--> Agent Mail -- encrypted letters, replaceable routes --> private mailbox
```

## MCP Interfaces

General MCP-capable agents should integrate through a local Agent Protocols MCP connector, which owns signing, nonce management, request JWTs, room state, and live SSE synchronization. The connector is a local adapter over the existing protocols, not a new Agent Protocol. See [docs/mcp/local-connector/1.0.md](docs/mcp/local-connector/1.0.md).

Agent Mail has native Rust, TypeScript, and Python SDK modules. Mail support in the local MCP connector remains future work.

## Maturity

All specifications in this repository are currently **drafts**. Implementers should expect clarifications, test vectors, JSON Schemas, and conformance tests to be added before a stable 1.0 release.

Draft requirements use the RFC 2119 terms `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY`.

## Repository Layout

```text
crates/
  agent-protocols/      Rust SDK for client and server implementations
packages/
  agent-protocols/      TypeScript SDK for client and server implementations
python/
  agent-protocols/      Python SDK for client and server implementations
docs/
  protocols/
    agent-identity/
    agent-profile/
    agent-delegation/
    agent-discourse/
    agent-knowledge/
    agent-mail/
  mcp/
    local-connector/
```

## SDKs

This repository includes SDKs for common client and server building blocks across the Identity, Profile, Delegation, Discourse, Knowledge, and Mail protocols:

- Rust: [crates/agent-protocols](crates/agent-protocols)
- TypeScript: [packages/agent-protocols](packages/agent-protocols)
- Python: [python/agent-protocols](python/agent-protocols)

The SDKs cover Agent ID encoding, strict Ed25519 verification, signed event envelopes, Profile materialization, Delegation controller authority, history, and credential verification, the Discourse kernel and type system, permission helpers, and HTTP clients. The Rust and TypeScript SDKs also include the local MCP connector core.

Knowledge support includes event builders and validators, dependency and lifecycle checks, evidence integrity, an in-memory reference store, text and structured queries, batch reads, checkpoint-bound pagination with `after_seq` polling, discovery, and HTTP clients with response validation. Ranked-search helpers validate caller-supplied candidates and the single-page response contract; they do not supply an embedding model or ranking engine. Durable storage, hosted services, disciplinary validators, and Knowledge-specific MCP tools remain application or future integration work. See each SDK's README for its public API and examples.

Mail support includes signed card and submission validation, sender-bound HPKE encryption and decryption, card rollback protection, retained decryption keys, logical message deduplication, pre-decryption sender blocking, in-memory relay state, and HTTP clients. Applications must persist security state and keys and commit inbox state before acknowledging delivery; in-memory helpers are not a durable mailbox service. Mail tests use the shared normative vectors and a three-language encryption/decryption matrix. Run `make test-mail-interop` after installing all three SDKs' development dependencies to exercise fresh packets across languages.

Future additions may include OpenAPI descriptions, SDK guidance for other languages, and broader conformance suites.

## Contributing

Issues and pull requests are welcome. Before proposing behavior changes, please read [CONTRIBUTING.md](CONTRIBUTING.md) and include interoperability and security considerations in the discussion.

## License

This repository is licensed under the [MIT License](LICENSE).
