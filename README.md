# Agent Protocols

[English](README.md) | [简体中文](README.zh-CN.md)

Agent Protocols is an open specification repository for interoperable autonomous agents. The repository currently defines three draft protocols:

1. **Agent Identity Protocol**: Ed25519-based agent identity, signed event envelopes, canonical encoding, and verification rules.
2. **Agent Profile Protocol**: portable agent profiles that describe names, capabilities, service endpoints, and provider metadata without replacing cryptographic identity.
3. **Agent Discourse Protocol**: lifecycle-bounded rooms for structured multi-agent discussion, with signed events, role rules, live transport, and verifiable archives.

English and Simplified Chinese versions are maintained side by side. The English version is the default working language for cross-implementation review. The Chinese version should preserve the same normative requirements.

## Specifications

| Protocol                 | English                                                                        | 简体中文                                                                                   | Status |
| ------------------------ | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ | ------ |
| Agent Identity Protocol  | [docs/protocols/agent-identity/1.0.md](docs/protocols/agent-identity/1.0.md)   | [docs/protocols/agent-identity/1.0.zh-CN.md](docs/protocols/agent-identity/1.0.zh-CN.md)   | Draft  |
| Agent Profile Protocol   | [docs/protocols/agent-profile/1.0.md](docs/protocols/agent-profile/1.0.md)     | [docs/protocols/agent-profile/1.0.zh-CN.md](docs/protocols/agent-profile/1.0.zh-CN.md)     | Draft  |
| Agent Discourse Protocol | [docs/protocols/agent-discourse/1.0.md](docs/protocols/agent-discourse/1.0.md) | [docs/protocols/agent-discourse/1.0.zh-CN.md](docs/protocols/agent-discourse/1.0.zh-CN.md) | Draft  |

## Protocol Relationship

The protocols are designed to compose without forcing one service to own everything:

- Agent Identity defines `did:agent:` identifiers and the signed event envelope shared by the other protocols.
- Agent Profile uses Agent Identity signatures to publish mutable descriptive metadata for an agent.
- Agent Discourse uses Agent Identity for all write operations and may resolve profiles from a local profile store or any compatible third-party Agent Profile service.

```text
Agent Identity
      |
      +--> Agent Profile
      |
      +--> Agent Discourse -- may resolve --> third-party Agent Profile service
```

## Maturity

All specifications in this repository are currently **drafts**. Implementers should expect clarifications, test vectors, JSON Schemas, and conformance tests to be added before a stable 1.0 release.

Draft requirements use the RFC 2119 terms `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY`.

## Repository Layout

```text
docs/
  protocols/
    agent-identity/
    agent-profile/
    agent-discourse/
```

Future additions may include JSON Schema files, test vectors, OpenAPI descriptions, SDK guidance, and conformance suites.

## Contributing

Issues and pull requests are welcome. Before proposing behavior changes, please read [CONTRIBUTING.md](CONTRIBUTING.md) and include interoperability and security considerations in the discussion.

## License

This repository is licensed under the [MIT License](LICENSE).
