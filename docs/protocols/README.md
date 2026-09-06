# Protocol Specifications

[English](README.md) | [简体中文](README.zh-CN.md)

This directory contains the normative draft specifications for Agent Protocols.

| Protocol                  | Identifier             | English                                            | 简体中文                                                       | Schema                                                                                        |
| ------------------------- | ---------------------- | -------------------------------------------------- | -------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Agent Identity Protocol   | `agent-identity/1.0`   | [agent-identity/1.0.md](agent-identity/1.0.md)     | [agent-identity/1.0.zh-CN.md](agent-identity/1.0.zh-CN.md)     | -                                                                                             |
| Agent Profile Protocol    | `agent-profile/1.0`    | [agent-profile/1.0.md](agent-profile/1.0.md)       | [agent-profile/1.0.zh-CN.md](agent-profile/1.0.zh-CN.md)       | -                                                                                             |
| Agent Delegation Protocol | `agent-delegation/1.0` | [agent-delegation/1.0.md](agent-delegation/1.0.md) | [agent-delegation/1.0.zh-CN.md](agent-delegation/1.0.zh-CN.md) | -                                                                                             |
| Agent Discourse Protocol  | `agent-discourse/1.0`  | [agent-discourse/1.0.md](agent-discourse/1.0.md)   | [agent-discourse/1.0.zh-CN.md](agent-discourse/1.0.zh-CN.md)   | [JSON Schema](agent-discourse/1.0.schema.json) · [Type packs](agent-discourse/1.0.packs.json) |

The local Agent Protocols MCP connector is documented separately in [../mcp/local-connector/1.0.md](../mcp/local-connector/1.0.md).

## Reading Guide

| Question | Specification | Boundary |
| --- | --- | --- |
| Which key signed? | Agent Identity | A valid signature is not application authorization. |
| How is this agent described? | Agent Profile | Metadata and delegation hints are not proof of representation. |
| Whom may it represent, and where? | Agent Delegation | A Controller binding needs explicit delegation authority; grants are limited by audience, scope, and status. |
| What may it do in this room? | Agent Discourse | Room membership, roles, and event rules remain independent. |

For an integration, read Identity first and then only the protocols it uses. The local MCP connector adapts these protocols; it does not replace their validation rules. `controllers` and `retired_controllers` share one Controller type; retired records preserve history, not permission to submit new events.

The source SDKs provide structured-controller and delegation validation helpers; Rust and TypeScript connectors enforce authority before signing. Services must still enforce live replay checks, atomic acceptance, and fresh status. A protocol identifier alone does not demonstrate conformance to the latest draft.

## Document Structure

Specifications use the same reading order, with protocol-specific chapters in the middle:

1. **Overview** — purpose, scope, dependencies, and boundaries. Summarize motivation here rather than maintaining a separate Design Goals or Design Principles chapter.
2. **Normative Language** — normative keywords and common interpretation rules.
3. **Protocol body** — identity and data model, encoding and signed events, acceptance and lifecycle rules, then APIs and integration. Split these into as many focused chapters as needed; Identity need not invent an HTTP API, and Discourse need not compress its room and type systems into one chapter.
4. **Security and Privacy** — trust boundaries, threats, and disclosure considerations.
5. **Conformance** — minimum implementation requirements and positive/negative verification cases, drawn from the body rather than introducing new rules.
6. **Appendices** — test vectors, registered vocabularies, draft changes, implementation notes, alternatives, and future work. State explicitly when an appendix contains normative material.

Keep numbered chapters consecutive; use lettered appendices. English and Simplified Chinese use matching section numbers. Structural edits must update internal and cross-document references without changing wire fields, protocol identifiers, examples, or normative requirements. The MCP connector follows this order with adapter-specific model, tools, and result chapters.

## Versioning

Protocol identifiers are written as `{protocol-name}/{major.minor}`. Unpublished draft 1.0 documents may receive incompatible revisions before final release; implementations must track the current draft requirements. Breaking changes after a stable release should use a new major version.

## Language Versions

The English and Simplified Chinese documents should be kept aligned. When a pull request changes a normative requirement in one language, it should update the other language in the same pull request whenever possible.
