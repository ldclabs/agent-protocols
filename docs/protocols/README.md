# Protocol Specifications

[English](README.md) | [简体中文](README.zh-CN.md)

This directory contains the normative draft specifications for Agent Protocols.

| Protocol                  | Identifier             | English                                            | 简体中文                                                       | Machine-readable                                                                                                                                  |
| ------------------------- | ---------------------- | -------------------------------------------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| Agent Identity Protocol   | `agent-identity/1.0`   | [agent-identity/1.0.md](agent-identity/1.0.md)     | [agent-identity/1.0.zh-CN.md](agent-identity/1.0.zh-CN.md)     | [Test vectors](agent-identity/1.0.vectors.json)                                                                                                   |
| Agent Profile Protocol    | `agent-profile/1.0`    | [agent-profile/1.0.md](agent-profile/1.0.md)       | [agent-profile/1.0.zh-CN.md](agent-profile/1.0.zh-CN.md)       | [JSON Schema](agent-profile/1.0.schema.json) · [Test vectors](agent-profile/1.0.vectors.json)                                                     |
| Agent Delegation Protocol | `agent-delegation/1.0` | [agent-delegation/1.0.md](agent-delegation/1.0.md) | [agent-delegation/1.0.zh-CN.md](agent-delegation/1.0.zh-CN.md) | [JSON Schema](agent-delegation/1.0.schema.json) · [Test vectors](agent-delegation/1.0.vectors.json)                                               |
| Agent Discourse Protocol  | `agent-discourse/1.0`  | [agent-discourse/1.0.md](agent-discourse/1.0.md)   | [agent-discourse/1.0.zh-CN.md](agent-discourse/1.0.zh-CN.md)   | [JSON Schema](agent-discourse/1.0.schema.json) · [Type packs](agent-discourse/1.0.packs.json) · [Test vectors](agent-discourse/1.0.vectors.json) |
| Agent Knowledge Protocol | `agent-knowledge/1.0` | [agent-knowledge/1.0.md](agent-knowledge/1.0.md) | [agent-knowledge/1.0.zh-CN.md](agent-knowledge/1.0.zh-CN.md) | [JSON Schema](agent-knowledge/1.0.schema.json) · [Test vectors](agent-knowledge/1.0.vectors.json) |
| Agent Mail Protocol | `agent-mail/1.0` | [agent-mail/1.0.md](agent-mail/1.0.md) | [agent-mail/1.0.zh-CN.md](agent-mail/1.0.zh-CN.md) | [JSON Schema](agent-mail/1.0.schema.json) · [Test vectors](agent-mail/1.0.vectors.json) |

The local Agent Protocols MCP connector is documented separately in [../mcp/local-connector/1.0.md](../mcp/local-connector/1.0.md).

## Reading Guide

| Question | Specification | Boundary |
| --- | --- | --- |
| Which key signed? | Agent Identity | A valid signature is not application authorization. |
| How is this agent described? | Agent Profile | Metadata and delegation hints are not proof of representation. |
| Whom may it represent, and where? | Agent Delegation | A Controller binding needs explicit delegation authority; grants are limited by audience, scope, and status. |
| What may it do in this room? | Agent Discourse | Room membership, roles, and event rules remain independent. |
| How can agents discover, examine, reuse, and collaboratively develop knowledge? | Agent Knowledge | Queries identify their service and checkpoint scope; relevance, signed provenance, and disciplinary validation are separate from universal truth. |
| How can agents exchange private letters asynchronously? | Agent Mail | Encryption protects letter content; relays still observe delivery metadata, and receiving a letter grants no execution authority. |

For an integration, read Identity first — it also defines the HTTP conventions the other protocols share — and then only the protocols it uses. The local MCP connector adapts these protocols; it does not replace their validation rules.

Test vectors are normative: an implementation that disagrees with a vector does not conform. A protocol identifier alone does not demonstrate conformance to the latest draft.

Agent Knowledge has native Rust, TypeScript, and Python SDK modules with validation, in-memory state and retrieval, and HTTP clients. Their tests run the shared vectors. SDK support does not supply a hosted service, disciplinary validator, ranking engine, or Knowledge MCP adapter.

Agent Mail has native Rust, TypeScript, and Python SDK modules for validation, HPKE encryption, card and key lifecycle, in-memory recipient and relay state, and HTTP clients. Their tests run the shared Mail vectors and exchange freshly encrypted packets across languages. Applications supply durable storage and operating policy; the local MCP connector does not yet support Mail.

## Versioning

Protocol identifiers are written as `{protocol-name}/{major.minor}`. Unpublished draft 1.0 documents may receive incompatible revisions before final release; implementations must track the current draft requirements. Changes between drafts are recorded in the Git history rather than in the specifications. Breaking changes after a stable release should use a new major version.

## Language Versions

The English and Simplified Chinese documents should be kept aligned. When a pull request changes a normative requirement in one language, it should update the other language in the same pull request whenever possible. Authoring conventions for specifications are in [CONTRIBUTING.md](../../CONTRIBUTING.md#specification-structure).
