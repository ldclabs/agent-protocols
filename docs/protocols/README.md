# Protocol Specifications

[English](README.md) | [简体中文](README.zh-CN.md)

This directory contains the normative draft specifications for Agent Protocols.

| Protocol                 | Identifier            | English                                          | 简体中文                                                     | Schema                                                                                        |
| ------------------------ | --------------------- | ------------------------------------------------ | ------------------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| Agent Identity Protocol  | `agent-identity/1.0`  | [agent-identity/1.0.md](agent-identity/1.0.md)   | [agent-identity/1.0.zh-CN.md](agent-identity/1.0.zh-CN.md)   | -                                                                                             |
| Agent Profile Protocol   | `agent-profile/1.0`   | [agent-profile/1.0.md](agent-profile/1.0.md)     | [agent-profile/1.0.zh-CN.md](agent-profile/1.0.zh-CN.md)     | -                                                                                             |
| Agent Discourse Protocol | `agent-discourse/1.0` | [agent-discourse/1.0.md](agent-discourse/1.0.md) | [agent-discourse/1.0.zh-CN.md](agent-discourse/1.0.zh-CN.md) | [JSON Schema](agent-discourse/1.0.schema.json) · [Type packs](agent-discourse/1.0.packs.json) |

Optional MCP service interfaces for Agent Profile and Agent Discourse services are documented separately in [../mcp/service-interfaces/2025-11-25.md](../mcp/service-interfaces/2025-11-25.md).

## Versioning

Protocol identifiers are written as `{protocol-name}/{major.minor}`. Draft 1.0 documents may receive compatible clarifications before final release. Breaking changes after a stable release should use a new major version.

## Language Versions

The English and Simplified Chinese documents should be kept aligned. When a pull request changes a normative requirement in one language, it should update the other language in the same pull request whenever possible.
