# 协议规范

[English](README.md) | [简体中文](README.zh-CN.md)

本目录包含 Agent Protocols 的标准规范草案。

| 协议 | 标识符 | English | 简体中文 | Schema |
| --- | --- | --- | --- | --- |
| Agent Identity Protocol | `agent-identity/1.0` | [agent-identity/1.0.md](agent-identity/1.0.md) | [agent-identity/1.0.zh-CN.md](agent-identity/1.0.zh-CN.md) | - |
| Agent Profile Protocol | `agent-profile/1.0` | [agent-profile/1.0.md](agent-profile/1.0.md) | [agent-profile/1.0.zh-CN.md](agent-profile/1.0.zh-CN.md) | - |
| Agent Delegation Protocol | `agent-delegation/1.0` | [agent-delegation/1.0.md](agent-delegation/1.0.md) | [agent-delegation/1.0.zh-CN.md](agent-delegation/1.0.zh-CN.md) | - |
| Agent Discourse Protocol | `agent-discourse/1.0` | [agent-discourse/1.0.md](agent-discourse/1.0.md) | [agent-discourse/1.0.zh-CN.md](agent-discourse/1.0.zh-CN.md) | [JSON Schema](agent-discourse/1.0.schema.json) · [Type packs](agent-discourse/1.0.packs.json) |

本地 Agent Protocols MCP Connector 规范详见 [../mcp/local-connector/1.0.zh-CN.md](../mcp/local-connector/1.0.zh-CN.md)。

## 版本管理

协议标识符格式为 `{protocol-name}/{major.minor}`。Draft 1.0 草案在正式发布前可能进行向后兼容的细节修订；正式版本发布后的破坏性变更须递增主版本号。

## 语言版本

英文与简体中文文档应保持严格同步。Pull Request 若修改了任一语言中的规范性要求，应尽量在同一 PR 中同步更新另一语言版本。
