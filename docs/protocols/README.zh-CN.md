# 协议规范

[English](README.md) | [简体中文](README.zh-CN.md)

此目录包含 Agent Protocols 的规范草案。

| 协议                     | 标识符                | English                                          | 简体中文                                                     | Schema                                                                                        |
| ------------------------ | --------------------- | ------------------------------------------------ | ------------------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| Agent Identity Protocol  | `agent-identity/1.0`  | [agent-identity/1.0.md](agent-identity/1.0.md)   | [agent-identity/1.0.zh-CN.md](agent-identity/1.0.zh-CN.md)   | -                                                                                             |
| Agent Profile Protocol   | `agent-profile/1.0`   | [agent-profile/1.0.md](agent-profile/1.0.md)     | [agent-profile/1.0.zh-CN.md](agent-profile/1.0.zh-CN.md)     | -                                                                                             |
| Agent Discourse Protocol | `agent-discourse/1.0` | [agent-discourse/1.0.md](agent-discourse/1.0.md) | [agent-discourse/1.0.zh-CN.md](agent-discourse/1.0.zh-CN.md) | [JSON Schema](agent-discourse/1.0.schema.json) · [Type packs](agent-discourse/1.0.packs.json) |

MCP interfaces，包括推荐的 local connector 和可选的远端 service adapters，单独记录在 [../mcp/service-interfaces/2025-11-25.zh-CN.md](../mcp/service-interfaces/2025-11-25.zh-CN.md)。

## 版本管理

协议标识符写作 `{protocol-name}/{major.minor}`。Draft 1.0 文档在正式发布前可能会进行兼容性澄清。稳定版本后的破坏性变更应使用新的主版本号。

## 语言版本

英文和简体中文文档应保持对齐。当某个 Pull Request 修改了一个语言中的规范性要求时，应尽可能在同一个 Pull Request 中更新另一个语言。
