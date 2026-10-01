# 协议规范

[English](README.md) | [简体中文](README.zh-CN.md)

本目录包含 Agent Protocols 的规范性草案。

| 协议                      | 标识符                 | English                                            | 简体中文                                                       | 机器可读文件                                                                                                                                  |
| ------------------------- | ---------------------- | -------------------------------------------------- | -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Agent Identity Protocol   | `agent-identity/1.0`   | [agent-identity/1.0.md](agent-identity/1.0.md)     | [agent-identity/1.0.zh-CN.md](agent-identity/1.0.zh-CN.md)     | [测试向量](agent-identity/1.0.vectors.json)                                                                                                   |
| Agent Profile Protocol    | `agent-profile/1.0`    | [agent-profile/1.0.md](agent-profile/1.0.md)       | [agent-profile/1.0.zh-CN.md](agent-profile/1.0.zh-CN.md)       | [JSON Schema](agent-profile/1.0.schema.json) · [测试向量](agent-profile/1.0.vectors.json)                                                     |
| Agent Delegation Protocol | `agent-delegation/1.0` | [agent-delegation/1.0.md](agent-delegation/1.0.md) | [agent-delegation/1.0.zh-CN.md](agent-delegation/1.0.zh-CN.md) | [JSON Schema](agent-delegation/1.0.schema.json) · [测试向量](agent-delegation/1.0.vectors.json)                                               |
| Agent Discourse Protocol  | `agent-discourse/1.0`  | [agent-discourse/1.0.md](agent-discourse/1.0.md)   | [agent-discourse/1.0.zh-CN.md](agent-discourse/1.0.zh-CN.md)   | [JSON Schema](agent-discourse/1.0.schema.json) · [类型包](agent-discourse/1.0.packs.json) · [测试向量](agent-discourse/1.0.vectors.json) |
| Agent Knowledge Protocol | `agent-knowledge/1.0` | [agent-knowledge/1.0.md](agent-knowledge/1.0.md) | [agent-knowledge/1.0.zh-CN.md](agent-knowledge/1.0.zh-CN.md) | [JSON Schema](agent-knowledge/1.0.schema.json) · [测试向量](agent-knowledge/1.0.vectors.json) |
| Agent Mail Protocol | `agent-mail/1.0` | [agent-mail/1.0.md](agent-mail/1.0.md) | [agent-mail/1.0.zh-CN.md](agent-mail/1.0.zh-CN.md) | [JSON Schema](agent-mail/1.0.schema.json) · [测试向量](agent-mail/1.0.vectors.json) |

本地 Agent Protocols MCP Connector 另见 [../mcp/local-connector/1.0.zh-CN.md](../mcp/local-connector/1.0.zh-CN.md)。

## 阅读指南

| 问题 | 规范 | 边界 |
| --- | --- | --- |
| 哪把密钥签名？ | Agent Identity | 签名有效不等于应用操作获授权。 |
| 这个智能体如何描述自己？ | Agent Profile | 元数据和 delegation 提示不是代理关系证明。 |
| 它可以代表谁、用于哪个应用？ | Agent Delegation | Controller 绑定需要显式 delegation 权限；grant 受 audience、scope 和状态限制。 |
| 它在这个 Room 中能做什么？ | Agent Discourse | Room 成员、角色与事件规则仍独立生效。 |
| 智能体如何发现、审视、复用并共同发展知识？ | Agent Knowledge | 查询标明服务与检查点范围；相关性、签名来源和学科验证各有边界，不建立普遍真理认证。 |
| 智能体如何异步交换私密信件？ | Agent Mail | 加密保护信件内容；中继可验证明文可见的发件人并执行准入策略，收到信件不代表授权执行。 |

接入时先读 Identity（它还定义了其他协议共享的 HTTP 约定），再只读所用到的协议。本地 MCP Connector 负责适配这些协议，不替代它们的验证规则。

测试向量是规范性的：与向量结果不一致的实现即不符合规范。仅凭协议标识符相同，并不能证明实现符合最新草案。

Agent Knowledge 提供原生 Rust、TypeScript 和 Python SDK 模块，包含验证、内存状态与检索，以及 HTTP 客户端。其测试运行共享向量。SDK 支持不包含托管服务、学科验证器、排名引擎或 Knowledge MCP 适配器。

Agent Mail 提供原生 Rust、TypeScript 和 Python SDK 模块，包含签名投递验证、绑定发件人的 HPKE 加密、准入策略、卡片与密钥生命周期、内存收件与中继状态，以及 HTTP 客户端。测试运行共享 Mail 向量，并跨语言交换新加密的数据包。应用负责持久化存储与运行策略；本地 MCP Connector 尚不支持 Mail。

## 版本管理

协议标识符格式为 `{protocol-name}/{major.minor}`。尚未发布的 1.0 草案可能在正式发布前进行不兼容修订；实现须跟进当前草案要求。草案之间的变更记录在 Git 历史中，而不写入规范正文。正式版本发布后的破坏性变更应使用新的主版本号。

## 语言版本

英文与简体中文文档应保持一致。Pull Request 修改任一语言中的规范性要求时，应尽量在同一 PR 中同步更新另一语言。规范的写作约定见 [CONTRIBUTING.zh-CN.md](../../CONTRIBUTING.zh-CN.md#规范结构)。
