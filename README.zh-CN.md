# Agent Protocols

[English](README.md) | [简体中文](README.zh-CN.md)

Agent Protocols 是一个面向自治智能体互操作的开放规范仓库。本仓库目前定义了六个草案协议：

1. **Agent Identity Protocol**：基于 Ed25519 的智能体身份、签名事件信封、规范编码和验证规则。
2. **Agent Profile Protocol**：可移植的智能体 Profile，用于描述名称、能力、服务端点和提供方元数据，但不替代密码学身份。
3. **Agent Delegation Protocol**：可移植、可验证的代理授权凭证，声明智能体可以代表谁行动——由 principal 的 controller key 签名的授权与撤销事件，携带 scopes、constraints、有效期与撤销状态。
4. **Agent Discourse Protocol**：面向多智能体讨论的有生命周期 Room 协议，由小内核（成员、签名消息、有序记录、可验证归档）加类型系统构成；每个 Room 通过类型系统声明带 schema 校验的自定义事件类型，可内联定义或从可复用类型包导入。
5. **Agent Knowledge Protocol**：面向跨学科知识发现、分享与协同演进的开放网络。签名研究胶囊通过来源、评估和复用报告连接。公开文本与结构化查询、批量读取、关系探索及可选的排序检索帮助智能体发现并审视贡献；学科应用规范定义更精确的解释与验证要求。
6. **Agent Mail Protocol**：去中心化、异步的端到端加密私信。收件人签名的 Mailbox Card 绑定独立加密密钥与可替换投递路由；签名 Letter 在本地加密为不透明 Packet，支持离线投递、回复与附件。

本仓库并列维护英文和简体中文版本。英文版本作为跨实现评审的默认工作语言；中文版本应保持相同的规范要求。

## 规范

| 协议                      | English                                                                          | 简体中文                                                                                     | 状态 |
| ------------------------- | -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ---- |
| Agent Identity Protocol   | [docs/protocols/agent-identity/1.0.md](docs/protocols/agent-identity/1.0.md)     | [docs/protocols/agent-identity/1.0.zh-CN.md](docs/protocols/agent-identity/1.0.zh-CN.md)     | 草案 |
| Agent Profile Protocol    | [docs/protocols/agent-profile/1.0.md](docs/protocols/agent-profile/1.0.md)       | [docs/protocols/agent-profile/1.0.zh-CN.md](docs/protocols/agent-profile/1.0.zh-CN.md)       | 草案 |
| Agent Delegation Protocol | [docs/protocols/agent-delegation/1.0.md](docs/protocols/agent-delegation/1.0.md) | [docs/protocols/agent-delegation/1.0.zh-CN.md](docs/protocols/agent-delegation/1.0.zh-CN.md) | 草案 |
| Agent Discourse Protocol  | [docs/protocols/agent-discourse/1.0.md](docs/protocols/agent-discourse/1.0.md)   | [docs/protocols/agent-discourse/1.0.zh-CN.md](docs/protocols/agent-discourse/1.0.zh-CN.md)   | 草案 |
| Agent Knowledge Protocol | [docs/protocols/agent-knowledge/1.0.md](docs/protocols/agent-knowledge/1.0.md) | [docs/protocols/agent-knowledge/1.0.zh-CN.md](docs/protocols/agent-knowledge/1.0.zh-CN.md) | 草案 |
| Agent Mail Protocol | [docs/protocols/agent-mail/1.0.md](docs/protocols/agent-mail/1.0.md) | [docs/protocols/agent-mail/1.0.zh-CN.md](docs/protocols/agent-mail/1.0.zh-CN.md) | 草案 |

各规范的机器可读文件（JSON Schema、ADP 类型包与规范性测试向量）均在 [docs/protocols](docs/protocols/README.zh-CN.md) 中列出。Rust、TypeScript 和 Python SDK 运行共享协议向量，包括 Agent Knowledge 的对象、接受、检索与发现用例。

## 协议关系

这些协议可以组合使用，但不要求同一个服务拥有所有能力：

- Agent Identity 定义 `did:agent:` 身份和其他协议共享的签名事件信封。
- Agent Profile 使用 Agent Identity 签名发布可变的智能体描述元数据。
- Agent Delegation 声明智能体可以代表谁行动。授权与撤销就是普通的 Agent Identity 签名事件，其 `actor` 必须是 principal 的 HTTPS URL 所发布的 controller key；Agent Profile 可以携带 delegation 发现提示。
- Agent Discourse 对所有写操作使用 Agent Identity，并且可以从本地 Profile 存储或任意兼容的第三方 Agent Profile 服务解析 Profile。
- Agent Knowledge 使用 Agent Identity 签名可跨服务传播的公开研究贡献，支持持续评估、复用与演进。Profile 可以发布知识服务发现提示，Discourse 可以讨论知识胶囊或提供公开证据；知识图谱不依赖这两个协议。学科应用规范补充结构化解释与验证要求，不改变核心身份或权限。
- Agent Mail 使用 Agent Identity 签名收件配置与私信，再通过 HPKE 加密完整信件。Profile 可提供 Mailbox Card 的发现提示；独立中继存储密文，收件人在本地解密并验证。接收信件不代表获得行动授权。

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

通用 MCP 智能体 SHOULD 通过本地 Agent Protocols MCP connector 集成；该 connector 负责签名、nonce 管理、request JWT、room 状态和实时 SSE 同步。Connector 是既有协议上的本地适配层，不是新的 Agent Protocol。参见 [docs/mcp/local-connector/1.0.zh-CN.md](docs/mcp/local-connector/1.0.zh-CN.md)。

Agent Mail 已提供原生 Rust、TypeScript 和 Python SDK 模块。Mail 的本地 MCP Connector 支持仍属于后续工作。

## 成熟度

本仓库中的所有规范当前均为 **草案**。在稳定的 1.0 版本发布前，实现者应预期规范将会增加澄清说明、测试向量、JSON Schema 和一致性测试。

草案要求中的 `MUST`、`MUST NOT`、`SHOULD`、`SHOULD NOT`、`MAY` 按 RFC 2119 含义理解。

## 仓库结构

```text
crates/
  agent-protocols/      面向客户端和服务端实现的 Rust SDK
packages/
  agent-protocols/      面向客户端和服务端实现的 TypeScript SDK
python/
  agent-protocols/      面向客户端和服务端实现的 Python SDK
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

## SDK

本仓库包含 Identity、Profile、Delegation、Discourse、Knowledge 和 Mail 协议的通用客户端和服务端构建模块：

- Rust：[crates/agent-protocols](crates/agent-protocols)
- TypeScript：[packages/agent-protocols](packages/agent-protocols)
- Python：[python/agent-protocols](python/agent-protocols)

这些 SDK 覆盖 Agent ID 编码、严格 Ed25519 验证、签名事件信封、Profile 物化、Delegation controller 权限、历史与凭证验证、Discourse 内核与类型系统、权限 helper，以及 HTTP client。Rust 与 TypeScript SDK 还包含本地 MCP Connector 核心。

Knowledge 支持包括事件构建与验证、依赖与生命周期检查、证据完整性、内存参考存储、文本与结构化查询、批量读取、绑定检查点的分页与 `after_seq` 轮询、服务发现，以及带响应验证的 HTTP 客户端。排序搜索工具验证调用方提供的候选项和单页响应契约，不提供嵌入模型或排名引擎。持久化存储、托管服务、学科验证器和 Knowledge 专用 MCP 工具仍属于应用或后续集成工作。各 SDK 的 README 提供公共 API 与示例。

Mail 支持包括签名卡片与信件验证、HPKE 加解密、卡片回滚防护、旧解密密钥保留、收件去重、内存中继状态和 HTTP 客户端。应用需要持久保存安全状态与密钥，并在确认投递前提交收件状态；内存工具不是持久化邮箱服务。Mail 测试使用共享规范性向量和三语言加解密矩阵。安装三种 SDK 的开发依赖后，可运行 `make test-mail-interop` 验证各语言新生成密文的互操作性。

未来可能会增加 OpenAPI 描述、其他语言的 SDK 指南和更完整的一致性测试套件。

## 参与贡献

欢迎提交 issue 和 pull request。提出行为变更前，请先阅读 [CONTRIBUTING.md](CONTRIBUTING.md)，并在讨论中包含对互操作性和安全性的考虑。

## 许可

本仓库使用 [MIT License](LICENSE)。
