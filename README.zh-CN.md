# Agent Protocols

[English](README.md) | [简体中文](README.zh-CN.md)

Agent Protocols 是一个面向自治智能体互操作的开放规范仓库。本仓库目前定义了三个草案协议：

1. **Agent Identity Protocol**：基于 Ed25519 的智能体身份、签名事件信封、规范编码和验证规则。
2. **Agent Profile Protocol**：可移植的智能体 Profile，用于描述名称、能力、服务端点和提供方元数据，但不替代密码学身份。
3. **Agent Discourse Protocol**：面向多智能体讨论的有生命周期 Room 协议，由小内核（成员、签名消息、有序记录、可验证归档）加类型系统构成；每个 Room 通过类型系统声明带 schema 校验的自定义事件类型，可内联定义或从可复用类型包导入。

本仓库并列维护英文和简体中文版本。英文版本作为跨实现评审的默认工作语言；中文版本应保持相同的规范要求。

## 规范

| 协议                     | English                                                                        | 简体中文                                                                                   | 状态 |
| ------------------------ | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ | ---- |
| Agent Identity Protocol  | [docs/protocols/agent-identity/1.0.md](docs/protocols/agent-identity/1.0.md)   | [docs/protocols/agent-identity/1.0.zh-CN.md](docs/protocols/agent-identity/1.0.zh-CN.md)   | 草案 |
| Agent Profile Protocol   | [docs/protocols/agent-profile/1.0.md](docs/protocols/agent-profile/1.0.md)     | [docs/protocols/agent-profile/1.0.zh-CN.md](docs/protocols/agent-profile/1.0.zh-CN.md)     | 草案 |
| Agent Discourse Protocol | [docs/protocols/agent-discourse/1.0.md](docs/protocols/agent-discourse/1.0.md) | [docs/protocols/agent-discourse/1.0.zh-CN.md](docs/protocols/agent-discourse/1.0.zh-CN.md) | 草案 |

## 协议关系

三个协议可以组合使用，但不要求同一个服务拥有所有能力：

- Agent Identity 定义 `did:agent:` 身份和其他协议共享的签名事件信封。
- Agent Profile 使用 Agent Identity 签名发布可变的智能体描述元数据。
- Agent Discourse 对所有写操作使用 Agent Identity，并且可以从本地 Profile 存储或任意兼容的第三方 Agent Profile 服务解析 Profile。

```text
Agent Identity
      |
      +--> Agent Profile
      |
      +--> Agent Discourse -- may resolve --> third-party Agent Profile service
```

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
    agent-discourse/
```

## SDK

本仓库包含三个草案协议的通用客户端和服务端构建模块：

- Rust：[crates/agent-protocols](crates/agent-protocols)
- TypeScript：[packages/agent-protocols](packages/agent-protocols)
- Python：[python/agent-protocols](python/agent-protocols)

这些 SDK 覆盖 Agent ID 编码、签名事件信封、Profile 物化、Discourse payload 类型、权限 helper，以及 HTTP client。

未来可能会增加更多 JSON Schema 文件、测试向量、OpenAPI 描述、其他语言的 SDK 指南和一致性测试套件。

## 参与贡献

欢迎提交 issue 和 pull request。提出行为变更前，请先阅读 [CONTRIBUTING.md](CONTRIBUTING.md)，并在讨论中包含对互操作性和安全性的考虑。

## 许可

本仓库使用 [MIT License](LICENSE)。
