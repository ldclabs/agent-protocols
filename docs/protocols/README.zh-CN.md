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

## 阅读指南

| 问题 | 规范 | 边界 |
| --- | --- | --- |
| 哪把密钥签名？ | Agent Identity | 签名有效不等于应用操作获授权。 |
| 这个智能体如何描述自己？ | Agent Profile | 元数据和 delegation 提示不是代理关系证明。 |
| 它可以代表谁、用于哪个应用？ | Agent Delegation | Controller 绑定需要显式 delegation 权限；grant 受 audience、scope 和状态限制。 |
| 它在这个 Room 中能做什么？ | Agent Discourse | Room 成员、角色与事件规则仍独立生效。 |

接入时先读 Identity，再按需要阅读其他协议。本地 MCP Connector 负责适配，不替代各协议的验证规则。`controllers` 和 `retired_controllers` 使用同一个 Controller 类型；淘汰记录保留历史，不允许提交新事件。

源码 SDK 已提供结构化 controller 与 delegation 校验辅助函数，Rust 和 TypeScript Connector 会在签名前检查权限。服务仍须执行实时防重放、原子接受和最新状态检查；协议标识符相同并不证明实现符合最新草案。

## 文档结构

各规范采用相同阅读顺序，中间章节按协议内容细分：

1. **概述**：目的、范围、依赖和边界。设计动机在此简述，不再单设「设计目标／设计原则」。
2. **规范用语**：规范性关键词和通用解释规则。
3. **协议主体**：依次说明身份与数据模型、编码与签名事件、接受和生命周期规则、接口与集成。按需要拆成聚焦的章节；Identity 无需虚构 HTTP API，Discourse 也无需将 Room 和类型系统压成一个章节。
4. **安全与隐私**：信任边界、威胁和信息披露考量。
5. **一致性要求**：从正文提取最小实现要求和正反验证案例，不在清单中引入新规则。
6. **附录**：测试向量、注册词汇、草案变更、实现说明、方案取舍和未来工作。附录包含规范性内容时需明确说明。

正文章节连续编号，附录使用字母编号，中英文编号保持一致。调整文档结构时须同步更新内部与跨文档引用，不得改动协议传输字段、协议标识符、示例或规范性要求。MCP Connector 沿用此组织顺序，主体按适配器模型、工具定义和返回格式组织。

## 版本管理

协议标识符格式为 `{protocol-name}/{major.minor}`。尚未发布的 Draft 1.0 草案可在正式发布前进行不兼容修订，实现应跟进当前草案要求；正式版本发布后的破坏性变更须递增主版本号。

## 语言版本

英文与简体中文文档应保持严格同步。Pull Request 若修改了任一语言中的规范性要求，应尽量在同一 PR 中同步更新另一语言版本。
