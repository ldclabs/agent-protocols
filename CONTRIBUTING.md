# Contributing

Thank you for helping improve Agent Protocols. This repository contains protocol specifications, so changes should be reviewed for interoperability, security, and long-term compatibility.

## Types of Contributions

Useful contributions include:

- Clarifying ambiguous normative language.
- Proposing protocol changes with compatibility notes.
- Adding examples, diagrams, test vectors, JSON Schemas, or conformance tests.
- Reporting implementation experience from independent clients, hosts, or SDKs.
- Keeping English and Simplified Chinese documents aligned.

## Normative Language

The words `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` are normative. Pull requests that change those words are behavior changes and should explain why the change is needed.

## Pull Request Checklist

Before opening a pull request, please check:

- The change is scoped to one protocol or one clear cross-protocol concern.
- English and Simplified Chinese versions are both updated when normative behavior changes.
- Backward compatibility is described.
- Security and abuse implications are described.
- New identifiers, fields, and event types are stable and consistently named.
- Examples use `did:agent:` Agent IDs and signed event envelopes when relevant.

## Specification Structure

Specifications use the same reading order, with protocol-specific chapters in the middle:

1. **Overview** — purpose, scope, dependencies, and boundaries. Summarize motivation here rather than maintaining a separate Design Goals or Design Principles chapter.
2. **Normative Language** — normative keywords and common interpretation rules.
3. **Protocol body** — identity and data model, encoding and signed events, acceptance and lifecycle rules, then APIs and integration. Split these into as many focused chapters as needed.
4. **Security and Privacy** — trust boundaries, threats, and disclosure considerations.
5. **Conformance** — minimum implementation requirements and positive/negative verification cases, drawn from the body rather than introducing new rules.
6. **Appendices** — test vectors, registered vocabularies, implementation notes, alternatives, and future work. State explicitly when an appendix contains normative material.

Keep numbered chapters consecutive; use lettered appendices. English and Simplified Chinese use matching section numbers. Structural edits must update internal and cross-document references without changing wire fields, protocol identifiers, examples, or normative requirements. The MCP connector follows this order with adapter-specific model, tools, and result chapters.

Specifications describe the current draft only. Do not add "changes from the previous draft" sections; the Git history records how a draft evolved. Keep machine-readable files — JSON Schemas, type packs, and test vectors — in the same pull request as the prose they implement, and keep the SDKs in `crates/`, `packages/`, and `python/` passing those vectors.

## Compatibility Expectations

Draft specifications may change, but changes should avoid unnecessary churn. Prefer additive changes when possible. Breaking changes should call out migration impact and whether a new major protocol version is required.

## Issue Discussions

When proposing a protocol change, please include:

1. Problem statement.
2. Affected protocol documents.
3. Proposed behavior.
4. Alternatives considered.
5. Interoperability impact.
6. Security and privacy impact.

## Language Alignment

The English document is the default cross-implementation review text. The Simplified Chinese document should preserve the same normative requirements. If you can only update one language, please say so in the pull request so maintainers can help align the other version.
