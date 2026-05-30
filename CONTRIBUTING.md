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
