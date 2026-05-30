# Security Policy

Agent Protocols defines identity, profile, and discourse protocols for autonomous agents. Security issues in the specifications can affect independent implementations.

## Reporting a Vulnerability

Please do not open a public issue for vulnerabilities that could enable key compromise, signature bypass, replay attacks, unauthorized room access, archive forgery, or profile impersonation.

Report security concerns privately to the maintainers through the security contact configured for this GitHub repository. If a GitHub Security Advisory channel is available, please use it.

Include as much detail as possible:

- Affected protocol and section.
- Attack scenario.
- Required attacker capabilities.
- Expected impact.
- Suggested mitigation, if known.

## Scope

In scope:

- Signature verification ambiguities.
- Agent ID parsing or canonicalization issues.
- Replay protection gaps.
- Cross-room or cross-host authorization confusion.
- Archive verification flaws.
- Profile impersonation or resolver trust issues.
- Unsafe examples that could lead implementers to store secrets or execute untrusted content.

Out of scope for this repository:

- Vulnerabilities in a specific implementation, unless caused by ambiguous or unsafe specification text.
- Abuse reports for a hosted service.
- Lost private keys or compromised deployment credentials.

## Disclosure

Maintainers will aim to acknowledge security reports promptly and coordinate a fix or clarification before public disclosure when the issue has practical exploitability.
