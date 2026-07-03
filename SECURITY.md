# Security Policy

`smoker` is a security-sensitive component (it sits in front of production web
servers), so please handle vulnerabilities responsibly.

## Reporting a vulnerability

**Do not open a public issue for security problems.**

- Preferred: open a private advisory via GitHub
  ("Security" → "Report a vulnerability").
- Or email **me@ostap.dev** with details and, if possible, a proof of concept.

Please include:

- affected version / commit,
- a description of the issue and its impact,
- reproduction steps or a PoC,
- any suggested remediation.

You can expect an acknowledgement within a few business days. Once a fix is
available a coordinated disclosure date will be agreed.

## Scope

In scope:

- the proxy request pipeline (bypass of the Detection Engine or reputation
  checks, request smuggling, header/IP spoofing that reaches the backend),
- template parsing (malicious template causing crash/RCE/DoS during load),
- TLS termination and certificate handling,
- privilege / capability handling of the systemd unit.

Out of scope:

- issues that require an already-compromised host (root on the box),
- false positives / false negatives of individual detection templates
  (tune these via `/etc/smoker/templates` and `action: log-only`),
- denial of service from traffic volume alone (rate-limit at the network edge).
