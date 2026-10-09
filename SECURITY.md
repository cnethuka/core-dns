# Security

## Reporting a vulnerability

Please don't open a public issue for security problems. Use GitHub's
"Report a vulnerability" button on the repository's Security tab, and
include enough detail to reproduce the issue.

We try to respond within a few days.

## Scope

This library parses DNS responses, which are untrusted input arriving
from the network. The things we care most about:

- memory-safety bugs in packet parsing (out-of-bounds reads/writes,
  compression-pointer loops)
- crashes caused by malformed or malicious responses
- cache/poisoning-adjacent issues (wrong answers accepted for a name)

Bugs in parsing are treated as security issues even when they "only"
crash, because this code runs inside whatever application links it.

## Notes

- Responses are matched to queries by transaction ID. There is no DNSSEC
  validation yet; treat results as untrusted as any plain UDP DNS.
- The resolver only talks UDP to the configured nameserver. Keep that
  server trusted (your system resolver, typically).
