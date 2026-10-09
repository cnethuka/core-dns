# Roadmap

## Current — v0.1.0

A working stub resolver:

- UDP queries to the system nameserver (`/etc/resolv.conf`, falling back
  to `8.8.8.8`), 2.5 s timeout with one retry
- `resolve_a` / `resolve_aaaa` — host name to address lists, following
  CNAME chains
- `localhost` and `/etc/hosts` short-circuit before any network traffic
- `query` — full replies with answer + authority sections, TTLs, and
  formatted rdata for A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV, CAA
- Wire-level helpers (`dnspkt`) public for anyone building tooling

## Planned

**v0.2 — robustness**
- TCP retry when a reply arrives truncated (TC bit set)
- IPv6 nameservers from `/etc/resolv.conf`
- IPv6 entries honored in `/etc/hosts`
- Response cache with TTLs (repeat lookups shouldn't hit the wire)

**v0.3 — parity with system resolvers**
- `search`-domain expansion for short names
- `options timeout:`/`attempts:` from resolv.conf
- HTTPS/SVCB record support (service discovery for modern protocols)
- Happy Eyeballs (RFC 8305) helper: interleaved A/AAAA + connect ordering

**Later / maybe**
- `getaddrinfo`-shaped one-call API
- DoT/DoH transports
- async queries (the pieces exist: threads + nonblocking sockets)
- DNSSEC validation (needs real crypto; only with a good reason)

## Not planned

- Authoritative server features (zone files, AXFR, answering queries)
- A full-service daemon. This stays a small client library.

## Guiding rule

Stay small, correct and general. Features that serve the whole Core
ecosystem get priority; anything that narrows the library to one kind of
consumer can wait.
