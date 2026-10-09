# Contributing

Bug reports, fixes and new record types are all welcome.

## Setup

You need the Core toolchain (Linux x86_64, aarch64 or riscv64):

```console
curl -fsSL https://raw.githubusercontent.com/snitchbossdotcom/corelang/main/install.sh | bash
git clone https://github.com/cnethuka/core-dns.git
cd core-dns
core test
```

## Layout

```
src/
  dns.cr       public API: query, resolve_a, resolve_aaaa
  dnspkt.cr    wire format: packet build/parse, name compression
  dnssock.cr   UDP socket FFI
  dnssys.cr    /etc/resolv.conf and /etc/hosts
  dnsip.cr     dotted quads, ascii_lower
tests/         offline unit tests (one main() per file)
examples/      smoke example, used by CI
docs/          API reference and design notes
```

Module names come from file stems, and this package's files are all
`dns*`-prefixed to avoid colliding with consumer modules.

## Ground rules

- No garbage collector: every `alloc_array`/`alloc_bytes` you add needs a
  matching, documented owner who frees it.
- Anything reachable from another module must be `pub`; keep everything
  else private.
- `core test` must pass. Tests must not touch the network.
- Match the existing style: tabs of 4 spaces, newline-terminated
  statements, short comments that explain *why*, not what.
- Packet fields are read/written byte by byte in network order — don't
  introduce typed-struct overlays onto the wire.

## Pull requests

One change per PR, with a test in `tests/` when the change is testable
offline. If you fix something that only shows up against real DNS
traffic, say how you reproduced it in the PR description.
