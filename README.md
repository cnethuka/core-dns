# core-dns

[![CI](https://github.com/cnethuka/core-dns/actions/workflows/ci.yml/badge.svg)](https://github.com/cnethuka/core-dns/actions/workflows/ci.yml)

A stub DNS resolver for Core — the client side of DNS. Any program that
touches the network starts here: host names in, addresses and records out.
Pure Core: sockets and the system files are reached through `extern`
libc calls, no dependencies.

It sends queries to a recursive nameserver (the one in `/etc/resolv.conf`,
or `8.8.8.8` if there isn't one) over UDP and parses the replies. It's not
an authoritative server and never answers queries itself.

## Usage

The module to import is `dns`:

```toml
# consumer core.toml
[dependencies]
core-dns = "github.com/cnethuka/core-dns@^0.1"
```

```core
import dns
import dnsip

func main() {
    addrs = dns.resolve_a("example.com")
    if addrs.ok() {
        say dnsip.ipv4_to_string(addrs.first())
    }
    addrs.dispose()
}
```

- `dns.resolve_a(host, server = "") -> dns.AddressList` — IPv4 addresses
  (u32, network order). Checks `localhost`, then `/etc/hosts`, then DNS,
  following CNAMEs.
- `dns.resolve_aaaa(host, server = "") -> dns.AddressList6` — IPv6, 16
  bytes per address via `.at(i)`.
- `dns.query(name, qtype, server = "") -> dns.Response` — the full reply:
  answer + authority records with TTLs and formatted rdata.
  `dns.print_response(resp)` dumps it dig-style.
- `dispose()` / `dns.dispose_response(resp)` release the heap arrays.
- `dnsip.parse_ipv4` / `dnsip.ipv4_to_string` for dotted quads.
- `dnspkt` has the wire-level pieces (`build_query`, `encode_name`,
  `read_name`, `TYPE_*`, ...) if you need them.

`server = ""` (the default) uses the first `nameserver` in
`/etc/resolv.conf`, falling back to `8.8.8.8`.

Every result carries a `status`: the DNS rcode (`0` = NOERROR, `3` =
NXDOMAIN), or negative when the query itself failed (`-1` transport/parse,
`-2` bad arguments). UDP queries time out after 2.5 s, one retry.

Full reference: [docs/api.md](docs/api.md).

## Testing

```
core test
```

## Layout

```
src/
  dns.cr       the public API (query, resolve_a, resolve_aaaa)
  dnspkt.cr    wire format: packet build/parse, name compression
  dnssock.cr   UDP socket FFI
  dnssys.cr    /etc/resolv.conf and /etc/hosts
  dnsip.cr     dotted quads, ascii_lower
tests/         offline unit tests
examples/      live smoke example (used by CI)
docs/          api.md, design.md
```

## Limitations

- UDP only; a truncated reply (TC bit) is reported as-is, no TCP retry.
- The DNS server must be IPv4. No EDNS, no DNSSEC validation.
- Display formatting knows A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV,
  CAA; anything else prints as `\# <len> <hex>`.

## More

- [INSTALL.md](INSTALL.md) — dependency setup, local checkouts
- [ROADMAP.md](ROADMAP.md) — what's here and what's next
- [CONTRIBUTING.md](CONTRIBUTING.md) — dev setup and ground rules
- [SECURITY.md](SECURITY.md) — reporting vulnerabilities
- [docs/design.md](docs/design.md) — how it works inside

## License

MIT (same as the Core compiler).
