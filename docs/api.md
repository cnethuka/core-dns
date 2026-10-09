# API reference

The import-facing module is `dns`; helper modules are `dnsip`, `dnspkt`,
`dnssock` and `dnssys`. Everything listed here is `pub`.

Conventions:

- IPv4 addresses are `u32` in network byte order (`8.8.8.8` =
  `0x08080808`).
- `status` fields carry the DNS rcode (`0` = NOERROR, `3` = NXDOMAIN) or a
  negative library error: `-1` transport/parse failure, `-2` bad
  arguments.
- Heap arrays in results are yours to release: `dispose()` on address
  lists, `dns.dispose_response()` on responses.

## Module `dns`

### Types

```core
dns.Record        // name, rtype, rclass, ttl, data (formatted string)
dns.Response      // status, answers/ancount, authorities/nscount, arcount
dns.AddressList   // addrs: ptr<u32>, count, status
dns.AddressList6  // addrs: ptr<u8> (16 bytes per entry), count, status
```

`AddressList` / `AddressList6` methods:

```core
ok() -> bool            // count > 0
first() -> u32          // AddressList6: first() -> ptr<u8>
at(i: usize)            // AddressList: u32; AddressList6: ptr<u8>
dispose()               // frees the backing array
```

### Functions

```core
dns.resolve_a(host: string, server: string = "") -> dns.AddressList
dns.resolve_aaaa(host: string, server: string = "") -> dns.AddressList6
```

Host name to addresses. `localhost` and `/etc/hosts` are checked first;
DNS answers are walked through CNAME chains. Empty `server` means the
first nameserver in `/etc/resolv.conf`, else `8.8.8.8`.

```core
dns.query(name: string, qtype: u16, server: string = "") -> dns.Response
```

Full query: parsed answer and authority records with formatted rdata.

```core
dns.print_response(r: dns.Response)    // dig-style dump
dns.dispose_response(r: dns.Response)  // frees the record arrays
```

## Module `dnsip`

```core
dnsip.parse_ipv4(s: string) -> Option<u32>   // "1.2.3.4" -> network-order u32
dnsip.ipv4_to_string(ip: u32) -> string      // and back
dnsip.ascii_lower(s: string) -> string       // DNS names fold case
```

## Module `dnspkt` (wire format)

```core
dnspkt.TYPE_A / TYPE_NS / TYPE_CNAME / TYPE_SOA / TYPE_PTR /
dnspkt.TYPE_MX / TYPE_TXT / TYPE_AAAA / TYPE_SRV / TYPE_CAA
dnspkt.CLASS_IN

dnspkt.build_query(buf: ptr<u8>, id: u16, name: string, qtype: u16) -> i32
dnspkt.encode_name(buf: ptr<u8>, off: usize, name: string) -> i32
dnspkt.read_name(buf: ptr<u8>, off: usize, msglen: usize) -> dnspkt.NameResult
dnspkt.format_rdata(msg: ptr<u8>, rdata: usize, rdlen: usize, rtype: u16, msglen: usize) -> string

dnspkt.get_u16 / dnspkt.get_u32 / dnspkt.put_u16   // big-endian accessors
dnspkt.type_name(t: u16) -> string
dnspkt.type_from_string(s: string) -> u16          // 0 if unknown
dnspkt.class_name(c: u16) -> string
dnspkt.rcode_name(rc: i32) -> string
```

`read_name` follows compression pointers (hop-capped) and returns
`NameResult { name, next }`, with `next == -1` on malformed input.

## Module `dnssock`

```core
dnssock.udp_exchange(ip_be: u32, port: u16, qbuf: ptr<u8>, qlen: usize,
                     rbuf: ptr<u8>, rcap: usize, timeout_ms: i64) -> i64
```

One datagram out, one reply in. Reply length, or `-1` on error/timeout.

## Module `dnssys`

```core
dnssys.default_nameserver() -> Option<string>       // from /etc/resolv.conf
dnssys.hosts_lookup_ipv4(host: string) -> Option<u32>   // from /etc/hosts
```
