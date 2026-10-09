# Design notes

## What this is

A stub resolver: it asks a recursive nameserver questions and parses the
answers. It never answers queries itself and holds no zone data. It serves
any program that needs `hostname -> addresses` or record lookups.

## Module map

```
dns.cr      public API, query orchestration, CNAME chasing
dnspkt.cr   wire format: header/question/record encode+decode
dnssock.cr  one UDP exchange via libc (socket/sendto/recvfrom)
dnssys.cr   /etc/resolv.conf, /etc/hosts
dnsip.cr    dotted-quad conversion, case folding
```

Dependencies point inward: `dns` sits on top, `dnspkt` and `dnsip` depend
on nothing. File stems are `dns*`-prefixed so consumers' modules don't
collide with them on the import path.

## Wire format choices

All multibyte packet fields are read and written byte by byte in network
order. No `@packed` struct overlays onto the packet: explicit accessors
(`get_u16`/`put_u16`) are endian-neutral by construction and keep the
parser honest about bounds.

`read_name` follows compression pointers with a hop cap (128) so a
malformed response can't send the parser into a loop. Every read checks
against the message length before touching memory.

## Resolution order in resolve_a/resolve_aaaa

1. `localhost` (answered locally, both families)
2. `/etc/hosts` (IPv4 only for now)
3. DNS query, following CNAMEs inside the answer section (max 8 hops,
   loop-safe)

The nameserver is the first valid IPv4 `nameserver` line in
`/etc/resolv.conf`, or `8.8.8.8` when that file is missing or unusable.

## Errors

No exceptions exist in Core, so results carry a `status`: the DNS rcode
when a reply arrived, negative when the query itself failed. Parsing is
best-effort — a malformed record ends the section early instead of
poisoning the whole response.

## Memory

No GC. Query/response buffers are freed inside the library. What escapes
into results is documented: the address arrays (freed by `dispose()`) and
the record arrays (freed by `dispose_response()`). Strings inside
`Record` follow the normal Core idiom — runtime-allocated, process
lifetime — same as any string concatenation in the language.

## Threads

The resolver is blocking and keeps no global state besides the query-id
counter, so calling it from several threads is safe. The counter itself
is a plain `u32`; worst case two concurrent queries share an id and one
reply is discarded as a mismatch and retried.

## Deliberate limits

- UDP only, no TCP retry on truncation (planned, v0.2)
- IPv4 nameservers only (planned, v0.2)
- no EDNS, no DNSSEC validation
- no caching (planned, v0.2)
