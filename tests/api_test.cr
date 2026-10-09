// Smoke test for the public API. Only touches paths that never hit the
// network ("localhost" is answered locally), and pulls in the whole
// module tree so everything gets compiled by `core test`.
import dns
import dnsip

func main() {
    addrs = dns.resolve_a("localhost")
    assert(addrs.ok(), "localhost resolves")
    assert(addrs.count == 1, "one address")
    assert(addrs.first() == 0x7F000001, "localhost is 127.0.0.1")
    assert(str_eq(dnsip.ipv4_to_string(addrs.first()), "127.0.0.1"), "dotted quad")
    addrs.dispose()

    a6 = dns.resolve_aaaa("localhost")
    assert(a6.ok(), "localhost v6 resolves")
    p = a6.at(0)
    assert(p[0] == 0, "::1 starts zeroed")
    assert(p[15] == 1, "::1 ends in 1")
    a6.dispose()

    say "api_test: all tests passed"
}
