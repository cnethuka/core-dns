// Offline tests for the wire format and address helpers.
// (The network path is easier to eyeball through real queries than to
// mock here.)
import memory
import dnsip
import dnspkt

func main() {
    buf = memory.alloc_array<u8>(512)

    // encode_name
    n = dnspkt.encode_name(buf, 12, "www.example.com")
    assert(n == 29, "encode_name length")
    assert(buf[12] == 3, "label len www")
    assert(buf[13] == ('w' as u8), "label bytes")
    assert(buf[16] == 7, "label len example")
    assert(buf[24] == 3, "label len com")
    assert(buf[28] == 0, "root terminator")

    // one trailing dot is fine
    assert(dnspkt.encode_name(buf, 12, "www.example.com.") == 29, "trailing dot")

    // read_name roundtrip
    nr = dnspkt.read_name(buf, 12, 29)
    assert(nr.next == 29, "read_name next")
    assert(str_eq(nr.name, "www.example.com"), "read_name value")

    // read_name with a compression pointer back into the name above
    buf[100] = 4
    buf[101] = ('m' as u8)
    buf[102] = ('a' as u8)
    buf[103] = ('i' as u8)
    buf[104] = ('l' as u8)
    buf[105] = 0xC0
    buf[106] = 16
    nr2 = dnspkt.read_name(buf, 100, 200)
    assert(nr2.next == 107, "compression next")
    assert(str_eq(nr2.name, "mail.example.com"), "compression value")

    // bad names get rejected (note: these scribble on buf, so they run
    // after anything that still reads the encoded name)
    assert(dnspkt.encode_name(buf, 12, "") == -1, "empty name")
    assert(dnspkt.encode_name(buf, 12, ".") == -1, "root only")
    assert(dnspkt.encode_name(buf, 12, "a..b") == -1, "empty label")

    // build_query header layout
    qlen = dnspkt.build_query(buf, 0x1234, "example.com", dnspkt.TYPE_A)
    assert(qlen == 29, "query length")
    assert(dnspkt.get_u16(buf, 0) == 0x1234, "query id")
    assert(dnspkt.get_u16(buf, 2) == 0x0100, "RD flag")
    assert(dnspkt.get_u16(buf, 4) == 1, "qdcount")
    assert(dnspkt.get_u16(buf, 25) == dnspkt.TYPE_A, "qtype")
    assert(dnspkt.get_u16(buf, 27) == dnspkt.CLASS_IN, "qclass")

    // parse_ipv4
    m = dnsip.parse_ipv4("8.8.8.8")
    match m {
        Some(v) { assert(v == 0x08080808, "parse 8.8.8.8") }
        None { assert(false, "parse 8.8.8.8 returned None") }
    }
    m2 = dnsip.parse_ipv4("255.255.255.255")
    match m2 {
        Some(v) { assert(v == 0xFFFFFFFF, "parse broadcast") }
        None { assert(false, "parse broadcast returned None") }
    }
    bad1 = dnsip.parse_ipv4("8.8.8")
    match bad1 {
        Some(_) { assert(false, "short quad accepted") }
        None { }
    }
    bad2 = dnsip.parse_ipv4("8.8.8.256")
    match bad2 {
        Some(_) { assert(false, "octet overflow accepted") }
        None { }
    }
    bad3 = dnsip.parse_ipv4("8.8.8.x")
    match bad3 {
        Some(_) { assert(false, "garbage accepted") }
        None { }
    }

    assert(str_eq(dnsip.ipv4_to_string(0x7F000001), "127.0.0.1"), "format loopback")
    assert(str_eq(dnsip.ascii_lower("WwW.Example.COM."), "www.example.com."), "ascii_lower")

    assert(dnspkt.type_from_string("MX") == 15, "type MX")
    assert(dnspkt.type_from_string("aaaa") == 28, "type aaaa")
    assert(dnspkt.type_from_string("bogus") == 0, "type bogus")
    assert(str_eq(dnspkt.type_name(15), "MX"), "type name MX")

    memory.free(buf)
    say "dns_test: all tests passed"
}
