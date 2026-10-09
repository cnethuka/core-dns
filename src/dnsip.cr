// dnsip: dotted-quad helpers and ASCII lowercasing.
//
// IPv4 addresses are passed around as u32 in network byte order,
// so "8.8.8.8" is 0x08080808 - ready to drop into a sockaddr_in.

// "a.b.c.d" -> u32, None if malformed
pub func parse_ipv4(s: string) -> Option<u32> {
    n = len(s)
    if n < 7 or n > 15 { return Option<u32>.None }
    mut result: u32 = 0
    mut octet: u32 = 0
    mut ndots: i32 = 0
    mut ndigits: i32 = 0
    mut i: usize = 0
    while i < n {
        ch = s[i]
        if ch == '.' {
            if ndigits == 0 or octet > 255 { return Option<u32>.None }
            result = (result << 8) | octet
            octet = 0
            ndigits = 0
            ndots += 1
        } else {
            if ch < '0' or ch > '9' { return Option<u32>.None }
            octet = octet * 10 + ((ch as u8 - 48) as u32)
            ndigits += 1
        }
        i += 1
    }
    if ndigits == 0 or ndots != 3 or octet > 255 { return Option<u32>.None }
    result = (result << 8) | octet
    return Option<u32>.Some(result)
}

// u32 -> "a.b.c.d"
pub func ipv4_to_string(ip: u32) -> string {
    return to_string(ip >> 24) + "." + to_string((ip >> 16) & 0xFF) + "." + to_string((ip >> 8) & 0xFF) + "." + to_string(ip & 0xFF)
}

// DNS names compare case-insensitively (RFC 1035 2.3.3)
pub func ascii_lower(s: string) -> string {
    mut out: string = ""
    mut i: usize = 0
    n = len(s)
    while i < n {
        c = s[i]
        if c >= 'A' and c <= 'Z' {
            out = out + to_string((c as u8 + 32) as char)
        } else {
            out = out + to_string(c)
        }
        i += 1
    }
    return out
}
