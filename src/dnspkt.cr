// dnspkt: the DNS wire format (RFC 1035, UDP, no EDNS).
//
// Multibyte packet fields are read and written byte by byte in network
// order, so nothing here depends on host endianness.

// record types
pub const TYPE_A: u16 = 1
pub const TYPE_NS: u16 = 2
pub const TYPE_CNAME: u16 = 5
pub const TYPE_SOA: u16 = 6
pub const TYPE_PTR: u16 = 12
pub const TYPE_MX: u16 = 15
pub const TYPE_TXT: u16 = 16
pub const TYPE_AAAA: u16 = 28
pub const TYPE_SRV: u16 = 33
pub const TYPE_CAA: u16 = 257

pub const CLASS_IN: u16 = 1

// read_name's answer: the dotted name (no trailing dot) plus the offset
// just past the encoded name. next is -1 on error.
pub struct NameResult {
    name: string
    next: i32
}

pub func get_u16(buf: ptr<u8>, off: usize) -> u16 {
    return (buf[off] as u16 << 8) | (buf[off + 1] as u16)
}

pub func get_u32(buf: ptr<u8>, off: usize) -> u32 {
    return (buf[off] as u32 << 24) | (buf[off + 1] as u32 << 16) | (buf[off + 2] as u32 << 8) | (buf[off + 3] as u32)
}

pub func put_u16(buf: ptr<u8>, off: usize, v: u16) {
    buf[off] = (v >> 8) as u8
    buf[off + 1] = (v & 0xFF) as u8
}

// Write "www.example.com" as DNS labels at buf[off]. One trailing dot is
// fine (FQDN form). Returns the offset after the name, -1 if invalid.
pub func encode_name(buf: ptr<u8>, off: usize, name: string) -> i32 {
    n = len(name)
    if n == 0 { return -1 }
    mut end = n
    if end > 1 and name[end - 1] == '.' { end = end - 1 }
    mut pos = off
    mut lstart = off
    mut llen: usize = 0
    pos = pos + 1
    mut i: usize = 0
    while i < end {
        ch = name[i]
        if ch == '.' {
            if llen == 0 { return -1 }
            buf[lstart] = llen as u8
            lstart = pos
            pos = pos + 1
            llen = 0
        } else {
            if llen >= 63 { return -1 }
            buf[pos] = ch as u8
            pos = pos + 1
            llen = llen + 1
        }
        i += 1
    }
    if llen == 0 { return -1 }
    buf[lstart] = llen as u8
    buf[pos] = 0
    pos = pos + 1
    return pos as i32
}

// Decode the name at buf[off], following compression pointers
// (RFC 1035 4.1.4). The hop cap guards against pointer loops.
pub func read_name(buf: ptr<u8>, off: usize, msglen: usize) -> NameResult {
    mut result: string = ""
    mut pos = off
    mut next: i32 = -1
    mut jumped = false
    mut hops = 0
    mut ok = true
    mut done = false
    while !done {
        if pos >= msglen { ok = false; break }
        b = buf[pos] as i32
        if b == 0 {
            if !jumped { next = (pos + 1) as i32 }
            done = true
        } else if (b & 0xC0) == 0xC0 {
            if pos + 1 >= msglen { ok = false; break }
            target = ((b & 0x3F) << 8) | (buf[pos + 1] as i32)
            if !jumped { next = (pos + 2) as i32 }
            jumped = true
            pos = target as usize
            hops += 1
            if hops > 128 { ok = false; break }
        } else if (b & 0xC0) == 0 {
            labellen = b as usize
            if pos + 1 + labellen > msglen { ok = false; break }
            if len(result) > 0 { result = result + "." }
            mut j: usize = 0
            while j < labellen {
                result = result + to_string(buf[pos + 1 + j] as char)
                j += 1
            }
            pos = pos + 1 + labellen
        } else {
            ok = false
            break
        }
    }
    if !ok { return NameResult { name: "", next: -1 } }
    return NameResult { name: result, next: next }
}

// Standard query, RD set, one question. buf needs room for the packet
// (512 is plenty). Returns packet length, -1 if the name is invalid.
pub func build_query(buf: ptr<u8>, id: u16, name: string, qtype: u16) -> i32 {
    if len(name) == 0 or len(name) > 253 { return -1 }
    put_u16(buf, 0, id)
    put_u16(buf, 2, 0x0100)
    put_u16(buf, 4, 1)
    put_u16(buf, 6, 0)
    put_u16(buf, 8, 0)
    put_u16(buf, 10, 0)
    qend = encode_name(buf, 12, name)
    if qend < 0 { return -1 }
    p = qend as usize
    put_u16(buf, p, qtype)
    put_u16(buf, p + 2, CLASS_IN)
    return (p + 4) as i32
}

pub func type_name(t: u16) -> string {
    switch t {
        case 1: return "A"
        case 2: return "NS"
        case 5: return "CNAME"
        case 6: return "SOA"
        case 12: return "PTR"
        case 15: return "MX"
        case 16: return "TXT"
        case 28: return "AAAA"
        case 33: return "SRV"
        case 257: return "CAA"
        default: return "TYPE" + to_string(t)
    }
}

// mnemonic -> numeric type, 0 if unknown
pub func type_from_string(s: string) -> u16 {
    if str_eq(s, "A") or str_eq(s, "a") { return TYPE_A }
    if str_eq(s, "NS") or str_eq(s, "ns") { return TYPE_NS }
    if str_eq(s, "CNAME") or str_eq(s, "cname") { return TYPE_CNAME }
    if str_eq(s, "SOA") or str_eq(s, "soa") { return TYPE_SOA }
    if str_eq(s, "PTR") or str_eq(s, "ptr") { return TYPE_PTR }
    if str_eq(s, "MX") or str_eq(s, "mx") { return TYPE_MX }
    if str_eq(s, "TXT") or str_eq(s, "txt") { return TYPE_TXT }
    if str_eq(s, "AAAA") or str_eq(s, "aaaa") { return TYPE_AAAA }
    if str_eq(s, "SRV") or str_eq(s, "srv") { return TYPE_SRV }
    if str_eq(s, "CAA") or str_eq(s, "caa") { return TYPE_CAA }
    return 0
}

pub func class_name(c: u16) -> string {
    switch c {
        case 1: return "IN"
        case 3: return "CH"
        case 4: return "HS"
        default: return "CLASS" + to_string(c)
    }
}

pub func rcode_name(rc: i32) -> string {
    switch rc {
        case 0: return "NOERROR"
        case 1: return "FORMERR"
        case 2: return "SERVFAIL"
        case 3: return "NXDOMAIN"
        case 4: return "NOTIMP"
        case 5: return "REFUSED"
        default: return "RCODE" + to_string(rc)
    }
}

func hex_d(n: u16) -> string {
    if n < 10 { return to_string(n) }
    return to_string((n + 87) as char)
}

func hex4(v: u16) -> string {
    return hex_d((v >> 12) & 0xF) + hex_d((v >> 8) & 0xF) + hex_d((v >> 4) & 0xF) + hex_d(v & 0xF)
}

// dig-style fallback for rdata we don't understand: \# <len> <hex>
func hex_dump(msg: ptr<u8>, off: usize, count: usize) -> string {
    mut out: string = "\\# " + to_string(count)
    mut i: usize = 0
    while i < count {
        b = msg[off + i] as u16
        out = out + " " + hex_d((b >> 4) & 0xF) + hex_d(b & 0xF)
        i += 1
    }
    return out
}

// Format rdata for display. msg/msglen is the whole packet (compressed
// names can point anywhere in it); caller checked rdata + rdlen <= msglen.
pub func format_rdata(msg: ptr<u8>, rdata: usize, rdlen: usize, rtype: u16, msglen: usize) -> string {
    if rtype == TYPE_A {
        if rdlen != 4 { return hex_dump(msg, rdata, rdlen) }
        return to_string(msg[rdata]) + "." + to_string(msg[rdata + 1]) + "." + to_string(msg[rdata + 2]) + "." + to_string(msg[rdata + 3])
    }
    if rtype == TYPE_AAAA {
        if rdlen != 16 { return hex_dump(msg, rdata, rdlen) }
        mut out6: string = ""
        mut g: usize = 0
        while g < 8 {
            if g > 0 { out6 = out6 + ":" }
            out6 = out6 + hex4(get_u16(msg, rdata + g * 2))
            g += 1
        }
        return out6
    }
    if rtype == TYPE_CNAME or rtype == TYPE_NS or rtype == TYPE_PTR {
        nr = read_name(msg, rdata, msglen)
        if nr.next < 0 { return "<malformed name>" }
        return nr.name + "."
    }
    if rtype == TYPE_MX {
        if rdlen < 3 { return hex_dump(msg, rdata, rdlen) }
        pref = get_u16(msg, rdata)
        nr = read_name(msg, rdata + 2, msglen)
        if nr.next < 0 { return "<malformed name>" }
        return to_string(pref) + " " + nr.name + "."
    }
    if rtype == TYPE_SOA {
        mname = read_name(msg, rdata, msglen)
        if mname.next < 0 { return "<malformed name>" }
        rname = read_name(msg, mname.next as usize, msglen)
        if rname.next < 0 { return "<malformed name>" }
        p = rname.next as usize
        if p + 20 > msglen { return "<truncated soa>" }
        return mname.name + ". " + rname.name + ". " + to_string(get_u32(msg, p)) + " " + to_string(get_u32(msg, p + 4)) + " " + to_string(get_u32(msg, p + 8)) + " " + to_string(get_u32(msg, p + 12)) + " " + to_string(get_u32(msg, p + 16))
    }
    if rtype == TYPE_TXT {
        mut out: string = ""
        mut q = rdata
        fin = rdata + rdlen
        while q < fin {
            slen = msg[q] as usize
            q += 1
            if q + slen > fin { break }
            out = out + " \""
            mut j: usize = 0
            while j < slen {
                out = out + to_string(msg[q + j] as char)
                j += 1
            }
            out = out + "\""
            q += slen
        }
        return out
    }
    if rtype == TYPE_SRV {
        if rdlen < 7 { return hex_dump(msg, rdata, rdlen) }
        prio = get_u16(msg, rdata)
        weight = get_u16(msg, rdata + 2)
        port = get_u16(msg, rdata + 4)
        nr = read_name(msg, rdata + 6, msglen)
        if nr.next < 0 { return "<malformed name>" }
        return to_string(prio) + " " + to_string(weight) + " " + to_string(port) + " " + nr.name + "."
    }
    if rtype == TYPE_CAA {
        if rdlen < 2 { return hex_dump(msg, rdata, rdlen) }
        flags = msg[rdata] as i32
        taglen = msg[rdata + 1] as usize
        if 2 + taglen > rdlen { return hex_dump(msg, rdata, rdlen) }
        mut tag: string = ""
        mut k: usize = 0
        while k < taglen {
            tag = tag + to_string(msg[rdata + 2 + k] as char)
            k += 1
        }
        mut val: string = ""
        k = rdata + 2 + taglen
        vend = rdata + rdlen
        while k < vend {
            val = val + to_string(msg[k] as char)
            k += 1
        }
        return to_string(flags) + " " + tag + " \"" + val + "\""
    }
    return hex_dump(msg, rdata, rdlen)
}
