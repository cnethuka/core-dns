// dns: a stub resolver for Core.
//
// Sends queries to a recursive nameserver (the one in /etc/resolv.conf,
// or 8.8.8.8) and parses what comes back. This is the client side of
// DNS - the part any networked program needs to turn a host name into
// an address.
//
//   addrs = dns.resolve_a("example.com")
//   if addrs.ok() {
//       ip = addrs.first()                 // u32, network order
//       say dnsip.ipv4_to_string(ip)
//   }
//   addrs.dispose()
//
// The ptr arrays in AddressList/AddressList6/Response are heap-allocated;
// release them with dispose() / dispose_response().
import memory
import time
import dnsip
import dnspkt
import dnssock
import dnssys

// One resource record, decoded and formatted for display.
pub struct Record {
    name: string
    rtype: u16
    rclass: u16
    ttl: u32
    data: string
}

// A parsed query result. status is the header rcode (0 = NOERROR,
// 3 = NXDOMAIN, ...); negative means the query itself never got a usable
// reply: -1 transport/parse failure, -2 bad arguments.
pub struct Response {
    status: i32
    answers: ptr<Record>
    ancount: usize
    authorities: ptr<Record>
    nscount: usize
    arcount: usize
}

pub struct AddressList {
    addrs: ptr<u32>
    count: usize
    status: i32

    pub func ok() -> bool { return self.count > 0 }
    pub func first() -> u32 {
        if self.count == 0 { return 0 }
        return self.addrs[0]
    }
    pub func at(i: usize) -> u32 { return self.addrs[i] }
    pub func dispose() { memory.free(self.addrs) }
}

// IPv6 variant: addrs holds count entries of 16 bytes each.
pub struct AddressList6 {
    addrs: ptr<u8>
    count: usize
    status: i32

    pub func ok() -> bool { return self.count > 0 }
    pub func first() -> ptr<u8> { return self.addrs }
    pub func at(i: usize) -> ptr<u8> { return self.addrs + i * 16 }
    pub func dispose() { memory.free(self.addrs) }
}

mut g_next_id: u32 = 0

// query ids: wall clock mixed with a per-process counter
func make_id() -> u16 {
    g_next_id += 1
    mixed = (time.time_ms() as u32) ^ (g_next_id * 2654435761)
    return (mixed & 0xFFFF) as u16
}

// lowercase + drop one trailing dot, so names compare cleanly
func normalize(host: string) -> string {
    h = dnsip.ascii_lower(host)
    n = len(h)
    if n > 1 and h[n - 1] == '.' {
        mut out: string = ""
        mut i: usize = 0
        limit = n - 1
        while i < limit {
            out = out + to_string(h[i])
            i += 1
        }
        return out
    }
    return h
}

struct RawResult {
    status: i32
    buf: ptr<u8>
    len: usize
}

// One query on the wire (plus one retry). server "" means: system
// nameserver, else 8.8.8.8. On success status >= 0 (the rcode) and the
// caller owns buf; on failure status < 0 and buf is null.
func query_raw(name: string, qtype: u16, server: string) -> RawResult {
    mut srv = server
    if len(srv) == 0 {
        nsopt = dnssys.default_nameserver()
        match nsopt {
            Some(v) { srv = v }
            None { srv = "8.8.8.8" }
        }
    }
    ipopt = dnsip.parse_ipv4(srv)
    mut ipbe: u32 = 0
    match ipopt {
        Some(v) { ipbe = v }
        None { return RawResult { status: -2, buf: null, len: 0 } }
    }
    qbuf = memory.alloc_array<u8>(512)
    rbuf = memory.alloc_array<u8>(4096)
    id = make_id()
    qlen = dnspkt.build_query(qbuf, id, name, qtype)
    if qlen < 0 {
        memory.free(qbuf)
        memory.free(rbuf)
        return RawResult { status: -2, buf: null, len: 0 }
    }
    mut tries = 0
    mut rlen: i64 = -1
    while tries < 2 {
        rlen = dnssock.udp_exchange(ipbe, 53, qbuf, qlen as usize, rbuf, 4096, 2500)
        if rlen >= 12 { break }
        tries += 1
    }
    memory.free(qbuf)
    if rlen < 12 {
        memory.free(rbuf)
        return RawResult { status: -1, buf: null, len: 0 }
    }
    rlen_u = rlen as usize
    // answer must echo our id and be a response, not a stray datagram
    if dnspkt.get_u16(rbuf, 0) != id {
        memory.free(rbuf)
        return RawResult { status: -1, buf: null, len: 0 }
    }
    flags = dnspkt.get_u16(rbuf, 2)
    if (flags & 0x8000) == 0 {
        memory.free(rbuf)
        return RawResult { status: -1, buf: null, len: 0 }
    }
    rcode = (flags & 0xF) as i32
    return RawResult { status: rcode, buf: rbuf, len: rlen_u }
}

// Offset of the first answer record, -1 if the question section is broken.
func answers_offset(buf: ptr<u8>, msglen: usize) -> i32 {
    qd = dnspkt.get_u16(buf, 4)
    mut off: usize = 12
    mut i: u16 = 0
    while i < qd {
        nr = dnspkt.read_name(buf, off, msglen)
        if nr.next < 0 { return -1 }
        if (nr.next as usize) + 4 > msglen { return -1 }
        off = (nr.next as usize) + 4
        i += 1
    }
    return off as i32
}

// Parse up to count records starting at off into out (which must have
// room for count). *parsed gets how many actually parsed; returns the
// offset past the last one.
func parse_records(buf: ptr<u8>, off: usize, msglen: usize, count: usize, out: ptr<Record>, parsed: ptr<usize>) -> usize {
    mut filled: usize = 0
    mut pos = off
    mut i: usize = 0
    while i < count {
        nr = dnspkt.read_name(buf, pos, msglen)
        if nr.next < 0 { break }
        p = nr.next as usize
        if p + 10 > msglen { break }
        rtype = dnspkt.get_u16(buf, p)
        rclass = dnspkt.get_u16(buf, p + 2)
        ttl = dnspkt.get_u32(buf, p + 4)
        rdlen = dnspkt.get_u16(buf, p + 8) as usize
        rdata = p + 10
        if rdata + rdlen > msglen { break }
        out[filled] = Record { name: nr.name, rtype: rtype, rclass: rclass, ttl: ttl, data: dnspkt.format_rdata(buf, rdata, rdlen, rtype, msglen) }
        filled += 1
        pos = rdata + rdlen
        i += 1
    }
    *parsed = filled
    return pos
}

// Full query: parsed answer and authority sections, formatted rdata.
// Free it with dispose_response().
pub func query(name: string, qtype: u16, server: string = "") -> Response {
    rr = query_raw(name, qtype, server)
    if rr.status < 0 {
        return Response { status: rr.status, answers: null, ancount: 0, authorities: null, nscount: 0, arcount: 0 }
    }
    an = dnspkt.get_u16(rr.buf, 6) as usize
    ns = dnspkt.get_u16(rr.buf, 8) as usize
    ar = dnspkt.get_u16(rr.buf, 10) as usize
    aoff = answers_offset(rr.buf, rr.len)
    if aoff < 0 {
        memory.free(rr.buf)
        return Response { status: -1, answers: null, ancount: 0, authorities: null, nscount: 0, arcount: 0 }
    }
    mut recs: ptr<Record> = null
    if an > 0 { recs = memory.alloc_array<Record>(an) }
    mut filled: usize = 0
    aend = parse_records(rr.buf, aoff as usize, rr.len, an, recs, &filled)
    mut authrecs: ptr<Record> = null
    if ns > 0 { authrecs = memory.alloc_array<Record>(ns) }
    mut nfilled: usize = 0
    parse_records(rr.buf, aend, rr.len, ns, authrecs, &nfilled)
    memory.free(rr.buf)
    return Response { status: rr.status, answers: recs, ancount: filled, authorities: authrecs, nscount: nfilled, arcount: ar }
}

pub func dispose_response(r: Response) {
    if r.ancount > 0 { memory.free(r.answers) }
    if r.nscount > 0 { memory.free(r.authorities) }
}

func one_address(ip: u32) -> AddressList {
    out = memory.alloc_array<u32>(1)
    out[0] = ip
    return AddressList { addrs: out, count: 1, status: 0 }
}

// Host name -> IPv4 addresses. localhost and /etc/hosts are checked
// before touching the network; CNAME chains are followed in the reply.
pub func resolve_a(host: string, server: string = "") -> AddressList {
    h = normalize(host)
    if str_eq(h, "localhost") { return one_address(0x7F000001) }
    hip = dnssys.hosts_lookup_ipv4(h)
    match hip {
        Some(v) { return one_address(v) }
        None { }
    }
    rr = query_raw(host, dnspkt.TYPE_A, server)
    if rr.status != 0 {
        memory.free(rr.buf)
        return AddressList { addrs: null, count: 0, status: rr.status }
    }
    aoff = answers_offset(rr.buf, rr.len)
    if aoff < 0 {
        memory.free(rr.buf)
        return AddressList { addrs: null, count: 0, status: -1 }
    }
    an = dnspkt.get_u16(rr.buf, 6) as usize
    mut out: ptr<u32> = memory.alloc_array<u32>(4)
    mut outlen: usize = 0
    mut outcap: usize = 4
    mut target = h
    mut hops = 0
    mut done = false
    // walk the answers, retargeting through CNAMEs until we hit A records
    while !done and hops < 8 {
        mut found = false
        mut cname_target: string = ""
        mut have_cname = false
        mut off = aoff as usize
        mut i: usize = 0
        while i < an {
            nr = dnspkt.read_name(rr.buf, off, rr.len)
            if nr.next < 0 { break }
            p = nr.next as usize
            if p + 10 > rr.len { break }
            rtype = dnspkt.get_u16(rr.buf, p)
            rdlen = dnspkt.get_u16(rr.buf, p + 8) as usize
            rdata = p + 10
            if rdata + rdlen > rr.len { break }
            if str_eq(dnsip.ascii_lower(nr.name), target) {
                if rtype == dnspkt.TYPE_A and rdlen == 4 {
                    if outlen == outcap {
                        outcap = outcap * 2
                        out = memory.realloc_array<u32>(out, outcap)
                    }
                    out[outlen] = dnspkt.get_u32(rr.buf, rdata)
                    outlen += 1
                    found = true
                }
                if rtype == dnspkt.TYPE_CNAME {
                    cn = dnspkt.read_name(rr.buf, rdata, rr.len)
                    if cn.next >= 0 {
                        cname_target = dnsip.ascii_lower(cn.name)
                        have_cname = true
                    }
                }
            }
            off = rdata + rdlen
            i += 1
        }
        if found {
            done = true
        } else {
            if have_cname {
                target = cname_target
                hops += 1
            } else {
                done = true
            }
        }
    }
    memory.free(rr.buf)
    if outlen == 0 {
        memory.free(out)
        return AddressList { addrs: null, count: 0, status: 0 }
    }
    return AddressList { addrs: out, count: outlen, status: 0 }
}

// Host name -> IPv6 addresses (16 bytes each). Same deal as resolve_a.
pub func resolve_aaaa(host: string, server: string = "") -> AddressList6 {
    h = normalize(host)
    if str_eq(h, "localhost") {
        lo = memory.alloc_zeroed_array<u8>(16)
        lo[15] = 1
        return AddressList6 { addrs: lo, count: 1, status: 0 }
    }
    rr = query_raw(host, dnspkt.TYPE_AAAA, server)
    if rr.status != 0 {
        memory.free(rr.buf)
        return AddressList6 { addrs: null, count: 0, status: rr.status }
    }
    aoff = answers_offset(rr.buf, rr.len)
    if aoff < 0 {
        memory.free(rr.buf)
        return AddressList6 { addrs: null, count: 0, status: -1 }
    }
    an = dnspkt.get_u16(rr.buf, 6) as usize
    mut out: ptr<u8> = memory.alloc_array<u8>(64)
    mut outlen: usize = 0
    mut outcap: usize = 4
    mut target = h
    mut hops = 0
    mut done = false
    while !done and hops < 8 {
        mut found = false
        mut cname_target: string = ""
        mut have_cname = false
        mut off = aoff as usize
        mut i: usize = 0
        while i < an {
            nr = dnspkt.read_name(rr.buf, off, rr.len)
            if nr.next < 0 { break }
            p = nr.next as usize
            if p + 10 > rr.len { break }
            rtype = dnspkt.get_u16(rr.buf, p)
            rdlen = dnspkt.get_u16(rr.buf, p + 8) as usize
            rdata = p + 10
            if rdata + rdlen > rr.len { break }
            if str_eq(dnsip.ascii_lower(nr.name), target) {
                if rtype == dnspkt.TYPE_AAAA and rdlen == 16 {
                    if outlen == outcap {
                        outcap = outcap * 2
                        out = memory.realloc_array<u8>(out, outcap * 16)
                    }
                    memory.memcpy(out + outlen * 16, rr.buf + rdata, 16)
                    outlen += 1
                    found = true
                }
                if rtype == dnspkt.TYPE_CNAME {
                    cn = dnspkt.read_name(rr.buf, rdata, rr.len)
                    if cn.next >= 0 {
                        cname_target = dnsip.ascii_lower(cn.name)
                        have_cname = true
                    }
                }
            }
            off = rdata + rdlen
            i += 1
        }
        if found {
            done = true
        } else {
            if have_cname {
                target = cname_target
                hops += 1
            } else {
                done = true
            }
        }
    }
    memory.free(rr.buf)
    if outlen == 0 {
        memory.free(out)
        return AddressList6 { addrs: null, count: 0, status: 0 }
    }
    return AddressList6 { addrs: out, count: outlen, status: 0 }
}

func print_records(recs: ptr<Record>, count: usize) {
    mut i: usize = 0
    while i < count {
        r = recs[i]
        mut nm = r.name
        if len(nm) == 0 { nm = "." } else { nm = nm + "." }
        say nm + "\t" + to_string(r.ttl) + "\t" + dnspkt.class_name(r.rclass) + "\t" + dnspkt.type_name(r.rtype) + "\t" + r.data
        i += 1
    }
}

// dig-like dump, handy when debugging
pub func print_response(r: Response) {
    say ";; status: " + dnspkt.rcode_name(r.status) + ", answers: " + to_string(r.ancount) + ", authority: " + to_string(r.nscount) + ", additional: " + to_string(r.arcount)
    if r.ancount > 0 { say ";; ANSWER SECTION:" }
    print_records(r.answers, r.ancount)
    if r.nscount > 0 { say ";; AUTHORITY SECTION:" }
    print_records(r.authorities, r.nscount)
}
