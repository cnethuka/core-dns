// dnssys: system resolver config - /etc/resolv.conf and /etc/hosts.
// The stdlib has no file I/O yet, so this uses open/read directly.
import memory
import dnsip

extern func open(path: ptr<char>, flags: i32) -> i32
extern func read(fd: i32, buf: ptr<u8>, count: usize) -> i64
extern func close(fd: i32) -> i32

// Slurp a file into buf (cap bytes max). Byte count, or -1.
func read_file(path: string, buf: ptr<u8>, cap: usize) -> i64 {
    fd = open(c_str(path), 0)
    if fd < 0 { return -1 }
    n = read(fd, buf, cap)
    close(fd)
    return n
}

// The which-th whitespace-separated token of buf[start..e], or "" if
// there isn't one. '#' comments out the rest of the line.
func line_token(buf: ptr<u8>, start: usize, e: usize, which: i32) -> string {
    mut i = start
    mut idx: i32 = 0
    while i < e {
        c = buf[i] as char
        if c == '#' { return "" }
        if c == ' ' or c == '\t' or c == '\r' {
            i += 1
        } else {
            mut j = i
            mut stop = false
            while j < e and !stop {
                cj = buf[j] as char
                if cj == ' ' or cj == '\t' or cj == '\r' or cj == '#' {
                    stop = true
                } else {
                    j += 1
                }
            }
            if idx == which {
                mut out: string = ""
                mut k = i
                while k < j {
                    out = out + to_string(buf[k] as char)
                    k += 1
                }
                return out
            }
            idx += 1
            i = j
        }
    }
    return ""
}

// First usable IPv4 nameserver from /etc/resolv.conf.
pub func default_nameserver() -> Option<string> {
    buf = memory.alloc_array<u8>(16384)
    n = read_file("/etc/resolv.conf", buf, 16384)
    if n <= 0 {
        memory.free(buf)
        return Option<string>.None
    }
    total = n as usize
    mut start: usize = 0
    while start < total {
        mut e = start
        while e < total and buf[e] as char != '\n' { e += 1 }
        kw = line_token(buf, start, e, 0)
        if str_eq(kw, "nameserver") {
            addr = line_token(buf, start, e, 1)
            if len(addr) > 0 {
                v = dnsip.parse_ipv4(addr)
                match v {
                    Some(_) {
                        memory.free(buf)
                        return Option<string>.Some(addr)
                    }
                    None { }
                }
            }
        }
        start = e + 1
    }
    memory.free(buf)
    return Option<string>.None
}

// First IPv4 address for host (already lowercased) in /etc/hosts.
pub func hosts_lookup_ipv4(host: string) -> Option<u32> {
    buf = memory.alloc_array<u8>(65536)
    n = read_file("/etc/hosts", buf, 65536)
    if n <= 0 {
        memory.free(buf)
        return Option<u32>.None
    }
    total = n as usize
    mut start: usize = 0
    while start < total {
        mut e = start
        while e < total and buf[e] as char != '\n' { e += 1 }
        iptok = line_token(buf, start, e, 0)
        if len(iptok) > 0 {
            v = dnsip.parse_ipv4(iptok)
            match v {
                Some(ip) {
                    mut t: i32 = 1
                    loop {
                        nm = line_token(buf, start, e, t)
                        if len(nm) == 0 { break }
                        if str_eq(dnsip.ascii_lower(nm), host) {
                            memory.free(buf)
                            return Option<u32>.Some(ip)
                        }
                        t += 1
                    }
                }
                None { }
            }
        }
        start = e + 1
    }
    memory.free(buf)
    return Option<u32>.None
}
