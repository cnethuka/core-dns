// dnssock: UDP I/O through libc sockets (Linux).
import memory

const AF_INET: i32 = 2
const SOCK_DGRAM: i32 = 2
const SOL_SOCKET: i32 = 1
const SO_RCVTIMEO: i32 = 20

extern func socket(domain: i32, stype: i32, protocol: i32) -> i32
extern func sendto(fd: i32, buf: ptr<u8>, len: usize, flags: i32, addr: ptr<u8>, addrlen: u32) -> i64
extern func recvfrom(fd: i32, buf: ptr<u8>, len: usize, flags: i32, addr: ptr<u8>, addrlen: ptr<u32>) -> i64
extern func setsockopt(fd: i32, level: i32, optname: i32, optval: ptr<i64>, optlen: u32) -> i32
extern func close(fd: i32) -> i32

// 16-byte sockaddr_in. ip_be and port go in network byte order;
// sin_family is host order, hence the typed store.
func build_sockaddr(sa: ptr<u8>, ip_be: u32, port: u16) {
    unsafe {
        fam = sa as ptr<u16>
        *fam = 2
    }
    sa[2] = (port >> 8) as u8
    sa[3] = (port & 0xFF) as u8
    sa[4] = (ip_be >> 24) as u8
    sa[5] = ((ip_be >> 16) & 0xFF) as u8
    sa[6] = ((ip_be >> 8) & 0xFF) as u8
    sa[7] = (ip_be & 0xFF) as u8
}

// Send one datagram to ip_be:port, wait for one reply.
// Returns reply length, -1 on error/timeout.
pub func udp_exchange(ip_be: u32, port: u16, qbuf: ptr<u8>, qlen: usize, rbuf: ptr<u8>, rcap: usize, timeout_ms: i64) -> i64 {
    fd = socket(AF_INET, SOCK_DGRAM, 0)
    if fd < 0 { return -1 }

    // SO_RCVTIMEO so a dropped packet can't hang us
    tv = memory.alloc_array<i64>(2)
    tv[0] = timeout_ms / 1000
    tv[1] = (timeout_ms % 1000) * 1000
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, tv, 16)
    memory.free(tv)

    sa = memory.alloc_zeroed_array<u8>(16)
    build_sockaddr(sa, ip_be, port)
    sent = sendto(fd, qbuf, qlen, 0, sa, 16)
    memory.free(sa)
    if sent < 0 {
        close(fd)
        return -1
    }
    n = recvfrom(fd, rbuf, rcap, 0, null, null)
    close(fd)
    if n < 0 { return -1 }
    return n
}
