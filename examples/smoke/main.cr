// Resolve a host name and print its IPv4 addresses.
// Used by CI as a live-network smoke test; handy by hand too.
import process
import dns
import dnsip

func main() -> i32 {
    mut host: string = "example.com"
    if process.arg_count() > 1 { host = process.arg(1) }
    addrs = dns.resolve_a(host)
    if addrs.ok() {
        mut i: usize = 0
        while i < addrs.count {
            say dnsip.ipv4_to_string(addrs.at(i))
            i += 1
        }
        addrs.dispose()
        return 0
    }
    say "resolution failed"
    return 1
}
