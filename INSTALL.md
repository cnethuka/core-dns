# Installing core-dns

## Requirements

- Linux (x86_64, aarch64 or riscv64)
- The Core toolchain — one line:

```console
curl -fsSL https://raw.githubusercontent.com/snitchbossdotcom/corelang/main/install.sh | bash
```

core-dns is pure Core with libc FFI only. There are no other
dependencies.

## As a dependency (the normal case)

In your project's `core.toml`:

```toml
[dependencies]
core-dns = "github.com/cnethuka/core-dns@^0.1"
```

or let the tool write that for you:

```console
core install github.com/cnethuka/core-dns
```

Then in your code:

```core
import dns

addrs = dns.resolve_a("example.com")
```

## From a local checkout (development)

```console
git clone https://github.com/cnethuka/core-dns.git
```

and point your project at it with a path dependency:

```toml
[dependencies]
core-dns = { path = "../core-dns" }
```

An absolute or `./`-relative path is used in place — edits take effect on
your next `core build`, nothing to reinstall.

## Verifying the checkout

```console
cd core-dns
core test                            # offline unit tests
cd examples/smoke
core install "$PWD/../.."            # point the smoke consumer at this checkout
core build
./smoke example.com                  # live lookup, should print IPv4 addresses
```

## Uninstalling

`core remove core-dns` drops it from your project. Nothing is installed
system-wide; the git cache under `~/.cache/core` can be deleted freely.
