# injspoof

injspoof is a high-performance Layer-2 packet tunnel. It takes UDP traffic from a
local application, wraps each datagram in a raw Ethernet frame whose source IP is
drawn from a configurable pool, and ships it to a remote peer. A 5-byte Host
IDentifier (HID) prepended to every payload lets a single server demultiplex many
clients. The wire encapsulation can masquerade as TCP, UDP, or ICMP.

The core is written in C with an optional XDP/AF_XDP fast path and is built to
sustain millions of concurrent flows on commodity hardware.

## How it works

```
 local app --UDP--> [ client ] --raw L2, spoofed src IP--> [ server ] --UDP--> backend
                        |  prepend 11-byte header              |  strip header, route by HID
                        +--------------- return path ----------+
```

- **Client mode** reads UDP from a local `forward` listener, prepends the peer's
  header, builds a spoofed raw frame, and transmits it to the server.
- **Server mode** captures raw frames, reads the HID to find the originating peer,
  removes the header, and forwards the payload to the configured redirect target.
  Replies travel back through the same tunnel using the peer's firewall rule.

## Quick start

```bash
# Build (portable AF_PACKET build)
make

# Grant raw-socket capability instead of running as root
sudo setcap cap_net_raw+ep ./injspoof

# Run
sudo ./injspoof --mode server --config example/server.json
sudo ./injspoof --mode client --config example/client.json
```

Copy a file from [`example/`](example/), set your interface names, peer addresses,
IP pools, and a strong `api.token`, then launch. injspoof validates the entire
configuration before opening any socket.

> Spoofed TCP/ICMP flows require host firewall rules so the kernel does not reset
> them. See [docs/OPERATIONS.md](docs/OPERATIONS.md#blocking-unwanted-kernel-responses).

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Internals: module map, data model, threading, concurrency, reload, eBPF. |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Exhaustive field reference, examples, validation rules, capacity limits. |
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | Wire format: the 11-byte header, HID routing, encapsulation, fragmentation. |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Build, capabilities, firewall blocking, management API, metrics, troubleshooting. |
| [docs/PERFORMANCE.md](docs/PERFORMANCE.md) | Optimizations, scaling, the fast path, tuning, and measurement. |

## Features

- Layer-2 raw injection with configurable source-IP and source-port pools.
- TCP / UDP / ICMP encapsulation with selectable TCP flags and SEQ/ACK policy.
- O(1) HID demultiplexing for many clients on a single server.
- Per-peer firewall rules, named interfaces, and per-direction protocols.
- Optional XDP/AF_XDP zero-copy fast path with automatic driver detection.
- Fail-fast validation of every configuration field.
- Non-blocking structured logger with per-segment colorized console output.
- Management HTTP API with live hot/hard reload and Prometheus metrics.

## Configuration at a glance

A configuration is one JSON document with five top-level sections: `api`,
`interfaces[]`, `firewall[]`, `peers[]`, and the optional `tuning` and `logger`.
Each peer binds to a firewall rule and an interface by tag; the client adds a
`forwards[]` list per peer. Full details and every field are in
[docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Requirements

- Linux with GCC.
- `CAP_NET_RAW` (plus `CAP_BPF` and `CAP_NET_ADMIN` for the fast path).
- For `FASTPATH=1`: clang, llvm, libbpf, libxdp, libelf, zlib.

## License

MIT. See [LICENSE](LICENSE).
