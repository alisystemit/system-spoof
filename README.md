# injspoof

injspoof is a high-performance Layer-2 packet tunnel. It takes UDP traffic from a
local application, wraps each datagram in a raw Ethernet frame whose source IP is
drawn from a configurable pool, and ships it to a remote peer. A 5-byte Host
IDentifier (HID) prepended to every payload lets a single server demultiplex many
clients. The wire encapsulation can masquerade as TCP, UDP, or ICMP.

The core is written in C with an optional XDP/AF_XDP fast path and is built to
sustain millions of concurrent flows on commodity hardware.

This repository documents two things, in this order:

| Part | What it is | Details |
|---|---|---|
| **[Part 1: the core](#part-1-the-core)** | The C engine itself: build, capabilities, config, service, API | [docs/](docs/) |
| **[Part 2: the web panel](#part-2-the-web-panel-and-the-installer)** | Persian web UI + the installer that lays down core, firewall and systemd units. The panel is a standalone project: it installs and runs without the C tree. | [panel/README.md](panel/README.md) · [panel/GUIDE.md](panel/GUIDE.md) |

---

# Part 1: the core

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

## Features

- Layer-2 raw injection with configurable source-IP and source-port pools.
- TCP / UDP / ICMP encapsulation with selectable TCP flags and SEQ/ACK policy.
- O(1) HID demultiplexing for many clients on a single server.
- Per-peer firewall rules, named interfaces, and per-direction protocols.
- Optional XDP/AF_XDP zero-copy fast path with automatic driver detection.
- Fail-fast validation of every configuration field.
- Non-blocking structured logger with per-segment colorized console output.
- Management HTTP API with live hot/hard reload and Prometheus metrics.

## Requirements

- Linux with GCC.
- `CAP_NET_RAW` (plus `CAP_BPF` and `CAP_NET_ADMIN` for the fast path).
- For `FASTPATH=1`: clang, llvm, libbpf, libxdp, libelf, zlib.

## Build

```bash
make                 # portable release (AF_PACKET)
make FASTPATH=1      # XDP / AF_XDP fast path
make DEBUG=1         # ASan + UBSan + symbols
sudo make install    # copy ./injspoof to /usr/local/bin
```

## Run

```bash
# Grant raw-socket capability instead of running as root
sudo setcap cap_net_raw+ep ./injspoof

sudo ./injspoof --mode server --config example/server.json
sudo ./injspoof --mode client --config example/client.json
```

Copy a file from [`example/`](example/), set your interface names, peer addresses,
IP pools, and a strong `api.token`, then launch. injspoof validates the entire
configuration before opening any socket.

> Spoofed TCP/ICMP flows require host firewall rules so the kernel does not reset
> them. See [docs/OPERATIONS.md](docs/OPERATIONS.md#blocking-unwanted-kernel-responses) —
> or let [the installer](#part-2-the-web-panel-and-the-installer) generate and apply
> them for you.

## Configuration at a glance

A configuration is one JSON document with five top-level sections: `api`,
`interfaces[]`, `firewall[]`, `peers[]`, and the optional `tuning` and `logger`.
Each peer binds to a firewall rule and an interface by tag; the client adds a
`forwards[]` list per peer. Full details and every field are in
[docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Management API

Each node serves a small HTTP API on `api.bind` (Bearer `api.token`):
`GET /api/v1/health`, `/info`, `/stats` (plus `/stats/traffic`, `/stats/pool`,
`/stats/log`), `/metrics` in Prometheus format, `GET|PUT /config`,
`POST /reload?mode=hot|hard`. It binds to `127.0.0.1` by default. See
[docs/OPERATIONS.md](docs/OPERATIONS.md#management-api) and
[docs/OPERATIONS.md](docs/OPERATIONS.md#metrics).

## Core documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Internals: module map, data model, threading, concurrency, reload, eBPF. |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Exhaustive field reference, examples, validation rules, capacity limits. |
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | Wire format: the 11-byte header, HID routing, encapsulation, fragmentation. |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Part 1: build, capabilities, running, firewall blocking, API, metrics, troubleshooting. Part 2: the installer and systemd layout. |
| [docs/PERFORMANCE.md](docs/PERFORMANCE.md) | Optimizations, scaling, the fast path, tuning, and measurement. |

---

# Part 2: the web panel and the installer

The panel is a Persian (RTL) Flask UI that talks to the node's own API, so it adds
nothing to the core and needs no root to run. It also controls the core installed
on the same machine through one narrow, sudoers-bounded helper.

## One-command install

One command provisions a bare Linux server with the core **and** the panel: it
builds `injspoof`, sets file capabilities, generates a starter config with a
random API token, writes the nftables blocker, installs three systemd units, and
registers the local node in the panel. The node is enabled but not started (its
peer has to be configured first) — add `--start-node` to bring it up.

```bash
git clone https://github.com/alisystemit/system-spoof.git /opt/injspoof-src && cd /opt/injspoof-src && sudo bash panel/install.sh
```

Update later (config, tokens and panel database are preserved):

```bash
cd /opt/injspoof-src && git pull && sudo bash panel/install.sh --update
```

Useful flags: `--role=server|client`, `--instance=NAME`, `--api-bind=HOST:PORT`,
`--fastpath`, `--start-node`, `--no-core`, `--with-core`, `--core-only`,
`--allow-update`, `--uninstall`. The full list, the on-disk layout and the
privilege boundary are in [panel/README.md](panel/README.md).

## Panel only (standalone project)

The panel does not need the C tree. It ships its own version (`panel/VERSION`),
its own license note, its own starter configs (`panel/seed/`) and its own
self-hosted Persian fonts, and `install.sh` skips the core when the source is
absent instead of failing:

```bash
git clone --filter=blob:none --sparse https://github.com/alisystemit/system-spoof.git /opt/injspoof-src && cd /opt/injspoof-src && git sparse-checkout set panel && sudo bash panel/install.sh --no-core
```

Copy `panel/` anywhere else and `sudo bash install.sh` does the same thing. In
this mode the panel manages remote nodes over their API; the **هسته** page simply
reports that no local core is installed. `--with-core` or `--src=DIR` makes the
core mandatory again.

## Documentation for the panel

Step by step — install, first tunnel, nodes, firewall, backups, troubleshooting —
is in [panel/GUIDE.md](panel/GUIDE.md) (Persian). [panel/README.md](panel/README.md)
keeps the reference material: installer options, systemd units, the
`injspoof-nodectl` helper and its sudoers boundary, the rules the panel derives
from the C source, and the two test suites (65 logic checks, 38 end-to-end).

## Reaching the panel

The panel listens on `127.0.0.1:8088` only. Reach it from your own machine with an
SSH tunnel rather than opening the port:

```bash
ssh -L 8088:127.0.0.1:8088 root@SERVER-IP
```

## What you get

- **Live dashboard** — packets/bytes per second and drops from `/api/v1/stats`,
  send failures split by errno, source-IP pool usage, syscall and reload counters.
- **Config editor** — read the live config from a node, edit it as a tree or as
  raw JSON, validate it with the same rules the C loader applies, apply with
  hot/hard reload, and roll back from full history.
- **Pair wizard** — generate an aligned `client.json` + `server.json` pair plus the
  nftables (and iptables) script that blocks kernel RSTs.
- **Core page** — for the node on this machine: start/stop/restart, `daemon-reload`,
  journal logs, build version and capabilities, write config straight to disk when
  the node is down, apply firewall rules, and update.

## Panel documentation

[panel/README.md](panel/README.md) — installer options, systemd units, the
`injspoof-nodectl` helper and its sudoers boundary, the rules the panel derives
from the C source, and how to run its two test suites.

## License

MIT. See [LICENSE](LICENSE).
