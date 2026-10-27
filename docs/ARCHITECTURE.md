# Architecture

This document describes the internal design of the injspoof core: how it is laid
out, how data flows through it, and how it stays correct under concurrency and
live reconfiguration. For the wire format see [PROTOCOL.md](PROTOCOL.md); for
configuration see [CONFIGURATION.md](CONFIGURATION.md).

## Table of contents

- [Design goals](#design-goals)
- [Component overview](#component-overview)
- [Module map](#module-map)
- [Configuration model](#configuration-model)
- [Packet path](#packet-path)
- [Threading model](#threading-model)
- [Concurrency and memory model](#concurrency-and-memory-model)
- [Live reconfiguration](#live-reconfiguration)
- [eBPF / XDP layer](#ebpf--xdp-layer)
- [Observability](#observability)
- [Failure handling](#failure-handling)

## Design goals

The core is engineered around four priorities, in order:

1. **Correctness under concurrency.** Many threads touch shared state; none may
   observe a torn or freed configuration.
2. **Predictable latency on the packet path.** The hot loop never blocks on disk,
   locks, or allocation.
3. **Horizontal scale.** State is bounded and indexed so the system handles
   millions of flows without per-flow heap growth.
4. **Operational safety.** Invalid input is rejected before any socket opens, and
   every drop reason is independently observable.

## Component overview

```
                +-------------------+        +-------------------+
   local app -->|  forward listener |  HID   |   raw injector    |--> wire
   (UDP)        |  (client mode)    |------->|  (spoofed L2)     |
                +-------------------+        +-------------------+
                          ^                            |
                          |        +-----------+       v
            backend <-----+--------|  HID demux|<-- raw capture (server mode)
                                   +-----------+
                +-----------------------------------------------+
                |  cross-cutting: config (RCU), logger, metrics, |
                |  management API                                |
                +-----------------------------------------------+
```

Client mode and server mode share the same configuration model, packet assembly,
socket layer, logger, metrics, and management API. They differ only in the
direction of translation: the client turns local UDP into spoofed frames, the
server turns captured frames back into local UDP.

## Module map

| Module | Responsibility |
|---|---|
| `main.c` | CLI parsing, mode selection, process lifecycle, signal handling. |
| `config.c` / `config.h` | JSON parse, exhaustive validation, the resolved `config_t`, and O(1) HID lookup. |
| `client.c` | UDP-to-tunnel forwarding, HID prepend, spoofed frame construction. |
| `server.c` | Raw capture, HID demux, payload delivery to redirect targets. |
| `packet.c` / `packet.h` | Ethernet/IP/TCP/UDP/ICMP assembly, checksums, IP fragmentation. |
| `raw_socket.c` / `raw_socket.h` | AF_PACKET TX/RX, `recvmmsg`/`sendmmsg` batching, socket tuning. |
| `fastpath.c` / `fastpath.h` | XDP program loading and AF_XDP zero-copy rings. |
| `pool.c` / `pool.h` | Lock-free fixed-size buffer pool. |
| `rcu.c` / `rcu.h` | Quiescent-state reclamation for hot config swaps. |
| `metrics.c` / `metrics.h` | Atomic counters for traffic, drops, syscalls, reloads. |
| `logger.c` / `logger.h` | Asynchronous, non-blocking structured logger. |
| `api.c` / `api.h` | Management HTTP/1.1 server and reload dispatch. |
| `bpf/injspoof.bpf.c` | Kernel-side XDP capture filter. |
| `vendor/cJSON` | Bundled JSON parser. |

## Configuration model

`config_load()` parses the JSON document into a single flat `config_t` with
fixed-capacity arrays. No per-flow allocation occurs after start-up. The key
entities and their relationships:

| Entity | Capacity | Role |
|---|---|---|
| `peers[]` | `MAX_PEERS` (4096) | Remote endpoints; each resolves a `rule` tag and an `interface` tag to array indices at load time. |
| `firewall[]` | `MAX_FIREWALL_RULES` (32) | Named rules; each holds an outgoing and incoming `source_pool_t` plus wire protocol. |
| `interfaces[]` | `MAX_INTERFACES` (16) | Named NICs; MAC and ifindex auto-detected from the outgoing name. |
| `hid_hash[]` | `HID_HASH_SIZE` (16384) | Open-addressed map: 5-byte HID -> peer index in O(1). |
| `source_pool_t.subnets[]` | `MAX_SOURCE_BLOCKS` (4096) | CIDR blocks with a prefix-sum index for O(log N) selection. |

Because tags are resolved to indices during load, the packet path performs only
integer-indexed lookups — never string comparison.

### HID hash

The HID map uses FNV-1a over the 5 HID bytes with open addressing into a
power-of-two table, so lookup masks instead of dividing:

```
h = FNV1a(hid) & (HID_HASH_SIZE - 1)
while slot occupied and not a match: h = (h + 1) & (HID_HASH_SIZE - 1)
```

Lookup and insertion are O(1) on average and independent of peer count, which is
what lets a single server fan out to thousands of clients without slowing demux.

## Packet path

### Client (local -> wire)

1. A `forward` listener receives a UDP datagram from the local application.
2. The owning peer's 11-byte header (HID + redirect target) is prepended.
3. `packet.c` builds an Ethernet + IP + L4 frame; the source IP and source port
   are drawn from the peer's outgoing pool using the configured strategy.
4. If the frame exceeds `fragment_size`, it is split into IP fragments.
5. `raw_socket.c` injects the frame(s) with a single batched `sendmmsg`.

### Server (wire -> local)

1. `raw_socket.c` (or the XDP fast path) captures frames in batches via
   `recvmmsg`.
2. The BPF filter and a userspace recheck discard frames outside the configured
   source/port/protocol bounds.
3. The 5-byte HID indexes `hid_hash[]` to find the originating peer.
4. The header is stripped and the payload delivered to the redirect target.
5. Replies re-enter the tunnel using the same peer's firewall rule.

## Threading model

The core runs a small, fixed set of threads:

| Thread | Purpose | Scheduling |
|---|---|---|
| Packet thread | Owns capture/injection sockets; runs the hot loop. | Normal/high priority. |
| Logger writer | Drains the log ring and writes with `writev`. | Lowest priority (`SCHED_OTHER`, nice 0). |
| Management API | Serves HTTP and dispatches reloads. | Normal priority. |

The packet thread never performs slow work directly: logging is handed to the
writer thread through a lock-free ring, and configuration reloads are applied
behind an atomic pointer rather than under a lock.

## Concurrency and memory model

- **Counters** are plain `_Atomic` integers updated with relaxed ordering, so the
  packet thread publishes statistics without locks.
- **Buffers** come from a lock-free fixed-size pool (`pool.c`): each slot is
  page-aligned and jumbo-safe, claimed and released with a single atomic CAS.
  Thread-local TX buffers eliminate pool churn while assembling frames.
- **Configuration** is referenced through an atomic pointer. A reader on the
  packet path loads the pointer once and uses that snapshot for the whole packet.
- **Reclamation** of a replaced configuration is deferred until a quiescent state
  (`rcu.c`), guaranteeing no reader can still hold a pointer into freed memory.

## Live reconfiguration

Two reload modes are exposed through the management API:

| Mode | Mechanism | Use |
|---|---|---|
| Hot (`reload?mode=hot`) | Re-parse the file and atomically swap pools, ports, protocol options, filters, and logger settings. | Changes that do not affect sockets or interfaces. |
| Hard (`reload?mode=hard`) | `execve()` the process in place, preserving the PID. | Changes to API binding, peer endpoints, interfaces, gateway MAC, or protocol family. |

A hot reload never drops traffic: the packet thread continues serving the old
snapshot until the new one is published, then the old one is reclaimed once no
reader references it.

## eBPF / XDP layer

When built with `FASTPATH=1`, `bpf/injspoof.bpf.c` is compiled to an XDP program
and attached to the capture interface. It performs CIDR-bounds and protocol
gating in the kernel so unwanted frames are dropped before they reach userspace.
On supported NIC drivers, AF_XDP zero-copy sockets then deliver matching frames
straight into userspace rings with no skbuff allocation and no kernel copy. The
CIDR blocks are sorted ascending so both the kernel filter and the userspace
recheck can early-out once a source address falls below a block's lower bound.

## Observability

Every meaningful event on the packet path increments a distinct atomic counter
(see [OPERATIONS.md](OPERATIONS.md#metrics)). Traffic, drops (split by cause and
by send errno), syscall counts, reload counts, and logger emitted/dropped totals
are all exposed through `/api/v1/stats` and in Prometheus format at
`/api/v1/metrics`.

## Failure handling

Validation is fail-fast: `config_load()` returns an error and the process exits
before any socket is opened if a field is malformed. On the packet path, errors
are never silently swallowed — each drop is attributed to a specific counter
(filter, parse, pool exhaustion, oversize, receive backpressure, or a specific
send errno) so operational problems surface in metrics rather than in logs alone.
