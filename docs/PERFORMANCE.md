# Performance

How injspoof achieves high throughput and how to tune it. For the structures
referenced here, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Table of contents

- [Design principles](#design-principles)
- [Hot-path optimizations](#hot-path-optimizations)
- [Scaling to many flows](#scaling-to-many-flows)
- [Adaptive backpressure](#adaptive-backpressure)
- [The XDP / AF_XDP fast path](#the-xdp--af_xdp-fast-path)
- [Build-level optimizations](#build-level-optimizations)
- [Tuning checklist](#tuning-checklist)
- [Measuring](#measuring)

## Design principles

The packet path follows three rules: never allocate per packet, never block the
packet thread, and batch every syscall that can be batched. Every technique below
is a consequence of one of those rules.

## Hot-path optimizations

| Technique | Effect |
|---|---|
| Layer-2 raw send with `PACKET_QDISC_BYPASS` | Frames go from the kernel ring to the NIC without traversing the qdisc layer. |
| `recvmmsg` / `sendmmsg` batching | Up to 32 packets per syscall, amortizing syscall and copy cost. |
| Level-triggered `epoll`, 1 ms timeout | Low wake-up latency with bounded per-fd drain to avoid starvation. |
| `SO_BUSY_POLL` | Lower latency under light load by briefly polling the device. |
| Persistent thread-local TX buffers | Zero pool churn while assembling outgoing frames. |
| Batched fragmentation | All IP fragments of one packet leave in a single `sendmmsg`. |
| Lock-free fixed-size pool | Page-aligned, jumbo-safe slots claimed with one atomic CAS. |
| Atomic config pointer + QSBR reclaim | Readers snapshot without locking; reloads never stall the packet path. |
| Prefix-sum source-IP selection | O(log N) selection across thousands of CIDR blocks via binary search. |
| Kernel BPF / XDP pre-filter | Unwanted frames dropped before reaching userspace. |
| `__builtin_expect` branch hints | Keeps the common path straight-line for the branch predictor. |

## Scaling to many flows

State is bounded and indexed, not per-flow:

- **HID lookup is O(1)** through an open-addressed hash, so adding peers does not
  slow demux.
- **Source-IP rotation is O(log N)** in the number of CIDR blocks, independent of
  how many addresses those blocks contain.
- **No heap allocation** occurs on the packet path after start-up, so throughput
  does not degrade as flow count grows and there is no allocator contention.

The practical consequence is that a single instance can fan out to thousands of
peers and rotate across very large address pools without per-flow memory growth.

## Adaptive backpressure

Under load the receive path can outrun the send path. When `sendmmsg` returns
`ENOBUFS` or `EAGAIN`, the drain loop breaks early instead of spinning, which
bounds memory use. Receive buffers are sized to safe limits rather than forced to
the maximum. Each event increments `congestion_events`, and the specific failure
is attributed to a `drop_send_*` counter, so the condition is visible in metrics.

## The XDP / AF_XDP fast path

`make FASTPATH=1` builds the optional fast path. In `auto` mode injspoof probes the
NIC driver via `/sys/class/net/<iface>/device/driver` and enables AF_XDP zero-copy
only on drivers known to support it, falling back to AF_PACKET everywhere else.

| Mode | Behaviour |
|---|---|
| `auto` | Probe the driver; AF_XDP on known-good drivers, AF_PACKET otherwise. |
| `af_xdp` | Force AF_XDP regardless of driver. |
| `af_packet` | Force the legacy raw-socket path; the XDP program is never loaded. |

Known-good AF_XDP drivers: `i40e`, `ice`, `ixgbe`, `mlx5_core`, `mlx4_en`, `nfp`,
`bnxt_en`, `sfc`, `veth`.

> AF_XDP copy-mode is unreliable on common virtual NIC drivers (`virtio_net`,
> `vmxnet3`, `hyperv-netvsc`). `auto` avoids them; forcing `af_xdp` on such a
> driver can capture zero packets while `tcpdump` still shows frames arriving.

Zero-copy AF_XDP delivers frames straight from the NIC into userspace rings with
no skbuff allocation and no kernel copy — the largest single throughput gain
available on supported hardware.

## Build-level optimizations

The release build uses `-O3 -march=x86-64-v2 -flto -fno-plt
-fno-semantic-interposition -fstack-protector-strong`. Link-time optimization lets
the compiler inline across translation units (for example, folding packet
assembly into the send loop), and `-fno-plt` / `-fno-semantic-interposition`
remove indirection on hot internal calls.

## Tuning checklist

- Pin the process to a CPU on the same NUMA node as the NIC.
- Set `fragment_size` to just under the path MTU to minimize fragmentation.
- Match RX queue count (`tuning.fastpath.queues`) to the NIC and CPU layout.
- Keep `mode: auto` unless AF_XDP is verified on your driver.
- Watch `/api/v1/stats`: rising `drop_send_enobufs` or `congestion_events` means
  the send path is the bottleneck; rising `drop_filter` means the capture filter
  is too loose.

## Measuring

Compare `pkts_out_wire` against the `drop_send_*` counters to find where packets
are lost, and divide `pkts_in_wire` by `recvmmsg_calls` to gauge the average
receive batch size — a low ratio under load suggests the receive path is
under-fed or the filter is rejecting too much. `/api/v1/metrics` exposes all of
this in Prometheus format for continuous scraping.
