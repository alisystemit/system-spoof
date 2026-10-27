# Operations

Everything needed to build, deploy, secure, observe, and troubleshoot injspoof in
production. For field-by-field config see [CONFIGURATION.md](CONFIGURATION.md).

## Table of contents

- [Building](#building)
- [Privileges and capabilities](#privileges-and-capabilities)
- [Running](#running)
- [Blocking unwanted kernel responses](#blocking-unwanted-kernel-responses)
  - [Table 1 - block outbound TCP RST](#table-1--block-outbound-tcp-rst)
  - [Table 2 - block outbound ICMP and UDP errors](#table-2--block-outbound-icmp-and-udp-errors)
- [Management API](#management-api)
- [Metrics](#metrics)
- [Tuning](#tuning)
- [Troubleshooting](#troubleshooting)

## Building

injspoof targets Linux and builds with GCC. Objects are written out-of-tree to
`build/`, and header dependencies are tracked automatically (`-MMD -MP`).

```bash
# Dependencies
sudo apt update
sudo apt install -y build-essential pkg-config                    # portable build
sudo apt install -y clang llvm libbpf-dev libxdp-dev libelf-dev zlib1g-dev  # fast path

# Build targets
make                 # portable release (AF_PACKET)
make FASTPATH=1      # high-performance build with XDP / AF_XDP
make DEBUG=1         # debug build (ASan + UBSan + symbols)
make STATIC_BPF=1    # statically link libbpf / libxdp
sudo make install    # install ./injspoof to /usr/local/bin
make clean
```

| Target / flag | Effect |
|---|---|
| `make` | Optimized AF_PACKET build. |
| `FASTPATH=1` | Compile and embed the XDP program; enable AF_XDP. |
| `DEBUG=1` | AddressSanitizer + UndefinedBehaviorSanitizer + debug symbols. |
| `STATIC_BPF=1` | Static libbpf/libxdp for a self-contained binary. |
| `make install` | Copy the binary to `/usr/local/bin`. |

## Privileges and capabilities

injspoof needs raw-socket access. Grant capabilities per-binary with `setcap`
rather than running as root.

| Build | Capabilities | Command |
|---|---|---|
| AF_PACKET (default) | `CAP_NET_RAW` | `sudo setcap cap_net_raw+ep ./injspoof` |
| FASTPATH (AF_XDP) | `CAP_NET_RAW`, `CAP_BPF`, `CAP_NET_ADMIN` | `sudo setcap cap_net_raw,cap_bpf,cap_net_admin+ep ./injspoof` |

## Running

```bash
sudo ./injspoof --mode server --config example/server.json
sudo ./injspoof --mode client --config example/client.json
```

Copy a file from [`../example/`](../example/), set your real interface names, peer
addresses, IP pools, and a strong `api.token`, then launch. The process validates
the entire configuration before opening any socket and exits with a descriptive
error if anything is wrong.

## Blocking unwanted kernel responses

Because injspoof writes raw frames the kernel created no socket for, the OS will
emit TCP RST segments and ICMP errors for the spoofed flows. These must be
suppressed on the host or they leak and reset the tunnel. Apply the rules below at
startup, substituting your real source port for `443`. On each row pick **either**
the nftables or the iptables command — they are equivalent.

Create the nftables scaffolding once before adding rules:

```bash
sudo nft add table inet injspoof
sudo nft add chain inet injspoof output '{ type filter hook output priority 0; }'
sudo nft add chain inet injspoof raw    '{ type filter hook output priority -300; }'
```

### Table 1 - block outbound TCP RST

| Purpose | nftables | iptables |
|---|---|---|
| Drop kernel RST on the spoofed source port | `sudo nft add rule inet injspoof output tcp sport 443 tcp flags rst drop` | `sudo iptables -A OUTPUT -p tcp --sport 443 --tcp-flags RST RST -j DROP` |
| Drop RST on the spoofed destination port (return path) | `sudo nft add rule inet injspoof output tcp dport 443 tcp flags rst drop` | `sudo iptables -A OUTPUT -p tcp --dport 443 --tcp-flags RST RST -j DROP` |
| Stop conntrack tracking the spoofed flow | `sudo nft add rule inet injspoof raw tcp sport 443 notrack` | `sudo iptables -t raw -A OUTPUT -p tcp --sport 443 -j NOTRACK` |

### Table 2 - block outbound ICMP and UDP errors

| Purpose | nftables | iptables |
|---|---|---|
| Drop ICMP "destination unreachable" for spoofed UDP | `sudo nft add rule inet injspoof output icmp type destination-unreachable drop` | `sudo iptables -A OUTPUT -p icmp --icmp-type destination-unreachable -j DROP` |
| Drop ICMP "port unreachable" specifically | `sudo nft add rule inet injspoof output icmp type destination-unreachable icmp code port-unreachable drop` | `sudo iptables -A OUTPUT -p icmp --icmp-type port-unreachable -j DROP` |
| Stop conntrack tracking the spoofed UDP flow | `sudo nft add rule inet injspoof raw udp sport 443 notrack` | `sudo iptables -t raw -A OUTPUT -p udp --sport 443 -j NOTRACK` |

Remove everything afterwards with `sudo nft delete table inet injspoof`
(nftables) or by flushing the relevant chains (iptables).

## Management API

When `api` is configured, the core serves HTTP/1.1 on `api.bind`, authenticated by
the bearer `token`. Send the token as `Authorization: Bearer <token>`.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/health` | Liveness probe. |
| `GET` | `/api/v1/info` | Version, mode, pid, uptime, config path. |
| `GET` | `/api/v1/stats` | Full counter snapshot. |
| `GET` | `/api/v1/stats/traffic` | Traffic counters only. |
| `GET` | `/api/v1/stats/pool` | Pool utilisation. |
| `GET` | `/api/v1/stats/log` | Logger emitted/dropped counters. |
| `GET` | `/api/v1/config` | Current on-disk config. |
| `PUT` | `/api/v1/config` | Atomically replace the on-disk config. |
| `POST` | `/api/v1/reload?mode=hot` | Re-parse and apply hot-swappable fields. |
| `POST` | `/api/v1/reload?mode=hard` | `execve()` self, preserving the PID. |
| `GET` | `/api/v1/metrics` | Prometheus text format. |

## Metrics

`/api/v1/stats` exposes a full snapshot; `/api/v1/metrics` renders it for
Prometheus. Counters are grouped:

| Category | Counters |
|---|---|
| Traffic | `pkts_in_local`, `pkts_in_wire`, `pkts_out_wire`, `pkts_out_local`, `bytes_in`, `bytes_out`, `frags_sent` |
| Drops | `drop_filter`, `drop_parse`, `drop_pool`, `drop_send`, `drop_oversize`, `drop_recv_backpressure` |
| Send errors | `drop_send_enobufs`, `drop_send_eagain`, `drop_send_emsgsize`, `drop_send_enetdown`, `drop_send_eperm` |
| Congestion | `congestion_events` |
| Syscalls | `recvmmsg_calls`, `sendmmsg_calls`, `sendto_calls` |
| Reloads | `reloads_hot`, `reloads_hard` |
| Logger | `log_emitted`, `log_dropped` |

## Tuning

- Pin the process to a CPU on the NIC's NUMA node.
- Set `fragment_size` just under the path MTU.
- Match `tuning.fastpath.queues` to the NIC/CPU layout.
- Prefer `mode: auto` unless you have verified AF_XDP on your driver.

See [PERFORMANCE.md](PERFORMANCE.md) for the rationale behind each knob.

## Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| Exits immediately with a `config:` error | Invalid field. | Read the message; fix the named field. All validation is fail-fast. |
| Tunnel resets intermittently | Kernel RST leaking. | Apply [Table 1](#table-1--block-outbound-tcp-rst). |
| UDP flows die after one packet | Kernel ICMP unreachable leaking. | Apply [Table 2](#table-2--block-outbound-icmp-and-udp-errors). |
| `tcpdump` shows frames but capture sees none | AF_XDP forced on an unsupported VM driver. | Use `mode: auto` or `af_packet`. |
| Rising `drop_send_enobufs` / `congestion_events` | Send path is the bottleneck. | Reduce load, add queues, check NIC. |
| Rising `drop_filter` | Capture filter too loose. | Tighten `incoming.source`/`port`. |
| Rising `log_dropped` | Logger ring overrun. | Raise the log level or reduce console output. |
