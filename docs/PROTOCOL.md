# Wire protocol

This document specifies the on-wire format injspoof uses: the per-packet header,
how the HID identifies peers, how payloads are encapsulated, and how oversized
packets are fragmented. For the components that implement this, see
[ARCHITECTURE.md](ARCHITECTURE.md).

## Table of contents

- [Frame layout](#frame-layout)
- [Per-packet header](#per-packet-header)
- [HID routing](#hid-routing)
- [Encapsulation modes](#encapsulation-modes)
- [Source spoofing](#source-spoofing)
- [Fragmentation](#fragmentation)
- [Return path](#return-path)

## Frame layout

Every tunnelled packet is a complete Ethernet frame built by injspoof, not a
socket payload handed to the kernel. The layout is:

```
+-----------+------+-----------------+------------------------+-----------+
| Ethernet  |  IP  | TCP / UDP / ICMP | injspoof header (11 B) |  payload  |
+-----------+------+-----------------+------------------------+-----------+
```

- The Ethernet header carries the configured next-hop gateway MAC as the
  destination and the outgoing interface's MAC as the source.
- The IP header carries a **spoofed** source address drawn from the peer's pool.
- The L4 header is whichever encapsulation the firewall rule selects.
- The injspoof header and payload ride in the L4 data section.

## Per-packet header

Immediately after the L4 header, injspoof prepends an 11-byte fixed header:

```
 byte:  0   1   2   3   4   5   6   7   8   9   10
       +---+---+---+---+---+---+---+---+---+---+---+
       |      HID (5)      |  redirect IP (4)  | port|
       +---+---+---+---+---+---+---+---+---+---+---+
                            big-endian        BE(2)
```

| Field | Size | Encoding | Meaning |
|---|---|---|---|
| HID | 5 bytes | ASCII | Host IDentifier of the originating peer. |
| Redirect IP | 4 bytes | big-endian | IPv4 address the server should deliver the payload to. |
| Redirect port | 2 bytes | big-endian | UDP port the server should deliver the payload to. |

The redirect fields come from the client forwarder's `redirect` setting; they let
the server deliver each peer's traffic to a different backend without any
server-side per-peer routing table.

## HID routing

The HID is a 5-character identifier unique to each peer. It is the key that lets a
single server demultiplex many clients.

- **Client side.** Before transmitting, the client writes its peer's HID into the
  header. Example: `52sxd` is the byte sequence `0x35 0x32 0x73 0x78 0x64`.
- **Server side.** On capture, the server reads the 5 HID bytes and looks them up
  in an open-addressed FNV-1a hash table (`hid_hash[]`) to find the peer index in
  O(1). From the peer it derives which firewall rule and interface to use for the
  reply.

Because lookup is O(1) and independent of peer count, demux cost does not grow as
clients are added. HIDs must be exactly 5 characters and unique; the loader
rejects configurations that violate either rule.

## Encapsulation modes

The L4 encapsulation is chosen per direction by `firewall[].<dir>.protocol.name`:

| Mode | L4 header | Notes |
|---|---|---|
| `udp` | UDP datagram | Simplest and lowest overhead. Default. |
| `tcp` | TCP segment | Configurable flags (e.g. `psh+ack`) and SEQ/ACK policy (`fixed`, `random`, `sequential`). Useful where only TCP is permitted. |
| `icmp` | ICMP message | Payload carried in the ICMP data field (default type 8 / code 0). Useful where only ICMP passes. |

Because the TCP and ICMP encapsulations are synthetic — there is no real socket or
connection behind them — the host kernel must be told not to interfere with these
flows. See [OPERATIONS.md](OPERATIONS.md#blocking-unwanted-kernel-responses).

### TCP SEQ/ACK policy

For the TCP encapsulation the sequence-number behaviour is selectable:

| `seq` | Behaviour |
|---|---|
| `fixed` | Every segment uses `seq_base` / `ack_base` verbatim. |
| `random` | SEQ is randomized per segment. |
| `sequential` | SEQ advances monotonically. |

Defaults are `seq_base = 0x12345678` and `ack_base = 0x87654321`.

## Source spoofing

The IP source address and L4 source port are selected per packet from the active
direction's pool:

- **Addresses** are expanded from the configured CIDR blocks into a prefix-sum
  index, and one is chosen by round-robin or random strategy in O(log N) over the
  number of blocks.
- **Ports** are chosen from `port.src` by the configured strategy; if none is
  given on the outgoing direction, a random ephemeral port (1024-65535) is used.

Exclusion filters (`private`, `reserved`, `multicast`) are applied while the pool
is built, so excluded ranges are never selected.

## Fragmentation

If an assembled frame exceeds the interface's `fragment_size`, injspoof splits the
IP payload into standard IPv4 fragments. All fragments of one packet are emitted
in a single batched `sendmmsg` call. Set `fragment_size` just under the path MTU
to avoid black-holing; the valid range is 576-9216 bytes.

## Return path

On the server, after the HID identifies the peer and the header is stripped, the
payload is delivered to the redirect target as local UDP. Replies from the backend
re-enter the tunnel and are re-spoofed using the **same peer's** firewall rule, so
the source identity of the return traffic is consistent with the outbound flow and
remains isolated from every other peer.
