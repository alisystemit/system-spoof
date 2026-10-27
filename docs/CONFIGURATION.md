# Configuration reference

A configuration is a single JSON document passed with `--config`. The same
top-level shape is used for both modes; the client additionally attaches
`forwards[]` to each peer. Every field is validated at load time — see
[Validation](#validation). Ready-to-edit files live in [`../example/`](../example/).

## Table of contents

- [Top-level sections](#top-level-sections)
- [`api`](#api)
- [`interfaces[]`](#interfaces)
- [`firewall[]`](#firewall)
  - [Direction object](#direction-object)
  - [Source providers](#source-providers)
  - [Protocol](#protocol)
  - [Selection options](#selection-options)
- [`peers[]`](#peers)
  - [`forwards[]` (client)](#forwards-client)
- [`tuning.fastpath`](#tuningfastpath)
- [`logger`](#logger)
- [Validation](#validation)
- [Capacity limits](#capacity-limits)

## Top-level sections

| Section | Mode | Required | Description |
|---|---|---|---|
| `api` | both | yes | Management HTTP endpoint and bearer token. |
| `interfaces[]` | both | yes (>= 1) | Named NICs used for capture and injection. |
| `firewall[]` | both | yes | Named rules: source-IP pools, ports, and wire protocol per direction. |
| `peers[]` | both | yes (>= 1) | Remote endpoints, each bound to a firewall rule and interface. |
| `tuning` | both | no | XDP/AF_XDP fast-path settings. |
| `logger` | both | no | Log level, driver, format, and rotation. |

## `api`

| Key | Type | Required | Default | Description |
|---|---|---|---|---|
| `bind` | string | yes | — | `host:port` for the management API. Host must be a valid IPv4 literal. |
| `token` | string | yes | — | Bearer token required on every `/api/v1/*` request. Must be non-empty. |

```json
"api": { "bind": "127.0.0.1:9090", "token": "use_a_long_random_secret" }
```

## `interfaces[]`

Each entry names a NIC pair. The source MAC and interface index are detected
automatically from `outgoing.name`; if `incoming.name` is omitted it defaults to
the outgoing name.

| Key | Type | Required | Default | Description |
|---|---|---|---|---|
| `tag` | string | yes | — | Unique name referenced by `peers[].interface`. |
| `outgoing.name` | string | yes | — | NIC used to inject spoofed frames. Must resolve to a real interface. |
| `outgoing.gateway.mac_address` | string | no | — | Next-hop MAC (`aa:bb:cc:dd:ee:ff`) for outgoing frames. |
| `incoming.name` | string | no | = outgoing | NIC used for capture. |
| `fragment_size` | int | no | 1400 | IP fragmentation threshold in bytes. Range 576-9216. |

```json
"interfaces": [
  {
    "tag": "wan",
    "incoming": { "name": "eth0" },
    "outgoing": { "name": "eth0", "gateway": { "mac_address": "00:00:5e:00:53:01" } },
    "fragment_size": 1400
  }
]
```

## `firewall[]`

A firewall rule has a `tag` and two directions, `outgoing` and `incoming`. Peers
reference a rule by its tag. Both directions are required.

| Key | Type | Required | Description |
|---|---|---|---|
| `tag` | string | yes | Unique rule name referenced by `peers[].rule`. |
| `outgoing` | object | yes | Direction used when sending into the tunnel. |
| `incoming` | object | yes | Direction used for captured/return traffic. |

### Direction object

| Key | Type | Required | Description |
|---|---|---|---|
| `source[]` | array/object | yes | One or more [providers](#source-providers). |
| `port.src[]` | int[] | no | Source ports (1-65535). For `outgoing`, a random ephemeral port is auto-selected if omitted. |
| `port.dst[]` | int[] | no | Destination ports (1-65535). `dest` is accepted as an alias. |
| `protocol` | object | no | [Wire protocol](#protocol). Defaults to UDP. |
| `options` | object | no | [Selection options](#selection-options). |

For an `incoming` direction an empty port list means "match any port"; for
`outgoing` a concrete value must go on the wire, so a random ephemeral port is
chosen when the list is empty.

### Source providers

Each provider is an object with a `type` and a `value`.

| `type` | `value` | Description |
|---|---|---|
| `static` | string or string[] | One or more IPs/CIDR blocks, e.g. `["203.0.113.0/24", "192.0.2.7"]`. |
| `file` | string | Path to a file with one IP/CIDR per line; `#` comments and blanks ignored. |

```json
"source": [
  { "type": "static", "value": ["203.0.113.0/24"] },
  { "type": "file",   "value": "/etc/injspoof/pool.txt" }
]
```

CIDR prefixes 0-32 are accepted. A `/32` is a single host; `/31` yields both
addresses; wider blocks exclude the network and broadcast addresses.

### Protocol

`protocol.name` selects the wire encapsulation. `mode` is accepted as an alias.

| Key | Type | Applies to | Default | Description |
|---|---|---|---|---|
| `name` | string | all | `udp` | `tcp`, `udp`, or `icmp`. |
| `options.flags` | string | tcp | — | `+`-separated TCP flags from {fin, syn, rst, psh, ack, urg}, e.g. `psh+ack`. |
| `options.seq` | string | tcp | `fixed` | Sequence mode: `fixed`, `random`, or `sequential`. |
| `options.seq_base` | uint32 | tcp | `0x12345678` | Initial/fixed SEQ. Decimal or `0x` hex. |
| `options.ack_base` | uint32 | tcp | `0x87654321` | Fixed ACK. Decimal or `0x` hex. |
| `options.icmp_type` | int | icmp | 8 | ICMP type, 0-255. |
| `options.icmp_code` | int | icmp | 0 | ICMP code, 0-255. |

### Selection options

`options` tunes how the source pool for a direction is built and rotated.

| Key | Type | Default | Description |
|---|---|---|---|
| `deduplicate` | bool | false | Drop duplicate `/32` entries. |
| `exclude.private` | bool | false | Drop RFC 1918 ranges. |
| `exclude.reserved` | bool | false | Drop IANA reserved ranges. |
| `exclude.multicast` | bool | false | Drop `224.0.0.0/4`. |
| `strategies.ip` | string | `round_robin` | `round_robin` or `random`. |
| `strategies.port` | string | `round_robin` | `round_robin` or `random`. |

## `peers[]`

| Key | Type | Mode | Description |
|---|---|---|---|
| `hid` | string | both | Exactly 5 characters. Unique across all peers. |
| `address` | string | both | Remote peer IPv4 address. |
| `rule` | string | both | Must match a `firewall[].tag`. |
| `interface` | string | both | Must match an `interfaces[].tag`. |
| `forwards[]` | array | client | One or more [forwarders](#forwards-client). At least one total is required in client mode. |

### `forwards[]` (client)

A forwarder is a local UDP listener whose traffic is tunnelled to the owning peer.
The redirect target is encoded into the per-packet header (see
[PROTOCOL.md](PROTOCOL.md)).

| Key | Type | Required | Description |
|---|---|---|---|
| `bind` | string | yes | `host:port` the client listens on for local app traffic. |
| `redirect` | string | yes | `host:port` the server should deliver the payload to. |

```json
"peers": [
  {
    "hid": "52sxd",
    "address": "192.0.2.10",
    "rule": "rule-a",
    "interface": "wan",
    "forwards": [
      { "bind": "127.0.0.1:51820", "redirect": "203.0.113.10:51820" }
    ]
  }
]
```

## `tuning.fastpath`

| Key | Type | Default | Description |
|---|---|---|---|
| `mode` | string | `auto` | `auto`, `af_xdp`, or `af_packet`. |
| `zero_copy` | bool | true | Request AF_XDP zero-copy. |
| `busy_poll` | bool | false | Enable socket busy-polling. |
| `queues` | int | 0 | RX queue count, 0-4096. `0` auto-detects. |

In `auto` mode injspoof enables AF_XDP only on NIC drivers known to support it and
falls back to AF_PACKET elsewhere. See [PERFORMANCE.md](PERFORMANCE.md#the-xdp--af_xdp-fast-path).

## `logger`

| Key | Type | Default | Description |
|---|---|---|---|
| `level` | string | `info` | `trace`, `debug`, `info`, `warn`, `error`, or `fatal`. |
| `driver` | string | `console` | `console`, `file`, `syslog`, or `composite`. |
| `console` | bool | true | Also echo to the console. |
| `async` | bool | true | Use the non-blocking writer thread. |
| `format` | string | see below | Python-style format string. |
| `options.file_path` | string | — | Target file for the `file`/`composite` driver. |
| `options.rotate_size` | int | 0 | Size in bytes that triggers rotation (0 = never). |
| `options.rotate_keep` | int | 5 | Number of rotated files to retain. |

Default format: `%(asctime)s - %(name)s - %(levelname)s - %(message)s`.
Placeholders: `%(asctime)s`, `%(name)s`, `%(levelname)s`, `%(message)s`,
`%(pathname)s`, `%(lineno)d`, `%(funcName)s`, `%(threadid)d`, `%(process)d`.

On a TTY the console driver colorizes each part of a line independently: white
timestamp, dim separators and logger name, a bold severity-colored level, and a
severity-colored message (grey/blue/green/yellow/red). Output to a file, pipe, or
syslog is always plain text with no escape codes.

## Validation

`config_load()` returns an error and the process exits if any field is malformed.
There is no silent fallback. The full set of checks:

| Area | Rule |
|---|---|
| `api` | Object present; `bind` is a valid `host:port`; `token` non-empty. |
| `interfaces` | At least one; each `outgoing.name` resolves; any `gateway.mac_address` parses; `fragment_size` in 576-9216. |
| `firewall` | Non-empty `tag`; both directions present; `source` present; ports in 1-65535; protocol in {tcp, udp, icmp}; valid TCP flags; `seq` in {fixed, random, sequential}; numeric `seq_base`/`ack_base`; ICMP type/code 0-255. |
| `peers` | At least one; `hid` exactly 5 chars and unique; valid IPv4 `address`; `rule` and `interface` reference existing definitions. |
| `tuning.fastpath` | `mode` in {auto, af_xdp, af_packet}; `queues` in 0-4096. |
| `logger` | `level` is a recognized level. |
| client mode | At least one forwarder defined across all peers. |

## Capacity limits

These are compile-time bounds (overridable in `config.h`):

| Limit | Value |
|---|---|
| Peers | 4096 |
| Firewall rules | 32 |
| Interfaces | 16 |
| Forwarders per peer | 16 |
| Source CIDR blocks per pool | 4096 |
| Source/destination ports per pool | 64 |
| Providers per pool | 8 |
| HID length | 5 |
