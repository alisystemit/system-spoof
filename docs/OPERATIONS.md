# Operations

Everything needed to build, deploy, secure, observe, and troubleshoot injspoof in
production. For field-by-field config see [CONFIGURATION.md](CONFIGURATION.md).

The document follows the structure of the repository: **Part 1** covers the C core
on its own, **Part 2** covers the installer and the web panel that wraps it.

## Table of contents

### [Part 1: the core](#part-1-the-core)

- [Building](#building)
- [Privileges and capabilities](#privileges-and-capabilities)
- [Running](#running)
- [Blocking unwanted kernel responses](#blocking-unwanted-kernel-responses)
  - [Table 1 — block outbound TCP RST](#table-1--block-outbound-tcp-rst)
  - [Table 2 — block outbound ICMP and UDP errors](#table-2--block-outbound-icmp-and-udp-errors)
- [Management API](#management-api)
- [Metrics](#metrics)
- [Tuning](#tuning)
- [Troubleshooting](#troubleshooting)

### [Part 2: automated install and the web panel](#part-2-automated-install-and-the-web-panel)

- [What the installer does](#what-the-installer-does)
- [Panel only: the standalone project](#panel-only-the-standalone-project)
- [Layout on disk](#layout-on-disk)
- [Flags](#flags)
- [Static assets and fonts](#static-assets-and-fonts)
- [Updating and uninstalling](#updating-and-uninstalling)
- [Controlling the core from an unprivileged panel](#controlling-the-core-from-an-unprivileged-panel)
- [Panel pages](#panel-pages)
- [Testing the panel without Linux](#testing-the-panel-without-linux)

---

# Part 1: the core

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

### Table 1 — block outbound TCP RST

| Purpose | nftables | iptables |
|---|---|---|
| Drop kernel RST on the spoofed source port | `sudo nft add rule inet injspoof output tcp sport 443 tcp flags rst drop` | `sudo iptables -A OUTPUT -p tcp --sport 443 --tcp-flags RST RST -j DROP` |
| Drop RST on the spoofed destination port (return path) | `sudo nft add rule inet injspoof output tcp dport 443 tcp flags rst drop` | `sudo iptables -A OUTPUT -p tcp --dport 443 --tcp-flags RST RST -j DROP` |
| Stop conntrack tracking the spoofed flow | `sudo nft add rule inet injspoof raw tcp sport 443 notrack` | `sudo iptables -t raw -A OUTPUT -p tcp --sport 443 -j NOTRACK` |

### Table 2 — block outbound ICMP and UDP errors

| Purpose | nftables | iptables |
|---|---|---|
| Drop ICMP "destination unreachable" for spoofed UDP | `sudo nft add rule inet injspoof output icmp type destination-unreachable drop` | `sudo iptables -A OUTPUT -p icmp --icmp-type destination-unreachable -j DROP` |
| Drop ICMP "port unreachable" specifically | `sudo nft add rule inet injspoof output icmp type destination-unreachable icmp code port-unreachable drop` | `sudo iptables -A OUTPUT -p icmp --icmp-type port-unreachable -j DROP` |
| Stop conntrack tracking the spoofed UDP flow | `sudo nft add rule inet injspoof raw udp sport 443 notrack` | `sudo iptables -t raw -A OUTPUT -p udp --sport 443 -j NOTRACK` |

Remove everything afterwards with `sudo nft delete table inet injspoof`
(nftables) or by flushing the relevant chains (iptables).

> These are the hand-written versions of what the installer generates per instance
> and re-applies on every restart — see
> [What the installer does](#what-the-installer-does).

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

> `PUT /api/v1/config` replaces the whole file and only works while the node is
> up. When it is down, write `/etc/injspoof/<instance>.json` through
> [the control helper](#controlling-the-core-from-an-unprivileged-panel) instead —
> that is what the panel's **هسته** page does.

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
| Panel says the node is not controllable | Helper not installed, or this node is remote. | Check `ls -l /usr/local/libexec/injspoof-nodectl` and the node's **محلی** flag. |

---

# Part 2: automated install and the web panel

Part 1 is enough to run a node by hand. This part is about `panel/install.sh`,
which builds and provisions the core plus a Persian web panel in one command, and
about the boundary the panel uses to control the core without being root.

## What the installer does

It installs only packages that are genuinely missing (`python3`/`venv` for the
panel, `gcc`/`make`/`libcap` for the core, `clang`/`libbpf`/`libxdp` with
`--fastpath`) and never touches PHP, MySQL, nginx, a domain, or any database user.

```bash
git clone https://github.com/alisystemit/system-spoof.git /opt/injspoof-src && cd /opt/injspoof-src && sudo bash panel/install.sh
```

Step by step:

1. Build the core with the repo's own `make` (`FASTPATH=1` first with
   `--fastpath`; falls back to the portable AF_PACKET build if the toolchain or
   driver is missing), install it to `/usr/local/bin/injspoof`, `setcap` it.
2. Generate a starter config for one instance — random `api.token`, the machine's
   real WAN interface and gateway MAC — and write
   `/etc/injspoof/<instance>.{json,conf}` plus its wrapper.
3. Install and enable three systemd units: `injspoof@<instance>` (the core),
   `injspoof-firewall@<instance>` (blocks kernel RST/ICMP on every restart, so the
   tables in [Part 1](#part-1-the-core) are generated per instance instead of
   hand-written), and `injspoof-panel` (the panel, as the unprivileged
   `injspoof-panel` user).
4. Install `/usr/local/libexec/injspoof-nodectl` and
   `/etc/sudoers.d/injspoof-panel` so the panel can control exactly the registered
   instances.
5. Register the local node in `panel.db`, apply the firewall rules, and health-check
   the panel over HTTP (the node API too, when it was started).

The node unit is enabled but **not** started — until the remote peer is configured
a running node only produces drops. Start it with `--start-node`, from the panel's
**هسته** page, or with `systemctl start injspoof@<instance>`.

## Panel only: the standalone project

`panel/` is a complete project on its own: its own `VERSION`, `LICENSE`,
`CHANGELOG.md`, `GUIDE.md`, starter configs (`panel/seed/`, a byte-identical copy
of `example/`) and self-hosted fonts. Nothing in the running panel reads the C
tree — `schema.py` mirrors the rules from `src/config.c` and `src/server.c` at
review time, not at runtime.

```bash
git clone --filter=blob:none --sparse https://github.com/alisystemit/system-spoof.git /opt/injspoof-src && cd /opt/injspoof-src && git sparse-checkout set panel && sudo bash panel/install.sh --no-core
```

Copying `panel/` somewhere else and running `sudo bash install.sh` is equivalent:
`install.sh` looks for `Makefile` and `src/main.c` next to the panel, and when they
are missing it installs the panel alone and says so. Steps 1, 2 and 4 above are
skipped; the panel still gets its unit, its user, its state directory and its
database. In this mode the **هسته** page reports that no local core is installed,
and every remote node is still manageable through its own API.

Make the core mandatory again with `--with-core` (missing source is then an error,
not a skip) or point at another checkout with `--src=DIR`.

## Layout on disk

| Artifact | Path |
|---|---|
| Binary (with `setcap`) | `/usr/local/bin/injspoof` |
| Build identity | `/etc/injspoof/build-info` |
| Starter config | `/etc/injspoof/<instance>.json` (0640, group `injspoof-panel`) |
| Config backups written by the helper | `/etc/injspoof/history/` |
| Instance whitelist read by the control helper | `/etc/injspoof/instances.cfg` |
| Kernel-response blocker, re-applied on every restart | `/etc/injspoof/firewall/<instance>.nft.sh` |
| systemd units | `injspoof@<instance>`, `injspoof-firewall@<instance>`, `injspoof-panel` |
| Privilege helper + sudoers drop-in | `/usr/local/libexec/injspoof-nodectl`, `/etc/sudoers.d/injspoof-panel` |
| Panel code / DB / settings | `/opt/injspoof-panel`, `/var/lib/injspoof-panel/panel.db`, `/etc/injspoof-panel/panel.env` |
| Logs | `journalctl -u injspoof@server -u injspoof-panel -f` |

The panel listens on `127.0.0.1:8088` only; reach it through an SSH tunnel
(`ssh -L 8088:127.0.0.1:8088 root@SERVER-IP`) instead of opening the port.

## Flags

| Flag | Effect |
|---|---|
| `--role=server\|client` | Role of the core on this machine (default `server`). |
| `--instance=NAME` | Instance name in `injspoof@NAME` (defaults to the role). |
| `--api-bind=HOST:PORT` | `api.bind` of the starter config (default `127.0.0.1:9090`, `9091` for client). |
| `--src=DIR` | Repo path (default: the parent of `panel/`). |
| `--fastpath` | Build with `FASTPATH=1` and grant `CAP_BPF`/`CAP_NET_ADMIN`. |
| `--start-node` / `--restart-node` | Start the node after install / restart it during `--update`. |
| `--allow-update` | Enable the panel's "update" button. |
| `--no-core` / `--core-only` | Panel only / core only (no panel venv needed). |
| `--with-core` | Require the core: a missing C source is an error instead of an automatic panel-only install. |
| `--host= --port= --prefix= --user= --no-enable` | Panel address, paths and service user. |
| `--update` | Refresh code and binary, restart services. |
| `--uninstall` | Remove services and system files (`--purge-binary` also removes the binary). |

## Static assets and fonts

The panel serves everything itself; there is no CDN, no Google Fonts and no
request to the internet when a page loads, so an air-gapped node renders
correctly.

| Asset | Where | Notes |
|---|---|---|
| `Vazirmatn` 33.003 | `panel/static/fonts/Vazirmatn-{Regular,Medium,SemiBold,Bold}.woff2` | The four weights the stylesheet actually uses (400/500/600/700); full Persian + Latin coverage, including ZWNJ and Persian digits. |
| `JetBrains Mono` | `panel/static/fonts/JetBrainsMono-{Regular,Bold}.woff2` | ASCII subset (~5 KB each) for JSON, logs and numeric tables; Persian inside a code block falls back to Vazirmatn. |
| Licenses | `static/fonts/OFL.txt`, `static/fonts/OFL-JetBrainsMono.txt` | Both fonts are SIL Open Font License 1.1; `panel/LICENSE` keeps the MIT notice for the code and points at them. |

`@font-face` rules sit at the top of `panel/static/style.css`,
`templates/base.html` preloads the regular weight, and `app.py` registers the
`font/woff2` MIME type because a few distributions do not know the extension.
`install.sh` copies `static/` recursively and curls the font URL as part of its
post-install smoke test; `selftest.py` fails the build if any `url()` points
outside `fonts/` or a `font-weight` used in the CSS has no matching face.

## Updating and uninstalling

```bash
cd /opt/injspoof-src && git pull && sudo bash panel/install.sh --update
```

`--update` refreshes code, binary and dependencies and restarts services; the
on-disk config, `panel.db`, `panel.env` and the API token stay untouched.
`--uninstall` keeps config and database by design.

A panel-only install updates the same way, without ever touching a binary:

```bash
cd /opt/injspoof-src && git pull && sudo bash panel/install.sh --no-core
```

## Controlling the core from an unprivileged panel

The panel runs as `injspoof-panel` and has no root rights. Everything that needs
privilege goes through one fixed command line:

```
sudo -n /usr/local/libexec/injspoof-nodectl <cmd> <instance> [args]
```

The sudoers drop-in grants only that user, only that path, `NOPASSWD`. The
helper, in turn, refuses anything outside its contract: it builds the unit name
itself (`injspoof@<instance>`), requires the instance to match
`[A-Za-z0-9_.@-]{1,64}` *and* to be listed in `instances.cfg` with its config and
wrapper on disk, accepts only panel-generated firewall text, and writes configs
only under `/etc/injspoof/` after dropping the previous version in
`/etc/injspoof/history/`. `update` runs `git pull --ff-only` only in the repo
path recorded at install time, and only if the install used `--allow-update`.

The core unit deliberately omits `NoNewPrivileges`: that option would disable
file capabilities and make `setcap` on the binary useless.

## Panel pages

- **داشبورد زنده** — live pps / bytes / drop charts, drop causes by errno, source-IP
  pool usage, syscall and reload counters, hot/hard reload buttons.
- **نودها** — register each node's `api_url` + token, connection test, live state;
  the **محلی** tick plus instance name unlocks the core page for that node.
- **هسته** — install state (binary, capabilities, build version, unit, firewall
  script, config path), start/stop/restart, `daemon-reload`, journal logs, apply or
  download the kernel-response blocker, write config to disk, pull the node's live
  config back to disk, and update (only when installed with `--allow-update`).
- **ویرایشگر کانفیگ** — read live config, tree or raw editing, validation with the
  same rules the C loader enforces, apply with hot/hard reload, full history + rollback.
- **ویزارد جفت کانفیگ** — aligned `client.json` + `server.json` plus nftables and
  iptables scripts, preview, ZIP download, push to registered nodes.

The rules the panel derives from the C source (why `incoming.port.src` must match
the sender, why `dst_ports` is inert, why ICMP has no source port, and the capacity
limits) are documented in [panel/README.md](../panel/README.md). For the
step-by-step operator manual — first tunnel, node registration, backups,
troubleshooting — see [panel/GUIDE.md](../panel/GUIDE.md) (Persian).

## Testing the panel without Linux

The panel and its two suites run anywhere Python runs:

```bash
python panel/mock_api.py --mode server --port 9090 --token devtoken --load-example &
python panel/mock_api.py --mode client --port 9091 --token devtoken --load-example &
python panel/run.py &
python panel/e2e_test.py
```

`panel/mock_nodectl.py` stands in for the root helper so the **هسته** page can be
exercised without systemctl or nft:

```bash
INJSPOOF_SUDO=python3 INJSPOOF_NODECTL=$PWD/panel/mock_nodectl.py python3 panel/run.py
```
