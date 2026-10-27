"""
gen.py — تولید کانفیگ هسته: استارتر، جفت client/server و اسکریپت فایروال

ساختار خروجی دقیقاً همان چیزی است که src/config.c انتظار دارد. هم‌راستایی
قوانین بر پایه‌ی منطق واقعی فیلتر در src/server.c و src/client.c ساخته می‌شود:

  فرستنده.outgoing.source      ->  گیرنده.incoming.source
  فرستنده.outgoing.port.src    ->  گیرنده.incoming.port.src
  فرستنده.outgoing.protocol    ->  گیرنده.incoming.protocol
  فرستنده.outgoing.port.dst[0] =  پورت مقصد واقعی روی سیم

CLI (همان توابعی که پنل صدا می‌زند؛ install.sh هسته هم از همین‌جا کانفیگ
استارتر و اسکریپت فایروال را می‌نویسد، پس منطق یک‌جاست و روی هر OS تست می‌شود):

    python3 gen.py starter --role server --api-bind 127.0.0.1:9090 \
                           --token <tok> --out /etc/injspoof/server.json
    python3 gen.py firewall --config /etc/injspoof/server.json \
                            --role server --out /etc/injspoof/firewall/server.nft.sh
    python3 gen.py detect            # نام WAN و MAC gateway از روی ماشین
"""

from __future__ import annotations

import copy
import json
import os
import re
import secrets
import string
import subprocess

import schema

HID_ALPHABET = string.ascii_letters + string.digits

DEFAULT_SPEC = {
    "name": "pair-1",
    "protocol": "tcp",
    "tcp_flags": "psh+ack",
    "tcp_seq": "fixed",
    "seq_base": "0x12345678",
    "ack_base": "0x87654321",
    "icmp_type": 8,
    "icmp_code": 0,
    "wire_dst_port": 443,
    "fragment_size": 1400,
    "fastpath_mode": "auto",
    "log_level": "info",
    "iface_tag": "wan",
    "rule_tag": "",
    "client": {
        "label": "client",
        "public_ip": "",
        "iface": "eth0",
        "gw_mac": "",
        "api_bind": "127.0.0.1:9091",
        "api_token": "",
        "pool": [],
        "src_ports": [3232],
    },
    "server": {
        "label": "server",
        "public_ip": "",
        "iface": "eth0",
        "gw_mac": "",
        "api_bind": "127.0.0.1:9090",
        "api_token": "",
        "pool": [],
        "src_ports": [5454],
    },
    "forwards": [{"bind": "127.0.0.1:51820", "redirect": "127.0.0.1:51820"}],
}


def gen_hid(existing=()):
    """hid پنج‌کاراکتری یکتا."""
    existing = set(existing)
    while True:
        hid = "".join(secrets.choice(HID_ALPHABET) for _ in range(schema.HID_LEN))
        if hid not in existing:
            return hid


def gen_token():
    return secrets.token_hex(32)


def _merge_spec(spec):
    out = copy.deepcopy(DEFAULT_SPEC)
    for k, v in (spec or {}).items():
        if k in ("client", "server") and isinstance(v, dict):
            out[k].update(v)
        else:
            out[k] = v
    return out


def _protocol_obj(spec):
    proto = {"name": spec["protocol"]}
    if spec["protocol"] == "tcp":
        opts = {"flags": spec.get("tcp_flags") or "psh+ack",
                "seq": spec.get("tcp_seq") or "fixed",
                "seq_base": spec.get("seq_base") or "0x12345678",
                "ack_base": spec.get("ack_base") or "0x87654321"}
        proto["options"] = opts
    elif spec["protocol"] == "icmp":
        proto["options"] = {"icmp_type": int(spec.get("icmp_type", 8)),
                            "icmp_code": int(spec.get("icmp_code", 0))}
    return proto


def _iface_obj(spec, side):
    tag = spec.get("iface_tag") or "wan"
    obj = {
        "tag": tag,
        "incoming": {"name": side["iface"]},
        "outgoing": {
            "name": side["iface"],
            "gateway": {"mac_address": side.get("gw_mac") or ""},
        },
        "fragment_size": int(spec.get("fragment_size", schema.DEFAULT_FRAGMENT_SIZE)),
    }
    if not obj["outgoing"]["gateway"]["mac_address"]:
        del obj["outgoing"]["gateway"]
    return obj


def build_pair(spec):
    """جفت کامل (client_cfg, server_cfg) برمی‌گرداند."""
    spec = _merge_spec(spec)
    rule_tag = spec.get("rule_tag") or f"rule-{spec['name']}"
    hid = spec.get("hid") or gen_hid()
    cli, srv = spec["client"], spec["server"]
    proto = _protocol_obj(spec)
    dst = [int(spec["wire_dst_port"])]

    client_cfg = {
        "api": {"bind": cli["api_bind"], "token": cli.get("api_token") or gen_token()},
        "interfaces": [_iface_obj(spec, cli)],
        "firewall": [{
            "tag": rule_tag,
            # کلاینت با استخر خودش ارسال می‌کند
            "outgoing": {
                "source": [{"type": "static", "value": list(cli["pool"])}],
                "port": {"src": list(cli["src_ports"]), "dst": dst},
                "protocol": copy.deepcopy(proto),
            },
            # و فقط پورت‌های مبدأ سرور را می‌پذیرد
            "incoming": {
                "source": [{"type": "static", "value": list(srv["pool"])}],
                "port": {"src": list(srv["src_ports"])},
                "protocol": copy.deepcopy(proto),
            },
        }],
        "peers": [{
            "hid": hid,
            "address": srv.get("public_ip") or "",
            "rule": rule_tag,
            "interface": rule_iface_tag(spec),
            "forwards": [dict(f) for f in spec["forwards"]],
        }],
        "tuning": {"fastpath": {"mode": spec.get("fastpath_mode", "auto"),
                                "zero_copy": True, "queues": 0}},
        "logger": {"level": spec.get("log_level", "info"), "driver": "console",
                   "console": True, "async": True,
                   "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"},
    }

    server_cfg = {
        "api": {"bind": srv["api_bind"], "token": srv.get("api_token") or gen_token()},
        "interfaces": [_iface_obj(spec, srv)],
        "firewall": [{
            "tag": rule_tag,
            "outgoing": {
                "source": [{"type": "static", "value": list(srv["pool"])}],
                "port": {"src": list(srv["src_ports"]), "dst": dst},
                "protocol": copy.deepcopy(proto),
            },
            "incoming": {
                "source": [{"type": "static", "value": list(cli["pool"])}],
                "port": {"src": list(cli["src_ports"])},
                "protocol": copy.deepcopy(proto),
            },
        }],
        "peers": [{
            "hid": hid,
            "address": cli.get("public_ip") or "",
            "rule": rule_tag,
            "interface": rule_iface_tag(spec),
        }],
        "tuning": copy.deepcopy(client_cfg["tuning"]),
        "logger": copy.deepcopy(client_cfg["logger"]),
    }

    # با encapsulation از نوع ICMP، فیلتر پورت مبدأ در incoming باید حذف شود:
    # روی فریم ICMP هیچ پورتی وجود ندارد و هر لیست غیرخالی همه‌چیز را drop می‌کند.
    if spec["protocol"] == "icmp":
        for cfg in (client_cfg, server_cfg):
            for fw in cfg["firewall"]:
                fw["incoming"].pop("port", None)

    return client_cfg, server_cfg, {"hid": hid, "rule_tag": rule_tag}


def rule_iface_tag(spec):
    return spec.get("iface_tag") or "wan"


# ======================================================================
#  افزودن یک کلاینت به کانفیگ سرور موجود
# ======================================================================

def merge_client_into_server(server_cfg, spec, existing_specs=()):
    """یک peer و rule جدید برای کلاینت به کانفیگ سرور اضافه می‌کند.

    اگر tag تکراری باشد یا سقف‌ها رد شوند، به‌جای تغییر، لیست Issue برمی‌گرداند.
    قاعده‌ای که append می‌شود نمایِ **سرور** است (outgoing = استخر سرور،
    incoming = استخر کلاینت) و peer.address IP واقعی کلاینت است.
    """
    issues = []
    cfg = copy.deepcopy(server_cfg or {})
    _client_cfg, srv_side, meta = build_pair(spec)
    hid, rule_tag = meta["hid"], meta["rule_tag"]
    srv_rule = srv_side["firewall"][0]
    srv_peer = srv_side["peers"][0]

    peers = cfg.setdefault("peers", [])
    if any(p.get("hid") == hid for p in peers if isinstance(p, dict)):
        issues.append(schema.Issue(schema.ERROR, "peers", f"hid تکراری: {hid}"))
        return cfg, issues
    if len(peers) + 1 > schema.MAX_PEERS:
        issues.append(schema.Issue(schema.ERROR, "peers",
                                   f"سقف {schema.MAX_PEERS} peer رد شده"))
        return cfg, issues

    rules = cfg.setdefault("firewall", [])
    if any(r.get("tag") == rule_tag for r in rules if isinstance(r, dict)):
        issues.append(schema.Issue(schema.ERROR, "firewall",
                                   f"rule تکراری: {rule_tag}",
                                   "برای هر کلاینت یک pair با نام دیگر بسازید "
                                   "(tag قاعده از نام pair گرفته می‌شود) یا rule_tag "
                                   "را دستی عوض کنید."))
        return cfg, issues
    if len(rules) + 1 > schema.MAX_FIREWALL_RULES:
        issues.append(schema.Issue(schema.ERROR, "firewall",
                                   f"سقف {schema.MAX_FIREWALL_RULES} rule رد شده"))
        return cfg, issues

    iface_tag = srv_peer["interface"]
    if not any(i.get("tag") == iface_tag for i in cfg.get("interfaces", [])):
        issues.append(schema.Issue(schema.ERROR, "interfaces",
                                   f"interface با tag '{iface_tag}' در کانفیگ سرور نیست؛ "
                                   "اول آن را در سرور تعریف کنید"))
        return cfg, issues

    rules.append(srv_rule)
    peers.append({
        "hid": hid,
        "address": srv_peer["address"],
        "rule": rule_tag,
        "interface": iface_tag,
    })
    return cfg, issues


# ======================================================================
#  اسکریپت فایروال
# ======================================================================

def _wire_ports(cfg):
    """پورت‌هایی که این ماشین روی سیم می‌فرستد یا دریافت می‌کند."""
    spoofed, dst = [], []
    for fw in cfg.get("firewall") or []:
        out = fw.get("outgoing") or {}
        port = out.get("port") or {}
        for p in (port.get("src") or []):
            if isinstance(p, int) and p not in spoofed:
                spoofed.append(p)
        d = port.get("dst", port.get("dest")) or []
        if d and isinstance(d[0], int) and d[0] not in dst:
            dst.append(d[0])
    return spoofed, dst


def _protocols(cfg):
    names = set()
    for fw in cfg.get("firewall") or []:
        proto = (fw.get("outgoing") or {}).get("protocol") or {}
        names.add(proto.get("name", "udp") if isinstance(proto, dict) else "udp")
    return names


def _slug(text):
    """نام instance/هاست را به برچسب امن shell و nft تبدیل می‌کند."""
    out = re.sub(r"[^A-Za-z0-9_.-]", "-", str(text or "")).strip("-.")
    return out[:32] or "node"


def nftables_script(cfg, hostname="injspoof-node", instance=None):
    """اسکریپت idempotent بر پایه‌ی Table 1 و Table 2 در docs/OPERATIONS.md.

    اگر `instance` داده شود، chainها با پسوند همان instance نامیده می‌شوند
    (out_<inst> / raw_<inst>) و اول flush می‌شوند: روی یک ماشین با چند نود،
    اعمال دوباره‌ی کانفیگ یک نود قواعد نود دیگر را پاک نمی‌کند و قواعد
    تکراری هم انباشته نمی‌شود. بدون instance، خروجی دقیقاً همان نام‌های
    مستندات (output/raw) را می‌دهد تا برای کپی‌پیست دست‌کاری‌شده باشد.
    """
    spoofed, dst = _wire_ports(cfg)
    protos = _protocols(cfg)
    ports = sorted(set(spoofed) | set(dst))
    out_chain, raw_chain = "output", "raw"
    prelude = [
        "nft add table inet injspoof 2>/dev/null || true",
        f"nft add chain inet injspoof {out_chain} '{{ type filter hook output priority 0; }}'",
        f"nft add chain inet injspoof {raw_chain}    '{{ type filter hook output priority -300; }}'",
    ]
    if instance:
        slug = _slug(instance)
        out_chain, raw_chain = f"out_{slug}", f"raw_{slug}"
        prelude = [
            "nft add table inet injspoof 2>/dev/null || true",
            f"nft add chain inet injspoof {out_chain} '{{ type filter hook output priority 0; }}'",
            f"nft add chain inet injspoof {raw_chain}    '{{ type filter hook output priority -300; }}'",
            f"nft flush chain inet injspoof {out_chain}",
            f"nft flush chain inet injspoof {raw_chain}",
        ]
    lines = [
        "#!/usr/bin/env bash",
        f"# injspoof kernel-response blocker — {hostname}",
        "# تولیدشده توسط پنل; بدون این قواعد کرنل برای جریان‌های spoofed خودش",
        "# RST و ICMP error می‌فرستد و تونل را reset می‌کند (docs/OPERATIONS.md).",
        "set -euo pipefail",
        "",
    ] + prelude + [""]
    if not ports:
        lines.append("# هشدار: هیچ پورت مبدأ/مقصد مشخصی در کانفیگ نیست؛ "
                     "پورت‌ها در زمان بوت تصادفی انتخاب می‌شوند و این اسکریپت "
                     "کاری از پیش نمی‌تواند بکند.")
    if "tcp" in protos:
        lines.append("# --- Table 1: block outbound TCP RST ---")
        for p in ports:
            lines.append(f"nft add rule inet injspoof {out_chain} tcp sport {p} tcp flags rst drop")
        for p in ports:
            lines.append(f"nft add rule inet injspoof {out_chain} tcp dport {p} tcp flags rst drop")
        for p in spoofed:
            lines.append(f"nft add rule inet injspoof {raw_chain} tcp sport {p} notrack")
        lines.append("")
    if "udp" in protos or "icmp" in protos:
        lines.append("# --- Table 2: block outbound ICMP / UDP errors ---")
        lines.append(f"nft add rule inet injspoof {out_chain} icmp type destination-unreachable drop")
        lines.append(f"nft add rule inet injspoof {out_chain} icmp type destination-unreachable "
                     "icmp code port-unreachable drop")
        for p in spoofed:
            lines.append(f"nft add rule inet injspoof {raw_chain} udp sport {p} notrack")
        lines.append("")
    lines.append('echo "injspoof blocker applied: ports ' +
                 (",".join(map(str, ports)) or "-") + '"')
    lines.append("# برای پاک کردن: sudo nft delete table inet injspoof")
    return "\n".join(lines) + "\n"


def iptables_script(cfg, hostname="injspoof-node"):
    """هم‌ارز iptables همان قواعد (ستون سمت چپ docs/OPERATIONS.md)."""
    spoofed, dst = _wire_ports(cfg)
    protos = _protocols(cfg)
    ports = sorted(set(spoofed) | set(dst))
    lines = [
        "#!/usr/bin/env bash",
        f"# injspoof kernel-response blocker (iptables) — {hostname}",
        "set -euo pipefail",
        "",
    ]
    if "tcp" in protos:
        for p in ports:
            lines.append(f"iptables -A OUTPUT -p tcp --sport {p} --tcp-flags RST RST -j DROP")
        for p in ports:
            lines.append(f"iptables -A OUTPUT -p tcp --dport {p} --tcp-flags RST RST -j DROP")
        for p in spoofed:
            lines.append(f"iptables -t raw -A OUTPUT -p tcp --sport {p} -j NOTRACK")
        lines.append("")
    if "udp" in protos or "icmp" in protos:
        lines.append("iptables -A OUTPUT -p icmp --icmp-type destination-unreachable -j DROP")
        lines.append("iptables -A OUTPUT -p icmp --icmp-type port-unreachable -j DROP")
        for p in spoofed:
            lines.append(f"iptables -t raw -A OUTPUT -p udp --sport {p} -j NOTRACK")
    lines.append("# پاک کردن: iptables -t raw -F OUTPUT && iptables -F OUTPUT")
    lines.append("# هشدار: این نسخه هر اجرا قواعد را APPEND می‌کند؛ برای اعمال")
    lines.append("# دوباره‌شونده (systemd، پنل) نسخه‌ی nftables را با instance بگیرید.")
    return "\n".join(lines) + "\n"


# ======================================================================
#  کانفیگ استارتر برای نصب هسته (install.sh از همین‌جا می‌نویسد)
# ======================================================================

PANEL_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(PANEL_DIR)                       # ریپوی injspoof (اگر کنار پنل باشد)
EXAMPLE_DIR = os.path.join(ROOT, "example")             # منبع اصلی، کنار سورس C
SEED_DIR = os.path.join(PANEL_DIR, "seed")               # کپی هم‌رسانده داخل پنل


def example_path(role):
    """مسیر کانفیگ نمونه: اول example/ ریپو، بعد seed/ خودِ پنل.

    ردیف اول وقتی است که پنل کنار سورس C نصب شده (حالت عادی ریپو)؛ ردیف دوم
    پنل را مستقل می‌کند: پوشه‌ی panel را تنهایی هم ببرید، تولید کانفیگ
    استارتر کار می‌کند. seed/ همان example/ است، پس خروجی‌اش یکی است.
    """
    name = "client.json" if str(role).startswith("cli") else "server.json"
    for base in (EXAMPLE_DIR, SEED_DIR):
        path = os.path.join(base, name)
        if os.path.isfile(path):
            return path
    raise FileNotFoundError(
        f"کانفیگ نمونه‌ی {name} نه در {EXAMPLE_DIR} هست نه در {SEED_DIR}؛ "
        f"اگر پنل را مستقل می‌برید پوشه‌ی seed/ باید کنار app.py باشد.")


def load_example(role):
    """example/server.json یا example/client.json را می‌خواند."""
    with open(example_path(role), encoding="utf-8") as f:
        return json.load(f)


def detect_wan():
    """نام کارت شبکه‌ی پیش‌فرض و MAC gateway را از روی ماشین می‌خواند.

    خروجی (iface, gw_mac, via_ip)؛ هر کدام می‌تواند '' باشد (ماشین غیرلینوکسی
    یا iproute2 نصب‌نشده). فقط دستورهای read-only اجرا می‌شود.
    """
    def run(args):
        try:
            out = subprocess.run(args, capture_output=True, text=True, timeout=4)
        except (OSError, subprocess.SubprocessError):
            return ""
        return out.stdout or ""

    iface = via = gw_mac = ""
    text = run(["ip", "-o", "route", "show", "default"])
    m = re.search(r"\bdev\s+(\S+)", text)
    if m:
        iface = m.group(1)
    m = re.search(r"\bvia\s+(\d+\.\d+\.\d+\.\d+)", text)
    if m:
        via = m.group(1)
    if not iface and os.path.isdir("/sys/class/net"):
        # fallback: اولین اینترفیس up به‌جز lo
        for d in sorted(os.listdir("/sys/class/net")):
            if d == "lo":
                continue
            try:
                with open(f"/sys/class/net/{d}/operstate", encoding="ascii") as f:
                    if f.read().strip() == "up":
                        iface = d
                        break
            except OSError:
                continue
    if via:
        for line in run(["ip", "neigh", "show", via]).splitlines():
            m = re.search(r"\blladdr\s+([0-9a-fA-F:]{17})", line)
            if m and schema.MAC_RE.match(m.group(1)):
                gw_mac = m.group(1).lower()
                break
    return iface, gw_mac, via


def starter_config(role="server", api_bind="127.0.0.1:9090", token=None,
                   iface=None, gw_mac=None):
    """کانفیگ اولیه‌ی قابل‌لود برای یک نود تازه.

    از example/ همان ریپو ساخته می‌شود، پس loader آن را می‌پذیرد و نود بالا
    می‌آید تا پنل بتواند از راه API کانفیگ واقعی را PUT کند. این کانفیگ
    ترافیک معناداری حمل نمی‌کند (IPهای documentation-class و توکن پیش‌فرض
    در example): pool/peer/gateway را پنل در ویزارد جفت کانفیگ کامل می‌کند.
    """
    cfg = load_example(role)
    cfg.setdefault("api", {})
    cfg["api"]["bind"] = api_bind
    cfg["api"]["token"] = token or gen_token()
    for itf in cfg.get("interfaces") or []:
        if iface:
            itf.setdefault("incoming", {})["name"] = iface
            out = itf.setdefault("outgoing", {})
            out["name"] = iface
            gw = out.get("gateway")
            if gw_mac and schema.MAC_RE.match(gw_mac):
                (gw if isinstance(gw, dict) else out.setdefault("gateway", {}))["mac_address"] = gw_mac
            elif isinstance(gw, dict) and "gateway" in out:
                del out["gateway"]    # MAC نمونه‌ی ریپو روی VPS واقعی اشتباه است
        # logger را روی console می‌گذاریم تا systemd journal پر شود
    cfg["logger"] = {"level": "info", "driver": "console", "console": True,
                     "async": True,
                     "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"}
    return cfg


# ======================================================================
#  CLI — همان توابعی که UI صدا می‌زند، از shell هم قابل‌استفاده
# ======================================================================

def _cli(argv=None):
    import argparse
    import sys

    try:  # کنسول ویندوز با cp1252 متن فارسی خروجی را چاپ نمی‌کند
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    p = argparse.ArgumentParser(prog="gen.py",
                                description="تولید کانفیگ/فایروال injspoof")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("starter", help="کانفیگ اولیه‌ی نود")
    s.add_argument("--role", default="server", choices=["server", "client"])
    s.add_argument("--api-bind", default="127.0.0.1:9090")
    s.add_argument("--token", default=None)
    s.add_argument("--iface", default=None)
    s.add_argument("--gw-mac", default=None)
    s.add_argument("--auto-detect", action="store_true",
                   help="نام کارت و MAC gateway را از ماشین بگیر (linux)")
    s.add_argument("--out", default=None)

    f = sub.add_parser("firewall", help="اسکریپت nftables از روی یک کانفیگ")
    f.add_argument("--config", required=True)
    f.add_argument("--role", default="server", choices=["server", "client"])
    f.add_argument("--instance", default=None)
    f.add_argument("--engine", default="nft", choices=["nft", "iptables"])
    f.add_argument("--out", default=None)

    sub.add_parser("detect", help="اینترفیس پیش‌فرض و MAC gateway را چاپ کن")

    a = p.parse_args(argv)
    if a.cmd == "detect":
        iface, gw, via = detect_wan()
        print(f"IFACE={iface}\nGW_MAC={gw}\nVIA={via}")
        return 0

    if a.cmd == "starter":
        iface, gw = a.iface, a.gw_mac
        if a.auto_detect:
            d_iface, d_gw, _via = detect_wan()
            iface = iface or d_iface
            gw = gw or d_gw
        cfg = starter_config(a.role, a.api_bind, a.token, iface, gw)
        text = json.dumps(cfg, indent=2, ensure_ascii=False) + "\n"
        if a.out:
            with open(a.out, "w", encoding="utf-8") as fh:
                fh.write(text)
        else:
            print(text, end="")
        return 0

    if a.cmd == "firewall":
        with open(a.config, encoding="utf-8") as fh:
            cfg = json.load(fh)
        name = a.instance or os.path.splitext(os.path.basename(a.config))[0]
        if a.engine == "nft":
            text = nftables_script(cfg, name, instance=a.instance or name)
        else:
            text = iptables_script(cfg, name)
        if a.out:
            with open(a.out, "w", encoding="utf-8") as fh:
                fh.write(text)
                os.chmod(a.out, 0o644)
        else:
            print(text, end="")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(_cli())

