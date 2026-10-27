"""
schema.py — اعتبارسنجی و تحلیل کانفیگ injspoof

قوانین این فایل از سورس واقعی پروژه استخراج شده‌اند، نه از فایل‌های نمونه:
  * src/config.c   -> لودر کانفیگ و کرش‌محدوده‌ها (fail-fast)
  * src/config.h   -> سقف‌های ظرفیت (MAX_PEERS و ...)
  * src/server.c   -> منطق فیلتر فریم‌های دریافتی (filter_match خط 95)
  * src/client.c   -> مسیر TX کلاینت (خط 507: dst_port = dst_ports[0])
  * src/api.c      -> مسیرهای API و اعتبار توکن

نکته‌ای که در کانفیگ‌های example/ خود ریپو نقض شده و اینجا اصلاح می‌شود:
فیلتر incoming فقط «IP مبدأ» و «پورت مبدأ فریمِ دریافتی» را مقایسه می‌کند.
پس incoming.port.src سمت گیرنده باید با outgoing.port.src سمت فرستنده برابر
باشد؛ مثال‌های ریپو مقدار 443 را در incoming.port.src گذاشته‌اند درحالی‌که
فرستنده با پورت 3232 ارسال می‌کند، یعنی همه فریم‌ها drop_filter می‌شوند.
"""

from __future__ import annotations

import ipaddress
import re

# --- سقف‌های ظرفیت (src/config.h:13-25) ---
MAX_SOURCE_BLOCKS = 4096
MAX_SOURCE_PORTS = 64
MAX_PROVIDERS = 8
MAX_PEERS = 4096
MAX_FORWARDERS_PER_PEER = 16
MAX_FIREWALL_RULES = 32
MAX_INTERFACES = 16
HID_LEN = 5
DEFAULT_FRAGMENT_SIZE = 1400
FRAGMENT_MIN, FRAGMENT_MAX = 576, 9216

TCP_FLAGS = {"fin", "syn", "rst", "psh", "ack", "urg"}
SEQ_MODES = {"fixed", "random", "sequential"}
PROTOCOLS = {"tcp", "udp", "icmp"}
FASTPATH_MODES = {"auto", "af_xdp", "af_packet"}
LOG_LEVELS = {"trace", "debug", "info", "warn", "error", "fatal"}
LOG_DRIVERS = {"console", "file", "syslog", "composite"}
STRATEGIES = {"round_robin", "random"}

MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
HEX_OR_DEC_RE = re.compile(r"^(0[xX][0-9a-fA-F]{1,8}|\d{1,10})$")

ERROR = "error"
WARN = "warn"
INFO = "info"


class Issue(dict):
    """یک ایراد یا هشدار در کانفیگ."""

    def __init__(self, level: str, path: str, message: str, hint: str = ""):
        super().__init__(level=level, path=path, message=message, hint=hint)

    @property
    def level(self):
        return self["level"]

    @property
    def path(self):
        return self["path"]

    @property
    def message(self):
        return self["message"]

    @property
    def hint(self):
        return self["hint"]


def is_ipv4(value) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return isinstance(ipaddress.IPv4Address(value.strip()), ipaddress.IPv4Address)
    except ValueError:
        return False


def is_ipv4_network(value) -> bool:
    if not isinstance(value, str):
        return False
    try:
        ipaddress.IPv4Network(value.strip(), strict=False)
        return True
    except ValueError:
        return False


def parse_hostport(value):
    """'host:port' را به (host, port) تبدیل می‌کند؛ None در صورت نامعتبر."""
    if not isinstance(value, str) or ":" not in value:
        return None
    host, _, port = value.rpartition(":")
    port = port.strip()
    if not port.isdigit():
        return None
    p = int(port)
    if not (1 <= p <= 65535):
        return None
    if not is_ipv4(host):
        return None
    return host, p


def cidr_host_count(cidr: str) -> int:
    """تعداد آدرس‌هایی که injspoof از یک بلاک استخراج می‌کند.

    طبق docs/CONFIGURATION.md: /32 یک آدرس، /31 هر دو آدرس، و بلاک‌های
    بزرگ‌تر network و broadcast را حذف می‌کنند.
    """
    net = ipaddress.IPv4Network(cidr.strip(), strict=False)
    prefix = net.prefixlen
    if prefix >= 31:
        return net.num_addresses
    return max(0, net.num_addresses - 2)


def expand_pool(source, exclude_private=False, exclude_reserved=False,
                exclude_multicast=False):
    """استخراج تعداد میزبان‌های مؤثر یک source pool.

    ورودی می‌تواند list از provider object باشد یا یک object تنها
    (loader هر دو شکل را می‌پذیرد، src/config.c:416).
    """
    blocks, errors = [], []
    providers = source if isinstance(source, list) else ([source] if source else [])
    for prov in providers:
        if not isinstance(prov, dict):
            errors.append("provider باید object باشد")
            continue
        ptype = prov.get("type")
        value = prov.get("value")
        if ptype == "static":
            values = value if isinstance(value, list) else ([value] if isinstance(value, str) else [])
            for v in values:
                if not isinstance(v, str) or not is_ipv4_network(v):
                    errors.append(f"CIDR/IP نامعتبر: {v!r}")
                    continue
                blocks.append(v.strip())
        elif ptype == "file":
            # مسیر فایل در پنل قابل باز کردن نیست (روی سرور نود است)؛ تعداد نامعلوم.
            blocks.append(None)
        else:
            errors.append(f"نوع provider ناشناخته: {ptype!r}")

    total, unknown = 0, False
    for b in blocks:
        if b is None:
            unknown = True
            continue
        try:
            n = cidr_host_count(b)
        except ValueError:
            continue
        if exclude_private and _overlap_private(b):
            n = 0
        if exclude_multicast and _is_multicast(b):
            n = 0
        if exclude_reserved and _overlap_reserved(b):
            n = 0
        total += n
    return total, unknown, errors


_RFC1918 = [ipaddress.IPv4Network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
_RESERVED = [ipaddress.IPv4Network(x) for x in ("0.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16",
                                                "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
                                                "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4")]
_MULTICAST = ipaddress.IPv4Network("224.0.0.0/4")


def _net(cidr):
    return ipaddress.IPv4Network(cidr, strict=False)


def _overlap_private(cidr):
    n = _net(cidr)
    return any(n.overlaps(p) for p in _RFC1918)


def _overlap_reserved(cidr):
    n = _net(cidr)
    return any(n.overlaps(p) for p in _RESERVED)


def _is_multicast(cidr):
    return _net(cidr).subnet_of(_MULTICAST) or _net(cidr).overlaps(_MULTICAST)


# ======================================================================
#  اعتبارسنجی اصلی
# ======================================================================

def validate(cfg, mode="server"):
    """برگشت list[Issue]. هر error یعنی injspoof با همین کانفیگ اجرا نمی‌شود."""
    issues: list[Issue] = []

    def err(path, msg, hint=""):
        issues.append(Issue(ERROR, path, msg, hint))

    def warn(path, msg, hint=""):
        issues.append(Issue(WARN, path, msg, hint))

    def note(path, msg, hint=""):
        issues.append(Issue(INFO, path, msg, hint))

    if not isinstance(cfg, dict):
        err("$", "کانفیگ باید یک object JSON باشد")
        return issues

    # ---------------- api ----------------
    api = cfg.get("api")
    if not isinstance(api, dict):
        err("api", "بخش api اجباری است (src/config.c:parse_api)")
    else:
        hp = parse_hostport(api.get("bind"))
        if not hp:
            err("api.bind", "bind باید به شکل host:port و با IPv4 معتبر باشد",
                "مثال: 127.0.0.1:9090")
        elif hp[0] != "127.0.0.1":
            warn("api.bind", f"API روی {hp[0]} باز می‌شود",
                 "اگر پنل کنار نود است، 127.0.0.1 امن‌تر است. روی 0.0.0.0 "
                 "این توکن عملاً کلید سرور شماست.")
        tok = api.get("token")
        if not isinstance(tok, str) or not tok:
            err("api.token", "token باید رشته‌ی غیرخالی باشد (src/config.c:587)")
        elif len(tok) < 24:
            warn("api.token", "توکن کوتاه است", "پیشنهاد: openssl rand -hex 32")
        elif tok.startswith("CHANGE_ME"):
            # لودر injspoof این را می‌پذیرد (فقط غیرخالی بودن اجباری است)، پس خطا
            # نیست؛ ولی عملاً یعنی کلید API روی همه‌ی نودها یکی و قابل‌حدس است.
            warn("api.token", "توکن پیش‌فرض CHANGE_ME هنوز تغییر نکرده",
                 "پیش از روشن کردن نود در پروداکیشن عوضش کنید: openssl rand -hex 32")

    # ---------------- interfaces ----------------
    ifaces = cfg.get("interfaces")
    if not isinstance(ifaces, list) or not ifaces:
        err("interfaces", "حداقل یک interface لازم است")
        ifaces = []
    if len(ifaces) > MAX_INTERFACES:
        err("interfaces", f"بیش از {MAX_INTERFACES} interface مجاز نیست (config.h:25)")
    iface_tags = set()
    for i, itf in enumerate(ifaces, 1):
        p = f"interfaces[{i}]"
        if not isinstance(itf, dict):
            err(p, "هر interface باید object باشد")
            continue
        tag = itf.get("tag")
        if not isinstance(tag, str) or not tag:
            err(f"{p}.tag", "tag اجباری است")
        elif tag in iface_tags:
            err(f"{p}.tag", f"tag تکراری: {tag}")
        else:
            iface_tags.add(tag)
        out = itf.get("outgoing") or {}
        if not isinstance(out, dict) or not out.get("name"):
            err(f"{p}.outgoing.name", "نام کارت شبکه برای outgoing اجباری است",
                "با `ip -br a` نام واقعی را ببینید (eth0/ens3/...)")
        gw = (out.get("gateway") or {}).get("mac_address") if isinstance(out, dict) else None
        if gw is not None and not MAC_RE.match(str(gw)):
            err(f"{p}.outgoing.gateway.mac_address", f"MAC نامعتبر: {gw!r}",
                "MAC بعدی‌پرش را با `ip neigh` بگیرید؛ مقدار نمونه ریپو روی "
                "بیشتر VPSها اشتباه است و فریم از NIC خارج نمی‌شود.")
        elif not gw:
            warn(f"{p}.outgoing.gateway.mac_address", "MAC gateway ست نشده",
                 "بدون آن فریم خام مقصد L2 ندارد.")
        frag = itf.get("fragment_size", DEFAULT_FRAGMENT_SIZE)
        if not isinstance(frag, int) or isinstance(frag, bool) or not (FRAGMENT_MIN <= frag <= FRAGMENT_MAX):
            err(f"{p}.fragment_size", f"fragment_size باید عددی بین {FRAGMENT_MIN}-{FRAGMENT_MAX} باشد")
        elif frag > 1500:
            warn(f"{p}.fragment_size", "بزرگ‌تر از MTU معمول اینترنت (1500)",
                 "مقدار را کمی پایین‌تر از path MTU بگذارید تا black-hole نشود.")
        if not out.get("name"):
            err(f"{p}.outgoing.name", "outgoing.name خالی است")

    # ---------------- firewall ----------------
    rules = cfg.get("firewall")
    if not isinstance(rules, list) or not rules:
        err("firewall", "حداقل یک firewall rule لازم است")
        rules = []
    if len(rules) > MAX_FIREWALL_RULES:
        err("firewall", f"بیش از {MAX_FIREWALL_RULES} rule مجاز نیست (config.h:23)")
    rule_tags = {}
    for i, fw in enumerate(rules, 1):
        p = f"firewall[{i}]"
        if not isinstance(fw, dict):
            err(p, "هر rule باید object باشد")
            continue
        tag = fw.get("tag")
        if not isinstance(tag, str) or not tag:
            err(f"{p}.tag", "tag اجباری و غیرخالی است")
        elif tag in rule_tags:
            err(f"{p}.tag", f"tag تکراری: {tag}")
        else:
            rule_tags[tag] = i
        for direction in ("outgoing", "incoming"):
            dp = f"{p}.{direction}"
            d = fw.get(direction)
            if not isinstance(d, dict):
                err(dp, f"جهت {direction} اجباری است (هر دو جهت لازم)")
                continue
            _validate_direction(d, dp, direction, err, warn, note)

    # ---------------- peers ----------------
    peers = cfg.get("peers")
    if not isinstance(peers, list) or not peers:
        err("peers", "حداقل یک peer لازم است")
        peers = []
    if len(peers) > MAX_PEERS:
        err("peers", f"بیش از {MAX_PEERS} peer مجاز نیست (config.h:20)")
    hids = set()
    total_forwards = 0
    for i, pr in enumerate(peers, 1):
        p = f"peers[{i}]"
        if not isinstance(pr, dict):
            err(p, "هر peer باید object باشد")
            continue
        hid = pr.get("hid")
        if not isinstance(hid, str) or len(hid) != HID_LEN:
            err(f"{p}.hid", f"hid باید دقیقاً {HID_LEN} کاراکتر باشد (مقدار فعلی: {hid!r})",
                "hid همان کلید demux سمت سرور است؛ در هر دو طرف باید یکی باشد.")
        elif hid in hids:
            err(f"{p}.hid", f"hid تکراری: {hid}")
        else:
            hids.add(hid)
        if not is_ipv4(pr.get("address")):
            err(f"{p}.address", f"address باید IPv4 معتبر باشد (مقدار: {pr.get('address')!r})",
                "این IP واقعی و قابل‌روت سمت مقابل است؛ spoofed نیست.")
        rule = pr.get("rule")
        if rule not in rule_tags:
            err(f"{p}.rule", f"rule '{rule}' در firewall تعریف نشده")
        itf = pr.get("interface")
        if itf not in iface_tags:
            err(f"{p}.interface", f"interface '{itf}' تعریف نشده")
        fwds = pr.get("forwards")
        if fwds is not None:
            if not isinstance(fwds, list):
                err(f"{p}.forwards", "forwards باید array باشد")
            else:
                if len(fwds) > MAX_FORWARDERS_PER_PEER:
                    err(f"{p}.forwards", f"حداکثر {MAX_FORWARDERS_PER_PEER} forward per peer")
                for j, f in enumerate(fwds, 1):
                    fp = f"{p}.forwards[{j}]"
                    total_forwards += 1
                    if not isinstance(f, dict):
                        err(fp, "forward باید object باشد")
                        continue
                    if not parse_hostport(f.get("bind")):
                        err(f"{fp}.bind", "bind باید host:port باشد",
                            "گوش‌سپار محلی UDP که ترافیک برنامه را می‌گیرد.")
                    if not parse_hostport(f.get("redirect")):
                        err(f"{fp}.redirect", "redirect باید host:port باشد",
                            "مقصدی که سرور بعد از حذف هدر به آن UDP می‌فرستد.")
        if mode == "server" and fwds:
            warn(f"{p}.forwards", "forwards در حالت server بی‌اثر است",
                 "list forwarder فقط در کلاینت معنا دارد.")

    if mode == "client" and total_forwards == 0:
        err("peers", "در حالت client حداقل یک forwarder لازم است (docs/CONFIGURATION.md)")

    # ---------------- tuning / logger ----------------
    tuning = cfg.get("tuning") or {}
    if isinstance(tuning, dict) and tuning:
        fp = tuning.get("fastpath") or {}
        if not isinstance(fp, dict):
            err("tuning.fastpath", "fastpath باید object باشد")
        else:
            m = fp.get("mode", "auto")
            if m not in FASTPATH_MODES:
                err("tuning.fastpath.mode", f"mode باید یکی از {sorted(FASTPATH_MODES)} باشد")
            elif m == "af_xdp":
                warn("tuning.fastpath.mode", "af_xdp اجباری شده",
                     "روی درایورهای VM معمولاً پشتیبانی نمی‌شود؛ auto امن‌تر است "
                     "(docs/OPERATIONS.md Troubleshooting).")
            q = fp.get("queues", 0)
            if not isinstance(q, int) or isinstance(q, bool) or not (0 <= q <= 4096):
                err("tuning.fastpath.queues", "queues باید 0 تا 4096 باشد")
    else:
        tuning = {}

    logger = cfg.get("logger") or {}
    if isinstance(logger, dict) and logger:
        lvl = logger.get("level", "info")
        if lvl not in LOG_LEVELS:
            err("logger.level", f"level باید یکی از {sorted(LOG_LEVELS)} باشد")
        drv = logger.get("driver", "console")
        if drv not in LOG_DRIVERS:
            err("logger.driver", f"driver باید یکی از {sorted(LOG_DRIVERS)} باشد")
        if drv in ("file", "composite") and not (logger.get("options") or {}).get("file_path"):
            warn("logger.options.file_path", f"driver={drv} ولی file_path ست نشده")
    return issues


def _validate_direction(d, dp, direction, err, warn, note):
    src = d.get("source")
    providers = src if isinstance(src, list) else ([src] if isinstance(src, dict) else [])
    if not providers:
        err(f"{dp}.source", "source اجباری است")
    if len(providers) > MAX_PROVIDERS:
        err(f"{dp}.source", f"حداکثر {MAX_PROVIDERS} provider برای هر pool (config.h:17)")

    opts = d.get("options") or {}
    ex = (opts.get("exclude") or {}) if isinstance(opts, dict) else {}
    if providers:
        count, unknown, perr = expand_pool(
            src,
            exclude_private=bool(ex.get("private")),
            exclude_reserved=bool(ex.get("reserved")),
            exclude_multicast=bool(ex.get("multicast")),
        )
        for e in perr:
            err(f"{dp}.source", e)
        blocks = _count_blocks(providers)
        if blocks > MAX_SOURCE_BLOCKS:
            err(f"{dp}.source", f"حداکثر {MAX_SOURCE_BLOCKS} بلاک CIDR در هر pool")
        if direction == "outgoing" and not unknown and count == 0:
            err(f"{dp}.source", "استخر IP مبدأ پس از فیلترها خالی شد",
                "مثلاً exclude.private روی بلاک خصوصی گذاشته شده.")

    port = d.get("port") or {}
    src_ports, dst_ports = [], []
    if isinstance(port, dict):
        src_ports = _port_list(port.get("src"), f"{dp}.port.src", err)
        dst_ports = _port_list(port.get("dst", port.get("dest")), f"{dp}.port.dst", err)
    if len(src_ports) > MAX_SOURCE_PORTS:
        err(f"{dp}.port.src", f"حداکثر {MAX_SOURCE_PORTS} پورت مبدأ")
    if len(dst_ports) > MAX_SOURCE_PORTS:
        err(f"{dp}.port.dst", f"حداکثر {MAX_SOURCE_PORTS} پورت مقصد")

    proto = d.get("protocol") or {}
    pname = "udp"
    if proto:
        if not isinstance(proto, dict):
            err(f"{dp}.protocol", "protocol باید object باشد")
        else:
            pname = proto.get("name", proto.get("mode", "udp"))
            if pname not in PROTOCOLS:
                err(f"{dp}.protocol.name", f"protocol باید یکی از {sorted(PROTOCOLS)} باشد")
            po = proto.get("options") or {}
            if pname == "tcp":
                flags = po.get("flags")
                if flags is not None:
                    parts = [f.strip().lower() for f in str(flags).split("+")]
                    bad = [f for f in parts if f and f not in TCP_FLAGS]
                    if bad:
                        err(f"{dp}.protocol.options.flags", f"فلگ نامعتبر: {bad}",
                            "فلگ‌ها با + جدا می‌شوند: fin syn rst psh ack urg")
                seq = po.get("seq", "fixed")
                if seq not in SEQ_MODES:
                    err(f"{dp}.protocol.options.seq", f"seq باید یکی از {sorted(SEQ_MODES)} باشد")
                for k in ("seq_base", "ack_base"):
                    v = po.get(k)
                    if v is not None and not _is_u32(v):
                        err(f"{dp}.protocol.options.{k}",
                            f"{k} باید عددی بین 0 و 4294967295 باشد (دهدهی یا 0x هگز)")
            elif pname == "icmp":
                for k, lim in (("icmp_type", 255), ("icmp_code", 255)):
                    v = po.get(k)
                    if v is not None and (not isinstance(v, int) or isinstance(v, bool) or not (0 <= v <= lim)):
                        err(f"{dp}.protocol.options.{k}", f"{k} باید 0 تا {lim} باشد")

    # --- قواعد مبتنی بر کد ---
    if direction == "outgoing":
        if not src_ports:
            warn(f"{dp}.port.src", "پورت مبدأ نداده‌اید؛ لودر یک پورت تصادفی "
                 "ephemeral در زمان بوت انتخاب می‌کند (src/config.c:459)",
                 "سمت مقابل نمی‌تواند incoming.port.src را دقیق ست کند؛ باید خالی "
                 "بماند تا «هر پورت» معنی شود.")
        if not dst_ports:
            warn(f"{dp}.port.dst", "پورت مقصد نداده‌اید؛ مقدار تصادفی انتخاب می‌شود "
                 "(src/config.c:464)")
        elif len(dst_ports) > 1:
            warn(f"{dp}.port.dst", f"فقط dst_ports[0] روی سیم می‌نشیند "
                 f"(src/client.c:507 و src/server.c:509)؛ {len(dst_ports) - 1} مقدار "
                 "اضافه نادیده گرفته می‌شود")
    else:  # incoming
        if pname == "icmp" and src_ports:
            err(f"{dp}.port.src", "با encapsulation از نوع ICMP هیچ پورت مبدأی روی "
                "فریم نیست (parse_rx مقدار 0 می‌دهد، src/server.c:143)؛ پس هر لیست "
                "پورتی همه فریم‌ها را drop می‌کند",
                "برای ICMP بخش port.src incoming را حذف کنید.")
        if len(src_ports) == 0:
            note(f"{dp}.port.src", "لیست خالی یعنی «هر پورت مبدأ» پذیرفته می‌شود "
                 "(src/server.c:107)",
                 "برای امنیت بیشتر، پورت‌های دقیق سمت مقابل را اینجا بگذارید.")


def _port_list(node, path, err):
    out = []
    if node is None:
        return out
    if not isinstance(node, list):
        err(path, "لیست پورت باید array باشد")
        return out
    for v in node:
        if isinstance(v, bool) or not isinstance(v, int):
            err(path, f"پورت باید عدد باشد: {v!r}")
            continue
        if not (1 <= v <= 65535):
            err(path, f"پورت خارج از بازه 1-65535: {v}")
            continue
        out.append(v)
    return out


def _count_blocks(providers):
    n = 0
    for prov in providers:
        if not isinstance(prov, dict):
            continue
        if prov.get("type") == "static":
            v = prov.get("value")
            n += len(v) if isinstance(v, list) else (1 if isinstance(v, str) else 0)
        elif prov.get("type") == "file":
            n += 1
    return n


def _is_u32(v):
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return 0 <= v <= 0xFFFFFFFF
    if isinstance(v, str):
        if not HEX_OR_DEC_RE.match(v.strip()):
            return False
        try:
            n = int(v.strip(), 0)
            return 0 <= n <= 0xFFFFFFFF
        except ValueError:
            return False
    return False


# ======================================================================
#  برچسب‌های فارسی برای نمایش
# ======================================================================

def summary(issues):
    return {
        "error": sum(1 for i in issues if i["level"] == ERROR),
        "warn": sum(1 for i in issues if i["level"] == WARN),
        "info": sum(1 for i in issues if i["level"] == INFO),
    }


def ok(issues):
    return not any(i["level"] == ERROR for i in issues)


# ======================================================================
#  هم‌راستایی جفت کانفیگ (کلاینت + سرور)
# ======================================================================

def _rule_of(cfg, tag):
    for fw in cfg.get("firewall") or []:
        if isinstance(fw, dict) and fw.get("tag") == tag:
            return fw
    return None


def _ports(direction_obj, key):
    port = (direction_obj or {}).get("port") or {}
    if not isinstance(port, dict):
        return []
    vals = port.get(key)
    if vals is None and key == "dst":
        vals = port.get("dest")
    if not isinstance(vals, list):
        return []
    return [v for v in vals if isinstance(v, int) and not isinstance(v, bool)]


def _source_values(direction_obj):
    """مجموعه‌ی CIDR/IP های static یک جهت (برای مقایسه‌ی استخرها)."""
    src = (direction_obj or {}).get("source")
    providers = src if isinstance(src, list) else ([src] if isinstance(src, dict) else [])
    nets = set()
    file_provider = False
    for prov in providers:
        if not isinstance(prov, dict):
            continue
        if prov.get("type") == "static":
            v = prov.get("value")
            for item in (v if isinstance(v, list) else ([v] if isinstance(v, str) else [])):
                nets.add(str(item).strip())
        elif prov.get("type") == "file":
            file_provider = True
    return nets, file_provider


def _nets_overlap(a_set, b_set):
    for a in a_set:
        try:
            na = ipaddress.IPv4Network(a, strict=False)
        except ValueError:
            continue
        for b in b_set:
            try:
                if na.overlaps(ipaddress.IPv4Network(b, strict=False)):
                    return True
            except ValueError:
                continue
    return False


def check_pair(client_cfg, server_cfg):
    """آیا دو کانفیگ واقعاً یکدیگر را می‌بینند؟ بر پایه‌ی filter_match نوشته شده."""
    issues: list[Issue] = []
    err = lambda p, m, h="": issues.append(Issue(ERROR, p, m, h))
    warn = lambda p, m, h="": issues.append(Issue(WARN, p, m, h))
    note = lambda p, m, h="": issues.append(Issue(INFO, p, m, h))

    cp = {p.get("hid"): p for p in (client_cfg.get("peers") or []) if isinstance(p, dict)}
    sp = {p.get("hid"): p for p in (server_cfg.get("peers") or []) if isinstance(p, dict)}

    shared = set(cp) & set(sp)
    for hid in set(cp) - set(sp):
        warn(f"client.peer[{hid}]", "این hid در کانفیگ سرور وجود ندارد؛ "
             "ترافیکش سمت سرور drop_parse/drop_filter می‌شود")
    for hid in set(sp) - set(cp):
        warn(f"server.peer[{hid}]", "این peer در سرور تعریف شده ولی کلاینتی برایش نیست")

    for hid in sorted(shared):
        cpeer, speer = cp[hid], sp[hid]
        ctag, stigma = cpeer.get("rule"), speer.get("rule")
        crule, srule = _rule_of(client_cfg, ctag), _rule_of(server_cfg, stigma)
        if crule is None:
            err(f"client.peer[{hid}].rule", f"rule '{ctag}' در کانفیگ کلاینت تعریف نشده")
            continue
        if srule is None:
            err(f"server.peer[{hid}].rule", f"rule '{stigma}' در کانفیگ سرور تعریف نشده")
            continue

        c_out = crule.get("outgoing") or {}
        c_in = crule.get("incoming") or {}
        s_out = srule.get("outgoing") or {}
        s_in = srule.get("incoming") or {}

        # ۱) استخر IP مبدأ فرستنده باید در incoming گیرنده باشد
        c_out_src, c_out_file = _source_values(c_out)
        c_in_src, _ = _source_values(c_in)
        s_out_src, s_out_file = _source_values(s_out)
        s_in_src, _ = _source_values(s_in)

        _compare_pools(hid, "کلاینت→سرور", c_out_src, s_in_src, err, warn, note, c_out_file)
        _compare_pools(hid, "سرور→کلاینت", s_out_src, c_in_src, err, warn, note, s_out_file)

        # ۲) incoming.port.src گیرنده باید پورت مبدأ فرستنده را بپوشاند
        _compare_ports(hid, "کلاینت→سرور", _ports(c_out, "src"), _ports(s_in, "src"),
                       err, warn, note)
        _compare_ports(hid, "سرور→کلاینت", _ports(s_out, "src"), _ports(c_in, "src"),
                       err, warn, note)

        # ۳) encapsulation دو طرف باید یکی باشد
        for label, a, b in (("رفت", c_out, s_in), ("برگشت", s_out, c_in)):
            pa = ((a.get("protocol") or {}) if isinstance(a.get("protocol"), dict) else {}).get("name", "udp")
            pb = ((b.get("protocol") or {}) if isinstance(b.get("protocol"), dict) else {}).get("name", "udp")
            if pa != pb:
                err(f"pair[{hid}].{label}.protocol",
                    f"encapsulation مسیر {label} یکی نیست: فرستنده {pa}، گیرنده {pb}",
                    "گیرنده بر اساس فیلد protocol هدر IP تفسیر می‌کند و فیلتر "
                    "fastpath هم از همین مقدار ساخته می‌شود.")

        # ۴) آدرس peerها باید IP واقعی طرف مقابل باشد
        c_addr, s_addr = cpeer.get("address"), speer.get("address")
        if c_addr and s_addr:
            s_out_ips = _public_first(s_out_src)
            c_out_ips = _public_first(c_out_src)
            if s_addr and c_out_ips and _in_pools(str(s_addr), c_out_src):
                warn(f"client.peer[{hid}].address",
                     f"آدرس peer ({s_addr}) داخل استخر spoofed خود کلاینت است؛ "
                     "peer.address باید IP واقعی/قابل‌روت سمت مقابل باشد")
            if c_addr and s_out_ips and _in_pools(str(c_addr), s_out_src):
                warn(f"server.peer[{hid}].address",
                     f"آدرس peer ({c_addr}) داخل استخر spoofed سرور است")

        # ۵) پورت مقصد مؤثر روی سیم
        c_dst = _ports(c_out, "dst")
        s_dst = _ports(s_out, "dst")
        note(f"pair[{hid}].dst_port",
             f"پورت مقصد واقعی روی سیم: رفت={'—' if not c_dst else c_dst[0]}، "
             f"برگشت={'—' if not s_dst else s_dst[0]} "
             "(src/client.c:507 و src/server.c:509 فقط dst_ports[0] را استفاده می‌کنند)")

    # ۶) صحت کلی هر دو کانفیگ هم باید بررسی شود
    for label, cfg_, mode in (("client", client_cfg, "client"), ("server", server_cfg, "server")):
        for i in validate(cfg_, mode):
            if i["level"] == ERROR:
                issues.append(Issue(ERROR, f"{label}:{i['path']}", i["message"], i["hint"]))

    # ۷) توکن‌ها و پورت‌های API
    c_api = (client_cfg.get("api") or {})
    s_api = (server_cfg.get("api") or {})
    if c_api.get("token") and c_api.get("token") == s_api.get("token"):
        note("pair.api.token", "هر دو نود یک توکن API دارند",
             "اگر یک نود لوگو برود، توکن مشترک دسترسی هر دو را می‌دهد.")
    if c_api.get("bind") and c_api.get("bind") == s_api.get("bind"):
        note("pair.api.bind", "bind یکسان در دو نود (مشکل ندارد چون روی هر ماشین جداست)")

    return issues


def _compare_pools(hid, direction, sender_pool, receiver_filter, err, warn, note,
                  sender_has_file):
    if sender_has_file:
        note(f"pair[{hid}].{direction}.source",
             "فرستنده provider از نوع file دارد؛ پنل نمی‌تواند محتوای فایل روی سرور "
             "نود را بخواند، پس هم‌راستایی بررسی نشد")
        return
    if not sender_pool:
        return
    if not receiver_filter:
        note(f"pair[{hid}].{direction}.source",
             "گیرنده فیلتر source ندارد (هر IP مبدأ قبول می‌شود) — کار می‌کند ولی "
             "هر ترافیک جعلی دیگری را هم می‌پذیرد")
        return
    if sender_pool == receiver_filter:
        return
    if _nets_overlap(sender_pool, receiver_filter):
        warn(f"pair[{hid}].{direction}.source",
             f"استخر فرستنده {sorted(sender_pool)} با فیلتر گیرنده {sorted(receiver_filter)} "
             "فقط همپوشانی دارد؛ بخش خارج از همپوشانی drop_filter می‌شود",
             "معمولاً باید دقیقاً همان CIDR فرستنده در incoming گیرنده تکرار شود.")
    else:
        err(f"pair[{hid}].{direction}.source",
            f"هیچ همپوشانی میان استخر مبدأ فرستنده {sorted(sender_pool)} و فیلتر "
            f"source گیرنده {sorted(receiver_filter)} نیست",
            "همه فریم‌های این مسیر drop_filter می‌شوند (src/server.c:99).")


def _compare_ports(hid, direction, sender_src, receiver_src, err, warn, note):
    if not sender_src:
        if receiver_src:
            warn(f"pair[{hid}].{direction}.port.src",
                 "فرستنده پورت مبدأ مشخصی ندارد (پورت تصادفی در زمان بوت) ولی گیرنده "
                 f"فقط {receiver_src} را می‌پذیرد → تقریباً همه فریم‌ها drop می‌شوند",
                 "یا برای فرستنده پورت ثابت بگذارید، یا لیست incoming گیرنده را خالی کنید.")
        return
    if not receiver_src:
        note(f"pair[{hid}].{direction}.port.src",
             "گیرنده هر پورت مبدأ را می‌پذیرد (لیست خالی)")
        return
    missing = [p for p in sender_src if p not in receiver_src]
    if missing:
        err(f"pair[{hid}].{direction}.port.src",
            f"پورت‌های مبدأ فرستنده {missing} در فیلتر port.src گیرنده نیستند",
            "فیلتر incoming فقط IP مبدأ و پورت مبدأ فریم دریافتی را مقایسه می‌کند "
            "(src/server.c:107)؛ این فریم‌ها drop_filter می‌شوند.")


def _in_pools(ip, pool):
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    for cidr in pool:
        try:
            if addr in ipaddress.IPv4Network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def _public_first(pool):
    for cidr in pool:
        try:
            return str(next(ipaddress.IPv4Network(cidr, strict=False).hosts()))
        except (ValueError, StopIteration):
            continue
    return None


# ======================================================================
#  ظرفیت استخر = سقف جریان هم‌زمان
# ======================================================================

def capacity_report(cfg):
    """بر هر rule: ظرفیت tuple (src IP × src port) که برای تمایز جریان‌ها دارد."""
    rows = []
    for fw in cfg.get("firewall") or []:
        if not isinstance(fw, dict):
            continue
        out = fw.get("outgoing") or {}
        opts = out.get("options") or {}
        ex = opts.get("exclude") or {} if isinstance(opts, dict) else {}
        hosts, unknown, _ = expand_pool(
            out.get("source"),
            exclude_private=bool(ex.get("private")),
            exclude_reserved=bool(ex.get("reserved")),
            exclude_multicast=bool(ex.get("multicast")),
        )
        ports = _ports(out, "src")
        port_n = len(ports) if ports else 1
        rows.append({
            "tag": fw.get("tag"),
            "direction": "outgoing",
            "hosts": hosts,
            "hosts_unknown": unknown,
            "ports": port_n,
            "explicit_ports": bool(ports),
            "flows": hosts * port_n,
            "protocol": ((out.get("protocol") or {}).get("name", "udp")
                         if isinstance(out.get("protocol"), dict) else "udp"),
        })
    return rows

