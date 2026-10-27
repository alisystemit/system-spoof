"""
selftest.py — آزمون منطقی اعتبارسنج و تولیدکننده‌ی پنل

اجرا:  python selftest.py          (از داخل پوشه‌ی panel)

سه چیز را ثابت می‌کند:
  ۱) کانفیگ‌های example/ خود ریپو با منطق فیلتر src/server.c هم‌راستا نیستند
  ۲) خروجی ویزارد پنل هم‌راستاست و خطای جدی ندارد
  ۳) خطاهای رایج (hid 4 کاراکتری، IPv6 در address، ICMP با پورت فیلترشده) گرفته می‌شوند

و از وقتی هسته داخل پنل نشست، چهار چیز دیگر:
  ۴) قواعد فایروال per-instance است و دو instance همدیگر را پاک نمی‌کنند
  ۵) starter کانفیگی که install.sh می‌سازد بدون خطا لود می‌شود
  ۶) قرارداد core.py با helper و مهاجرت ستون‌های is_local/core_instance در db
  ۷) قرارداد install.sh با injspoof-nodectl: گروه کانفیگ از state می‌آید، ثبت
     نود با کاربر سرویس انجام می‌شود، و --core-only به venv پنل نیاز ندارد

و از وقتی پنل مستقل شد و فونت گرفت، دو چیز دیگر:
  ۸) فونت‌ها خودمیزبان‌اند: هر @font-face یک فایل woff2 واقعی در static/fonts
     است، هیچ ارجاع بیرونی‌ای نیست و همه‌ی وزن‌های مصرفی پوشش دارند
  ۹) پنل بدون ریپوی C هم کار می‌کند: seed/ جای example/ را می‌گیرد، VERSION و
     LICENSE و GUIDE.md کنار کدند و install.sh نبودن سورس هسته را می‌بخشد
"""

from __future__ import annotations

import copy
import json
import os
import re
import sys

import gen
import schema

try:  # کنسول ویندوز با cp1252 متن فارسی را چاپ نمی‌کند
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PANEL = os.path.dirname(os.path.abspath(__file__))
EXAMPLE = os.path.join(ROOT, "example")
SEED = os.path.join(PANEL, "seed")

PASSED, FAILED = [], []


def check(name, condition, detail=""):
    (PASSED if condition else FAILED).append((name, detail))
    mark = "PASS" if condition else "FAIL"
    print(f"[{mark}] {name}" + (f"  -> {detail}" if detail and not condition else ""))


def load(name):
    """example/ ریپو را می‌خواند؛ اگر نبود seed/ خودِ پنل.

    با این fallback پنلِ مستقل (کپیِ پوشه‌ی panel بدون سورس C) هم می‌تواند
    کل selftest را اجرا کند. seed/ کپیِ هم‌سان example/ است (بررسی ۱۴).
    """
    for base in (EXAMPLE, SEED):
        path = os.path.join(base, name)
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                return json.load(f)
    raise FileNotFoundError(name)


def core_info_sample():
    """نمونه‌ی خروجی `injspoof-nodectl info` (همان KEY=valueهای واقعی)."""
    return "\n".join([
        "INSTANCE=server",
        "UNIT=injspoof@server",
        "CONFIG_PATH=/etc/injspoof/server.json",
        "BINARY=/usr/local/bin/injspoof",
        "BINARY_CAPS=/usr/local/bin/injspoof cap_net_raw=eip",
        "BUILD_INFO=version 1.0 built 2026-10-27",
        "SERVICE_STATE=active",
        "FIREWALL_SCRIPT=absent",
        "UPDATE_ALLOWED=no",
    ])


def main():
    # ---------- ۱) مثال‌های ریپو ----------
    client_cfg, server_cfg = load("client.json"), load("server.json")
    issues = schema.check_pair(client_cfg, server_cfg)
    errs = [i for i in issues if i["level"] == schema.ERROR]
    paths = " | ".join(i["path"] for i in errs)
    check("example pair is misaligned (expected)", not schema.ok(issues),
          f"{len(errs)} error: {paths}")
    port_errs = [i for i in errs if "port.src" in i["path"]]
    check("misalignment is the port.src kind", bool(port_errs),
          "; ".join(i["message"] for i in port_errs) or "no port.src error found")
    print("    نمونه خطای پنل:", port_errs[0]["message"] if port_errs else "—")

    # ---------- ۲) خروجی ویزارد ----------
    spec = {
        "name": "wg-1",
        "protocol": "tcp",
        "wire_dst_port": 443,
        "iface_tag": "wan",
        "client": {"public_ip": "185.1.2.3", "iface": "eth0",
                   "gw_mac": "00:11:22:33:44:55", "api_bind": "127.0.0.1:9091",
                   "api_token": "a" * 32, "pool": ["198.51.100.0/24"],
                   "src_ports": [3232]},
        "server": {"public_ip": "185.9.9.9", "iface": "eth0",
                   "gw_mac": "00:11:22:33:aa:bb", "api_bind": "127.0.0.1:9090",
                   "api_token": "b" * 32, "pool": ["203.0.113.0/24"],
                   "src_ports": [5454]},
        "forwards": [{"bind": "127.0.0.1:51820", "redirect": "127.0.0.1:51820"}],
    }
    c2, s2, meta = gen.build_pair(spec)
    pair_issues = schema.check_pair(c2, s2)
    check("wizard output passes check_pair", schema.ok(pair_issues),
          json.dumps([dict(i) for i in pair_issues if i["level"] == schema.ERROR],
                     ensure_ascii=False))
    check("client.json is valid on its own",
          schema.ok(schema.validate(c2, "client")),
          str([dict(i) for i in schema.validate(c2, "client")
               if i["level"] == schema.ERROR]))
    check("server.json is valid on its own",
          schema.ok(schema.validate(s2, "server")),
          str([dict(i) for i in schema.validate(s2, "server")
               if i["level"] == schema.ERROR]))

    # incoming کلاینت باید پورت مبدأ سرور را بپوشاند (نه پورت مقصد)
    cli_in = c2["firewall"][0]["incoming"]["port"]["src"]
    srv_out = s2["firewall"][0]["outgoing"]["port"]["src"]
    check("client incoming.port.src == server outgoing.port.src",
          cli_in == srv_out, f"{cli_in} vs {srv_out}")
    srv_in = s2["firewall"][0]["incoming"]["port"]["src"]
    cli_out = c2["firewall"][0]["outgoing"]["port"]["src"]
    check("server incoming.port.src == client outgoing.port.src",
          srv_in == cli_out, f"{srv_in} vs {cli_out}")

    # ---------- ۳) ICMP ----------
    spec_icmp = copy.deepcopy(spec)
    spec_icmp["protocol"] = "icmp"
    c3, s3, _ = gen.build_pair(spec_icmp)
    check("icmp drops incoming port filter",
          "port" not in c3["firewall"][0]["incoming"],
          str(c3["firewall"][0]["incoming"]))
    check("icmp pair still aligned", schema.ok(schema.check_pair(c3, s3)))

    bad = copy.deepcopy(c3)
    bad["firewall"][0]["incoming"]["port"] = {"src": [443]}
    found = [i for i in schema.validate(bad, "client")
             if i["level"] == schema.ERROR and "ICMP" in i["message"]]
    check("validator rejects icmp + port filter", bool(found),
          str([dict(i) for i in schema.validate(bad, "client")
               if i["level"] == schema.ERROR]))

    # ---------- ۴) خطاهای رایج ----------
    broken = copy.deepcopy(c2)
    broken["peers"][0]["hid"] = "abcd"
    broken["peers"][0]["address"] = "2001:db8::1"
    broken["api"]["token"] = "CHANGE_ME_use_a_long_random_secret"
    broken["interfaces"][0]["outgoing"]["gateway"]["mac_address"] = "not-a-mac"
    broken["interfaces"][0]["fragment_size"] = 9000
    broken["peers"][0]["rule"] = "ghost-rule"
    errs = {i["path"].split(".")[-1]: i for i in schema.validate(broken, "client")
            if i["level"] == schema.ERROR}
    check("rejects 4-char hid", "hid" in errs, str(list(errs)))
    check("rejects IPv6 peer address", "address" in errs, str(list(errs)))
    warns = {i["path"].split(".")[-1] for i in schema.validate(broken, "client")
             if i["level"] == schema.WARN}
    check("flags default CHANGE_ME token as a warning, not a blocker",
          "token" not in errs and "token" in warns,
          f"errs={list(errs)} warns={list(warns)}")
    check("rejects malformed MAC", "mac_address" in errs, str(list(errs)))
    check("rejects unknown rule reference", "rule" in errs, str(list(errs)))
    check("accepts fragment_size 9000 (jumbo, only a warning)",
          any(i["path"].endswith("fragment_size") and i["level"] == schema.WARN
              for i in schema.validate(broken, "client")))

    # ---------- ۵) merge روی کانفیگ سرور ----------
    second = copy.deepcopy(spec)
    second["name"] = "wg-2"
    second["hid"] = "cl2xx"
    second["client"]["public_ip"] = "185.1.2.4"
    second["client"]["pool"] = ["198.51.101.0/28"]
    second["client"]["src_ports"] = [3233]
    merged, m_issues = gen.merge_client_into_server(s2, second)
    check("merge adds one peer + one rule to server config",
          len(merged["peers"]) == 2 and len(merged["firewall"]) == 2 and schema.ok(m_issues),
          str([dict(i) for i in m_issues]))
    check("merged server config still valid",
          schema.ok(schema.validate(merged, "server")),
          str([dict(i) for i in schema.validate(merged, "server")
               if i["level"] == schema.ERROR]))
    second_client_cfg, _s2b, _m2 = gen.build_pair(second)
    aligned = schema.check_pair(second_client_cfg, merged)
    check("merged rule is the SERVER view (aligned with the new client)",
          schema.ok(aligned),
          str([dict(i) for i in aligned if i["level"] == schema.ERROR]))
    dupe, d_issues = gen.merge_client_into_server(merged, second)
    check("merge refuses duplicate hid", not schema.ok(d_issues),
          str([dict(i) for i in d_issues]))

    # ---------- ۶) ظرفیت استخر ----------
    caps = schema.capacity_report(c2)
    check("capacity = hosts x ports",
          caps[0]["hosts"] == 254 and caps[0]["flows"] == 254,
          str(caps))

    # ---------- ۷) اسکریپت فایروال ----------
    nft = gen.nftables_script(c2, "client")
    check("nft script creates table and chains",
          "add table inet injspoof" in nft and "priority -300" in nft)
    check("nft script blocks RST on wire ports",
          "tcp sport 3232 tcp flags rst drop" in nft
          and "tcp dport 443 tcp flags rst drop" in nft)
    check("nft script adds notrack for spoofed ports",
          "nft add rule inet injspoof raw tcp sport 3232 notrack" in nft)
    ipt = gen.iptables_script(c2, "client")
    check("iptables variant exists", "--tcp-flags RST RST -j DROP" in ipt)

    # ---------- ۸) فایروال per-instance (چند هسته روی یک ماشین) ----------
    nft_i = gen.nftables_script(c2, "client", instance="client-a")
    check("instance chains are named and flushed (idempotent re-apply)",
          "injspoof out_client-a" in nft_i and
          "nft flush chain inet injspoof out_client-a" in nft_i,
          nft_i[:200])
    nft_j = gen.nftables_script(c2, "client", instance="client-b")
    check("two instances do not overwrite each other's chains",
          "injspoof out_client-b" in nft_j and "out_client-a" not in nft_j)
    check("shared table is still created once",
          nft_i.count("add table inet injspoof") == 1)

    # ---------- ۹) starter config که install.sh می‌سازد ----------
    starter = gen.starter_config("server", "127.0.0.1:9090", "t" * 32, "eth0",
                                 "00:11:22:33:44:55")
    s_errs = [i for i in schema.validate(starter, "server")
              if i["level"] == schema.ERROR]
    check("install.sh starter config loads without errors", not s_errs,
          str([dict(i) for i in s_errs]))
    check("starter carries the given api token and interface",
          starter["api"]["token"] == "t" * 32 and
          starter["interfaces"][0]["outgoing"]["name"] == "eth0" and
          starter["interfaces"][0]["outgoing"]["gateway"]["mac_address"]
          == "00:11:22:33:44:55",
          str(starter.get("interfaces"))[:200])
    no_mac = gen.starter_config("server", "127.0.0.1:9090", "t" * 32, "eth0", "")
    check("starter omits a gateway MAC it does not know",
          "gateway" not in no_mac["interfaces"][0]["outgoing"],
          str(no_mac["interfaces"][0])[:200])

    # ---------- ۱۰) قرارداد core.py با helper ----------
    import core                                            # noqa: E402

    kv = core.parse_kv(core_info_sample())
    check("info KEY=value parses",
          kv["BINARY"] == "/usr/local/bin/injspoof" and
          kv["SERVICE_STATE"] == "active" and
          kv["UPDATE_ALLOWED"] == "no", str(kv)[:160])
    check("local_instance is None for a remote node",
          core.local_instance({"is_local": 0, "core_instance": "server"}) is None)
    check("local_instance reads core_instance",
          core.local_instance({"is_local": 1, "core_instance": "srv1"}) == "srv1")
    ok, msg = core.service("reboot", "server")
    check("unknown service action never reaches sudo", not ok and "reboot" in msg, msg)

    saved = core.NODECTL
    saved_sudo = core.SUDO
    try:
        # روی ماشین توسعه sudo ممکن است نباشد؛ برای سنجیدن «helper نیست» باید
        # خودِ which(sudo) موفق شود.
        core.SUDO = sys.executable
        core.NODECTL = "/nonexistent/injspoof-nodectl"
        ok, msg = core.run("info", "server")
        check("missing helper is reported, not raised", not ok and "install.sh" in msg, msg)
    finally:
        core.NODECTL = saved
        core.SUDO = saved_sudo

    # ---------- ۱۱) مهاجرت دیتابیس و ستون‌های محلی ----------
    import sqlite3                                         # noqa: E402
    import tempfile                                        # noqa: E402

    import db                                              # noqa: E402

    tmp = os.path.join(tempfile.mkdtemp(), "old.db")
    old = sqlite3.connect(tmp)
    old.executescript("""
        CREATE TABLE nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL CHECK (role IN ('client','server')),
            api_url TEXT NOT NULL, api_token TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            config_path TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')));
    """)
    old.execute("INSERT INTO nodes(name, role, api_url) VALUES('legacy','server','http://x')")
    old.commit()
    old.close()
    db.DB_PATH = tmp
    db.init()
    with db.connect() as conn:
        row = db.get_node_by_name(conn, "legacy")
        check("migrate adds is_local/core_instance to an old DB",
              row["is_local"] == 0 and row["core_instance"] == "", str(row)[:160])
        node_id = db.upsert_node(conn, {
            "name": "local-server", "role": "server",
            "api_url": "http://127.0.0.1:9090", "api_token": "x" * 32,
            "is_local": 1, "core_instance": "server",
            "config_path": "/etc/injspoof/server.json"})
        back = db.get_node(conn, node_id)
        check("upsert_node persists the local columns",
              int(back["is_local"]) == 1 and back["core_instance"] == "server",
              str(back)[:200])
        back["core_instance"] = "srv2"
        db.upsert_node(conn, back)
        check("update path keeps is_local",
              db.get_node(conn, node_id)["core_instance"] == "srv2",
              str(db.get_node(conn, node_id))[:160])
        check("local node sorts first",
              db.list_nodes(conn)[0]["name"] == "local-server",
              str([n["name"] for n in db.list_nodes(conn)]))

    # ---------- ۱۲) قرارداد install.sh ↔ injspoof-nodectl ----------
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "install.sh"), encoding="utf-8") as fh:
        sh = fh.read()
    with open(os.path.join(here, "deploy", "injspoof-nodectl"), encoding="utf-8") as fh:
        ctl = fh.read()
    check("install.sh tells the helper which group owns the config",
          "SERVICE_USER=%s" in sh,
          sh[sh.find("state برای helper"):][:200])
    check("helper takes that group from state instead of hardcoding it",
          'read_state SERVICE_USER' in ctl and '-g "$SERVICE_USER"' in ctl
          and "-g injspoof-panel" not in ctl,
          ctl[ctl.find("read_state SERVICE_USER"):][:160])
    check("panel.db registration runs as the service user, not root",
          "as_panel_user \"$REG_PY\"" in sh,
          sh[sh.find("# ---- \u062b\u0628\u062a \u0646\u0648\u062f \u0645\u062d\u0644\u06cc"):][:180])
    check("--core-only no longer needs the panel venv",
          'py_tool()' in sh and 'die "با --core-only' not in sh)

    # ---------- ۱۳) فونت خودمیزبان ----------
    with open(os.path.join(here, "static", "style.css"), encoding="utf-8") as fh:
        css = fh.read()
    faces = re.findall(r"@font-face\s*\{.*?\}", css, re.S)
    face_urls = [u for f in faces for u in re.findall(r'url\("([^"]+)"\)', f)]
    check("stylesheet declares @font-face rules", len(faces) >= 4,
          f"{len(faces)} rule")
    check("every @font-face url is a local static/fonts path",
          bool(face_urls) and all(u.startswith("fonts/") for u in face_urls), str(face_urls))
    font_files = [os.path.join(here, "static", u) for u in face_urls]
    check("every declared font file exists on disk",
          all(os.path.isfile(p) for p in font_files),
          str([p for p in font_files if not os.path.isfile(p)]))
    check("bundled fonts are real woff2 files",
          all(open(p, "rb").read(4) == b"wOF2" for p in font_files if os.path.isfile(p)),
          str([open(p, "rb").read(4) for p in font_files]))
    check("no CDN or remote font reference (offline installs included)",
          "http://" not in css and "https://" not in css and "@import" not in css,
          str(re.findall(r"https?://\S+", css))[:160])
    declared = {}
    for f in faces:
        fam = re.search(r'font-family:\s*"([^"]+)"', f)
        wgt = re.search(r"font-weight:\s*(\d{3})", f)
        if fam and wgt:
            declared.setdefault(fam.group(1), set()).add(wgt.group(1))
    used = set(re.findall(r"font-weight:\s*(\d{3})", css))
    declared_lists = {k: sorted(v) for k, v in declared.items()}
    check("every weight the CSS asks for has a matching face",
          used <= set().union(*declared.values()),
          f"used={sorted(used)} declared={declared_lists}")
    check("Vazirmatn ships the four UI weights",
          declared.get("Vazirmatn") == {"400", "500", "600", "700"}, str(declared_lists))
    with open(os.path.join(here, "templates", "base.html"), encoding="utf-8") as fh:
        base_html = fh.read()
    check("base.html preloads the regular face (no first-paint flash)",
          'rel="preload"' in base_html and "fonts/Vazirmatn-Regular.woff2" in base_html
          and 'as="font"' in base_html, base_html[:200])
    with open(os.path.join(here, "app.py"), encoding="utf-8") as fh:
        app_py = fh.read()
    check("app.py registers the woff2 mime type",
          'add_type("font/woff2", ".woff2")' in app_py, "mimetypes")
    check("installer smoke-tests the font URL",
          "/static/fonts/Vazirmatn-Regular.woff2" in sh, "install.sh smoke test")

    # ---------- ۱۴) پنل به‌عنوان پروژه‌ی مستقل ----------
    check("gen resolves the seed dir inside the panel",
          gen.SEED_DIR == os.path.join(here, "seed"), gen.SEED_DIR)
    real_example = gen.EXAMPLE_DIR
    try:
        gen.EXAMPLE_DIR = os.path.join(here, "__no_repo_example__")
        picked = gen.example_path("server")
        check("starter config falls back to seed/ when the C repo is absent",
              picked == os.path.join(gen.SEED_DIR, "server.json"), picked)
        seed_cfg = gen.load_example("server")
        seed_starter = gen.starter_config("server", "127.0.0.1:9090", "t" * 32,
                                          "eth0", "00:11:22:33:44:55")
        seed_errs = [i for i in schema.validate(seed_starter, "server")
                     if i["level"] == schema.ERROR]
        check("panel-only starter config still validates", not seed_errs and bool(seed_cfg["api"]),
              str([dict(i) for i in seed_errs])[:220])
    finally:
        gen.EXAMPLE_DIR = real_example
    drift = [n for n in ("server.json", "client.json")
             if os.path.isfile(os.path.join(EXAMPLE, n))
             and open(os.path.join(EXAMPLE, n), "rb").read()
             != open(os.path.join(SEED, n), "rb").read()]
    check("seed/ is a byte-identical copy of example/ (drift detector)",
          not drift, str(drift))
    for extra in ("VERSION", "LICENSE", "GUIDE.md", "CHANGELOG.md"):
        check(f"panel carries its own {extra}",
              os.path.isfile(os.path.join(here, extra)), here)
    check("install.sh copies the standalone files",
          "GUIDE.md CHANGELOG.md LICENSE VERSION" in sh and '"$SRC/seed"' in sh,
          sh[sh.find("install_panel_code"):][:260])
    check("install.sh skips the core instead of dying when its source is absent",
          "resolve_core" in sh and "core_has_src()" in sh and "--with-core)" in sh,
          sh[sh.find("core_has_src()"):][:200])
    check("panel version comes from VERSION, not a hardcoded string",
          "def read_version()" in app_py and '"APP_VERSION": APP_VERSION' in app_py
          and "PANEL_VERSION\", \"1.0\"" not in app_py, "app.py")

    # ---------- نتیجه ----------
    print("\n" + "=" * 62)
    print(f"PASS: {len(PASSED)}   FAIL: {len(FAILED)}")
    if FAILED:
        for name, detail in FAILED:
            print(f"  - {name}: {detail}")
        return 1
    print("همه‌ی بررسی‌های منطقی پنل پاس شد.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
