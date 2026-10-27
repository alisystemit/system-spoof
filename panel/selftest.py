"""
selftest.py — آزمون منطقی اعتبارسنج و تولیدکننده‌ی پنل

اجرا:  python selftest.py          (از داخل پوشه‌ی panel)

سه چیز را ثابت می‌کند:
  ۱) کانفیگ‌های example/ خود ریپو با منطق فیلتر src/server.c هم‌راستا نیستند
  ۲) خروجی ویزارد پنل هم‌راستاست و خطای جدی ندارد
  ۳) خطاهای رایج (hid 4 کاراکتری، IPv6 در address، ICMP با پورت فیلترشده) گرفته می‌شوند
"""

from __future__ import annotations

import copy
import json
import os
import sys

import gen
import schema

try:  # کنسول ویندوز با cp1252 متن فارسی را چاپ نمی‌کند
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, "example")

PASSED, FAILED = [], []


def check(name, condition, detail=""):
    (PASSED if condition else FAILED).append((name, detail))
    mark = "PASS" if condition else "FAIL"
    print(f"[{mark}] {name}" + (f"  -> {detail}" if detail and not condition else ""))


def load(name):
    with open(os.path.join(EXAMPLE, name), encoding="utf-8") as f:
        return json.load(f)


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
