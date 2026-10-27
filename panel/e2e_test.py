"""
e2e_test.py — آزمون سرتاسری پنل با API واقعی (mock یا نود واقعی)

پنل و دو mock API باید بالا باشند:

    # از ریشه‌ی ریپو:
    python panel/mock_api.py --mode server --port 9090 --token devtoken --load-example
    python panel/mock_api.py --mode client --port 9091 --token devtoken --load-example
    python panel/run.py                      # PANEL_PORT=8088

    python panel/e2e_test.py

مسیرهای نوشتنی را واقعاً صدا می‌زند (PUT کانفیگ، reload، rollback، push) و نتیجه
را از نود دوباره می‌خواند؛ یعنی اگر چیزی روی نود ننشیند، تست رد می‌شود.
هر اجرا اول ردیف‌های e2e-* قبلی را پاک می‌کند تا نتیجه تکرارپذیر بماند.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8088"
SERVER_NAME = "e2e-server"
CLIENT_NAME = "e2e-client"
EXAMPLE_TOKEN = "CHANGE_ME_use_a_long_random_secret"
PASSED, FAILED = [], []


def req(path, data=None, method=None, raw=False):
    body = None
    headers = {}
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    r = urllib.request.Request(BASE + path, data=body, method=method or
                               ("POST" if body else "GET"), headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=25) as resp:
            text = resp.read().decode("utf-8")
            status = resp.status
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8")
        status = exc.code
    if raw:
        return status, text
    try:
        return status, json.loads(text)
    except json.JSONDecodeError:
        return status, {"_raw": text[:300]}


def form(path, fields):
    body = urllib.parse.urlencode(fields).encode()
    r = urllib.request.Request(BASE + path, data=body, method="POST",
                               headers={"Content-Type": "application/x-www-form-urlencoded"})
    opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
    resp = opener.open(r, timeout=25)
    return resp.status, resp.geturl()


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append((name, detail))
    mark = "PASS" if cond else "FAIL"
    print(f"[{mark}] {name}" + (f"  -> {detail}" if detail and not cond else ""))


def nodes_by_name():
    _, payload = req("/api/nodes")
    return {n["name"]: n for n in payload.get("nodes", [])}


def wait_for(desc, predicate, timeout=20.0, delay=0.5):
    """چیزی که نتیجه‌اش در رشته‌ی پس‌زمینه پدیدار می‌شود (نمونه‌های collector)."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(delay)
    print(f"    (timeout after {timeout}s waiting for {desc}; last={str(last)[:120]})")
    return last


def register(name, role, port, config_path):
    return form("/nodes/new", {"name": name, "role": role,
                               "api_url": f"http://127.0.0.1:{port}",
                               "api_token": "devtoken", "enabled": "1",
                               "check_token": "1", "config_path": config_path,
                               "note": "e2e"})


def main():
    # ---------- پاک‌سازی اجرای قبلی ----------
    before = nodes_by_name()
    for key in (SERVER_NAME, CLIENT_NAME):
        if key in before:
            form(f"/nodes/{before[key]['id']}/delete", {})
    after = nodes_by_name()
    check("previous e2e nodes cleaned up", SERVER_NAME not in after,
          "delete endpoint left the row behind")

    # ---------- نودها ----------
    register(SERVER_NAME, "server", 9090, "/etc/injspoof/server.json")
    register(CLIENT_NAME, "client", 9091, "/etc/injspoof/client.json")
    by_name = nodes_by_name()
    srv, cli = by_name.get(SERVER_NAME), by_name.get(CLIENT_NAME)
    check("two nodes registered", bool(srv) and bool(cli),
          str(sorted(by_name)))
    if not (srv and cli):
        report()
        return 1

    # توکن نود نباید هیچ‌وقت به مرورگر برود (هم JSON، هم HTML)
    st, listing = req("/api/nodes")
    check("node list JSON does not carry the bearer token",
          "devtoken" not in json.dumps(listing) and
          all("api_token" not in n for n in listing.get("nodes", [])),
          str(listing)[:200])
    check("node edit form does not echo the token",
          "devtoken" not in req(f"/nodes/{srv['id']}/edit", raw=True)[1],
          "token found in the rendered HTML")

    st, probe = req(f"/api/nodes/{srv['id']}/test", {})
    check("probe reaches the node API", probe.get("ok") and probe.get("mode") == "server",
          str(probe)[:200])

    # ---------- سلامتی collector ----------
    _, snap = req(f"/api/nodes")
    st, ser = req(f"/api/nodes/{srv['id']}/series?limit=60&fresh=1")
    def stats_samples():
        got = [s for s in req(f"/api/nodes/{srv['id']}/series?limit=60")[1]
               .get("samples", []) if s["stats"]]
        return got if len(got) >= 2 else None

    samples = wait_for("two stats samples", stats_samples)
    check("fresh=1 samples on demand", ser.get("sampled_now") is True, str(ser)[:120])
    check("collector gathered >=2 samples (rate needs a delta)",
          bool(samples) and len(samples) >= 2,
          f"{len(samples or [])} samples")
    snap = req("/api/nodes")[1]
    srv_row = next((n for n in snap.get("nodes", []) if n["id"] == srv["id"]), {})
    check("node listed as alive", srv_row.get("status", {}).get("alive") is True,
          str(srv_row.get("status"))[:160])

    # ---------- health/info/metrics ----------
    st, info = req(f"/api/nodes/{srv['id']}/info")
    check("info proxied from node", info.get("ok") and info["info"]["mode"] == "server",
          str(info)[:200])
    st, met = req(f"/api/nodes/{srv['id']}/metrics")
    check("prometheus parsed", met.get("ok") and any(
        k.startswith("injspoof_pkts_in") for k in met.get("parsed", {})),
          str(met)[:160])

    # ---------- خواندن کانفیگ از نود ----------
    st, loaded = req(f"/api/config/load/{srv['id']}")
    cfg = json.loads(loaded["config"])
    check("config loaded from node", cfg.get("api", {}).get("bind") == "127.0.0.1:9090",
          str(cfg.get("api")))

    # تست باید idempotent باشد: اگر اجرای قبلی توکن را چرخانده، اینجا به
    # مقدار مثال برگردانده می‌شود تا مسیر هشدار CHANGE_ME حتماً سنجیده شود.
    if cfg.get("api", {}).get("token") != EXAMPLE_TOKEN:
        seed = json.loads(loaded["config"])
        seed["api"]["token"] = EXAMPLE_TOKEN
        req(f"/api/config/apply/{srv['id']}",
            {"config": json.dumps(seed), "note": "e2e seed example token",
             "reload": "hot"})
        st, loaded = req(f"/api/config/load/{srv['id']}")
    check("loader flags the CHANGE_ME token as a warning (not a blocker)",
          any(i["path"].endswith("token") and i["level"] == "warn"
              for i in loaded["issues"]),
          str(loaded["issues"])[:300])

    # ---------- گیت اعتبارسنجی: کانفیگ خراب نباید اعمال شود ----------
    bad = json.loads(loaded["config"])
    bad["peers"][0]["hid"] = "abcd"
    st, res = req(f"/api/config/apply/{srv['id']}",
                  {"config": json.dumps(bad), "note": "bad", "reload": "hot"})
    check("apply blocked by validator (422)", st == 422 and not res.get("ok"),
          f"status={st} {str(res)[:200]}")
    st, after_bad = req(f"/api/config/load/{srv['id']}")
    check("node config untouched after blocked apply",
          json.loads(after_bad["config"])["peers"][0]["hid"] != "abcd",
          json.loads(after_bad["config"])["peers"][0]["hid"])

    # ---------- اعمال سالم ----------
    # snapshot همان چیزی است که پنل باید قبل از PUT در تاریخچه بگذارد
    good = json.loads(loaded["config"])
    pre_apply = json.loads(json.dumps(good))
    good["interfaces"][0]["fragment_size"] = 1420
    st, res = req(f"/api/config/apply/{srv['id']}",
                  {"config": json.dumps(good), "note": "e2e fragment tune",
                   "reload": "hot"})
    check("apply ok", res.get("ok"), str(res)[:250])
    check("hot reload confirmed by node",
          (res.get("reloaded") or {}).get("status") == "reloaded", str(res)[:160])
    st, loaded2 = req(f"/api/config/load/{srv['id']}")
    cfg2 = json.loads(loaded2["config"])
    check("new config landed on the node",
          cfg2["interfaces"][0]["fragment_size"] == 1420, str(cfg2["interfaces"]))

    # ---------- هشدار قفل‌شدن پنل با عوض‌کردن توکن ----------
    lock = json.loads(loaded2["config"])
    lock["api"]["token"] = "z" * 32
    st, res2 = req(f"/api/config/apply/{srv['id']}",
                   {"config": json.dumps(lock), "note": "e2e token rotate",
                    "reload": "hot"})
    check("panel warns when api.token changes", res2.get("token_changed") is True,
          str(res2)[:200])

    # ---------- تاریخچه و rollback ----------
    # بکاپ «قبل از اعمال» باید دقیقاً همان snapshot اولیه باشد؛ مقایسه با
    # فایل example سخت‌گیرانه نبود چون mock سراسری، حالت بین اجراها را نگه
    # می‌دارد.
    st, vers = req(f"/api/nodes/{srv['id']}/versions")
    target = None
    for v in vers.get("versions", []):
        stv, doc = req(f"/versions/{v['id']}.json")
        if stv != 200 or "config" not in doc:
            continue
        try:
            c = json.loads(doc["config"])
        except json.JSONDecodeError:
            continue
        if c == pre_apply:
            target = v["id"]
            break
    check("pre-apply backup is in history", target is not None,
          f"{len(vers.get('versions', []))} versions, none matches the pre-apply snapshot")
    if target:
        form(f"/versions/{target}/rollback", {})
        st, back = req(f"/api/config/load/{srv['id']}")
        cfg3 = json.loads(back["config"])
        check("rollback restored the original config on the node",
              cfg3 == pre_apply and
              cfg3["interfaces"][0]["fragment_size"] != 1420,
              str(cfg3.get("interfaces")) + " " + str(cfg3.get("api")))

    # ---------- ویزارد جفت کانفیگ ----------
    spec = {
        "name": "e2e-pair", "protocol": "tcp", "wire_dst_port": 443, "iface_tag": "wan",
        "client": {"public_ip": "185.1.2.3", "iface": "eth0",
                   "gw_mac": "00:11:22:33:44:55", "api_bind": "127.0.0.1:9091",
                   "api_token": "c" * 32, "pool": ["198.51.100.0/24"],
                   "src_ports": [3232]},
        "server": {"public_ip": "185.9.9.9", "iface": "eth0",
                   "gw_mac": "00:11:22:33:aa:bb", "api_bind": "127.0.0.1:9090",
                   "api_token": "s" * 32, "pool": ["203.0.113.0/24"],
                   "src_ports": [5454]},
        "forwards": [{"bind": "127.0.0.1:51820", "redirect": "127.0.0.1:51820"}],
    }
    st, prev = req("/api/pair/preview", {"spec": spec})
    check("wizard preview returns aligned pair", prev.get("ok"),
          str([i for i in prev.get("issues", []) if i["level"] == "error"])[:400])
    check("wizard emits nftables blocker for both sides",
          "tcp flags rst drop" in prev.get("client_nft", "") and
          "notrack" in prev.get("server_nft", ""))
    check("wizard reports pool capacity",
          prev.get("capacity", {}).get("client") and
          prev["capacity"]["client"][0]["flows"] == 254,
          str(prev.get("capacity"))[:200])

    # هم‌راستایی واقعی خروجی ویزارد: گیرنده باید پورت مبدأ فرستنده را بپذیرد
    srv_cfg = json.loads(prev["server_json"])
    cli_cfg = json.loads(prev["client_json"])
    cli_sport = cli_cfg["firewall"][0]["outgoing"]["port"]["src"]
    srv_in = srv_cfg["firewall"][0]["incoming"]["port"]["src"]
    check("receiver filter admits the sender's source port",
          all(p in srv_in for p in cli_sport) and cli_sport == spec["client"]["src_ports"],
          f"client src={cli_sport} server incoming={srv_in}")
    check("receiver incoming.source == sender outgoing.source",
          [b.get("value") for b in cli_cfg["firewall"][0]["outgoing"]["source"]] ==
          [b.get("value") for b in srv_cfg["firewall"][0]["incoming"]["source"]],
          "pool cross-reference differs")

    # ورودی نامعتبر باید رد شود (نه اینکه کانفیگ نصفه‌نیمه بدهد)
    st, broken = req("/api/pair/preview", {"spec": {
        **spec, "name": "e2e-bad", "hid": None,
        "client": {**spec["client"], "pool": ["198.51.100.0/33"]}}})
    broken_errs = [i for i in (broken.get("issues") or []) if i["level"] == "error"]
    check("wizard rejects an invalid CIDR",
          (not broken.get("ok")) and bool(broken_errs),
          f"status={st} {str(broken)[:200]}")

    st, saved = req("/api/pair/save", {"name": "e2e-pair", "spec": spec,
                                       "client_node_id": cli["id"],
                                       "server_node_id": srv["id"]})
    check("pair saved", saved.get("ok"), str(saved)[:200])
    pid = saved.get("pair_id")

    # ---------- push روی نود کلاینت ----------
    if pid:
        st, pushed = req(f"/api/pair/{pid}/push",
                         {"client_node_id": cli["id"], "server_node_id": None})
        check("push applied client config", pushed.get("ok"), str(pushed)[:300])
        st, live_cli = req(f"/api/config/load/{cli['id']}")
        cfgc = json.loads(live_cli["config"])
        check("client node now runs wizard config",
              cfgc.get("peers", [{}])[0].get("hid") == saved.get("hid"),
              str(cfgc.get("peers"))[:200])

        # ---------- لینتر هم‌راستایی روی داده‌ی زنده‌ی ناهم‌راستا ----------
        # باور قبلی («پنل ناهم‌راستایی را در پیش‌نمایش می‌گیرد») بی‌معنا بود:
        # build_pair از ساختار هم‌راستا تولید می‌کند. پس عمداً سمت سرور را روی
        # نود خراب می‌کنیم و بررسی می‌کنیم که پنل از روی نودها تشخیص دهد.
        # hid را پین می‌کنیم تا پیش‌نمایش دقیقاً همان جفت ذخیره‌شده باشد
        # (هر preview یک hid تصادفی تازه می‌سازد).
        st, prev2 = req("/api/pair/preview", {"spec": {**spec, "hid": saved["hid"]}})
        check("preview with pinned hid reproduces the saved pair",
              prev2.get("hid") == saved.get("hid"),
              f"{prev2.get('hid')} != {saved.get('hid')}")
        mis = json.loads(prev2["server_json"])
        mis["firewall"][0]["incoming"]["port"]["src"] = [9999]
        st, applied = req(f"/api/config/apply/{srv['id']}",
                          {"config": json.dumps(mis), "note": "e2e misalign",
                           "reload": "hot"})
        check("misaligned server config applied (setup step)", applied.get("ok"),
              str(applied)[:200])
        st, livecheck = req(f"/api/pair/{pid}/check")
        lc_errs = [i for i in livecheck.get("issues", []) if i["level"] == "error"]
        check("pair check catches live misalignment",
              livecheck.get("ok") is False and
              any("port.src" in i["path"] for i in lc_errs),
              f"{str(livecheck)[:120]} | errs={[i['path'] for i in lc_errs]}")

    report()
    return 1 if FAILED else 0


def report():
    print("\n" + "=" * 62)
    print(f"PASS: {len(PASSED)}   FAIL: {len(FAILED)}")
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    sys.exit(main())
