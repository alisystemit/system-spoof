"""
mock_api.py — شبیه‌ساز API هسته‌ی injspoof برای توسعه و دموی پنل

رفتارش از src/api.c استخراج شده است:
  * همان 8 مسیر، همان شکل JSON، همان خطاهای 401/404
  * Authorization: Bearer <token>
  * PUT /api/v1/config بدنه را اعتبارسنجی JSON می‌کند و نگه می‌دارد
  * POST /api/v1/reload?mode=hot|hard

این فایل هیچ کد تزریق بسته‌ای ندارد و فقط برای این است که پنل روی ماشین
توسعه (ویندوز/WSL) بدون سرور لینوکسی هم قابل تست و نمایش باشد.

  python mock_api.py --mode server --port 9090 --token devtoken
  python mock_api.py --mode client --port 9091 --token devtoken
"""

from __future__ import annotations

import argparse
import json
import os
import random
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

START = time.time()
STATE = {
    "mode": "server",
    "token": "devtoken",
    "config": {},
    "config_path": "example/server.json",
    "pkts_in": 0,
    "pkts_out": 0,
    "bytes_in": 0,
    "bytes_out": 0,
    "pkts_in_local": 0,
    "pkts_in_wire": 0,
    "pkts_out_wire": 0,
    "pkts_out_local": 0,
    "frags_sent": 0,
    "drop_filter": 3,
    "drop_parse": 0,
    "drop_pool": 0,
    "drop_send": 0,
    "drop_oversize": 0,
    "enobufs": 0,
    "eagain": 0,
    "emsgsize": 0,
    "enetdown": 0,
    "eperm": 0,
    "other": 0,
    "recvmmsg": 0,
    "sendmmsg": 0,
    "sendto": 0,
    "reloads_hot": 0,
    "reloads_hard": 0,
    "log_emitted": 0,
    "log_dropped": 0,
    "pool_avail": 254,
    "pool_capacity": 254,
    "hits": 0,
    "misses": 0,
}
LOCK = threading.Lock()


def traffic_loop(rate_scale=1.0):
    while True:
        with LOCK:
            burst = int(random.gauss(1400, 700) * rate_scale)
            burst = max(120, burst)
            STATE["pkts_in"] += burst
            STATE["pkts_out"] += int(burst * random.uniform(0.92, 0.99))
            STATE["pkts_in_wire"] += burst
            STATE["pkts_in_local"] += int(burst * 0.0)
            STATE["pkts_out_wire"] += int(burst * 0.95)
            STATE["pkts_out_local"] += int(burst * 0.05)
            STATE["bytes_in"] += burst * random.randint(300, 900)
            STATE["bytes_out"] += burst * random.randint(280, 860)
            STATE["frags_sent"] += random.randint(0, 6)
            STATE["recvmmsg"] += random.randint(40, 90)
            STATE["sendmmsg"] += random.randint(30, 80)
            STATE["sendto"] += random.randint(0, 4)
            STATE["log_emitted"] += random.randint(0, 3)
            if random.random() < 0.05:
                STATE["drop_filter"] += random.randint(1, 20)
            if random.random() < 0.03:
                STATE["eagain"] += random.randint(1, 5)
                STATE["drop_send"] += 1
            STATE["pool_avail"] = max(1, min(STATE["pool_capacity"],
                                    STATE["pool_avail"] + random.randint(-8, 8)))
            STATE["hits"] += burst
            STATE["misses"] += random.randint(0, 2)
        time.sleep(1.0)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "injspoof-mock/1.0"

    def log_message(self, fmt, *args):
        pass

    # ---------- helpers ----------
    def _send(self, status, ctype, body, extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status, obj):
        self._send(status, "application/json", json.dumps(obj))

    def _authed(self):
        token = STATE["token"]
        if not token:
            return True
        return self.headers.get("Authorization", "") == f"Bearer {token}"

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    # ---------- verbs ----------
    def do_OPTIONS(self):
        self._send(204, "text/plain", b"")

    def do_GET(self):
        if not self._authed():
            return self._json(401, {"error": "unauthorized"})
        path = self.path.split("?")[0]
        if path == "/api/v1/health":
            return self._json(200, {"status": "ok"})
        if path == "/api/v1/info":
            return self._json(200, {
                "name": "injspoof", "version": "mock-1.0", "api_version": "1",
                "mode": STATE["mode"], "pid": 4242, "config": STATE["config_path"]})
        if path == "/api/v1/stats":
            with LOCK:
                return self._json(200, {
                    "uptime_ms": int((time.time() - START) * 1000),
                    "traffic": {
                        "pkts_in": STATE["pkts_in"], "pkts_out": STATE["pkts_out"],
                        "pkts_in_local": STATE["pkts_in_local"],
                        "pkts_in_wire": STATE["pkts_in_wire"],
                        "pkts_out_wire": STATE["pkts_out_wire"],
                        "pkts_out_local": STATE["pkts_out_local"],
                        "bytes_in": STATE["bytes_in"], "bytes_out": STATE["bytes_out"],
                        "frags_sent": STATE["frags_sent"]},
                    "drops": {
                        "filter": STATE["drop_filter"], "parse": STATE["drop_parse"],
                        "pool": STATE["drop_pool"], "send": STATE["drop_send"],
                        "oversize": STATE["drop_oversize"],
                        "send_by_errno": {
                            "enobufs": STATE["enobufs"], "eagain": STATE["eagain"],
                            "emsgsize": STATE["emsgsize"], "enetdown": STATE["enetdown"],
                            "eperm": STATE["eperm"], "other": STATE["other"]}},
                    "syscalls": {"recvmmsg": STATE["recvmmsg"],
                                 "sendmmsg": STATE["sendmmsg"], "sendto": STATE["sendto"]},
                    "reloads": {"hot": STATE["reloads_hot"], "hard": STATE["reloads_hard"]},
                    "log": {"emitted": STATE["log_emitted"], "dropped": STATE["log_dropped"]},
                    "pool": {"avail": STATE["pool_avail"], "capacity": STATE["pool_capacity"],
                             "hits": STATE["hits"], "misses": STATE["misses"]}})
        if path == "/api/v1/stats/traffic":
            with LOCK:
                return self._json(200, {"pkts_in": STATE["pkts_in"],
                                        "pkts_out": STATE["pkts_out"],
                                        "bytes_in": STATE["bytes_in"],
                                        "bytes_out": STATE["bytes_out"],
                                        "frags_sent": STATE["frags_sent"]})
        if path == "/api/v1/stats/pool":
            with LOCK:
                return self._json(200, {"avail": STATE["pool_avail"],
                                        "capacity": STATE["pool_capacity"],
                                        "hits": STATE["hits"], "misses": STATE["misses"]})
        if path == "/api/v1/stats/log":
            with LOCK:
                return self._json(200, {"emitted": STATE["log_emitted"],
                                        "dropped": STATE["log_dropped"]})
        if path == "/api/v1/config":
            return self._json(200, STATE["config"])
        if path == "/api/v1/metrics":
            with LOCK:
                text = (
                    "# TYPE injspoof_pkts_in counter\n"
                    f"injspoof_pkts_in {STATE['pkts_in']}\n"
                    f"injspoof_pkts_out {STATE['pkts_out']}\n"
                    f"injspoof_bytes_in {STATE['bytes_in']}\n"
                    f"injspoof_bytes_out {STATE['bytes_out']}\n"
                    f"injspoof_frags_sent {STATE['frags_sent']}\n"
                    f'injspoof_drops{{reason="filter"}} {STATE["drop_filter"]}\n'
                    f'injspoof_drops{{reason="send"}} {STATE["drop_send"]}\n'
                    f'injspoof_reloads{{mode="hot"}} {STATE["reloads_hot"]}\n'
                    f"injspoof_uptime_seconds {time.time() - START:.3f}\n")
            return self._send(200, "text/plain; version=0.0.4", text)
        return self._json(404, {"error": "not found"})

    def do_PUT(self):
        if not self._authed():
            return self._json(401, {"error": "unauthorized"})
        if self.path.split("?")[0] != "/api/v1/config":
            return self._json(404, {"error": "not found"})
        raw = self._body()
        if not raw:
            return self._json(400, {"error": "empty or too large body"})
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._json(400, {"error": "config parse failed"})
        with LOCK:
            STATE["config"] = parsed
        return self._json(200, {"status": "ok"})

    def do_POST(self):
        if not self._authed():
            return self._json(401, {"error": "unauthorized"})
        path, _, query = self.path.partition("?")
        if path != "/api/v1/reload":
            return self._json(404, {"error": "not found"})
        hard = "mode=hard" in query
        with LOCK:
            if hard:
                STATE["reloads_hard"] += 1
            else:
                STATE["reloads_hot"] += 1
        return self._json(202 if hard else 200,
                          {"status": "restarting" if hard else "reloaded"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["client", "server"], default="server")
    ap.add_argument("--port", type=int, default=9090)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--token", default="devtoken")
    ap.add_argument("--config", help="فایل JSON که به‌عنوان کانفیگ نود ارائه شود")
    ap.add_argument("--load-example", action="store_true",
                    help="کانفیگ نمونه‌ی خود ریپو را بارگذاری کن")
    args = ap.parse_args()

    STATE["mode"] = args.mode
    STATE["token"] = args.token
    if args.config:
        STATE["config_path"] = args.config
        with open(args.config, encoding="utf-8") as f:
            STATE["config"] = json.load(f)
    elif args.load_example:
        name = "server" if args.mode == "server" else "client"
        # مسیر را مستقل از cwd پیدا کن: example/ ریپو وگرنه seed/ خودِ پنل.
        here = os.path.dirname(os.path.abspath(__file__))
        candidates = [os.path.join("example", f"{name}.json"),
                      os.path.join(here, "..", "example", f"{name}.json"),
                      os.path.join(here, "seed", f"{name}.json")]
        path = next((c for c in candidates if os.path.exists(c)), candidates[-1])
        STATE["config_path"] = path
        STATE["config"] = json.loads(open(path, encoding="utf-8").read())
        # api.bind باید با پورت واقعی mock بخواند، وگرنه پنل آدرس دیگری
        # در تست می‌بیند.
        STATE["config"].setdefault("api", {})["bind"] = f"{args.host}:{args.port}"
    else:
        STATE["config"] = {"api": {"bind": f"127.0.0.1:{args.port}", "token": args.token},
                           "interfaces": [], "firewall": [], "peers": []}

    threading.Thread(target=traffic_loop, daemon=True).start()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[mock injspoof] mode={args.mode} http://{args.host}:{args.port} "
          f"token={args.token}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
