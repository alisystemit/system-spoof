"""
app.py — پنل تحت وب injspoof (Flask)

معماری: مرورگر هرگز توکن API نود را نمی‌بیند. همه‌ی تماس‌ها با نود از سمت
پایتون (injclient) انجام می‌شود و UI فقط با /api/* داخلی پنل حرف می‌زند.
پنل به‌صورت پیش‌فرض فقط روی 127.0.0.1 می‌نشیند؛ کنار نود اجرا می‌شود.
"""

from __future__ import annotations

import collections
import hmac
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import threading
import time
from functools import wraps

from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                   request, session, url_for)

import db
import gen
import injclient
import schema
from core import CoreError            # noqa: F401  (برای خوانایی روت‌ها)
import core as coreops

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
APP = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)
APP.secret_key = os.environ.get("PANEL_SECRET") or secrets.token_hex(32)
PANEL_PASSWORD = os.environ.get("PANEL_PASSWORD") or ""
SAMPLE_INTERVAL = float(os.environ.get("PANEL_INTERVAL", "2"))
NODE_TIMEOUT = float(os.environ.get("PANEL_TIMEOUT", "4"))

# فایل‌های فونت از /static سرو می‌شوند؛ در دیکشنری MIME چند توزیع پسوند
# .woff2 ثبت نشده و application/octet-stream می‌شود.
mimetypes.add_type("font/woff2", ".woff2")


def read_version():
    """نسخه‌ی پنل: متغیر محیطی PANEL_VERSION، وگرنه فایل VERSION کنار کد.

    پنل پروژه‌ای مستقل است، پس شماره‌ی نسخه‌اش را خودش نگه می‌دارد و به
    ریپوی هسته‌ی C وابسته نیست. اگر هیچ‌کدام نبود "dev".
    """
    env = os.environ.get("PANEL_VERSION", "").strip()
    if env:
        return env
    try:
        with open(os.path.join(BASE_DIR, "VERSION"), encoding="utf-8") as fh:
            return fh.read().strip() or "dev"
    except OSError:
        return "dev"


APP_VERSION = read_version()

# همان الگویی که injspoof-nodectl برای نام instance می‌پذیرد. نگه داشتن یک
# کپی در پنل یعنی پیام خطای فارسی قبل از رسیدن به helper، نه بعد از آن.
INSTANCE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")

# ======================================================================
#  جمع‌آور نمونه‌ها در حافظه (برای نمودار زنده)
# ======================================================================

class Collector:
    def __init__(self, interval=SAMPLE_INTERVAL, keep=300):
        self.interval = interval
        self.keep = keep
        self._series = {}
        self._lock = threading.Lock()
        self._status = {}
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, name="panel-sampler",
                                         daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.wait(self.interval):
            try:
                with db.connect() as conn:
                    nodes = [n for n in db.list_nodes(conn) if n["enabled"]]
            except Exception:                         # noqa: BLE001
                # خطای لحظه‌ای SQLite نباید نخ نمونه‌بردار را برای همیشه بخوابد
                continue
            for node in nodes:
                try:
                    self._sample(node)
                except Exception:                     # noqa: BLE001
                    pass

    def _sample(self, node):
        key = node["id"]
        try:
            client = node_client(node)
            stats = client.stats()
            err = None
        except Exception as exc:                      # noqa: BLE001
            stats, err = None, str(exc)
        with self._lock:
            buf = self._series.setdefault(key, collections.deque(maxlen=self.keep))
            buf.append({"ts": time.time(), "stats": stats, "error": err})
            self._status[key] = {"alive": err is None, "error": err,
                                 "last_ts": time.time()}

    def last_ts(self, node_id):
        with self._lock:
            buf = self._series.get(node_id)
            return buf[-1]["ts"] if buf else 0.0

    def sample_now(self, node, min_gap=0.4):
        """نمونه‌برداری فوری برای دکمه‌ی «همین حالا» و برای تست.

        اگر نمونه‌ی بسیار تازه وجود داشته، دوباره نمونه نمی‌گیرد: نرخ بر پایه‌ی
        اختلاف شمارنده‌ها حساب می‌شود و فاصله‌ی زیر میلی‌ثانیه اسپایک ساختگی
        می‌سازد.
        """
        if time.time() - self.last_ts(node["id"]) < min_gap:
            return False
        self._sample(node)
        return True

    def series(self, node_id):
        with self._lock:
            buf = list(self._series.get(node_id, []))
            status = dict(self._status.get(node_id, {}))
        return buf, status

    def snapshot(self):
        with self._lock:
            return {k: dict(v) for k, v in self._status.items()}


COLLECTOR = Collector()


def node_client(node):
    return injclient.InjClient(node["api_url"], node["api_token"], timeout=NODE_TIMEOUT)


def _valid_api_url(url):
    """http://host:port را می‌سنجد تا نود بی‌هدف ذخیره نشود."""
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    try:
        port = parsed.port
    except ValueError:
        return False
    return port is not None and 1 <= port <= 65535


# ======================================================================
#  احراز هویت اختیاری (فقط اگر PANEL_PASSWORD ست شده باشد)
# ======================================================================

def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if PANEL_PASSWORD and not session.get("authed"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapper


@APP.route("/login", methods=["GET", "POST"])
def login():
    if not PANEL_PASSWORD:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        given = request.form.get("password", "")
        if hmac.compare_digest(given, PANEL_PASSWORD):
            session["authed"] = True
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("رمز عبور درست نبود.", "error")
    return render_template("login.html")


@APP.route("/logout")
def logout():
    session.pop("authed", None)
    return redirect(url_for("login"))


# ======================================================================
#  قالب‌ها و صفحات
# ======================================================================

@APP.context_processor
def helpers():
    return {
        "levels": {"error": "خطا", "warn": "هشدار", "info": "نکته"},
        "fmt_bytes": fmt_bytes,
        "fmt_uptime": fmt_uptime,
        "APP_VERSION": APP_VERSION,
        "needs_auth": bool(PANEL_PASSWORD),
    }


@APP.route("/")
@login_required
def dashboard():
    with db.connect() as conn:
        nodes = db.list_nodes(conn)
    selected = request.args.get("node", type=int)
    if selected is None and nodes:
        selected = nodes[0]["id"]
    snap = COLLECTOR.snapshot()
    return render_template("dashboard.html", nodes=nodes, selected=selected,
                           status=snap)


@APP.route("/nodes")
@login_required
def nodes_page():
    with db.connect() as conn:
        nodes = db.list_nodes(conn)
    return render_template("nodes.html", nodes=nodes, status=COLLECTOR.snapshot())


@APP.route("/nodes/new", methods=["GET", "POST"])
@APP.route("/nodes/<int:node_id>/edit", methods=["GET", "POST"])
@login_required
def node_form(node_id=None):
    node = None
    if node_id is not None:
        with db.connect() as conn:
            node = db.get_node(conn, node_id)
        if not node:
            abort(404)
    if request.method == "POST":
        form = request.form
        given_token = form.get("api_token", "").strip()
        data = {
            "id": node_id,
            "name": form.get("name", "").strip(),
            "role": form.get("role", "server"),
            "api_url": form.get("api_url", "").strip().rstrip("/"),
            # فیلد توکن عمداً خالی رندر می‌شود؛ خالی گذاشتنش یعنی
            # «همان مقدار ذخیره‌شده»، نه «پاک کن».
            "api_token": given_token or (node or {}).get("api_token", ""),
            "config_path": form.get("config_path", "").strip(),
            "note": form.get("note", "").strip(),
            "enabled": 1 if form.get("enabled") else 0,
            # نود محلی = هسته‌ای که systemd آن را روی همین ماشین کنترل می‌کند.
            "is_local": 1 if form.get("is_local") else 0,
            "core_instance": form.get("core_instance", "").strip(),
        }
        errors = []
        if not data["name"]:
            errors.append("نام نود لازم است.")
        if data["role"] not in ("client", "server"):
            errors.append("نقش باید client یا server باشد.")
        if not data["api_url"].startswith(("http://", "https://")):
            errors.append("api_url باید با http:// یا https:// شروع شود.")
        elif not _valid_api_url(data["api_url"]):
            errors.append("api_url قابل‌تحلیل نیست (مثال: http://127.0.0.1:9090)")
        if data["role"] == "client" and form.get("check_token") and not data["api_token"]:
            errors.append("توکن API خالی است.")
        if data["is_local"]:
            # همان الگویی که injspoof-nodectl می‌پذیرد؛ اینجا زودتر ردش می‌کنیم
            # تا کاربر پیام خوانا ببیند نه «nodectl: نام instance نامعتبر».
            inst = data["core_instance"]
            if not inst or not INSTANCE_RE.match(inst):
                errors.append("برای نود محلی، نام instance باید فقط حروف لاتین، رقم، "
                              "نقطه، آدر یا خط تیره باشد (مثال: server).")
            elif not coreops.available():
                errors.append("روی این ماشین /usr/local/libexec/injspoof-nodectl نصب "
                              "نیست؛ هسته را با panel/install.sh نصب کنید یا این تیک را "
                              "بردارید و نود را فقط از راه API مدیریت کنید.")
        if errors:
            for e in errors:
                flash(e, "error")
        else:
            try:
                with db.connect() as conn, conn:
                    saved = db.upsert_node(conn, data)
            except sqlite3.IntegrityError:
                flash(f"نودی با نام «{data['name']}» از قبل ثبت شده؛ نام دیگری بگذارید "
                      f"یا از صفحه‌ی نودها ویرایشش کنید.", "error")
                return redirect(url_for("nodes_page"))
            node = {**data, "id": saved}
            result = probe_node(node)
            if result["ok"]:
                flash(f"نود ذخیره شد و health OK است (mode={result['mode']}).", "ok")
            else:
                flash(f"نود ذخیره شد، ولی تماس با API موفق نبود: {result['error']}",
                      "warn")
            return redirect(url_for("nodes_page"))
    return render_template("node_form.html", node=node, tokens=_token_preview(node),
                           interval=int(round(SAMPLE_INTERVAL)),
                           core_available=coreops.available(),
                           helper_path=coreops.helper_path(),
                           default_instance=coreops.DEFAULT_INSTANCE)


@APP.route("/nodes/<int:node_id>/delete", methods=["POST"])
@login_required
def node_delete(node_id):
    with db.connect() as conn, conn:
        db.delete_node(conn, node_id)
    flash("نود حذف شد.", "ok")
    return redirect(url_for("nodes_page"))


# ======================================================================
#  ویرایشگر کانفیگ
# ======================================================================

@APP.route("/editor")
@login_required
def editor_page():
    node_id = request.args.get("node", type=int)
    with db.connect() as conn:
        node = db.get_node(conn, node_id) if node_id else None
        versions = db.list_versions(conn, node_id) if node_id else []
    if node_id and not node:
        abort(404)
    caps = schema.capacity_report({}) if not node else None
    return render_template("editor.html", node=node, nodes=db_list_nodes(),
                           versions=versions, capacity=caps)


@APP.route("/history/<int:node_id>")
@login_required
def history_page(node_id):
    with db.connect() as conn:
        node = db.get_node(conn, node_id)
        if not node:
            abort(404)
        versions = db.list_versions(conn, node_id, limit=100)
    return render_template("history.html", node=node, versions=versions,
                           nodes=db_list_nodes())


@APP.route("/versions/<int:version_id>.json")
@login_required
def version_json(version_id):
    with db.connect() as conn:
        row = db.get_version(conn, version_id)
    if not row:
        abort(404)
    return jsonify({"id": row["id"], "sha256": row["sha256"], "note": row["note"],
                    "created_at": row["created_at"], "config": row["config_json"]})


@APP.route("/versions/<int:version_id>/rollback", methods=["POST"])
@login_required
def version_rollback(version_id):
    with db.connect() as conn:
        row = db.get_version(conn, version_id)
        if not row:
            abort(404)
        node = db.get_node(conn, row["node_id"])
    if not node:
        abort(404)
    result = apply_config(node, row["config_json"],
                          # «#» در متن RTL جای رقم را عوض می‌کند، پس بی‌آن نوشته
                          # می‌شود تا یادداشت تاریخچه خوانا بماند.
                          note=f"rollback to version {version_id}",
                          source="rollback")
    if result["ok"]:
        flash("نسخه‌ی قبلی با موفقیت روی نود اعمال شد.", "ok")
    else:
        flash(f"بازگشت ناموفق: {result['error']}", "error")
    return redirect(url_for("history_page", node_id=node["id"]))


# ======================================================================
#  ویزارد جفت کانفیگ
# ======================================================================

@APP.route("/pair")
@login_required
def pair_page():
    pid = request.args.get("pair", type=int)
    with db.connect() as conn:
        pairs = db.list_pairs(conn)
        nodes = db.list_nodes(conn)
        pair = db.get_pair(conn, pid) if pid else None
    return render_template("pair.html", pairs=pairs, nodes=nodes, pair=pair,
                           defaults=json.dumps(gen.DEFAULT_SPEC, ensure_ascii=False))


@APP.route("/api/pair/preview", methods=["POST"])
@login_required
def pair_preview():
    payload = request.get_json(force=True, silent=True) or {}
    spec = payload.get("spec") or {}
    try:
        client_cfg, server_cfg, meta = gen.build_pair(spec)
    except Exception as exc:                          # noqa: BLE001
        return jsonify({"ok": False, "summary": schema.summary([]), "issues": [
            {"level": "error", "path": "spec", "message": f"تولید کانفیگ شکست: {exc}",
             "hint": "مقادیر نامعتبر در ورودی ویزارد (CIDR، MAC، پورت یا hid)"}]}), 200
    issues = schema.check_pair(client_cfg, server_cfg)
    return jsonify({
        "ok": schema.ok(issues),
        "summary": schema.summary(issues),
        "issues": issues,
        "hid": meta["hid"],
        "rule_tag": meta["rule_tag"],
        "client_json": json.dumps(client_cfg, indent=2, ensure_ascii=False),
        "server_json": json.dumps(server_cfg, indent=2, ensure_ascii=False),
        "client_nft": gen.nftables_script(client_cfg, "client"),
        "server_nft": gen.nftables_script(server_cfg, "server"),
        "capacity": {"client": schema.capacity_report(client_cfg),
                     "server": schema.capacity_report(server_cfg)},
    })


@APP.route("/api/pair/save", methods=["POST"])
@login_required
def pair_save():
    payload = request.get_json(force=True, silent=True) or {}
    spec = payload.get("spec") or {}
    name = (payload.get("name") or spec.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "نام pair لازم است"}), 400
    try:
        client_cfg, server_cfg, meta = gen.build_pair(spec)
    except Exception as exc:                          # noqa: BLE001
        return jsonify({"ok": False, "error": f"تولید کانفیگ شکست: {exc}",
                       "issues": [{"level": "error", "path": "spec",
                                   "message": str(exc), "hint": ""}]}), 200
    issues = schema.check_pair(client_cfg, server_cfg)
    if not schema.ok(issues):
        return jsonify({"ok": False, "error": "کانفیگ خطای جدی دارد",
                        "issues": issues}), 422
    row = {
        "id": payload.get("pair_id"),
        "name": name,
        "hid": meta["hid"],
        "spec": spec,
        "client_json": json.dumps(client_cfg, indent=2, ensure_ascii=False),
        "server_json": json.dumps(server_cfg, indent=2, ensure_ascii=False),
        "client_node_id": payload.get("client_node_id"),
        "server_node_id": payload.get("server_node_id"),
    }
    try:
        with db.connect() as conn, conn:
            pid = db.save_pair(conn, row)
    except sqlite3.IntegrityError:
        # نام UNIQUE است: اگر pair هم‌نام وجود دارد، همان را به‌روز کن تا
        # ویزارد با «نام تکراری» نشکند.
        with db.connect() as conn:
            existing = None
            for p in db.list_pairs(conn):
                if p["name"] == name:
                    existing = p
                    break
        if not existing:
            return jsonify({"ok": False, "error": "ذخیره‌ی pair شکست (نام تکراری)"}), 409
        row["id"] = existing["id"]
        with db.connect() as conn, conn:
            pid = db.save_pair(conn, row)
    return jsonify({"ok": True, "pair_id": pid, "hid": meta["hid"]})


@APP.route("/api/pair/<int:pair_id>/push", methods=["POST"])
@login_required
def pair_push(pair_id):
    """اعمال pair روی نودهای انتخاب‌شده: کلاینت کامل، سرور با merge peer جدید."""
    payload = request.get_json(force=True, silent=True) or {}
    target_client = payload.get("client_node_id")
    target_server = payload.get("server_node_id")
    with db.connect() as conn:
        pair = db.get_pair(conn, pair_id)
    if not pair:
        abort(404)
    steps = []
    if target_client:
        with db.connect() as conn:
            node = db.get_node(conn, target_client)
        if node:
            steps.append(("client", node, pair["client_json"]))
    if target_server:
        with db.connect() as conn:
            node = db.get_node(conn, target_server)
        if node:
            merged, issues = merge_into_node(node, pair)
            if not schema.ok(issues):
                return jsonify({"ok": False, "step": "server-merge",
                                "issues": issues}), 422
            steps.append(("server", node, json.dumps(merged, indent=2,
                                                     ensure_ascii=False)))
    results = []
    for role, node, text in steps:
        r = apply_config(node, text, note=f"اعمال pair #{pair_id}", source="pair-wizard")
        results.append({"role": role, "node": node["name"], **r})
    return jsonify({"ok": all(r["ok"] for r in results), "results": results})


@APP.route("/pair/<int:pair_id>/delete", methods=["POST"])
@login_required
def pair_delete(pair_id):
    with db.connect() as conn, conn:
        db.delete_pair(conn, pair_id)
    flash("pair حذف شد.", "ok")
    return redirect(url_for("pair_page"))


@APP.route("/pair/<int:pair_id>/download")
@login_required
def pair_download(pair_id):
    import io
    import zipfile

    with db.connect() as conn:
        pair = db.get_pair(conn, pair_id)
    if not pair:
        abort(404)
    spec = pair.get("spec") or {}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("client.json", pair["client_json"])
        zf.writestr("server.json", pair["server_json"])
        client_cfg = json.loads(pair["client_json"])
        server_cfg = json.loads(pair["server_json"])
        zf.writestr("client-firewall.sh", gen.nftables_script(client_cfg, "client"))
        zf.writestr("server-firewall.sh", gen.nftables_script(server_cfg, "server"))
        zf.writestr("iptables-firewall.sh",
                    gen.iptables_script(client_cfg, "client-iptables"))
        zf.writestr("README.txt", _pair_readme(pair, spec))
    buf.seek(0)
    from flask import send_file
    return send_file(buf, mimetype="application/zip", as_attachment=True,
                     download_name=f"injspoof-{pair['name']}.zip")


def _pair_readme(pair, spec):
    return (
        f"injspoof pair: {pair['name']}\n"
        f"HID مشترک: {pair['hid']}\n\n"
        "۱) فایل‌ها را روی هر نود بگذارید (مثلاً /etc/injspoof/).\n"
        "۲) روی هر دو ماشین اسکریپت فایروال را اجرا کنید:\n"
        "     sudo bash client-firewall.sh    # سمت کلاینت\n"
        "     sudo bash server-firewall.sh   # سمت سرور\n"
        "۳) بیلد و اجرا:\n"
        "     make && sudo setcap cap_net_raw+ep ./injspoof\n"
        f"     ./injspoof --mode client --config client.json\n"
        f"     ./injspoof --mode server --config server.json\n\n"
        "پیش از اجرا چک کنید:\n"
        "  - outgoing.gateway.mac_address روی هر دو = MAC واقعی gateway (ip neigh)\n"
        "  - IPهای داخل pool توسط provider شما اجازه‌ی spoofing دارند\n"
        "  - api.token عوض شده و api.bind روی 127.0.0.1 است\n")


def merge_into_node(node, pair):
    """peer جدید را در کانفیگ زنده‌ی سرور تزریق می‌کند."""
    try:
        current = node_client(node).get_config()
    except Exception:                                  # noqa: BLE001
        current = {}
    spec = dict(pair.get("spec") or {})
    spec["hid"] = pair.get("hid") or spec.get("hid")
    merged, issues = gen.merge_client_into_server(current, spec)
    return merged, issues


# ======================================================================
#  هسته روی همین ماشین: سرویس، کانفیگ روی دیسک، فایروال، به‌روزرسانی
# ======================================================================
#
# پنل خودroot نیست؛ همه‌ی این کارها از راه helper ریشه‌پای
# /usr/local/libexec/injspoof-nodectl انجام می‌شود (core.py). آن helper فقط
# instanceهایی را می‌پذیرد که در /etc/injspoof/instances.cfg ثبت شده‌اند، و
# نام واحد را خودشان می‌سازد؛ پس پنل نمی‌تواند هر سرویسی را restart کند.

def local_nodes():
    with db.connect() as conn:
        return [n for n in db.list_nodes(conn) if int(n.get("is_local") or 0)]


def core_context(node=None):
    """همه‌چیزی که صفحه‌ی «هسته» نشان می‌دهد: وضعیت نصب، سرویس، کانفیگ دیسک، API زنده."""
    node = node or (local_nodes() or [None])[0]
    state = coreops.describe(node)
    out = {
        "state": state,
        "node": node,
        "installed": bool(state.get("BINARY")) and state.get("BINARY") != "missing",
        "controllable": bool(state.get("controllable")),
        "service": state.get("SERVICE_STATE", "unknown"),
        "firewall_service": state.get("FIREWALL_STATE", "unknown"),
        "instance": state.get("instance", ""),
        "config_path": state.get("CONFIG_PATH", ""),
        "config_error": state.get("CONFIG_ERROR", ""),
        "build_info": state.get("BUILD_INFO", ""),
        "binary_caps": state.get("BINARY_CAPS", ""),
        "update_allowed": state.get("UPDATE_ALLOWED") == "yes",
        "disk_config": "",
        "issues": [],
        "summary": {"error": 0, "warn": 0, "info": 0},
        "api_alive": None,
        "api_error": "",
    }
    if out["controllable"] and out["instance"]:
        ok, text = coreops.config_show(out["instance"])
        if ok and text:
            out["disk_config"] = text
            try:
                cfg = json.loads(text)
                issues = schema.validate(cfg, (node or {}).get("role") or "server")
                out["issues"] = issues
                out["summary"] = schema.summary(issues)
            except json.JSONDecodeError as exc:
                out["config_error"] = f"کانفیگ دیسک JSON معتبر نیست: {exc}"
    if node:
        try:
            info = node_client(node).info()
            out["api_alive"] = True
            out["api_info"] = info
        except Exception as exc:                          # noqa: BLE001
            out["api_alive"] = False
            out["api_error"] = str(exc)
    # رکورد نود در panel.db توکن API را دارد؛ هیچ‌وقت به JSON/مرورگر نمی‌رود.
    if isinstance(out["node"], dict):
        out["node"] = {k: v for k, v in out["node"].items() if k != "api_token"}
    return out


@APP.route("/core")
@login_required
def core_page():
    node_id = request.args.get("node", type=int)
    node = None
    if node_id:
        with db.connect() as conn:
            node = db.get_node(conn, node_id)
    ctx = core_context(node)
    return render_template("core.html", nodes=local_nodes(), **ctx)


@APP.route("/api/core/info")
@login_required
def api_core_info():
    node_id = request.args.get("node", type=int)
    node = None
    if node_id:
        with db.connect() as conn:
            node = db.get_node(conn, node_id)
    return jsonify(core_context(node))


def core_instance_for(node):
    """instance را از رکورد نود می‌گیرد؛ برای نود غیرمحلی None."""
    if not node:
        return None, "نودی انتخاب نشده."
    inst = coreops.local_instance(node)
    if not inst:
        return None, (f"نود «{node['name']}» نود محلی این ماشین نیست؛ سرویسش از "
                      "راه systemctl روی همان سرور کنترل می‌شود.")
    return inst, ""


@APP.route("/api/core/service", methods=["POST"])
@login_required
def api_core_service():
    payload = request.get_json(force=True, silent=True) or {}
    action = (payload.get("action") or "").strip()
    with db.connect() as conn:
        node = db.get_node(conn, payload.get("node_id") or 0)
    inst, err = core_instance_for(node)
    if err:
        return jsonify({"ok": False, "error": err}), 400
    ok, text = coreops.service(action, inst)
    if ok and action in ("start", "restart"):
        # توکن/آدرس تازه را در رکورد نود بنشان تا پنل قفل نشود
        sync_local_node_token(node)
    return jsonify({"ok": ok, "output": text, "action": action,
                    "instance": inst}), (200 if ok else 502)


@APP.route("/api/core/logs", methods=["POST"])
@login_required
def api_core_logs():
    payload = request.get_json(force=True, silent=True) or {}
    with db.connect() as conn:
        node = db.get_node(conn, payload.get("node_id") or 0)
    inst = coreops.local_instance(node) if node else coreops.DEFAULT_INSTANCE
    ok, text = coreops.logs(inst, payload.get("lines") or 120)
    return jsonify({"ok": ok, "output": text}), (200 if ok else 502)


@APP.route("/api/core/rescan", methods=["POST"])
@login_required
def api_core_rescan():
    """daemon-reload + وضعیت واحد؛ برای وقتی فایل .service تازه شده است."""
    payload = request.get_json(force=True, silent=True) or {}
    with db.connect() as conn:
        node = db.get_node(conn, payload.get("node_id") or 0)
    inst = coreops.local_instance(node) if node else coreops.DEFAULT_INSTANCE
    ok, text = coreops.rescan(inst)
    return jsonify({"ok": ok, "output": text}), (200 if ok else 502)


@APP.route("/api/core/config/write", methods=["POST"])
@login_required
def api_core_config_write():
    """کانفیگ را روی دیسک نود محلی می‌نویسد و سرویس را restart می‌کند.

    مسیر جایگزین PUT /api/v1/config است: آن مسیر فقط وقتی کار می‌کند که هسته
    بالا باشد. اینجا عمداً اول با همان قواعد schema.py اعتبارسنجی می‌شود تا
    کانفیگی که loader رد می‌کند روی سرویس restart‌شده نگذارد (چرخه‌ی crash).
    """
    payload = request.get_json(force=True, silent=True) or {}
    text = payload.get("config") or ""
    restart = bool(payload.get("restart", True))
    with db.connect() as conn:
        node = db.get_node(conn, payload.get("node_id") or 0)
    inst, err = core_instance_for(node)
    if err:
        return jsonify({"ok": False, "error": err}), 400
    try:
        cfg = json.loads(text)
    except json.JSONDecodeError as exc:
        return jsonify({"ok": False, "stage": "json",
                        "error": f"JSON نامعتبر: {exc}"}), 422
    issues = schema.validate(cfg, node["role"])
    if not schema.ok(issues):
        return jsonify({"ok": False, "stage": "validate",
                        "error": "کانفیگ خطای جدی دارد",
                        "issues": [i for i in issues if i["level"] == schema.ERROR]}), 422
    with db.connect() as conn, conn:
        current = None
        ok_show, shown = coreops.config_show(inst)
        if ok_show and shown:
            current = shown
            db.save_version(conn, node["id"], current,
                            note="بکاپ کانفیگ دیسک قبل از نوشتن پنل", source="pre-apply")
        db.save_version(conn, node["id"], text,
                        note=payload.get("note") or "نوشتن کانفیگ روی دیسک",
                        source="core-disk")
    ok, out = coreops.config_write(inst, json.dumps(cfg, indent=2, ensure_ascii=False))
    if not ok:
        return jsonify({"ok": False, "stage": "write", "error": out}), 502
    result = {"ok": True, "stage": "written", "output": out, "instance": inst}
    if restart:
        rok, rout = coreops.service("restart", inst)
        result["restart"] = {"ok": rok, "output": rout}
        if rok:
            sync_local_node_token(node)
        if not rok:
            logr, lout = coreops.logs(inst, 40)
            result["logs"] = lout if logr else lout
    return jsonify(result)


@APP.route("/api/core/firewall/apply", methods=["POST"])
@login_required
def api_core_firewall_apply():
    """قواعد بستن RST/ICMP کرنل را از روی کانفیگ فعلی می‌سازد و root اجرا می‌کند."""
    payload = request.get_json(force=True, silent=True) or {}
    with db.connect() as conn:
        node = db.get_node(conn, payload.get("node_id") or 0)
    inst, err = core_instance_for(node)
    if err:
        return jsonify({"ok": False, "error": err}), 400
    cfg = None
    try:
        cfg = node_client(node).get_config()
    except Exception:                                     # noqa: BLE001
        ok, text = coreops.config_show(inst)
        if ok and text:
            try:
                cfg = json.loads(text)
            except json.JSONDecodeError:
                cfg = None
    if not cfg:
        return jsonify({"ok": False,
                        "error": "کانفیگ فعلی نود خوانده نشد؛ اول کانفیگ را اعمال کنید"}), 502
    script = gen.nftables_script(cfg, node["name"], instance=inst)
    ok, out = coreops.firewall_apply(inst, script)
    return jsonify({"ok": ok, "output": out, "script": script}), (200 if ok else 502)


@APP.route("/api/core/firewall/script")
@login_required
def api_core_firewall_script():
    """پیش‌نمایش/دانلود اسکریپت فایروال (بدون اجرای هیچ دستوری)."""
    node_id = request.args.get("node", type=int)
    engine = request.args.get("engine", "nft")
    with db.connect() as conn:
        node = db.get_node(conn, node_id or 0)
    inst = (coreops.local_instance(node) if node else "") or "server"
    cfg = {}
    text = ""
    if node:
        ok, shown = coreops.config_show(inst)
        if ok and shown:
            text = shown
        else:
            try:
                cfg = node_client(node).get_config()
            except Exception:                             # noqa: BLE001
                cfg = {}
    if not cfg and text:
        try:
            cfg = json.loads(text)
        except json.JSONDecodeError:
            cfg = {}
    if not cfg:
        return jsonify({"ok": False, "error": "کانفیگی برای تولید قواعد نیست"}), 404
    script = (gen.nftables_script(cfg, node["name"] if node else inst, instance=inst)
              if engine == "nft" else gen.iptables_script(cfg, inst))
    return jsonify({"ok": True, "script": script, "engine": engine})


@APP.route("/api/core/update", methods=["POST"])
@login_required
def api_core_update():
    ok, out = coreops.update()
    return jsonify({"ok": ok, "output": out}), (200 if ok else 502)


def sync_local_node_token(node):
    """api.token نود محلی را از کانفیگ دیسک به panel.db می‌آورد.

    hot reload مقدار token را اعمال می‌کند؛ اگر کاربر توکن را در کانفیگ عوض
    کرده باشد و رکورد پنل کهنه بماند، پنل خودش را از نود قفل می‌کند.
    """
    inst = coreops.local_instance(node)
    if not (node and inst):
        return False
    ok, text = coreops.config_show(inst)
    if not ok or not text:
        return False
    try:
        token = (json.loads(text).get("api") or {}).get("token") or ""
    except (json.JSONDecodeError, AttributeError):
        return False
    if not token or token == node.get("api_token"):
        return False
    with db.connect() as conn, conn:
        row = db.get_node(conn, node["id"])
        if not row:
            return False
        data = dict(row)
        data["api_token"] = token
        db.upsert_node(conn, data)
        node["api_token"] = token
    return True


# ======================================================================
#  اعمال کانفیگ (validate -> backup -> PUT -> reload)
# ======================================================================

def apply_config(node, config_text, note="", source="panel", reload_mode="hot"):
    """جریان کامل اعمال. همیشه قبل از PUT نسخه‌ی فعلی را بکاپ می‌گیرد."""
    try:
        cfg = json.loads(config_text)
    except json.JSONDecodeError as exc:
        return {"ok": False, "stage": "json", "error": f"JSON نامعتبر: {exc}"}

    issues = schema.validate(cfg, node["role"])
    if not schema.ok(issues):
        return {"ok": False, "stage": "validate", "error": "کانفیگ خطای جدی دارد",
                "issues": [i for i in issues if i["level"] == schema.ERROR]}

    client = node_client(node)
    try:
        current = client.get_config()
    except Exception as exc:                          # noqa: BLE001
        current = None
        with db.connect() as conn, conn:
            db.save_version(conn, node["id"], config_text,
                            note=f"{note} (بکاپ اولیه خوانده نشد)", source=source)
    else:
        with db.connect() as conn, conn:
            db.save_version(conn, node["id"], json.dumps(current, indent=2,
                                                         ensure_ascii=False),
                            note=f"بکاپ قبل از: {note}", source="pre-apply")
            db.save_version(conn, node["id"], config_text, note=note, source=source)

    try:
        client.put_config(cfg)
    except Exception as exc:                          # noqa: BLE001
        return {"ok": False, "stage": "put", "error": str(exc)}

    reload_result = None
    if reload_mode in ("hot", "hard"):
        try:
            reload_result = client.reload(reload_mode)
        except Exception as exc:                      # noqa: BLE001
            return {"ok": False, "stage": "reload",
                    "error": f"کانفیگ نوشته شد ولی reload شکست: {exc}",
                    "rollback_hint": f"/history/{node['id']}"}
    new_token = (cfg.get("api") or {}).get("token") if isinstance(cfg, dict) else None
    token_changed = bool(new_token) and new_token != (node.get("api_token") or "")
    result = {"ok": True, "reloaded": reload_result, "stage": "done",
              "token_changed": token_changed}
    if token_changed:
        result["warning"] = ("api.token نود عوض شد و hot reload آن را اعمال می‌کند؛ "
                             "پنل با توکن قدیمی دیگر به این نود دسترسی ندارد. "
                             "همین حالا توکن را در صفحه‌ی «نودها» به‌روز کنید.")
    return result


@APP.route("/api/config/validate", methods=["POST"])
@login_required
def api_validate():
    payload = request.get_json(force=True, silent=True) or {}
    text = payload.get("config") or "{}"
    mode = payload.get("mode") or "server"
    try:
        cfg = json.loads(text) if isinstance(text, str) else text
    except json.JSONDecodeError as exc:
        return jsonify({"ok": False, "issues": [
            {"level": "error", "path": "$", "message": f"JSON نامعتبر: {exc}",
             "hint": ""}], "summary": {"error": 1, "warn": 0, "info": 0}})
    issues = schema.validate(cfg, mode)
    return jsonify({"ok": schema.ok(issues), "issues": issues,
                    "summary": schema.summary(issues),
                    "capacity": schema.capacity_report(cfg) if isinstance(cfg, dict) else []})


@APP.route("/api/config/load/<int:node_id>")
@login_required
def api_config_load(node_id):
    with db.connect() as conn:
        node = db.get_node(conn, node_id)
    if not node:
        abort(404)
    try:
        cfg = node_client(node).get_config()
    except Exception as exc:                          # noqa: BLE001
        return jsonify({"ok": False, "error": str(exc)}), 502
    issues = schema.validate(cfg, node["role"])
    with db.connect() as conn, conn:
        db.save_version(conn, node["id"], json.dumps(cfg, indent=2, ensure_ascii=False),
                        note="خوانده‌شده از نود", source="node")
    return jsonify({"ok": True, "config": json.dumps(cfg, indent=2, ensure_ascii=False),
                    "issues": issues, "summary": schema.summary(issues),
                    "capacity": schema.capacity_report(cfg)})


@APP.route("/api/config/apply/<int:node_id>", methods=["POST"])
@login_required
def api_config_apply(node_id):
    with db.connect() as conn:
        node = db.get_node(conn, node_id)
    if not node:
        abort(404)
    payload = request.get_json(force=True, silent=True) or {}
    result = apply_config(node, payload.get("config") or "",
                          note=payload.get("note") or "ویرایش دستی",
                          source="manual",
                          reload_mode=payload.get("reload", "hot"))
    return jsonify(result), (200 if result["ok"] else 422)


@APP.route("/api/reload/<int:node_id>", methods=["POST"])
@login_required
def api_reload(node_id):
    with db.connect() as conn:
        node = db.get_node(conn, node_id)
    if not node:
        abort(404)
    mode = (request.get_json(silent=True) or {}).get("mode", "hot")
    try:
        return jsonify({"ok": True, "result": node_client(node).reload(mode)})
    except Exception as exc:                          # noqa: BLE001
        return jsonify({"ok": False, "error": str(exc)}), 502


# ======================================================================
#  API داخلی پنل
# ======================================================================

@APP.route("/api/nodes")
@login_required
def api_nodes():
    snap = COLLECTOR.snapshot()
    with db.connect() as conn:
        nodes = db.list_nodes(conn)
    for n in nodes:
        n["status"] = snap.get(n["id"], {"alive": None, "error": None})
        # توکن نود هرگز به مرورگر نمی‌رود؛ فقط «ست شده» بودنش لازم است
        n["token_set"] = bool(n.get("api_token"))
        n.pop("api_token", None)
    return jsonify({"nodes": nodes})


@APP.route("/api/nodes/<int:node_id>/series")
@login_required
def api_series(node_id):
    limit = request.args.get("limit", default=120, type=int)
    with db.connect() as conn:
        node = db.get_node(conn, node_id)
    if not node:
        abort(404)
    fresh = request.args.get("fresh") in ("1", "true", "yes")
    sampled = COLLECTOR.sample_now(node) if fresh else False
    samples, status = COLLECTOR.series(node_id)
    samples = samples[-limit:]
    return jsonify({
        "node": {k: node[k] for k in ("id", "name", "role", "api_url", "config_path")},
        "status": status,
        "samples": [{"ts": s["ts"], "stats": s["stats"], "error": s["error"]}
                    for s in samples],
        "interval": SAMPLE_INTERVAL,
        "sampled_now": sampled,
    })


@APP.route("/api/nodes/<int:node_id>/info")
@login_required
def api_node_info(node_id):
    with db.connect() as conn:
        node = db.get_node(conn, node_id)
    if not node:
        abort(404)
    try:
        return jsonify({"ok": True, "info": node_client(node).info()})
    except Exception as exc:                          # noqa: BLE001
        return jsonify({"ok": False, "error": str(exc)}), 502


@APP.route("/api/nodes/<int:node_id>/versions")
@login_required
def api_node_versions(node_id):
    """فهرست نسخه‌ها به‌صورت JSON (برای UI و برای تست‌های سرتاسری)."""
    with db.connect() as conn:
        node = db.get_node(conn, node_id)
        versions = db.list_versions(conn, node_id, limit=200) if node else None
    if node is None:
        abort(404)
    return jsonify({"ok": True, "node_id": node_id, "versions": versions})


@APP.route("/api/nodes/<int:node_id>/metrics")
@login_required
def api_metrics(node_id):
    with db.connect() as conn:
        node = db.get_node(conn, node_id)
    if not node:
        abort(404)
    try:
        text = node_client(node).metrics_text()
    except Exception as exc:                          # noqa: BLE001
        return jsonify({"ok": False, "error": str(exc)}), 502
    return jsonify({"ok": True, "text": text,
                    "parsed": injclient.parse_prometheus(text)})


def probe_node(node):
    try:
        client = node_client(node)
        info = client.info()
        client.health()
        return {"ok": True, "mode": info.get("mode"), "version": info.get("version"),
                "config_path": info.get("config"), "pid": info.get("pid")}
    except Exception as exc:                          # noqa: BLE001
        return {"ok": False, "error": str(exc)}


@APP.route("/api/nodes/<int:node_id>/test", methods=["POST"])
@login_required
def api_node_test(node_id):
    with db.connect() as conn:
        node = db.get_node(conn, node_id)
    if not node:
        abort(404)
    return jsonify(probe_node(node))


@APP.route("/api/pair/<int:pair_id>/check")
@login_required
def api_pair_check(pair_id):
    """هم‌راستایی کانفیگ زنده‌ی دو نود را با spec یک pair می‌سنجد."""
    with db.connect() as conn:
        pair = db.get_pair(conn, pair_id)
        nodes = {n["id"]: n for n in db.list_nodes(conn)}
    if not pair:
        abort(404)
    ids = [pair.get("client_node_id"), pair.get("server_node_id")]
    live = {}
    for nid in ids:
        node = nodes.get(nid)
        if not node:
            continue
        try:
            live[nid] = node_client(node).get_config()
        except Exception as exc:                      # noqa: BLE001
            return jsonify({"ok": False, "error": f"{node['name']}: {exc}"}), 502
    if len(live) != 2:
        return jsonify({"ok": False,
                        "error": "برای بررسی هم‌راستایی، هر دو نود باید ثبت شده باشند"})
    client_cfg = live.get(pair["client_node_id"], {})
    server_cfg = live.get(pair["server_node_id"], {})
    issues = schema.check_pair(client_cfg, server_cfg)
    return jsonify({"ok": schema.ok(issues), "summary": schema.summary(issues),
                    "issues": issues})


# ======================================================================
#  ابزار نمایش
# ======================================================================

def fmt_bytes(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if n < 1024 or unit == "PB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def fmt_uptime(ms):
    try:
        sec = int(ms // 1000)
    except (TypeError, ValueError):
        return "—"
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if d:
        parts.append(f"{d} روز")
    if h:
        parts.append(f"{h} ساعت")
    if m:
        parts.append(f"{m} دقیقه")
    if not parts:
        parts.append(f"{s} ثانیه")
    return " ".join(parts)


def db_list_nodes():
    with db.connect() as conn:
        return db.list_nodes(conn)


def _token_preview(node):
    if not node:
        return {"set": False, "preview": "", "placeholder": "openssl rand -hex 32"}
    tok = node.get("api_token") or ""
    if not tok:
        return {"set": False, "preview": "", "placeholder": "openssl rand -hex 32"}
    return {"set": True,
            "preview": (tok[:4] + "…" + tok[-4:]) if len(tok) > 12 else "ست شده",
            "placeholder": "برای تغییر مقدار جدید را بنویسید (خالی = بدون تغییر)"}


# ======================================================================
#  راه‌اندازی
# ======================================================================

def create_app():
    db.init()
    COLLECTOR.start()
    return APP


app = create_app()
