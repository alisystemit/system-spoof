"""
register.py — ثبت/تازه‌سازی نودها در panel.db از خط فرمان

install.sh هسته بعد از نصب، نود محلی را با همین ابزار در دیتابیس پنل می‌نویسد؛
پنل از آنجا api_url و توکن را می‌شناسد و صفحه‌ی «هسته» می‌فهمد کدام نود با
systemdctl قابل‌کنترل است. بیرون از install.sh هم می‌شود استفاده کرد:

    python3 register.py local  --name local-server --api-url http://127.0.0.1:9090 \
                               --token <tok> --config-path /etc/injspoof/server.json \
                               --instance server
    python3 register.py remove --name local-server
"""

from __future__ import annotations

import argparse
import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass


def _open(db_path):
    os.environ["PANEL_DB"] = os.path.abspath(db_path)
    import db
    db.DB_PATH = os.environ["PANEL_DB"]
    db.init()
    return db


def cmd_local(a):
    db = _open(a.db)
    with db.connect() as conn, conn:
        row = {
            "name": a.name,
            "role": a.role,
            "api_url": a.api_url.rstrip("/"),
            "api_token": a.token,
            "config_path": a.config_path,
            "is_local": 1,
            "core_instance": a.instance,
            "enabled": 1,
            "note": a.note or "نود محلی همین ماشین (نوشته‌شده توسط install.sh)",
        }
        existing = db.get_node_by_name(conn, a.name)
        if existing:
            # توکن را همیشه از کانفیگ بگیر: اگر کانفیگ عوض شده باشد، پنل باید
            # همان توکن تازه را داشته باشد وگرنه قفل می‌شود.
            row["id"] = existing["id"]
            node_id = db.upsert_node(conn, row)
            print(f"node updated: id={node_id} name={a.name} instance={a.instance}")
        else:
            node_id = db.upsert_node(conn, row)
            print(f"node inserted: id={node_id} name={a.name} instance={a.instance}")
    return 0


def cmd_remove(a):
    db = _open(a.db)
    with db.connect() as conn, conn:
        existing = db.get_node_by_name(conn, a.name)
        if not existing:
            print(f"node not found: {a.name}")
            return 1
        db.delete_node(conn, existing["id"])
        print(f"node removed: id={existing['id']} name={a.name}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="register.py")
    p.add_argument("--db", default=os.environ.get(
        "PANEL_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "panel.db")))
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("local", help="نود محلی همین ماشین را ثبت/تازه کن")
    s.add_argument("--name", required=True)
    s.add_argument("--role", default="server", choices=["client", "server"])
    s.add_argument("--api-url", required=True, dest="api_url")
    s.add_argument("--token", required=True)
    s.add_argument("--config-path", default="", dest="config_path")
    s.add_argument("--instance", default="server")
    s.add_argument("--note", default="")
    s.set_defaults(func=cmd_local)

    r = sub.add_parser("remove", help="حذف یک نود (با تاریخچه‌اش)")
    r.add_argument("--name", required=True)
    r.set_defaults(func=cmd_remove)

    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    raise SystemExit(main())
