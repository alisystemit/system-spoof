"""
db.py — ذخیره‌سازی محلی پنل روی SQLite (stdlib، بدون سرویس دیتابیس)

سه جدول:
  nodes            نودهای injspoof که پنل مدیریت می‌کند (url + token)
  pairs          spec های تولید کانفیگ دوطرفه
  config_history  هر نسخه‌ی کانفیگی که روی نود اعمال شده، برای rollback
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager

DB_PATH = os.environ.get(
    "PANEL_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "panel.db"),
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS nodes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    role        TEXT NOT NULL CHECK (role IN ('client','server')),
    api_url     TEXT NOT NULL,
    api_token   TEXT NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,
    config_path TEXT NOT NULL DEFAULT '',
    note        TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS pairs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL UNIQUE,
    hid             TEXT NOT NULL DEFAULT '',
    spec_json       TEXT NOT NULL DEFAULT '{}',
    client_json     TEXT NOT NULL DEFAULT '',
    server_json     TEXT NOT NULL DEFAULT '',
    client_node_id  INTEGER,
    server_node_id  INTEGER,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS config_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id     INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    sha256      TEXT NOT NULL,
    config_json TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL DEFAULT 'panel',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_history_node ON config_history(node_id, id DESC);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);
"""


def connect():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def tx():
    conn = connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init():
    with tx() as conn:
        conn.executescript(SCHEMA_SQL)


def get_setting(conn, key, default=None):
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn, key, value):
    with tx() as c:
        c.execute("INSERT INTO settings(key, value) VALUES(?, ?) "
                  "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                  (key, str(value)))


# ======================================================================
#  nodes
# ======================================================================

def list_nodes(conn):
    return [dict(r) for r in conn.execute(
        "SELECT * FROM nodes ORDER BY name COLLATE NOCASE").fetchall()]


def get_node(conn, node_id):
    row = conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
    return dict(row) if row else None


def upsert_node(conn, node):
    if node.get("id"):
        conn.execute(
            "UPDATE nodes SET name=?, role=?, api_url=?, api_token=?, enabled=?, "
            "config_path=?, note=?, updated_at=datetime('now') WHERE id=?",
            (node["name"], node["role"], node["api_url"], node.get("api_token", ""),
             int(bool(node.get("enabled", True))), node.get("config_path", ""),
             node.get("note", ""), node["id"]))
        return node["id"]
    cur = conn.execute(
        "INSERT INTO nodes(name, role, api_url, api_token, enabled, config_path, note) "
        "VALUES(?,?,?,?,?,?,?)",
        (node["name"], node["role"], node["api_url"], node.get("api_token", ""),
         int(bool(node.get("enabled", True))), node.get("config_path", ""),
         node.get("note", "")))
    return cur.lastrowid


def delete_node(conn, node_id):
    conn.execute("DELETE FROM nodes WHERE id = ?", (node_id,))
    conn.execute("DELETE FROM config_history WHERE node_id = ?", (node_id,))


# ======================================================================
#  config history
# ======================================================================

def sha256_of(text):
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def save_version(conn, node_id, config_text, note="", source="panel"):
    if isinstance(config_text, (dict, list)):
        config_text = json.dumps(config_text, indent=2, ensure_ascii=False)
    digest = sha256_of(config_text)
    last = conn.execute("SELECT sha256 FROM config_history WHERE node_id = ? "
                        "ORDER BY id DESC LIMIT 1", (node_id,)).fetchone()
    if last and last["sha256"] == digest:
        return None
    cur = conn.execute(
        "INSERT INTO config_history(node_id, sha256, config_json, note, source) "
        "VALUES(?,?,?,?,?)", (node_id, digest, config_text, note, source))
    return cur.lastrowid


def list_versions(conn, node_id, limit=50):
    rows = conn.execute(
        "SELECT id, sha256, note, source, created_at, length(config_json) AS bytes "
        "FROM config_history WHERE node_id = ? ORDER BY id DESC LIMIT ?",
        (node_id, limit)).fetchall()
    return [dict(r) for r in rows]


def get_version(conn, version_id):
    row = conn.execute("SELECT * FROM config_history WHERE id = ?",
                       (version_id,)).fetchone()
    return dict(row) if row else None


# ======================================================================
#  pairs
# ======================================================================

def list_pairs(conn):
    rows = conn.execute("SELECT * FROM pairs ORDER BY name COLLATE NOCASE").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["spec"] = json.loads(d.get("spec_json") or "{}")
        except json.JSONDecodeError:
            d["spec"] = {}
        out.append(d)
    return out


def get_pair(conn, pair_id):
    row = conn.execute("SELECT * FROM pairs WHERE id = ?", (pair_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    try:
        d["spec"] = json.loads(d.get("spec_json") or "{}")
    except json.JSONDecodeError:
        d["spec"] = {}
    return d


def save_pair(conn, pair):
    spec_json = json.dumps(pair.get("spec", {}), ensure_ascii=False)
    if pair.get("id"):
        conn.execute(
            "UPDATE pairs SET name=?, hid=?, spec_json=?, client_json=?, server_json=?, "
            "client_node_id=?, server_node_id=?, updated_at=datetime('now') WHERE id=?",
            (pair["name"], pair.get("hid", ""), spec_json,
             pair.get("client_json", ""), pair.get("server_json", ""),
             pair.get("client_node_id"), pair.get("server_node_id"), pair["id"]))
        return pair["id"]
    cur = conn.execute(
        "INSERT INTO pairs(name, hid, spec_json, client_json, server_json, "
        "client_node_id, server_node_id) VALUES(?,?,?,?,?,?,?)",
        (pair["name"], pair.get("hid", ""), spec_json, pair.get("client_json", ""),
         pair.get("server_json", ""), pair.get("client_node_id"),
         pair.get("server_node_id")))
    return cur.lastrowid


def delete_pair(conn, pair_id):
    conn.execute("DELETE FROM pairs WHERE id = ?", (pair_id,))
