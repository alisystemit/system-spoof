"""
mock_nodectl.py — شبیه‌ساز injspoof-nodectl برای توسعه و دموی صفحه‌ی «هسته»

همین رابط را دارد که panel/deploy/injspoof-nodectl دارد (همان دستور ها، همان
خروجی KEY=value، کانفیگ از stdin) ولی هیچ systemctl/nft واقعی اجرا نمی‌کند؛
وضعیت را در یک پوشه‌ی محلی نگه می‌دارد. یعنی روی ویندوز یا WSL هم می‌توان
صفحه‌ی «هسته» را با داده‌ی کامل دید.

    INJSPOOF_SUDO=python INJSPOOF_NODECTL=panel/mock_nodectl.py python panel/run.py

اسم فایل در پروداکشن فرق دارد: install.sh نسخه‌ی sh را در
/usr/local/libexec/injspoof-nodectl می‌گذارد و این فایل هرگز نصب نمی‌شود.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = os.environ.get("INJSPOOF_MOCK_STATE") or os.path.join(HERE, ".mock-nodectl")
def _example_config():
    """example/ ریپو، وگرنه seed/ پنل — تا mock روی نصب مستقل هم کار کند."""
    for p in (os.path.join(HERE, "..", "example", "server.json"),
              os.path.join(HERE, "seed", "server.json")):
        if os.path.isfile(p):
            return p
    return os.path.join(HERE, "seed", "server.json")


EXAMPLE = os.environ.get("INJSPOOF_MOCK_CONFIG") or _example_config()


def config_path():
    return os.path.join(STATE_DIR, "config.json")


def state_path():
    return os.path.join(STATE_DIR, "service.state")


def ensure_state():
    os.makedirs(STATE_DIR, exist_ok=True)
    if not os.path.exists(config_path()):
        try:
            shutil.copyfile(EXAMPLE, config_path())
        except OSError:
            with open(config_path(), "w", encoding="utf-8") as f:
                f.write("{}\n")
    if not os.path.exists(state_path()):
        write_service("active")


def read_service():
    try:
        with open(state_path(), encoding="utf-8") as f:
            return f.read().strip() or "inactive"
    except OSError:
        return "inactive"


def write_service(value):
    with open(state_path(), "w", encoding="utf-8") as f:
        f.write(value + "\n")


def die(msg):
    print(f"mock-nodectl: {msg}", file=sys.stderr)
    raise SystemExit(2)


def cmd_service(action, inst):
    if action == "status":
        print(f"● injspoof@{inst}.service — {read_service()} (mock)")
        return
    write_service({"start": "active", "restart": "active", "stop": "inactive"}[action])
    print(f"{action} injspoof@{inst} — {read_service()} (mock)")


def cmd_info(inst):
    fw = os.path.join(STATE_DIR, "firewall.nft.sh")
    rows = [
        ("INSTANCE", inst),
        ("UNIT", f"injspoof@{inst}"),
        ("PREFIX", "/opt/injspoof-panel"),
        ("SRC_DIR", os.path.abspath(os.path.join(HERE, ".."))),
        ("CFG_GROUP", "injspoof-panel"),
        ("ALL_INSTANCES", inst),
        ("CONFIG_PATH", config_path()),
        ("BINARY", "/usr/local/bin/injspoof"),
        ("BINARY_LS", "-rwxr-xr-x 1 root root 210344 Jan 01 00:00 /usr/local/bin/injspoof"),
        ("BINARY_CAPS", "/usr/local/bin/injspoof cap_net_raw,cap_bpf,cap_net_admin=eip"),
        ("BUILD_INFO", "version mock built-for-ui-tests fastpath=1"),
        ("SERVICE_STATE", read_service()),
        ("FIREWALL_STATE", "active" if os.path.exists(fw) else "inactive"),
        ("FIREWALL_SCRIPT", "present" if os.path.exists(fw) else "absent"),
        ("UPDATE_ALLOWED", "yes"),
    ]
    for k, v in rows:
        print(f"{k}={v}")


def cmd_logs(inst, lines):
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    for i in range(min(int(lines), 24)):
        print(f"{now}+{i:02d} injspoof[{os.getpid()}]: mock: instance={inst} "
              f"pkts_in={1024 + i * 7} pkts_out={980 + i * 5} drops=0 pool_avail=253")


def cmd_config_show(inst):
    with open(config_path(), encoding="utf-8") as f:
        sys.stdout.write(f.read())


def read_stdin():
    """پنل stdin را بایتی و UTF-8 می‌فرستد؛ روی ویندوز stdin پیش‌فرض cp1252 است."""
    return sys.stdin.buffer.read().decode("utf-8", "replace")


def cmd_config_write(inst):
    text = read_stdin()
    if not text.strip():
        die("متن کانفیگ خالی است")
    try:
        json.loads(text)
    except json.JSONDecodeError as exc:
        die(f"JSON نامعتبر: {exc}")
    stamp = time.strftime("%Y%m%dT%H%M%SZ")
    hist = os.path.join(STATE_DIR, "history")
    os.makedirs(hist, exist_ok=True)
    if os.path.exists(config_path()):
        shutil.copyfile(config_path(), os.path.join(hist, f"{inst}-{stamp}.json"))
    with open(config_path(), "w", encoding="utf-8") as f:
        f.write(text)
    print(f"mock: کانفیگ در {config_path()} نوشته شد")


def cmd_firewall_apply(inst):
    text = read_stdin()
    if "injspoof kernel-response blocker" not in text:
        die("متن ارسالی اسکریپت فایروال تولیدشده‌ی پنل نیست")
    with open(os.path.join(STATE_DIR, "firewall.nft.sh"), "w", encoding="utf-8") as f:
        f.write(text)
    print(f"mock: قواعد اعمال و در {os.path.join(STATE_DIR, 'firewall.nft.sh')} ذخیره شد")


def main(argv):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ensure_state()
    default = os.environ.get("INJSPOOF_INSTANCE", "server")
    cmd = argv[0] if argv else "help"
    rest = argv[1:]
    # همان قرارداد helper واقعی: بعد از دستور، اولین آرگومان instance است؛
    # فقط logs اول تعداد خط و بعد instance را می‌گیرد.
    if cmd == "logs":
        lines, inst = (rest[0] if rest else "80"), (rest[1] if len(rest) > 1 else default)
    else:
        lines, inst = "80", (rest[0] if rest else default)

    if cmd in ("start", "stop", "restart", "status"):
        cmd_service(cmd, inst)
        return 0
    if cmd == "info":
        cmd_info(inst)
        return 0
    if cmd == "version":
        print("mock build — این شبیه‌ساز است، هسته‌ی واقعی injspoof نیست")
        return 0
    if cmd == "logs":
        cmd_logs(inst, lines)
        return 0
    if cmd == "rescan":
        print("systemctl daemon-reload (mock)")
        print(f"injspoof@{inst} — {read_service()}")
        return 0
    if cmd == "config-show":
        cmd_config_show(inst)
        return 0
    if cmd == "config-write":
        cmd_config_write(inst)
        return 0
    if cmd == "firewall-apply":
        cmd_firewall_apply(inst)
        return 0
    if cmd == "update":
        print("mock: git pull + install.sh --update (هیچ دستوری اجرا نشد)")
        return 0
    die(f"دستور ناشناخته: {cmd}")
    return 2


if __name__ == "__main__":
    # پنل این‌طور صدا می‌زند:  python -n mock_nodectl.py info server
    # (-n پرچم خودِ پایتون است؛ همان جای sudo -n در helper واقعی).
    raise SystemExit(main(sys.argv[1:]))
