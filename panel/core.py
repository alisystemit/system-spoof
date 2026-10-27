"""
core.py — کنترل هسته‌ی injspoofِ همان ماشین، از داخل پنل

پنل با کاربر بی‌اختیار `injspoof-panel` اجرا می‌شود و root نیست. install.sh در
ازای آن این‌ها را می‌چیند:

  /usr/local/libexec/injspoof-nodectl   helper ریشه‌پای (فقط دستورهای سفیدشده)
  /etc/sudoers.d/injspoof-panel         NOPASSWD فقط برای همان helper
  /etc/injspoof/instances.cfg           فهرست instanceهایی که می‌شود کنترل کرد

این ماژول فقط همان helper را صدا می‌زند؛ هیچ دستوری مستقیم به systemctl یا
shell نمی‌دهد و نام واحد را از ورودی کاربر نمی‌سازد — نام instance از رکورد
نود در panel.db می‌آید و خود helper آن را با instances.cfg می‌سنجد.

اگر هسته روی این ماشین نصب نباشد (مثلاً پنل روی ماشین دیگری نشسته)،
`available()` مقدار False می‌دهد و UI به‌جای دکمه‌ها توضیح می‌گذارد.
"""

from __future__ import annotations

import os
import shutil
import subprocess

NODECTL = os.environ.get("INJSPOOF_NODECTL", "/usr/local/libexec/injspoof-nodectl")
SUDO = os.environ.get("INJSPOOF_SUDO", "sudo")
DEFAULT_INSTANCE = os.environ.get("INJSPOOF_INSTANCE", "")
TIMEOUT = float(os.environ.get("INJSPOOF_CTL_TIMEOUT", "30"))


class CoreError(Exception):
    """خطای اجرای helper (پیامش مستقیم از stderr خود helper است)."""


def helper_path():
    return NODECTL


def which_sudo():
    return shutil.which(SUDO) or ""


def node_args(instance=None, extra=()):
    args = [NODECTL]
    if instance:
        args.append(instance)
    return args + list(extra)


def run(action, instance=None, extra=(), stdin_text=None, timeout=TIMEOUT):
    """یک دستور injspoof-nodectl اجرا می‌کند و (ok, text) برمی‌گرداند.

    ok یعنی exit code صفر. text همیشه متن خروجی است (stdout و در خطا stderr)،
    تا در UI همان چیزی را نشان دهد که خود helper نوشته است.
    """
    sudo = which_sudo()
    if not sudo:
        return False, "sudo روی این ماشین نیست؛ کنترل هسته از پنل غیرفعال است."
    if not os.path.exists(NODECTL):
        return False, f"{NODECTL} نصب نیست؛ هسته را با install.sh نصب کنید."
    cmd = [sudo, "-n", NODECTL, action]
    if instance:
        cmd.append(instance)
    cmd += list(extra)
    try:
        proc = subprocess.run(
            cmd, input=stdin_text.encode("utf-8") if stdin_text is not None else None,
            capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"{action} پس از {timeout:.0f} ثانیه تمام نشد"
    except OSError as exc:
        return False, f"اجرای {action} ممکن نشد: {exc}"
    out = (proc.stdout or b"").decode("utf-8", "replace").strip()
    err = (proc.stderr or b"").decode("utf-8", "replace").strip()
    if proc.returncode == 0:
        return True, out or err
    return False, (err or out or f"exit {proc.returncode}")


def parse_kv(text):
    """خروجی `info` (خط‌های KEY=value) را به dict تبدیل می‌کند."""
    out = {}
    for line in (text or "").splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip():
            out[key.strip()] = value.strip()
    return out


def info(instance=None):
    """وضعیت نصب هسته: باینری، capability، سرویس، کانفیگ، فایروال."""
    ok, text = run("info", instance)
    data = parse_kv(text)
    data["ok"] = ok
    data["raw"] = text
    data["helper"] = NODECTL if os.path.exists(NODECTL) else "missing"
    data["sudo"] = bool(which_sudo())
    return data


def available():
    """آیا اصلاً می‌شود روی این ماشین هسته را کنترل کرد؟"""
    return bool(which_sudo()) and os.path.exists(NODECTL)


SERVICE_ACTIONS = {"status", "start", "stop", "restart"}


def service(action, instance):
    if action not in SERVICE_ACTIONS:
        return False, f"عملیات سرویس ناشناخته: {action}"
    return run(action, instance)


def logs(instance, lines=80):
    lines = max(10, min(int(lines or 80), 500))
    return run("logs", None, extra=(str(lines),) + ((instance,) if instance else ()))


def config_show(instance):
    return run("config-show", instance)


def config_write(instance, text):
    return run("config-write", instance, stdin_text=text, timeout=max(TIMEOUT, 45))


def firewall_apply(instance, script_text):
    return run("firewall-apply", instance, stdin_text=script_text,
               timeout=max(TIMEOUT, 60))


def rescan(instance=None):
    return run("rescan", instance)


def update():
    """git pull + install.sh --update؛ فقط اگر نصب با --allow-update شده باشد."""
    return run("update", None, timeout=max(300.0, TIMEOUT))


def local_instance(node, fallback=DEFAULT_INSTANCE):
    """نام instance هسته از رکورد نود؛ برای نود غیرمحلی None می‌دهد."""
    if not node:
        return None
    if not int(node.get("is_local") or 0):
        return None
    return (node.get("core_instance") or "").strip() or (fallback or None)


def describe(node=None):
    """خلاصه‌ی وضعیت برای UI: نصب، سرویس، کانفیگ، و اینکه چه کارهایی مجاز است."""
    inst = local_instance(node) if node is not None else DEFAULT_INSTANCE
    st = info(inst)
    st["instance"] = inst or ""
    st["controllable"] = available()
    return st
