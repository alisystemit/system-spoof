#!/usr/bin/env bash
# ====================================================================
# install.sh — پنل تحت وب injspoof + (اختیاری) هسته‌ی C
#
#   sudo bash panel/install.sh              # build هسته + پنل + سرویس‌ها
#   sudo bash panel/install.sh --update     # کد/باینری نو؛ رمز، دیتابیس و کانفیگ دست‌نخورده
#   sudo bash panel/install.sh --uninstall  # سرویس‌ها و کد را بردار (کانفیگ و db می‌مانند)
#
# پنل یک پروژه‌ی مستقل است: همین پوشه‌ی panel/ را تنهایی هم بردارید،
# «bash install.sh» پنل را نصب می‌کند و چون سورس هسته پیدا نمی‌شود،
# هسته را رد می‌کند (با پیام روشن). هسته فقط وقتی build می‌شود که
# Makefile و src/main.c کنار پنل باشند، یا --with-core / --src= بدهید.
#
# گزینه‌ها:
#   --no-core              فقط پنل؛ هرگز سراغ هسته نرو
#   --with-core            هسته لازم است؛ نبودنِ سورس = خطا (پیش‌فرض: خودکار)
#   --core-only            فقط هسته؛ پنل نصب نمی‌شود (venv لازم نیست — gen.py
#                          و register.py فقط stdlib می‌خواهند)
#   --fastpath             build با FASTPATH=1 (XDP/AF_XDP؛ شکست بخورد به پورتابل برمی‌گردد)
#   --role=<server|client> نقش نود محلی (پیش‌فرض server)
#   --instance=<name>      نام instance هسته (پیش‌فرض همان role)
#   --api-bind=<ip:port>   api.bind کانفیگ محلی (پیش‌فرض 127.0.0.1:9090 / 9091 برای client)
#   --src=<dir>            مسیر ریپوی هسته (پیش‌فرض پوشه‌ی والد panel/)
#   --start-node           پس از نصب سرویس هسته روشن شود (پیش‌فرض خاموش)
#   --restart-node         در --update هم سرویس هسته restart شود
#   --allow-update         از پنل اجازه‌ی «git pull + install.sh --update» بده
#   --prefix/--user/--host/--port/--no-enable   (مخصوص پنل، مثل قبل)
#   --purge-binary         در --uninstall باینری هسته را هم حذف کن
#
# مراحل:
#   ۱) فقط بسته‌های نبودنی از مدیر بسته (python3-venv برای پنل، gcc/make/libcap
#      برای هسته). دست‌ی به PHP/MySQL/nginx/دامنه/کاربر دیتابیس نمی‌زند.
#   ۲) build با Makefile خود ریپو → /usr/local/bin/injspoof + setcap (CAP_NET_RAW،
#      با --fastpath اضافه‌ی CAP_BPF و CAP_NET_ADMIN). فقط در حالت هسته‌دار.
#   ۳) /etc/injspoof/<instance>.json اگر نیست ساخته می‌شود: کانفیگ استارتر
#      قابل‌لود از example/ (یا seed/ پنل) با api.token تصادفی و
#      اینترفیس/MAC gateway ماشین.
#   ۴) واحدهای systemd: injspoof@<instance> (هسته)،
#      injspoof-firewall@<instance> (بستن RST/ICMP کرنل)، injspoof-panel (پنل).
#   ۵) /usr/local/libexec/injspoof-nodectl + /etc/sudoers.d/injspoof-panel تا پنل
#      با همان کاربر بی‌اختیارش بتواند هسته را کنترل کند (start/stop/restart،
#      نوشتن کانفیگ، اعمال فایروال، خواندن لاگ).
#   ۶) نود محلی در panel.db ثبت می‌شود تا در داشبورد دیده شود.
#
# دو نکته‌ای که ساختار از آن‌ها آمده:
#   * PUT /api/v1/config هسته فقط وقتی کار می‌کند که هسته بالا باشد؛ برای نخستین
#     راه‌اندازی پنل کانفیگ را از راه nodectl config-write روی دیسک می‌نویسد و
#     سرویس را restart می‌کند.
#   * واحد هسته عمداً NoNewPrivileges ندارد: آن گزینه file-capability را بی‌اثر
#     می‌کند و setcap روی باینری بی‌فایده می‌شود.
# ====================================================================

set -euo pipefail

# ---------------------------------------------------------------- defaults
PREFIX=/opt/injspoof-panel
STATEDIR=/var/lib/injspoof-panel
ETCDIR=/etc/injspoof-panel
ENVFILE=$ETCDIR/panel.env
UNIT=/etc/systemd/system/injspoof-panel.service
SERVICE_USER=injspoof-panel
HOST=127.0.0.1
PORT=8088
MODE=install
ENABLE=1

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${INJSPOOF_SRC:-$(cd "$SRC/.." && pwd)}"

CORE=1
CORE_FORCED=0
ONLY_CORE=0
FASTPATH=0
ROLE=server
INSTANCE=""
API_BIND=""
START_NODE=0
RESTART_NODE=0
ALLOW_UPDATE=0
PURGE_BIN=0

CORE_PREFIX=/usr/local
CORE_BIN=$CORE_PREFIX/bin/injspoof
CORE_ETC=/etc/injspoof
CORE_STATE=/var/lib/injspoof
CORE_LOG=/var/log/injspoof
NODE_UNIT=/etc/systemd/system/injspoof@.service
FW_UNIT=/etc/systemd/system/injspoof-firewall@.service
NODECTL=/usr/local/libexec/injspoof-nodectl
SUDOERS=/etc/sudoers.d/injspoof-panel

CFG=""
NODE_TOKEN=""
CORE_VERSION=unknown

# ---------------------------------------------------------------- argparse
for arg in "$@"; do
  case "$arg" in
    --update)        MODE=update ;;
    --uninstall)     MODE=uninstall ;;
    --no-core)       CORE=0 ;;
    --with-core)     CORE=1; CORE_FORCED=1 ;;
    --core-only)     ONLY_CORE=1; CORE_FORCED=1 ;;
    --fastpath)      FASTPATH=1 ;;
    --role=*)        ROLE="${arg#*=}" ;;
    --instance=*)    INSTANCE="${arg#*=}" ;;
    --api-bind=*)    API_BIND="${arg#*=}" ;;
    --src=*)         REPO="${arg#*=}" ;;
    --prefix=*)      PREFIX="${arg#*=}" ;;
    --user=*)        SERVICE_USER="${arg#*=}" ;;
    --host=*)        HOST="${arg#*=}" ;;
    --port=*)        PORT="${arg#*=}" ;;
    --no-enable)     ENABLE=0 ;;
    --start-node)    START_NODE=1 ;;
    --restart-node)  RESTART_NODE=1 ;;
    --allow-update)  ALLOW_UPDATE=1 ;;
    --purge-binary)  PURGE_BIN=1 ;;
    -h|--help)       sed -n '2,/^# =\{10,\}/p' "$0"; exit 0 ;;
    *) echo "گزینه‌ی ناشناخته: $arg" >&2; exit 2 ;;
  esac
done

[[ $ONLY_CORE -eq 1 ]] && CORE=1
[[ -z "$INSTANCE" ]] && INSTANCE="$ROLE"
[[ -z "$API_BIND" ]] && {
  if [[ "$ROLE" == client ]]; then API_BIND=127.0.0.1:9091; else API_BIND=127.0.0.1:9090; fi
}
CFG=$CORE_ETC/$INSTANCE.json

log()  { printf '\033[1;36m[injspoof]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[injspoof!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[injspoof x]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "با sudo اجرا کنید: sudo bash $SRC/install.sh"
[[ -f "$SRC/app.py" ]] || die "app.py کنار این اسکریپت پیدا نشد؛ پوشه‌ی panel جابه‌جا شده؟"

is_linux() { [[ "$(uname -s)" == "Linux" ]]; }
have() { command -v "$1" >/dev/null 2>&1; }
jobs_n() { nproc 2>/dev/null || echo 2; }

# هر کاری که دیتابیس پنل را می‌نویسد با کاربر سرویس اجرا می‌شود: اگر root بنویسد،
# فایل‌های -journal/-wal ریشه‌پای می‌مانند و پنل بعداً روی همان db قفل می‌کند.
as_panel_user() {
  if have runuser; then runuser -u "$SERVICE_USER" -- "$@"
  elif have sudo; then sudo -u "$SERVICE_USER" "$@"
  else "$@"; fi
}

# پایتونِ gen.py و register.py: اگر venv پنل موجود باشد همان، وگرنه python3 سیستم.
# هر دو اسکریپت فقط stdlib می‌خواهند، پس --core-only روی ماشینِ بدون پنل هم کار می‌کند.
py_tool() {
  if [[ -x "$PREFIX/.venv/bin/python" ]]; then
    echo "$PREFIX/.venv/bin/python"
  elif have python3; then
    echo python3
  else
    echo ""
  fi
}

# ---------------------------------------------------------------- هسته اختیاری است
core_has_src() { [[ -f "$REPO/Makefile" && -f "$REPO/src/main.c" ]]; }

resolve_core() {
  [[ $CORE -eq 1 ]] || return 0
  if core_has_src; then return 0; fi
  if [[ $CORE_FORCED -eq 1 ]]; then
    die "سورس هسته در $REPO نیست (Makefile و src/main.c لازم‌اند). یا ریپوی injspoof را آنجا بگذارید، یا --src=/path بدهید، یا --no-core بزنید."
  fi
  warn "سورس هسته در $REPO پیدا نشد؛ پنل به‌عنوان پروژه‌ی مستقل نصب می‌شود و هسته build نمی‌شود."
  log "برای افزودن هسته بعداً: git clone https://github.com/alisystemit/system-spoof.git /opt/injspoof-src && sudo bash /opt/injspoof-src/panel/install.sh --with-core"
  CORE=0
}

# ---------------------------------------------------------------- pkg helper
# فقط بسته‌هایی را می‌گیرد که نیستند؛ سه سبک مدیر بسته (apt/dnf/pacman).
pkg_install() {
  if have apt-get; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    # shellcheck disable=SC2086
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $1
  elif have dnf; then
    # shellcheck disable=SC2086
    dnf install -y $2
  elif have pacman; then
    # shellcheck disable=SC2086
    pacman -Sy --noconfirm $3
  else
    return 1
  fi
}

# ====================================================================
#  uninstall
# ====================================================================
do_uninstall() {
  have systemctl || die "systemctl نیست"
  if [[ -r $CORE_ETC/instances.cfg ]]; then
    while read -r i; do
      [[ -n "$i" ]] || continue
      systemctl disable --now "injspoof@$i" >/dev/null 2>&1 || true
      systemctl disable --now "injspoof-firewall@$i" >/dev/null 2>&1 || true
    done < "$CORE_ETC/instances.cfg"
  fi
  systemctl disable --now injspoof-panel >/dev/null 2>&1 || true
  rm -f "$UNIT" "$NODE_UNIT" "$FW_UNIT" "$NODECTL" "$SUDOERS"
  [[ $PURGE_BIN -eq 1 ]] && rm -f "$CORE_BIN"
  systemctl daemon-reload
  cat <<DONE
سرویس‌ها و کد حذف شد.
  باینری هسته   : $CORE_BIN   $([[ $PURGE_BIN -eq 1 ]] && echo "(حذف شد)" || echo "(مانده)")
  کانفیگ هسته   : $CORE_ETC/  (نگه داشته شد — api.token اینجاست)
  دیتابیس پنل   : $STATEDIR/panel.db  (نگه داشته شد)
DONE
  exit 0
}
[[ $MODE == uninstall ]] && do_uninstall

# ====================================================================
#  ۱) وابستگی‌ها
# ====================================================================
resolve_core
if ! python3 -c 'import venv, ensurepip' >/dev/null 2>&1; then
  if have python3; then
    warn "python3 هست ولی venv/ensurepip ندارد؛ همان بسته را نو می‌کنیم."
  fi
  log "نصب python3 و venv"
  pkg_install "python3 python3-venv python3-pip" "python3 python3-pip" "python" \
    || die "مدیر بسته‌ی شناخته‌شده‌ای نیست؛ python3 (3.8+) را نصب کنید و دوباره اجرا کنید."
fi
have python3 || die "python3 پیدا نشد"
PYVER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' \
  || die "پنل به python 3.8+ نیاز دارد (نسخه‌ی شما: $PYVER)"
log "python $PYVER"

if [[ $CORE -eq 1 ]] && is_linux; then
  if ! have gcc || ! have make; then
    log "نصب toolchain (gcc, make, libcap, pkg-config)"
    pkg_install "build-essential libcap2-bin pkg-config" \
                "gcc make libcap pkgconf-pkg-config" \
                "base-devel libcap" \
      || warn "بسته‌ها نصب نشد؛ اگر gcc و make موجودند اشکالی ندارد."
  fi
  if [[ $FASTPATH -eq 1 ]]; then
    log "نصب وابستگی fastpath (clang/llvm/libbpf/libxdp)"
    pkg_install "clang llvm libbpf-dev libxdp-dev libelf-dev zlib1g-dev libzstd-dev" \
                "clang llvm libbpf-devel libxdp-devel elfutils-libelf-devel zlib-devel libzstd-devel" \
                "clang llvm libbpf libxdp libelf zstd" \
      || warn "fastpath deps نصب نشد؛ اگر build شکست بخورد نسخه‌ی پورتابل ساخته می‌شود."
  fi
fi

# ====================================================================
#  ۲) پنل
# ====================================================================
# کاربر بی‌اختیار سرویس: پنل با آن اجرا می‌شود و گروه کانفیگ هسته و helper است.
# --core-only هم به آن نیاز دارد (chown و sudoers)، پس مستقل از نصب پنل ساخته می‌شود.
ensure_service_user() {
  if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    log "ساخت کاربر سیستمی $SERVICE_USER"
    useradd --system --home-dir "$PREFIX" --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null ||
      useradd --system --home-dir "$PREFIX" --shell /sbin/nologin "$SERVICE_USER" ||
      die "ساخت کاربر $SERVICE_USER نشد؛ با --user= یک کاربر موجود بدهید"
  fi
  install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATEDIR"
}

install_panel_code() {
  install -d -m 0755 "$PREFIX" "$STATEDIR" "$ETCDIR"
  log "کپی کد پنل به $PREFIX"
  if have rsync; then
    rsync -a --delete \
      --exclude '.venv' --exclude '__pycache__' --exclude '*.pyc' \
      --exclude 'panel.db' --exclude '*.db-*' --exclude '_shots' \
      --exclude '.mock-nodectl' \
      "$SRC/" "$PREFIX/"
  else
    find "$PREFIX" -mindepth 1 -maxdepth 1 \
      ! -name '.venv' ! -name 'panel.db' -exec rm -rf {} +
    for f in app.py core.py db.py gen.py schema.py injclient.py register.py \
             mock_api.py mock_nodectl.py run.py install.sh selftest.py e2e_test.py \
             requirements.txt README.md GUIDE.md CHANGELOG.md LICENSE VERSION .gitignore; do
      if [[ -e "$SRC/$f" ]]; then cp -a "$SRC/$f" "$PREFIX/"; else warn "$f در $SRC نیست"; fi
    done
    # static/ پوشه‌ی fonts/ را هم با خودش می‌برد (Vazirmatn + JetBrains Mono، خودمیزبان)
    cp -a "$SRC/templates" "$SRC/static" "$SRC/deploy" "$SRC/seed" "$PREFIX/"
  fi

  VENV="$PREFIX/.venv"
  if [[ ! -x "$VENV/bin/python" ]]; then
    log "ساخت محیط مجازی در $VENV"
    python3 -m venv "$VENV"
  fi
  log "نصب وابستگی‌های پنل (Flask, gunicorn)"
  "$VENV/bin/python" -m pip install --quiet --upgrade pip wheel
  "$VENV/bin/python" -m pip install --quiet -r "$PREFIX/requirements.txt"

  ensure_service_user
  chown -R "$SERVICE_USER:$SERVICE_USER" "$PREFIX" "$STATEDIR"
  chmod 0750 "$STATEDIR"
}

write_panel_env() {
  local secret
  secret="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  if [[ -f "$ENVFILE" ]]; then
    log "$ENVFILE از قبل بود؛ رمزها و تنظیمات شما دست‌نخورده می‌ماند"
  else
    ( umask 077
      cat > "$ENVFILE" <<ENV
# پنل injspoof — تنظیمات زمان اجرا (systemd این فایل را می‌خواند)
PANEL_HOST=$HOST
PANEL_PORT=$PORT
PANEL_DB=$STATEDIR/panel.db
PANEL_INTERVAL=2
PANEL_TIMEOUT=4
PANEL_SECRET=$secret
# اگر بگذارید، پنل از مرورگر رمز می‌خواهد. پنل روی 127.0.0.1 است و رمز تنها
# لایه‌ی دفاعی است؛ اگر از تانل SSH بیرون می‌آورید خالی نگه ندارید.
PANEL_PASSWORD=
# کنترل هسته‌ی محلی (از راه sudoers + /usr/local/libexec/injspoof-nodectl)
INJSPOOF_NODECTL=$NODECTL
INJSPOOF_INSTANCE=$INSTANCE
ENV
    )
    log "$ENVFILE نوشته شد"
  fi
  chown "root:$SERVICE_USER" "$ENVFILE"
  chmod 0640 "$ENVFILE"
  if ! grep -q '^PANEL_SECRET=..*' "$ENVFILE"; then
    sed -i "s|^PANEL_SECRET=.*|PANEL_SECRET=$secret|" "$ENVFILE"
  fi
  # کلیدهای نسخه‌های تازه را همیشه هم‌راستا کن (بی‌دست‌زدن به بقیه)
  grep -q '^INJSPOOF_NODECTL=' "$ENVFILE" ||
    printf 'INJSPOOF_NODECTL=%s\n' "$NODECTL" >>"$ENVFILE"
  grep -q '^INJSPOOF_INSTANCE=' "$ENVFILE" ||
    printf 'INJSPOOF_INSTANCE=%s\n' "$INSTANCE" >>"$ENVFILE"
  sed -i "s|^INJSPOOF_INSTANCE=.*|INJSPOOF_INSTANCE=$INSTANCE|" "$ENVFILE"
}

write_panel_unit() {
  local tpl="$PREFIX/deploy/injspoof-panel.service"
  [[ -f "$tpl" ]] || die "قالب واحد systemd در $tpl پیدا نشد"
  log "نوشتن $UNIT"
  sed -e "s|@@PREFIX@@|$PREFIX|g" -e "s|@@VENV@@|$VENV|g" \
      -e "s|@@USER@@|$SERVICE_USER|g" -e "s|@@ENVFILE@@|$ENVFILE|g" \
      -e "s|@@STATEDIR@@|$STATEDIR|g" -e "s|@@HOST@@|$HOST|g" -e "s|@@PORT@@|$PORT|g" \
      "$tpl" > "$UNIT"
}

# ====================================================================
#  ۳) هسته
# ====================================================================
build_core() {
  [[ -f "$REPO/Makefile" && -f "$REPO/src/main.c" ]] ||
    die "ریپوی injspoof در $REPO نیست؛ با --src=path بدهید یا --no-core بزنید."
  log "build هسته از $REPO"
  CORE_VERSION="$(cd "$REPO" && git describe --tags --always --dirty 2>/dev/null || echo dev)"
  if [[ $FASTPATH -eq 1 ]]; then
    if ! make -C "$REPO" -j"$(jobs_n)" FASTPATH=1; then
      warn "build fastpath شکست؛ نسخه‌ی پورتابل (AF_PACKET) ساخته می‌شود."
      make -C "$REPO" clean >/dev/null 2>&1 || true
      FASTPATH=0
      make -C "$REPO" -j"$(jobs_n)" || die "build پورتابل هم شکست"
    fi
  else
    make -C "$REPO" -j"$(jobs_n)" || die "build شکست"
  fi
  install -d -m 0755 "$CORE_PREFIX/bin"
  install -m 0755 "$REPO/injspoof" "$CORE_BIN"
  log "هسته نصب شد: $CORE_BIN (نسخه $CORE_VERSION)"
  if have setcap; then
    if [[ $FASTPATH -eq 1 ]]; then
      setcap cap_net_raw,cap_bpf,cap_net_admin+ep "$CORE_BIN" || warn "setcap شکست"
    else
      setcap cap_net_raw+ep "$CORE_BIN" || warn "setcap شکست"
    fi
    log "capability: $(getcap "$CORE_BIN" 2>/dev/null || echo '—')"
  else
    warn "setcap نیست (بسته‌ی libcap); هسته فقط با root بالا می‌آید"
  fi
}

detect_wan() {
  DETECT_IFACE=""
  DETECT_MAC=""
  have ip || { log "iproute2 نیست؛ اینترفیس را خودتان در پنل تنظیم کنید"; return 0; }
  DETECT_IFACE="$(ip -o route show default 2>/dev/null |
                  sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)"
  local via
  via="$(ip -o route show default 2>/dev/null |
         sed -n 's/.* via \([0-9.][0-9.]*\).*/\1/p' | head -1)"
  if [[ -n "$via" ]]; then
    DETECT_MAC="$(ip neigh show "$via" 2>/dev/null |
                  sed -n 's/.*lladdr \([0-9a-fA-F:]\{17\}\).*/\1/p' | head -1)"
  fi
  log "اینترفیس: ${DETECT_IFACE:-ناشناخته}   MAC gateway: ${DETECT_MAC:-ناشناخته}"
}

write_core_files() {
  local PYT
  ensure_service_user
  PYT="$(py_tool)"
  [[ -n "$PYT" ]] || die "python3 پیدا نشد؛ برای تولید کانفیگ استارتر لازم است"
  install -d -m 0755 "$CORE_ETC" "$CORE_ETC/wrapper" "$CORE_ETC/firewall" \
                     "$CORE_ETC/history" "$CORE_STATE" "$CORE_LOG"

  # ---- کانفیگ استارتر: فقط اگر نبود ----
  if [[ ! -f "$CFG" ]]; then
    log "کانفیگ استارتر نوشته می‌شود: $CFG"
    NODE_TOKEN="$("$PYT" -c 'import secrets; print(secrets.token_hex(32))')"
    local args=(--role "$ROLE" --api-bind "$API_BIND" --token "$NODE_TOKEN" --out "$CFG")
    [[ -n "$DETECT_IFACE" ]] && args+=(--iface "$DETECT_IFACE")
    [[ -n "$DETECT_MAC" ]] && args+=(--gw-mac "$DETECT_MAC")
    "$PYT" "$SRC/gen.py" starter "${args[@]}" ||
      die "تولید کانفیگ استارتر شکست"
    log "api.token تصادفی برای این نود ساخته شد"
  else
    log "$CFG از قبل بود؛ دست نزدیم (توکن و pool شما حفظ می‌شود)"
    NODE_TOKEN="$("$PYT" - "$CFG" <<'PY' 2>/dev/null || true
import json, sys
print((json.load(open(sys.argv[1], encoding="utf-8")).get("api") or {}).get("token", ""))
PY
)"
  fi
  chown "root:$SERVICE_USER" "$CFG"
  chmod 0640 "$CFG"

  # ---- EnvironmentFile + wrapper ----
  printf '# نوشته‌شده توسط install.sh\nINJSPOOF_CONFIG=%s\nINJSPOOF_MODE=%s\n' \
    "$CFG" "$ROLE" > "$CORE_ETC/$INSTANCE.conf"
  chmod 0644 "$CORE_ETC/$INSTANCE.conf"
  cat > "$CORE_ETC/wrapper/$INSTANCE.sh" <<WRAP
#!/bin/sh
# injspoof instance: $INSTANCE  (role: $ROLE) — نوشته‌شده توسط install.sh
exec $CORE_BIN --mode "\${INJSPOOF_MODE:-$ROLE}" --config "\${INJSPOOF_CONFIG:-$CFG}"
WRAP
  chmod 0755 "$CORE_ETC/wrapper/$INSTANCE.sh"

  # ---- فهرست instanceها: منبع حقیقت injspoof-nodectl ----
  touch "$CORE_ETC/instances.cfg"
  grep -qx "$INSTANCE" "$CORE_ETC/instances.cfg" || echo "$INSTANCE" >>"$CORE_ETC/instances.cfg"

  printf 'version=%s\nfastpath=%s\nbinary=%s\nconfig=%s\nrole=%s\ninstance=%s\nbuilt_at=%s\n' \
    "$CORE_VERSION" "$FASTPATH" "$CORE_BIN" "$CFG" "$ROLE" "$INSTANCE" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$CORE_ETC/build-info"
  chmod 0644 "$CORE_ETC/build-info"

  # ---- قواعد بستن پاسخ کرنل، از همان کانفیگ ----
  if "$PYT" "$SRC/gen.py" firewall --config "$CFG" --role "$ROLE" \
        --instance "$INSTANCE" --out "$CORE_ETC/firewall/$INSTANCE.nft.sh" 2>/dev/null; then
    chmod 0644 "$CORE_ETC/firewall/$INSTANCE.nft.sh"
    log "اسکریپت فایروال: $CORE_ETC/firewall/$INSTANCE.nft.sh"
  else
    warn "تولید اسکریپت فایروال از این کانفیگ نشد؛ بعداً از پنل بگیرید"
  fi

  # ---- واحدهای systemd هسته + مستندات ----
  install -m 0644 "$SRC/deploy/injspoof@.service" "$NODE_UNIT"
  install -m 0644 "$SRC/deploy/injspoof-firewall@.service" "$FW_UNIT"
  install -d -m 0755 /usr/local/share/doc/injspoof
  for d in README.md docs/OPERATIONS.md docs/CONFIGURATION.md docs/PROTOCOL.md \
           docs/ARCHITECTURE.md docs/PERFORMANCE.md; do
    [[ -f "$REPO/$d" ]] && install -D -m 0644 "$REPO/$d" "/usr/local/share/doc/injspoof/$d"
  done

  # ---- اجازه‌ی update از پنل (فقط با --allow-update) ----
  if [[ $ALLOW_UPDATE -eq 1 ]]; then
    : > "$CORE_ETC/allow-update"
    chmod 0644 "$CORE_ETC/allow-update"
    log "به‌روزرسانی از پنل فعال شد ($CORE_ETC/allow-update)"
  fi

  # ---- helper ریشه‌پای پنل + sudoers ----
  install -d -m 0755 /usr/local/libexec
  install -m 0750 -g "$SERVICE_USER" "$SRC/deploy/injspoof-nodectl" "$NODECTL"
  cat > "$SUDOERS.tmp" <<SUDO
# پنل injspoof با کاربر بی‌اختیارش فقط همین helper را root اجرا می‌کند.
# helper نام واحد را از پنل نمی‌گیرد: واحد همیشه injspoof@<instance> است و
# instance باید در $CORE_ETC/instances.cfg ثبت شده باشد.
$SERVICE_USER ALL=(root) NOPASSWD: $NODECTL
SUDO
  mv "$SUDOERS.tmp" "$SUDOERS"
  chmod 0440 "$SUDOERS"
  chown root:root "$SUDOERS"
  if have visudo; then
    visudo -cf "$SUDOERS" || die "فایل sudoers نامعتبر است"
  else
    warn "visudo نیست؛ $SUDOERS را بدون بررسی گذاشتیم"
  fi

  # ---- state برای helper ----
  install -d -m 0755 "$ETCDIR"
  printf '# نوشته‌شده توسط install.sh\nPREFIX=%s\nSRC_DIR=%s\nSERVICE_USER=%s\n' \
    "$PREFIX" "$REPO" "$SERVICE_USER" > "$ETCDIR/state.conf"
  chmod 0644 "$ETCDIR/state.conf"
}

# ====================================================================
#  ۴) اجرا
# ====================================================================
VENV="$PREFIX/.venv"

if [[ $ONLY_CORE -eq 0 ]]; then
  install_panel_code
  write_panel_env
  write_panel_unit
else
  [[ -x "$VENV/bin/python" ]] ||
    warn "با --core-only محیط مجازی پنل نیست ($VENV)؛ هسته نصب می‌شود، پنل نه."
fi

DETECT_IFACE=""
DETECT_MAC=""
if [[ $CORE -eq 1 ]]; then
  if is_linux; then
    build_core
    detect_wan
    write_core_files
  else
    warn "این ماشین Linux نیست؛ build و واحد systemd هسته بی‌معناست. فقط پنل نصب شد."
    CORE=0
  fi
fi

have systemctl || die "systemctl نیست؛ واحدها نوشته شدند ولی باید خودتان اجرا کنید"
systemctl daemon-reload

if [[ $ENABLE -eq 1 && $ONLY_CORE -eq 0 ]]; then
  systemctl enable injspoof-panel >/dev/null 2>&1 || true
  systemctl restart injspoof-panel
fi

if [[ $CORE -eq 1 && $ENABLE -eq 1 ]]; then
  systemctl enable "injspoof-firewall@$INSTANCE" >/dev/null 2>&1 || true
  systemctl enable "injspoof@$INSTANCE" >/dev/null 2>&1 || true
  if [[ $START_NODE -eq 1 ]] || [[ $MODE == update && $RESTART_NODE -eq 1 ]]; then
    log "روشن کردن هسته: injspoof@$INSTANCE"
    systemctl restart "injspoof-firewall@$INSTANCE" || warn "اعمال قواعد فایروال شکست"
    systemctl restart "injspoof@$INSTANCE" ||
      warn "سرویس هسته بالا نیامد؛ لاگ: journalctl -u injspoof@$INSTANCE -n 50"
  else
    log "هسته نصب شد ولی عمداً روشن نشد (روشن کردن با --start-node یا صفحه‌ی «هسته»)"
  fi
fi

# ---- ثبت نود محلی در دیتابیس پنل ----
if [[ $CORE -eq 1 && -n "$NODE_TOKEN" ]]; then
  REG_PY="$(py_tool)"
  reg_args=("$SRC/register.py" --db "$STATEDIR/panel.db" local
            --name "local-$INSTANCE" --role "$ROLE"
            --api-url "http://$API_BIND" --token "$NODE_TOKEN"
            --config-path "$CFG" --instance "$INSTANCE")
  registered=0
  if [[ -n "$REG_PY" ]]; then
    # ترجیحاً با کاربر سرویس تا فایل‌های db متعلق به او بماند؛ اگر ریپو برای آن
    # کاربر خواندنی نبود (مثلاً زیر /root)، همان دستور را root اجرا و chown می‌کنیم.
    as_panel_user "$REG_PY" "${reg_args[@]}" && registered=1
    if [[ $registered -eq 0 ]]; then
      warn "ثبت نود با کاربر $SERVICE_USER نشد؛ با root امتحان می‌کنیم."
      "$REG_PY" "${reg_args[@]}" && registered=1
    fi
  fi
  if [[ $registered -eq 1 ]]; then
    log "نود محلی «local-$INSTANCE» در پنل ثبت شد"
  else
    warn "ثبت نود محلی نشد؛ از صفحه‌ی «نودها» دستی ثبت کنید"
  fi
  chown -R "$SERVICE_USER:$SERVICE_USER" "$STATEDIR" 2>/dev/null || true
fi

# ---- دودسنجی ----
if [[ $ONLY_CORE -eq 0 ]] && have curl; then
  ok=0
  for _ in 1 2 3 4 5 6 7 8; do
    if curl -fsS -m 3 "http://$HOST:$PORT/static/style.css" >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
  done
  if [[ $ok -eq 1 ]]; then
    log "پنل روی http://$HOST:$PORT پاسخ می‌دهد"
    if curl -fsS -m 3 "http://$HOST:$PORT/static/fonts/Vazirmatn-Regular.woff2" >/dev/null 2>&1; then
      log "فونت خودمیزبان (Vazirmatn) هم سرو می‌شود"
    else
      warn "فایل فونت سرو نشد؛ پوشه‌ی static/fonts به $PREFIX نرسیده؟"
    fi
  else
    warn "پنل پاسخ نداد. لاگ: journalctl -u injspoof-panel -n 50"
  fi
fi

if [[ $CORE -eq 1 && $START_NODE -eq 1 ]] && have curl; then
  if curl -fsS -m 3 -H "Authorization: Bearer $NODE_TOKEN" \
        "http://$API_BIND/api/v1/health" >/dev/null 2>&1; then
    log "API هسته روی http://$API_BIND پاسخ می‌دهد"
  else
    warn "API هسته پاسخ نداد؛ صفحه‌ی «هسته» و journalctl -u injspoof@$INSTANCE را ببینید"
  fi
fi

cat <<DONE

$( [[ $MODE == update ]] && echo "── به‌روزرسانی انجام شد ──" || echo "── نصب انجام شد ──" )

  پنل            : $PREFIX            (سرویس injspoof-panel)
  نسخه‌ی پنل     : $(cat "$SRC/VERSION" 2>/dev/null || echo dev)
  دیتابیس پنل    : $STATEDIR/panel.db
  تنظیمات و رمز  : $ENVFILE
  آدرس پنل       : http://$HOST:$PORT   (فقط روی همان ماشین)
  راهنمای کامل   : $PREFIX/GUIDE.md   (همین‌طور $SRC/GUIDE.md)
DONE

if [[ $CORE -eq 1 ]]; then
  cat <<DONE
  باینری هسته    : $CORE_BIN   (نسخه $CORE_VERSION)
  کانفیگ هسته    : $CFG
  سرویس هسته     : systemctl {start|stop|restart|status} injspoof@$INSTANCE
  فایروال هسته   : systemctl status injspoof-firewall@$INSTANCE
                   $CORE_ETC/firewall/$INSTANCE.nft.sh
  کنترل از پنل   : sudo -u $SERVICE_USER $NODECTL info
DONE
else
  cat <<DONE
  هسته           : نصب نشد (پنل مستقل). نودها را از «نودها → افزودن نود»
                   با API URL و توکن یک نود راه‌دور ثبت کنید.
                   برای افزودن هسته‌ی محلی بعداً:
                     sudo bash $SRC/install.sh --with-core            # اگر سورس C کنار پنل است
                     sudo bash $SRC/install.sh --src=/opt/injspoof-src
DONE
fi

cat <<DONE

  از بیرون با تانل SSH:
      ssh -L $PORT:127.0.0.1:$PORT root@IP-سرور     →   http://127.0.0.1:$PORT

  کانفیگ واقعی (pool/peer/MAC gateway) را از «ویزارد جفت کانفیگ» بسازید و
  «اعمال روی نود» بزنید؛ اگر نود بالا نباشد پنل کانفیگ را روی دیسک می‌نویسد
  و سرویس را restart می‌کند.

  تست‌های پنل روی همین ماشین:
      cd $PREFIX && .venv/bin/python selftest.py
DONE
