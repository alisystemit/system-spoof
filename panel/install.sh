#!/usr/bin/env bash
#
# install.sh — چیدن پنل تحت وب injspoof روی سرور لینوکسی
#
#   sudo bash panel/install.sh              # نصب کامل (venv + systemd + اجرا)
#   sudo bash panel/install.sh --update     # فقط کد و venv نو، بدون دست‌زدن به
#                                           #   رمزها و دیتابیس
#
# کاری که می‌کند:
#   1) python3 و ماژول venv را (فقط اگر نبودند) از بسته‌ی توزیع نصب می‌کند
#   2) پوشه‌ی panel را به /opt/injspoof-panel می‌کپی‌کند و venv می‌سازد
#   3) کاربر سیستمی بی‌اختیار injspoof-panel می‌سازد
#   4) /etc/injspoof-panel/panel.env را با PANEL_SECRET تصادفی می‌نویسد
#      (اگر از قبل باشد، دست نمی‌زند)
#   5) واحد systemd را می‌نویسد، enable و restart می‌کند
#
# پنل فقط با API خود نود (http://127.0.0.1:<port>) حرف می‌زند؛ پس برای
# اجرای آن به root، CAP_NET_RAW یا هیچ سرویس MySQL/PHP/nginx نیازی نیست و
# این اسکریپت آن‌ها را نصب یا تغییر نمی‌دهد.
#
set -euo pipefail

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

for arg in "$@"; do
  case "$arg" in
    --update)          MODE=update ;;
    --prefix=*)        PREFIX="${arg#*=}" ;;
    --user=*)          SERVICE_USER="${arg#*=}" ;;
    --host=*)          HOST="${arg#*=}" ;;
    --port=*)          PORT="${arg#*=}" ;;
    --no-enable)       ENABLE=0 ;;
    -h|--help)         sed -n '1,30p' "$0"; exit 0 ;;
    *) echo "گزینه‌ی ناشناخته: $arg" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;36m[panel]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[panel!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[panel x]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "با sudo اجرا کنید: sudo bash $SRC/install.sh"
[[ -f "$SRC/app.py" ]] || die "app.py کنار این اسکریپت پیدا نشد؛ پوشه‌ی panel جابه‌جا شده؟"

# ---------------------------------------------------------------- python
need_python=1
if command -v python3 >/dev/null 2>&1; then
  if python3 -c 'import venv, ensurepip' >/dev/null 2>&1; then
    need_python=0
  else
    warn "python3 هست ولی ماژول venv ندارد؛ فقط همین بسته نصب می‌شود."
  fi
fi

if [[ $need_python -eq 1 ]]; then
  if command -v apt-get >/dev/null 2>&1; then
    log "نصب python3 و python3-venv با apt"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-venv python3-pip
  elif command -v dnf >/dev/null 2>&1; then
    log "نصب python3 با dnf"
    dnf install -y python3 python3-pip
  elif command -v pacman >/dev/null 2>&1; then
    log "نصب python با pacman"
    pacman -Sy --noconfirm python
  else
    die "مدیر بسته‌ی شناخته‌شده‌ای نیست. python3 (نسخه 3.8+) را نصب کنید و دوباره اجرا کنید."
  fi
fi
command -v python3 >/dev/null 2>&1 || die "python3 پیدا نشد"
PYVER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
python3 - <<'PY' || die "پنل به python 3.8+ نیاز دارد (نسخه‌ی شما: $PYVER)"
import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)
PY
log "python $PYVER"

# ---------------------------------------------------------------- کپی کد
install -d -m 0755 "$PREFIX" "$STATEDIR" "$ETCDIR"
log "کپی کد پنل به $PREFIX"
if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete \
    --exclude '.venv' --exclude '__pycache__' --exclude '*.pyc' \
    --exclude 'panel.db' --exclude '*.db-*' --exclude '_shots' \
    "$SRC/" "$PREFIX/"
else
  # rsync نیست: دستی کپی می‌کنیم تا venv و دیتابیس موجود نپَرَد.
  find "$PREFIX" -mindepth 1 -maxdepth 1 \
    ! -name '.venv' ! -name 'panel.db' -exec rm -rf {} +
  for f in app.py db.py gen.py schema.py injclient.py mock_api.py run.py \
           selftest.py e2e_test.py requirements.txt README.md install.sh \
           .gitignore; do
    if [[ -e "$SRC/$f" ]]; then
      cp -a "$SRC/$f" "$PREFIX/"
    else
      warn "$f در $SRC نیست (کپی نشد)"
    fi
  done
  cp -a "$SRC/templates" "$SRC/static" "$SRC/deploy" "$PREFIX/"
fi

# ---------------------------------------------------------------- venv
VENV="$PREFIX/.venv"
if [[ ! -x "$VENV/bin/python" ]]; then
  log "ساخت محیط مجازی در $VENV"
  python3 -m venv "$VENV"
fi
log "نصب وابستگی‌ها (Flask, gunicorn)"
"$VENV/bin/python" -m pip install --quiet --upgrade pip wheel
"$VENV/bin/python" -m pip install --quiet -r "$PREFIX/requirements.txt"

# ---------------------------------------------------------------- کاربر
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  log "ساخت کاربر سیستمی $SERVICE_USER"
  useradd --system --home-dir "$PREFIX" --shell /usr/sbin/nologin "$SERVICE_USER" || \
    useradd --system --home-dir "$PREFIX" --shell /sbin/nologin "$SERVICE_USER"
fi
chown -R "$SERVICE_USER:$SERVICE_USER" "$PREFIX" "$STATEDIR"
chmod 0750 "$STATEDIR"

# ---------------------------------------------------------------- env file
SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
if [[ -f "$ENVFILE" ]]; then
  log "$ENVFILE از قبل بود؛ نگه داشته شد (رمزها و تنظیمات شما دست‌نخورده می‌ماند)"
else
  umask 077
  cat > "$ENVFILE" <<ENV
# پنل injspoof — تنظیمات زمان اجرا (systemd این فایل را می‌خواند)
PANEL_HOST=$HOST
PANEL_PORT=$PORT
PANEL_DB=$STATEDIR/panel.db
PANEL_INTERVAL=2
PANEL_TIMEOUT=4
# کلید session کوکی؛ با install.sh تصادفی ساخته شد.
PANEL_SECRET=$SECRET
# اگر بگذارید، پنل از مرورگر رمز می‌خواهد. پنل روی 127.0.0.1 است و
# رمز تنها لایه‌ی دفاعی است؛ پس اگر از تانل SSH بیرون می‌آورید، خالی نگه ندارید.
PANEL_PASSWORD=
ENV
  umask 022
  log "$ENVFILE نوشته شد"
fi
chown "root:$SERVICE_USER" "$ENVFILE"
chmod 0640 "$ENVFILE"

# اگر کاربر PANEL_PASSWORD را پر کرده ولی PANEL_SECRET خالی است، پر شود
grep -q '^PANEL_SECRET=..*' "$ENVFILE" || \
  sed -i "s|^PANEL_SECRET=.*|PANEL_SECRET=$SECRET|" "$ENVFILE"

# ---------------------------------------------------------------- systemd
TPL="$PREFIX/deploy/injspoof-panel.service"
[[ -f "$TPL" ]] || die "قالب واحد systemd در $TPL پیدا نشد"
log "نوشتن $UNIT"
sed -e "s|@@PREFIX@@|$PREFIX|g" \
    -e "s|@@VENV@@|$VENV|g" \
    -e "s|@@USER@@|$SERVICE_USER|g" \
    -e "s|@@ENVFILE@@|$ENVFILE|g" \
    -e "s|@@STATEDIR@@|$STATEDIR|g" \
    -e "s|@@HOST@@|$HOST|g" \
    -e "s|@@PORT@@|$PORT|g" \
    "$TPL" > "$UNIT"

command -v systemctl >/dev/null 2>&1 || die "systemctl نیست؛ واحد سرویس نوشته شد ولی باید خودتان gunicorn را اجرا کنید"
systemctl daemon-reload
if [[ $ENABLE -eq 1 ]]; then
  systemctl enable injspoof-panel >/dev/null 2>&1 || true
  systemctl restart injspoof-panel
fi

# ---------------------------------------------------------------- دودسنجی
if command -v curl >/dev/null 2>&1; then
  ok=0
  for _ in 1 2 3 4 5 6 7 8; do
    if curl -fsS -m 3 "http://$HOST:$PORT/static/style.css" >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
  done
  if [[ $ok -eq 1 ]]; then
    log "پنل روی http://$HOST:$PORT پاسخ می‌دهد"
  else
    warn "پنل پاسخ نداد. لاگ: journalctl -u injspoof-panel -n 50"
  fi
fi

cat <<DONE

$( [[ $MODE == update ]] && echo "── به‌روزرسانی انجام شد ──" || echo "── نصب انجام شد ──" )

  کد پنل        : $PREFIX
  دیتابیس       : $STATEDIR/panel.db   (جدول‌ها خودکار ساخته می‌شوند)
  تنظیمات/رمز   : $ENVFILE
  سرویس         : systemctl {status|restart|journal} injspoof-panel
  آدرس          : http://$HOST:$PORT  (فقط روی همان ماشین)

  از بیرون با تانل SSH وصل شوید:
      ssh -L 8088:127.0.0.1:8088 root@IP-سرور
      بعد در مرورگر: http://127.0.0.1:8088

  تست‌های پنل (روی همین ماشین، بدون نیاز به نود):
      cd $PREFIX && .venv/bin/python selftest.py
DONE
