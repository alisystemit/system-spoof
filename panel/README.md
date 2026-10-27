# پنل تحت وب injspoof

پنل مدیریتی فارسی (RTL، تم روشن) برای تونل لایه‌دو **injspoof**. کنار خودِ نود
اجرا می‌شود و با همان `http://127.0.0.1:<port>` API حرف می‌زند؛ یعنی چیزی به
ساختار injspoof اضافه نمی‌کند و برای اجرا به root یا CAP_NET_RAW نیاز ندارد.

سه کار اصلی:

1. **داشبورد مانیتورینگ زنده** — نمودار بسته/بایت در ثانیه و dropها از
   `/api/v1/stats`، شکست خطاهای `send` بر اساس errno، وضعیت استخر IP مبدأ،
   شمارنده‌های syscall و reload.
2. **ویرایشگر کانفیگ** — خواندن کانفیگ زنده از نود، ویرایش درختی یا خام،
   اعتبارسنجی با همان قواعدی که لودر C رد می‌کند، اعمال با hot/hard reload و
   تاریخچه‌ی کامل با rollback.
3. **ویزارد جفت کانفیگ** — تولید هم‌زمان `client.json` و `server.json`
   هم‌راستا به‌علاوه اسکریپت nftables (و نسخه‌ی iptables) برای بستن RSTهای
   kernel.

---

## نصب روی سرور لینوکسی

فرض: مخزن را روی سرور دارید (همان که injspoof را از آن build کرده‌اید).

```bash
git clone https://github.com/x1cen/injspoof /opt/injspoof-src
```

```bash
cd /opt/injspoof-src && sudo bash panel/install.sh
```

اسکریپت این کارها را می‌کند:

* فقط اگر نبودند، `python3` و `python3-venv` را از مدیر بسته‌ی توزیع نصب می‌کند
  (apt / dnf / pacman). هیچ دست‌ی به PHP، MySQL، nginx، دامنه یا نام کاربری
  دیتابیس نمی‌زند.
* کد `panel/` را به `/opt/injspoof-panel` کپی و محیط مجازی `.venv` را می‌سازد.
* کاربر سیستمی بی‌اختیار `injspoof-panel` را می‌سازد و سرویس را با آن اجرا می‌کند.
* `/etc/injspoof-panel/panel.env` را با `PANEL_SECRET` تصادفی می‌نویسد
  (اگر از قبل باشد، دست نمی‌زند).
* واحد systemd `injspoof-panel.service` را نصب، enable و restart می‌کند و در
  پایان با یک درخواست HTTP سلامت آن را چک می‌کند.

مسیرها:

| چیز | مسیر |
| --- | --- |
| کد پنل | `/opt/injspoof-panel` |
| دیتابیس پنل (نودها، تاریخچه، pairها) | `/var/lib/injspoof-panel/panel.db` |
| تنظیمات و رمز | `/etc/injspoof-panel/panel.env` |
| سرویس | `systemctl status injspoof-panel` |
| لاگ | `journalctl -u injspoof-panel -f` |

پنل پیش‌فرض فقط روی `127.0.0.1:8088` می‌نشیند. برای دیدنش از بیرون، تانل SSH
بزنید (نه باز کردن پورت):

```bash
ssh -L 8088:127.0.0.1:8088 root@IP-سرور
```

بعد در مرورگر خودتان: `http://127.0.0.1:8088`

گزینه‌های `install.sh`: `--port=`، `--host=`، `--prefix=`، `--user=`،
`--no-enable` (فقط چیدن، بدون start).

## به‌روزرسانی

```bash
cd /opt/injspoof-src && git pull && sudo bash panel/install.sh --update
```

`.venv`، `panel.db` و `panel.env` (پس رمزها و نودهای ثبت‌شده) حفظ می‌شوند؛ فقط
کد و وابستگی‌ها نو و سرویس restart می‌شود.

## اجرای دستی (توسعه)

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
PANEL_PORT=8088 .venv/bin/python run.py
```

اجرای پروداکشن بدون systemd، همان چیزی که واحد سرویس صدا می‌زند:

```bash
/opt/injspoof-panel/.venv/bin/gunicorn --bind 127.0.0.1:8088 \
  --worker-class gthread --workers 1 --threads 8 --timeout 60 \
  --chdir /opt/injspoof-panel app:APP
```

> `--workers 1` عمدی است: نخ نمونه‌بردار داخل هر worker اجرا می‌شود، پس با دو
> worker هر نود دو بار در هر بازه نمونه‌برداری می‌شود.

## تست

* `python selftest.py` — 25 بررسی بدون شبکه؛ منطق اعتبارسنج، ویزارد، لینتر
  هم‌راستایی و تولید اسکریپت فایروال را می‌سنجد.
* `python mock_api.py --mode server --port 9090 --token devtoken --load-example`
  یک API injspoof جعلی کامل می‌دهد (هر 8 endpoint + احراز Bearer) تا پنل روی
  ماشین بدون Linux هم قابل آزمایش باشد.
* `python e2e_test.py` — 32 بررسی سرتاسری؛ با پنل و دو mock بالا، مسیرهای
  نوشتنی واقعی را می‌زند: اعمال کانفیگ، hot reload، گیت اعتبارسنجی، rollback از
  تاریخچه، push ویزارد و بررسی هم‌راستایی روی داده‌ی زنده.

```bash
python panel/mock_api.py --mode server --port 9090 --token devtoken --load-example &
python panel/mock_api.py --mode client --port 9091 --token devtoken --load-example &
python panel/run.py &
python panel/e2e_test.py
```

## صفحه‌ها

* **داشبورد زنده** — انتخاب نود، KPIها، سه نمودار (pps، B/s، drop)، جدول علل
  drop با نرخ لحظه‌ای، سنجه‌ی استخر IP مبدأ، syscallها، شاخص‌های لاگ/reload و
  دکمه‌های hot/hard reload.
* **نودها** — ثبت `api_url` و توکن هر نود، تست اتصال، وضعیت زنده، pps لحظه‌ای،
  ورود تاریخچه و حذف.
* **ویرایشگر کانفیگ** — «خواندن از نود»، ویرایش درختی (افزودن/حذف کلید و عنصر
  آرایه) یا خام، «اعتبارسنجی»، «اعمال روی نود» با انتخاب `hot` / `hard` /
  بدون reload، و «تاریخچه».
* **ویزارد جفت کانفیگ** — مشخصات مشترک، سمت سرور، سمت کلاینت، forwarderها؛
  پیش‌نمایش چهار فایل، ذخیره، دانلود ZIP، و اعمال روی نودهای ثبت‌شده.

## قواعدی که پنل از سورس استخراج کرده

اینها دلیل وجود پنل‌اند؛ همه با ارجاع به کد در صفحه‌ی ویرایشگر هم نوشته شده‌اند:

* فیلتر ورودی گیرنده فقط **IP مبدأ** و **پورت مبدأ** فریم دریافتی را مقایسه
  می‌کند (`src/server.c:95-111`)، پس `sender.outgoing.source` باید دقیقاً در
  `receiver.incoming.source` تکرار شود و `outgoing.port.src` فرستنده باید در
  `incoming.port.src` گیرنده باشد.
* `dst_ports` روی سیم بی‌اثر است؛ فقط `dst_ports[0]` استفاده می‌شود
  (`src/client.c:507`، `src/server.c:509`).
* با encapsulation از نوع **ICMP** هیچ پورت مبدأی روی فریم نیست، پس
  `incoming.port.src` باید حذف شود وگرنه همه‌چیز drop می‌شود
  (`src/server.c:143`).
* پورت مبدأ/مقصدِ حذف‌شده در `outgoing` هنگام بوت تصادفی انتخاب می‌شود
  (`src/config.c:458-468`)؛ سمت مقابل نمی‌تواند فیلتر دقیقی داشته باشد.
* `api.token` پیش‌فرض `CHANGE_ME…` را لودر می‌پذیرد، ولی یعنی کلید API روی همه
  نودها یکی و قابل‌حدس است؛ پنل آن را **هشدار** می‌دهد (نه خطا، تا اعمال را
  بلوکه نکند).
* سقف‌ها (`MAX_PEERS=4096`، `MAX_FIREWALL_RULES=32`، `MAX_SOURCE_PORTS=64`،
  `MAX_SOURCE_BLOCKS=4096`، `HID_LEN=5`) قبل از ارسال به نود سنجیده می‌شوند.
* `PUT /api/v1/config` کل فایل را جایگزین می‌کند، پس پنل **همیشه** قبل از ارسال،
  نسخه‌ی فعلی نود را در تاریخچه می‌گذارد.
* hot reload مقدار `api.token` را هم اعمال می‌کند؛ اگر عوضش کنید پنل با توکن
  قدیمی قفل می‌شود، پس پیام هشدار می‌گیرید.

## امنیت

* پنل را روی `0.0.0.0` باز نکنید. `PANEL_HOST` پیش‌فرض `127.0.0.1` است و
  دسترسی بیرونی فقط با تانل SSH یا یک reverse proxy با احراز هویت منطقی است.
* برای هر نود یک `api.token` بلند و تصادفی بگذارید:
  `openssl rand -hex 32`.
* اگر API نود روی `0.0.0.0` bind شده، هر کسی که به آن پورت برسد می‌تواند
  `PUT /api/v1/config` و `POST /api/v1/reload` بزند. صفحه‌ی «نودها» این حالت را
  یادآوری می‌کند.
* توکن‌ها هیچ‌وقت به مرورگر نمی‌روند: همه‌ی تماس‌ها با نود از سمت پایتون (پروکسی
  داخلی `/api/*`) انجام می‌شود.
* اگر پنل را بیرون از ماشین نود اجرا می‌کنید، `PANEL_PASSWORD` را حتماً پر کنید
  و ترجیحاً بین دو ماشین TLS بگذارید.
* `panel.db` شامل آدرس و **توکن** نودهاست؛ مجوز `0750` روی
  `/var/lib/injspoof-panel` و `0640` روی `panel.env` گذاشته می‌شود.

## ساختار فایل‌ها

```
panel/
  app.py              Flask + روت‌ها + نخ نمونه‌بردار
  db.py               SQLite (nodes / pairs / config_history / settings)
  schema.py           اعتبارسنج + لینتر هم‌راستایی جفت (منطبق بر src/server.c)
  gen.py              تولید جفت کانفیگ + اسکریپت nftables/iptables
  injclient.py        کلاینت API نود (health/info/stats/PUT/reload)
  mock_api.py         API جعلی injspoof برای تست روی هر سیستم‌عامل
  run.py              اجرای توسعه
  selftest.py         25 بررسی منطقی بدون شبکه
  e2e_test.py         32 بررسی سرتاسری روی HTTP
  install.sh          چیدن روی لینوکس (venv + systemd)
  deploy/injspoof-panel.service
  templates/ static/
```
