# راهنمای کامل پنل injspoof

این فایل **راهنمای مرحله‌به‌مرحله** است: از نصب تا روز دوم، تا عیب‌یابی.
مستند دیگر مخزن سرِ «چرا» و «چطورِ داخلی» است؛ اینجا سرِ «چکار کنم».

| اگر دنبال این هستید | برو به |
|---|---|
| پنل چیست و چطور نصبش کنم | [بخش ۲](#۲-نصب) و [بخش ۳](#۳-نخستین-ورود) |
| پنل را بدون هسته‌ی C می‌خواهم | [بخش ۲.۲](#۲۲-نصب-پنل-بدون-سورس-هسته) |
| اولین تونل server + client را بسازم | [بخش ۴](#۴-اولین-تونل-ویزارد-جفت-کانفیگ) |
| نود راه‌دور اضافه یا مانیتور کنم | [بخش ۵](#۵-ثبت-نودها) و [بخش ۶](#۶-داشبورد-زنده-و-متریکها) |
| کانفیگ را عوض و بعد پشیمان شوم | [بخش ۷](#۷-ویرایش-کانفیگ-و-بازگشت-نسخه) |
| سرویس هسته‌ی همین ماشین را کنترل کنم | [بخش ۸](#۸-صفحهی-هسته-کنترل-سرویس-محلی) |
| تونل reset می‌شود / UDP می‌میرد | [بخش ۹](#۹-فایروال-بستن-پاسخهای-کرنل) و [بخش ۱۱](#۱۱-عیبیابی) |
| بکاپ، ارتقا، حذف | [بخش ۱۰](#۱۰-عملیات-روزانه) |
| فرمان‌ها و مسیرها را یک‌جا ببینم | [بخش ۱۴](#۱۴-مرجع-سریع) |

مستند مرتبط: [README.md](README.md) (ساختار دو-بخشی پنل + هسته) و در بالای مخزن
[../README.md](../README.md) و [../docs/OPERATIONS.md](../docs/OPERATIONS.md).

---

## ۱. پیش‌نیازها

**برای پنل** (هر جایی که پایتون دارد):

* Linux با systemd برای اجرای سرویس؛ روی macOS/ویندوز هم با `run.py` بالا می‌آید (توسعه).
* Python 3.8 یا بالاتر (با `python3 -V` چک کنید).
* حدود ۶۰MB فضای دیسک برای محیط مجازی + Flask + gunicorn.
* اینترنت فقط برای `pip install` لازم است. **فونت‌ها و همه‌ی فایل‌های ثابت داخل
  خودِ پوشه‌ی `panel/` هستند**؛ پنل روی سرور آفلاین هم بدون هیچ درخواست بیرونی
  کامل رندر می‌شود (بخش ۱۳).

**برای هسته** (اگر روی همان ماشین می‌خواهیدش):

* سورس C کنار پنل: پوشه‌ی `src/` و `Makefile` یعنی ریپوی
  `https://github.com/alisystemit/system-spoof.git`.
* `gcc`، `make`، `pkg-config` و `libcap` (برای `setcap`)؛ اگر `--fastpath`
  می‌خواهید `clang`، `llvm`، `libbpf`، `libxdp` و `libelf` هم لازم است.
* دسترسی root برای نصب (build و systemd)، ولی خودِ هسته بعداً بدون root و فقط با
  `CAP_NET_RAW` اجرا می‌شود.

نصب‌کننده فقط بسته‌های **نبودنی** را از مدیر بسته می‌گیرد و دست به PHP، MySQL،
nginx، دامنه یا کاربر دیتابیس نمی‌زند.

---

## ۲. نصب

### ۲.۱ نصب کامل: هسته + پنل

روی یک سرور تازه، از صفر تا پنلِ بالاآمده، با یک دستور:

```bash
git clone https://github.com/alisystemit/system-spoof.git /opt/injspoof-src && cd /opt/injspoof-src && sudo bash panel/install.sh
```

چی می‌بینید: مراحل build هسته، ساخت venv، واحدهای systemd، کانفیگ استارتر و
در پایان خلاصه‌ای از مسیرها و آدرس `http://127.0.0.1:8088`.

> **هسته عمداً روشن نمی‌شود.** تا peer و pool واقعی تنظیم نشده‌اند، یک هسته‌ی
> روشن فقط drop تولید می‌کند. روشن‌کردن: دوباره با `--start-node`، یا از
> صفحه‌ی «هسته»، یا `systemctl start injspoof@server`.

### ۲.۲ نصب پنل بدون سورس هسته

پنل یک پروژه‌ی مستقل است. دو حالت:

**الف) فقط پنل، هسته روی ماشین‌های دیگر:**

```bash
git clone --filter=blob:none --sparse https://github.com/alisystemit/system-spoof.git /opt/injspoof-src && cd /opt/injspoof-src && git sparse-checkout set panel && sudo bash panel/install.sh --no-core
```

**ب) کپی/خارج‌کردن پوشه‌ی `panel/` هر جایی که بخواهید:**

```bash
cp -a panel /srv/injspoof-panel && cd /srv/injspoof-panel && sudo bash install.sh
```

در هر دو حالت install.sh می‌فهمد که `Makefile` و `src/main.c` کنارش نیست و
پنل‌تنها نصب می‌کند؛ `--with-core` یا `--src=/path` همان رفتار اجباریِ قبل را
برمی‌گرداند و اگر سورس نباشد با پیام روشن می‌ایستد.

چیزهایی که پنل را واقعاً مستقل می‌کنند:

| فایل/مکانیزم | نقش |
|---|---|
| `seed/server.json`، `seed/client.json` | کانفیگ نمونه‌ی داخل پنل؛ `gen.example_path()` وقتی `example/` ریپو نیست از همین‌ها می‌خواند، پس «کانفیگ استارتر» و `selftest.py` بدون ریپوی C هم کار می‌کنند. |
| `VERSION` | شماره‌ی نسخه‌ی پنل، مستقل از هسته؛ در سایدبار نشان داده می‌شود و `PANEL_VERSION` فقط override است. |
| `LICENSE`، `CHANGELOG.md`، `GUIDE.md` | مجوز (MIT + OFL فونت‌ها)، تغییرات و همین راهنما. |
| `static/fonts/` | فونت‌های خودمیزبان؛ بدون CDN. |
| `deploy/injspoof-panel.service` | واحد systemd پنل؛ هیچ وابستگی به هسته ندارد. |

در حالت پنل‌تنها، صفحه‌ی «هسته» می‌گوید هسته‌ای برای کنترل نیست — که درست
است. مدیریت نودهای راه‌دور (ثبت، کانفیگ، reload، لاگ از راه API) کامل کار می‌کند.

### ۲.۳ گزینه‌های install.sh

| گزینه | کار |
|---|---|
| `--no-core` | فقط پنل؛ سراغ هسته نمی‌رود. |
| `--with-core` | هسته اجباری؛ نبودن سورس = خطا. (پیش‌فرض: خودکار — اگر سورس بود نصبش می‌کند، نبود رد می‌کند.) |
| `--core-only` | فقط هسته؛ پنل نصب نمی‌شود (venv لازم نیست). |
| `--fastpath` | build با `FASTPATH=1` (XDP/AF_XDP)؛ شکست بخورد به نسخه‌ی پورتابل برمی‌گردد. |
| `--role=server\|client` | نقش نود محلی (پیش‌فرض server). |
| `--instance=NAME` | نام instance هسته (پیش‌فرض همان role). |
| `--api-bind=IP:PORT` | `api.bind` کانفیگ محلی (پیش‌فرض `127.0.0.1:9090`؛ برای client `9091`). |
| `--src=DIR` | مسیر ریپوی هسته (پیش‌فرض پوشه‌ی والد `panel/`). |
| `--start-node` | بعد از نصب، سرویس هسته را روشن کن. |
| `--restart-node` | در `--update` سرویس هسته را هم restart کن. |
| `--allow-update` | از پنل اجازه‌ی «git pull + install.sh --update» بده. |
| `--prefix=DIR` | محل نصب کد پنل (پیش‌فرض `/opt/injspoof-panel`). |
| `--user=NAME` | کاربر سرویس پنل (پیش‌فرض `injspoof-panel`). |
| `--host=IP` `--port=N` | محل نشستن پنل (پیش‌فرض `127.0.0.1:8088`). |
| `--no-enable` | واحد را بنویس ولی enable نکن. |
| `--update` | کد/باینری نو؛ رمز، دیتابیس و کانفیگ دست‌نخورده. |
| `--uninstall` | سرویس‌ها و کد را بردار (`--purge-binary` باینری هسته را هم). |
| `-h` / `--help` | سرِ همان اسکریپت را چاپ می‌کند: همه‌ی مراحل و گزینه‌ها. |

### ۲.۴ روی دیسک چه می‌نشیند

| چیز | مسیر |
|---|---|
| کد پنل + venv | `/opt/injspoof-panel` (با `--prefix` عوض می‌شود) |
| دیتابیس پنل | `/var/lib/injspoof-panel/panel.db` (مالک: کاربر سرویس) |
| تنظیمات و رمزها | `/etc/injspoof-panel/panel.env` (root:injspoof-panel، 0640) |
| وضعیت نصب برای helper | `/etc/injspoof-panel/state.conf` |
| واحد systemd پنل | `/etc/systemd/system/injspoof-panel.service` |
| باینری هسته | `/usr/local/bin/injspoof` + `setcap` |
| کانفیگ هسته | `/etc/injspoof/<instance>.json` (root:injspoof-panel، 0640) |
| سفیدlist instanceها | `/etc/injspoof/instances.cfg` |
| فایروال per-instance | `/etc/injspoof/firewall/<instance>.nft.sh` |
| تاریخچه‌ی کانفیگ هسته | `/etc/injspoof/history/` |
| واحدهای هسته | `injspoof@.service`، `injspoof-firewall@.service` |
| helper کنترل + sudoers | `/usr/local/libexec/injspoof-nodectl`، `/etc/sudoers.d/injspoof-panel` |

---

## ۳. نخستین ورود

### ۳.۱ از بیرون باز کردنش

پنل فقط روی `127.0.0.1` می‌نشیند و این عمدی است. راه درستِ دیدنش از لپ‌تاپ،
تانل SSH است:

```bash
ssh -L 8088:127.0.0.1:8088 root@IP-سرور
```

و بعد در مرورگر: `http://127.0.0.1:8088`.

اگر اصرار دارید مستقیم از بیرون باز شود، `--host=0.0.0.0` را بدهید — و در همین
حال `PANEL_PASSWORD` را پر کنید و پورت را فایروال کنید. این کار را توصیه
نمی‌کنیم؛ سطح حمله‌ی «رمز + پورت عمومی» کوچیک است.

### ۳.۲ رمز عبور

در `/etc/injspoof-panel/panel.env`:

```
PANEL_PASSWORD=
```

خالی باشد = بدون صفحه‌ی ورود (منطقش این است که ترافیک فقط loopback است).
پر باشد، مرورگر را به `/login` می‌فرستد. بعد از تغییر:

```bash
sudo systemctl restart injspoof-panel
```

`PANEL_SECRET` رمزِ signing کوکی session است؛ اگر عوضش کنید همه‌ی sessionها
می‌افتند و اگر خالی بگذارید پنل هر بار یک رمز تصادفی می‌سازد (sessionها با
هر restart پاک می‌شوند). مقدارش را عوض نکنید مگر به‌دلیل نشت.

### ۳.۳ پنج صفحه‌ای که می‌بینید

| صفحه | آدرس | برای چه |
|---|---|---|
| داشبورد زنده | `/` | نمودار Rate/Drop بر ثانیه، وضعیت health هر نود، خلاصه‌ی pool. |
| نودها | `/nodes` | ثبت/ویرایش/حذف نودها، «تست اتصال»، روشن/خاموش کردن نمونه‌برداری. |
| هسته | `/core` | کنترل سرویس هسته‌ی **همین ماشین**: شروع/توقف/restart، لاگ journalctl، نوشتن کانفیگ روی دیسک، اعمال فایروال، به‌روزرسانی. |
| ویرایشگر کانفیگ | `/editor` | درخت/JSON خام کانفیگ یک نود، اعتبارسنجی، اعمال، نسخه‌ها. |
| ویزارد جفت کانفیگ | `/pair` | از چند ورودی ساده، کانفیگ ست سرور + کلاینت می‌سازد و هم‌راستایی‌شان را بررسی می‌کند. |

---

## ۴. اولین تونل: ویزارد جفت کانفیگ

`/pair` — سه بلوک دارد: **۱. مشخصات مشترک تونل**، **۲. سمت کلاینت**،
**۳. سمت سرور**. منطق تولید از `gen.py` است و منطق بررسی از `schema.py`؛
هر دو دقیقاً همان قواعدی‌اند که فیلتر واقعی هسته در `src/server.c` و
`src/client.c` اعمال می‌کند. برای همین است که «پیش‌نمایش سبز» یعنی نود
واقعاً قبولش می‌کند.

### ۴.۱ ورودی‌های اصلی

| ورودی | توضیح | نکته‌ی عملی |
|---|---|---|
| `hid` | شناسه‌ی ۵ بایتی که اول payload می‌چسبد و سرور با آن clientها را جدا می‌کند. | ۵ کاراکتر باشد؛ کوتاه‌ترش را پنل می‌گیرد و سرور drop می‌کند. |
| `iface` | کارت شبکه‌ای که فریم از آن می‌رود. | سمت سرور معمولاً WAN؛ سمت کلاینت همان کارت پیش‌فرض. |
| `MAC gateway` | مقصد لایه‌دوی فریم روی سیم. | اشتباهش = ترافیک هیچ‌جا نمی‌رسد و هیچ خطایی هم نمی‌گیرید. از `ip neigh` بگیرید. |
| IP pool | IPهایی که سرور sourceشان را جعل می‌کند. | باید در مسیرِ routingِ واقعی قابل‌استفاده باشند؛ `schema` CIDRهای تکراری و IPهای multicast را می‌گیرد. |
| `port` / `dst_ports` | پورت ظاهری بسته‌ها. | هسته سمت کلاینت فقط `dst_ports[0]` را استفاده می‌کند؛ بقیه‌ی لیست گول‌زننده است و پنل هشدار می‌دهد. |
| `encap` | TCP / UDP / ICMP روی سیم. | اگر `icmp` گرفتید، فیلتر پورتی `incoming` معنایش را از دست می‌دهد؛ پنل هشدار می‌دهد. |
| `api.bind` + `api.token` | API کنترل نود. | توکن را پنل تصادفی می‌سازد؛ «توکن تصادفی» را بزنید اگر دستی می‌نویسید. |

### ۴.۲ پیش‌نمایش و بررسی

«پیش‌نمایش و بررسی» را بزنید. سه چیز می‌گیرید:

* دو JSON (کلاینت و سرور) که روی سیم با هم حرف می‌زنند؛
* فهرست issueها با مسیر فیلد (مثلاً `interfaces[0].outgoing.gateway.mac_address`)
  و یک hint قابل‌فهم؛ خطای جدی (error) یعنی «اعمال نکن»، هشدار (warn) یعنی
  «کار می‌کند ولی شاید نه آن‌طور که می‌خواهید»؛
* گزارش ظرفیت (`capacity`) برای هر سمت: سقف flowها، peerها، pool.

«بررسی هم‌راستایی کانفیگ زنده» وقتی به کار می‌آید که نودی را دستی ویرایش
کرده‌اید: کانفیگ زنده را از API می‌خواند و با جفتِ مورد انتظار مقایسه می‌کند.

### ۴.۳ ذخیره، دانلود، اعمال

* **ذخیره‌ی pair** در `panel.db` می‌ماند (همراه spec، بعداً دوباره تولیدش می‌کنید).
* **دانلود** هر دو JSON + اسکریپت nftables را ZIP می‌دهد — برای نودی که هنوز
  بالا نیامده یا روی ماشین دیگری است.
* **اعمال روی نودها (PUT + hot reload)**: سمت کلاینت کامل جایگزین می‌شود؛ سمت
  سرور **merge** می‌شود تا forwarderهای clientهای دیگر نپرند. قبل از هر PUT،
  نسخه‌ی فعلی در تاریخچه بکاپ گرفته می‌شود (بخش ۷).

---

## ۵. ثبت نودها

نود = یک هسته‌ی injspoof با API فعال. پنل با همان `api.bind` + `api.token`
حرف می‌زند که در `/etc/injspoof/<instance>.json` است. مرورگر هیچ‌وقت توکن
نمی‌بیند؛ همه‌ی تماس‌ها سمت پایتون انجام می‌شود و UI فقط با `/api/*` خودِ پنل
حرف می‌زند.

### ۵.۱ نود راه‌دور

`/nodes` → «+ نود جدید»:

| فیلد | مقدار |
|---|---|
| نام | هر چیزی که خودتان تشخیص می‌دهید (یکتا باید باشد). |
| نقش | `server` یا `client` — روی اعتبارسنجی کانفیگ اثر دارد. |
| API URL | `http://127.0.0.1:9090`؛ اگر از راه SSH تانل می‌زنید همان loopback، اگر از راه شبکه `http://IP:9090`. |
| توکن API | دقیقاً `api.token` کانفیگ نود. فیلد عمداً خالی رندر می‌شود؛ خالی گذاشتن = «همان که ذخیره شده». |
| مسیر کانفیگ | اختیاری؛ برای لاگ و «کانفیگ زنده». |
| فعال | تیک نمونه‌برداری. بردارید تا نودی که خاموش است داشبورد را با خطا پر نکند. |

بعد از ذخیره، پنل یک `health` می‌زند و نتیجه را flash می‌کند. «تست اتصال» در
فهرست نودها همان کار را هر وقت می‌کند.

### ۵.۲ نود محلی (`is_local`)

اگر `install.sh` هسته را هم روی همین ماشین نصب کرده باشد، نود
`local-<instance>` خودکار ثبت شده است. تیک «نود محلی» + `core_instance` یعنی
پنل این نود را از راه systemd هم کنترل می‌کند (نوشتن کانفیگ روی دیسک، restart،
اعمال فایروال). اگر helper نصب نباشد، پنل با پیام خوانا می‌گوید و همان نود
فقط از راه API قابل مدیریت است.

نام instance باید `[A-Za-z0-9_.@-]{1,64}` باشد و در
`/etc/injspoof/instances.cfg` ثبت شده باشد — همان دو شرطی که خودِ helper
می‌گذارد؛ پنل زودتر چک می‌کند تا پیام فارسی بگیرید.

### ۵.۳ چند نود، یکی پس از دیگری

داشبورد یک نود را انتخاب می‌کند و نمودار را برایش می‌کشد؛ «+ نود جدید» برای
هر سرور/کلاینت جدا. نمونه‌بردار (نخ Collector) هر `PANEL_INTERVAL` ثانیه (پیش‌فرض
2) از نودهای فعال `stats` می‌گیرد و ۳۰۰ نمونه‌ی آخر را در حافظه نگه می‌دارد؛
`PANEL_TIMEOUT` (پیش‌فرض 4 ثانیه) سقف هر تماس است.

---

## ۶. داشبورد زنده و متریکها

* **Rate** / **Drop**: بسته و بایت در ثانیه، از سریِ حافظه — بعد از restart
  پنل خالی شروع می‌شود (سری‌ها در دیتابیس نیستند).
* **Hit / Miss pool**: چه مقدار از IP pool درگیر است.
* **PID / Uptime / version**: از `/api/v1/info`.
* **Dropها** به تفکیک علت (`drop_filter`، `drop_pool`، `drop_send_enobufs`، …)
  با counters هسته یکی‌اند؛ یعنی چیزی که اینجا می‌بینید دقیقاً همان چیزی است
  که `/api/v1/metrics` به Prometheus می‌دهد.
* `/api/nodes/<id>/metrics` متن Prometheus را proxy می‌کند؛ اگر Grafana دارید،
  همین آدرس را به‌عنوان scrape target پشت پنل بگذارید (نه API نود را).

---

## ۷. ویرایش کانفیگ و بازگشت نسخه

`/editor?node=<id>` دو حالت دارد: **فرم درختی** (همان کانفیگ، فیلد‌به‌فیلد با
قیدهای `schema.py`) و **JSON خام** (برای وقتی که می‌دانید چه می‌کنید).

جریان کار:

1. «بارگذاری از نود» → `GET /api/v1/config`.
2. ویرایش، بعد «اعتبارسنجی». پیام‌ها `path` + `message` + `hint` دارند و همان
   قواعد fail-fast هسته‌اند؛ چیزی که اینجا خطا گرفت، نود هم قبول نمی‌کند.
3. «اعمال روی نود» این ترتیب را می‌رود: JSON parse → schema validate →
   **بکاپ نسخه‌ی فعلی** → `PUT /api/v1/config` → `POST /api/v1/reload?mode=hot`.

دو حالت ویژه:

* **`api.token` را عوض کنید**: با hot reload عوض می‌شود و پنل بلافاصله همان
  توکن تازه را برای خودش ذخیره می‌کند؛ اگر همان لحظه پنل را نبستید و خطای 401
  دیدید، یک «تست اتصال» کافی است.
* **فیلدی hot نیست** (بعضی چیزهای `tuning` و ساختار interfaceها): باید
  «Hard reload (execve)» بزنید که PID را نگه می‌دارد و خودِ پروسه را جابه‌جا
  می‌کند؛ لحظه‌ای قطعی دارد.

تاریخچه: `/history/<node_id>` هر نسخه را با note و منبع (`panel`، `pair-wizard`،
`pre-apply`) نگه می‌دارد. `/versions/<id>.json` خامش را می‌دهد و «برگرداندن به
درخت» یک نسخه را دوباره PUT می‌کند. اگر نود وسط کار پایین بیاید، این تاریخچه
+ `/etc/injspoof/history/` هر دو هستند.

---

## ۸. صفحهی «هسته»: کنترل سرویس محلی

`/core` فقط سرویس **همین ماشین** را کنترل می‌کند و همه‌ی کارهای ریشه‌پای از یک
دربذهنِ واحد می‌روند:

```
sudo -n /usr/local/libexec/injspoof-nodectl <cmd> <instance> [args]
```

| دکمه | پشت صحنه |
|---|---|
| وضعیت / تازه‌سازی وضعیت | `nodectl info` → KEY=value (instance، unit، مسیر کانفیگ، باینری و capability، BUILD_INFO، SERVICE_STATE، FIREWALL_SCRIPT، UPDATE_ALLOWED). |
| شروع / توقف / restart | `systemctl … injspoof@<instance>` (helper نام واحد را خودش می‌سازد، از پنل نمی‌گیرد). |
| لاگ journalctl (120/300 خط) | `nodectl logs <n> <instance>`. |
| «همین کانفیگ را بنویس + restart» | `nodectl config-write` روی `/etc/injspoof/<instance>.json`؛ نسخه‌ی قبلی در `/etc/injspoof/history/`؛ بعد restart. |
| «اعمال روی این ماشین» (فایروال) | `nodectl firewall-apply` با متنی که پنل تولید کرده. |
| «دانلود اسکریپت» | همان `gen.nftables_script(cfg, role, instance)`. |
| rescan | `nodectl rescan <instance>` — مثلاً وقتی فایل کانفیگ را دستی عوض کرده‌اید. |
| «به‌روزرسانی هسته» | `git pull --ff-only` در ریپوی ثبت‌شده + `install.sh --update`؛ **فقط** اگر `/etc/injspoof/allow-update` باشد (یعنی نصب با `--allow-update` بوده). |

چرا اصلاً helper: پنل با کاربر بی‌اختیار `injspoof-panel` اجرا می‌شود و sudoers
فقط **همین یک مسیر** را با `NOPASSWD` باز کرده است. `PUT /api/v1/config` هسته
فقط وقتی کار می‌کند که هسته بالا باشد؛ برای نخستین راه‌اندازی، یا وقتی هسته
crash کرده، همین مسیرِ نوشتن روی دیسک لازم است.

---

## ۹. فایروال: بستن پاسخهای کرنل

هسته فریم‌هایی را می‌فرستد که کرنل براشان socket نساخته، برای همین کرنل برای
جریان‌های جعل‌شده **TCP RST** و **ICMP unreachable** می‌فرستد و تونل را reset
می‌کند. علامت‌هایش: reset متناوب، یا UDP بعد از یک بسته می‌میرد.

`install.sh` برای هر instance یک اسکریپت می‌سازد:

```
/etc/injspoof/firewall/<instance>.nft.sh
```

و واحد `injspoof-firewall@<instance>` آن را در هر بوت دوباره اعمال می‌کند. ساختار:

* table مشترک `inet injspoof`، به‌علاوه دو chain per-instance: `out_<slug>` و
  `raw_<slug>`؛
* قبل از افزودن، `nft flush chain` — پس اعمال دوباره‌پذیر است و قواعد را
  دو‌برابر نمی‌کند؛
* دو instance همدیگر را پاک نمی‌کنند (هر کدام chain خودش را flush می‌کند)؛
* یک خط marker دارد: `injspoof kernel-response blocker`.

helper فقط متنی را قبول می‌کند که پنل تولید کرده (خط‌ها فقط `nft`/`iptables`/
کامنت/`echo` باشند) و `iptables` را هم برای همان قواعد می‌نویسد اگر nftables
نباشد. پاک کردن دستی:

```bash
sudo nft delete table inet injspoof
```

---

## ۱۰. عملیات روزانه

### ۱۰.۱ بکاپ

سه چیز ارزش بکاپ گرفتن دارند؛ همه‌ی توکن‌ها اینجاست:

```bash
sudo tar czf /root/injspoof-backup-$(date +%F).tar.gz /etc/injspoof /etc/injspoof-panel /var/lib/injspoof-panel
```

* `/etc/injspoof/` — کانفیگ هر instance + `instances.cfg` + `history/`؛
* `/etc/injspoof-panel/panel.env` — `PANEL_SECRET` و `PANEL_PASSWORD`؛
* `/var/lib/injspoof-panel/panel.db` — نودها، pairها، تاریخچه‌ی کانفیگ.

برای hot-copy دیتابیس SQLite:

```bash
sudo -u injspoof-panel /opt/injspoof-panel/.venv/bin/python -c "import sqlite3;sqlite3.connect('/var/lib/injspoof-panel/panel.db').backup(sqlite3.connect('/root/panel-copy.db'))"
```

### ۱۰.۲ به‌روزرسانی

پنل (کد، بدون دست‌زدن به رمز/db/کانفیگ):

```bash
cd /opt/injspoof-src && git pull && sudo bash panel/install.sh --update
```

هسته را هم restart می‌خواهید، `--restart-node` را اضافه کنید. از دلِ پنل هم
همین کار می‌شود (دکمه‌ی «به‌روزرسانی هسته»، مشروط به `--allow-update`).

فقط پنل، بدون هسته:

```bash
cd /srv/injspoof-panel && git pull && sudo bash install.sh --no-core
```

### ۱۰.۳ حذف

```bash
sudo bash panel/install.sh --uninstall
```

سرویس‌ها، helper، sudoers و کد می‌روند؛ کانفیگ‌ها و `panel.db` **می‌مانند**
(چون `api.token` تنها نسخه‌ی موجودشان است). باینری را هم می‌خواهید:
`--uninstall --purge-binary`. پاک کردن کامل داده‌ها، دستی:

```bash
sudo rm -rf /etc/injspoof /etc/injspoof-panel /var/lib/injspoof-panel /opt/injspoof-panel
```

---

## ۱۱. عیب‌یابی

| علامت | علتِ محتمل | چکار کنید |
|---|---|---|
| نصب می‌ایستد با «سورس هسته در … نیست» | پنل مستقل است و `--with-core` داده‌اید. | `--src=/opt/injspoof-src` بدهید یا clone کنید. |
| `python 3.8+ لازم است` | پایتون قدیمی. | `python3 --version`؛ بسته‌ی پایتون تازه‌تر نصب کنید. |
| پنل بالا نمی‌آید | کد/محیط/مجوز فایل. | `journalctl -u injspoof-panel -n 50`؛ اگر ImportError بود همان خطا را با `sudo -u injspoof-panel /opt/injspoof-panel/.venv/bin/python -c "import sys; sys.path.insert(0, '/opt/injspoof-panel'); import app; print(app.APP_VERSION)"` تکرار کنید؛ اگر PermissionError بود با `ls -l /var/lib/injspoof-panel` ببینید مالک `panel.db*` کاربر سرویس هست یا root. |
| 401 روی همه‌ی نودها | توکن در `panel.db` با کانفیگ نود نمی‌خواند. | `grep -o '"token": "[^"]*"' /etc/injspoof/<instance>.json` و «توکن» فرم نود را مقایسه کنید. |
| داشبورد پر از خطای timeout | نود خاموش است ولی «فعال» تیک دارد. | نمونه‌برداری‌اش را خاموش کنید یا `PANEL_TIMEOUT` را بالا ببرید. |
| تونل reset می‌شود | RST کرنل نشت می‌کند. | بخش ۹؛ `nft -a list chain inet injspoof out_<instance>`. |
| UDP بعد از یک بسته می‌میرد | ICMP destination-unreachable. | همان جدول ۲ در [../docs/OPERATIONS.md](../docs/OPERATIONS.md). |
| `tcpdump` فریم را می‌بیند ولی Capture نمی‌کند | AF_XDP روی درایور VM اجباری شده. | `tuning.fastpath.mode` را روی `auto` یا `af_packet`. |
| `drop_send_enobufs` و `congestion_events` بالا می‌روند | مسیر TX کفایت نمی‌کند. | بار را کم کنید، queue اضافه کنید، NIC را ببینید. |
| «این نود از این ماشین کنترل نمی‌شود» | helper/instance ثبت نشده. | `sudo -u injspoof-panel /usr/local/libexec/injspoof-nodectl info <instance>`؛ بعد `rescan`. |
| فونت‌ها افتاده / UI بهم‌ریخته | `static/fonts` به مقصد نصب نرسیده. | `ls /opt/injspoof-panel/static/fonts` و `curl -sI http://127.0.0.1:8088/static/fonts/Vazirmatn-Regular.woff2`. |

---

## ۱۲. امنیت و مرز اختیارات

* پنل با کاربر سیستمی `injspoof-panel` اجرا می‌شود؛ root نیست.
* `ProtectSystem=full`، `ProtectHome=true`، `PrivateTmp=true`؛ نوشتن فقط در
  `/var/lib/injspoof-panel`.
* تنها راه ریشه‌پای: `/usr/local/libexec/injspoof-nodectl` با sudoers
  تک‌مسیره‌ی `NOPASSWD`. helper خودش نام واحد را می‌سازد، instance را با
  `instances.cfg` تطبیق می‌دهد، متن فایروال را whitelist می‌کند و `update`
  فقط با `allow-update` و فقط `git pull --ff-only`.
* واحدهای هسته و پنل عمداً `NoNewPrivileges=false` دارند: در هسته چون
  `setcap` با آن بی‌اثر می‌شود، در پنل چون `sudo -n` با آن کار نمی‌کند.
* توکن‌ها هرگز به مرورگر نمی‌رسند: `/api/core/info` فیلد `api_token` را
  حذف می‌کند و `/api/nodes/<id>` هم فقط preview توکن می‌دهد.
* `PANEL_PASSWORD` تنها لایه‌ی احراز است. چون پنل پیش‌فرض فقط روی loopback
  می‌نشیند، خالی‌گذاشتنش منطقی است؛ ولی `--host=0.0.0.0` با رمز خالی عملاً
  پنل را عمومی می‌کند.
* کانفیگ هسته و `panel.env` گروه‌شان کاربر سرویس است با 0640؛ هیچ‌کدام
  world-readable نیست.

---

## ۱۳. توسعه و تست

اجرای دستی (بدون systemd):

```bash
cd panel
python3 -m venv .venv && .venv/bin/python -m pip install -r requirements.txt
.venv/bin/python run.py            # http://127.0.0.1:8088
```

`run.py` reloader را خاموش نگه می‌دارد تا نخ نمونه‌بردار دوباره ساخته نشود.
برای تنظیمات اجرا از متغیر محیطی استفاده می‌کند:

```bash
PANEL_PORT=9000 PANEL_PASSWORD=devsecret .venv/bin/python run.py
```

شبیه‌سازها:

| ابزار | چه |
|---|---|
| `mock_api.py` | یک هسته‌ی جعلی با API واقعی (`--load-example` کانفیگ نمونه را بار می‌گذارد)؛ برای نمودار و editor. |
| `mock_nodectl.py` | جای helper: همان دستور ها و همان خروجی KEY=value را می‌دهد، بدون systemctl/nft واقعی؛ وضعیت را در `panel/.mock-nodectl/` نگه می‌دارد. یعنی صفحه‌ی «هسته» روی ویندوز یا WSL هم با داده‌ی کامل دیده می‌شود. |

صفحه‌ی «هسته» با شبیه‌ساز helper:

```bash
INJSPOOF_SUDO=python3 INJSPOOF_NODECTL=$PWD/mock_nodectl.py .venv/bin/python run.py
```

(`INJSPOOF_SUDO` باید به یک فایل اجراییِ قابل‌یافت با `which` اشاره کند؛ پنل
دستور را `[$sudo, -n, $NODECTL, …]` می‌سازد. برای تست مستقیم helper:
`python mock_nodectl.py info server`.)

تست‌ها:

```bash
python selftest.py     # منطق schema + فایروال + قراردادها + فونت + مستقل‌بودن
python e2e_test.py     # صفحات و مسیرهای HTTP روی stack محلی
```

هر دو باید `FAIL: 0` بدهند (countها را در [README.md](README.md) ببینید).

**فونت**: `static/fonts/` شش فایل woff2 خودمیزبان دارد — Vazirmatn 33.003 در
چهار وزن (400/500/600/700) و JetBrains Mono در دو وزن (400/700، زیرمجموعه‌ی
ASCII). هر دو تحت SIL OFL و متن مجوزشان کنار فایل‌هاست (`OFL.txt`،
`OFL-JetBrainsMono.txt`). `@font-face`ها در بالای `static/style.css`‌اند و
`templates/base.html` وزن Regular را preload می‌کند. هیچ ارجاع بیرونی در
stylesheet نیست و `selftest.py` همین را اجباری می‌کند؛ اگر فونت عوض می‌کنید،
همین قاعده را نگه دارید (CDN = نصب آفلاین می‌شکند).

---

## ۱۴. مرجع سریع

**پورت‌ها**: پنل `8088` · API هسته `9090` (server) و `9091` (client)، هر دو
پیش‌فرض روی `127.0.0.1`.

**سرویس‌ها**:

```bash
systemctl status injspoof-panel
systemctl restart injspoof-panel
systemctl status injspoof@server
systemctl restart injspoof-firewall@server
journalctl -u injspoof-panel -f
journalctl -u injspoof@server -n 100
```

**متغیرهای محیطی پنل** (`/etc/injspoof-panel/panel.env`):

| کلید | پیش‌فرض | کار |
|---|---|---|
| `PANEL_HOST` / `PANEL_PORT` | `127.0.0.1` / `8088` | محل نشستن پنل. |
| `PANEL_DB` | `/var/lib/injspoof-panel/panel.db` | دیتابیس SQLite. |
| `PANEL_INTERVAL` | `2` | ثانیه بین دو نمونه‌برداری. |
| `PANEL_TIMEOUT` | `4` | سقف هر تماس با API نود. |
| `PANEL_SECRET` | — | signing کوکی session. |
| `PANEL_PASSWORD` | خالی | خالی = بدون صفحه‌ی ورود. |
| `PANEL_VERSION` | از `VERSION` | override شماره‌ی نمایشی. |
| `INJSPOOF_NODECTL` | `/usr/local/libexec/injspoof-nodectl` | مسیر helper. |
| `INJSPOOF_INSTANCE` | نام instance نصب‌شده | instance پیش‌فرض صفحه‌ی «هسته». |
| `INJSPOOF_SUDO` | `sudo` | برای تست با mock خالی‌اش کنید. |
| `INJSPOOF_CTL_TIMEOUT` | `30` | سقف اجرای helper. |

**API هسته** که پنل استفاده می‌کند (Bearer `api.token`):

| مسیر | برای |
|---|---|
| `GET /api/v1/health` | تست اتصال. |
| `GET /api/v1/info` | نسخه، mode، PID، uptime. |
| `GET /api/v1/stats` (و `/stats/traffic`، `/stats/pool`، `/stats/log`) | شمارنده‌ها. |
| `GET /api/v1/config` · `PUT /api/v1/config` | خواندن/نوشتن کانفیگ. |
| `POST /api/v1/reload?mode=hot` · `?mode=hard` | اعمال کانفیگ. |
| `GET /api/v1/metrics` | خروجی Prometheus. |

**منطقه‌ی کد**: `app.py` (routes) · `db.py` (SQLite) · `core.py` (helper
wrapper) · `schema.py` (اعتبارسنجی، آینه‌ی `src/config.c` و `src/server.c`) ·
`gen.py` (ویزارد + فایروال + CLI `starter`/`firewall`/`detect`) ·
`injclient.py` (کلاینت API) · `register.py` (CLI ثبت نود) ·
`static/app.js` (UI بدون framework) · `templates/*.html` (RTL).
