# پنل تحت وب injspoof

مستند این پوشه دو بخش است و ترتیبشان مثل خودِ مخزن است:

| بخش | درباره‌ی چه چیزی‌ست |
| --- | --- |
| **[بخش ۱: هسته](#بخش-۱-هسته)** | خودِ engine به‌علاوه آنچه `install.sh` حول آن می‌چیند: بیلد، capability، واحدهای systemd، کانفیگ روی دیسک، قواعد فایروال و مرز کنترل بدون root |
| **[بخش ۲: پنل](#بخش-۲-پنل)** | رابط وب فارسی (RTL): صفحه ها، دسترسی، اجرای دستی، تست‌ها و امنیت |

پنل مدیریتی فارسی کنار خودِ نود اجرا می‌شود و با همان `http://127.0.0.1:<port>`
API حرف می‌زند؛ یعنی چیزی به ساختار injspoof اضافه نمی‌کند و برای اجرا به root یا
`CAP_NET_RAW` نیاز ندارد. `install.sh` هم هسته‌ی C را build و نصب می‌کند، پس یک
مخزن و یک دستور کافی است. مستندات خودِ هسته (معماری، پروتکل، کانفیگ، عملکرد) در
[../docs/](../docs/) است.

**پنل یک پروژه‌ی مستقل است.** پوشه‌ی `panel/` را تنهایی هم بردارید،
`bash install.sh` پنل را نصب می‌کند و اگر سورس هسته کنارش نبود، هسته را با پیام
روشن رد می‌کند (بخش [پنل بدون هسته](#پنل-بدون-هسته)). شماره‌ی نسخه، مجوز،
تغییرات و کانفیگ‌های نمونه‌ی خودش را دارد؛ فونت‌هایش هم خودمیزبان‌اند.

قدم‌به‌قدمِ کار با پنل — نصب، اولین تونل، نودها، فایروال، بکاپ، عیب‌یابی — در
**[راهنمای کامل](GUIDE.md)** است. این فایل مرجعِ ساختار و گزینه‌هاست.

## فهرست

**[بخش ۱: هسته](#بخش-۱-هسته)**

* [نصب با یک دستور](#نصب-با-یک-دستور)
* [پنل بدون هسته](#پنل-بدون-هسته)
* [کار install.sh با هسته](#کار-installsh-با-هسته)
* [واحدهای systemd و سرویس هسته](#واحدهای-systemd-و-سرویس-هسته)
* [گزینه های نصب](#گزینه-های-نصب)
* [مسیرها](#مسیرها)
* [مرز امنیت کنترل هسته](#مرز-امنیت-کنترل-هسته)
* [به روز رسانی و حذف](#به-روز-رسانی-و-حذف)

**[بخش ۲: پنل](#بخش-۲-پنل)**

* [صفحه های پنل](#صفحه-های-پنل)
* [دسترسی از بیرون](#دسترسی-از-بیرون)
* [اجرای دستی (توسعه)](#اجرای-دستی-توسعه)
* [فونت و فایل ثابت](#فونت-و-فایل-ثابت)
* [تست](#تست)
* [امنیت](#امنیت)
* [قواعدی که پنل از سورس استخراج کرده](#قواعدی-که-پنل-از-سورس-استخراج-کرده)
* [ساختار پوشه panel](#ساختار-پوشه-panel)

---

# بخش ۱: هسته

## نصب با یک دستور

یک دستور، از صفر تا هسته‌ی نصب‌شده و پنل بالاآمده:

```bash
git clone https://github.com/alisystemit/system-spoof.git /opt/injspoof-src && cd /opt/injspoof-src && sudo bash panel/install.sh
```

برای به‌روزرسانی (همین خط را بعد از `git pull` دوباره اجرا کنید):

```bash
cd /opt/injspoof-src && git pull && sudo bash panel/install.sh --update
```

> build هسته در ماشین‌های کم‌رمز ممکن است چند دقیقه طول بکشد. اگر فقط پنل را
> می‌خواهید و هسته از قبل نصب است: `--no-core`. اگر فقط هسته: `--core-only`
> (به venv پنل هم نیازی نیست؛ `gen.py` و `register.py` فقط stdlib می‌خواهند).

## پنل بدون هسته

پنل هسته را لازم ندارد: می‌تواند فقط مدیر نودهای راه‌دور باشد. دو راه:

```bash
git clone --filter=blob:none --sparse https://github.com/alisystemit/system-spoof.git /opt/injspoof-src && cd /opt/injspoof-src && git sparse-checkout set panel && sudo bash panel/install.sh --no-core
```

```bash
cp -a panel /srv/injspoof-panel && cd /srv/injspoof-panel && sudo bash install.sh
```

دومی حالت «پروژه‌ی مستقل» است: install.sh می‌بیند که `Makefile` و `src/main.c`
کنارش نیست، پس هسته را رد می‌کند و پنل را می‌نشیند. اگر هسته را واقعاً
می‌خواهید و سورس جابه‌جا شده، `--with-core` یا `--src=/path` بدهید؛ در آن حالت
نبودنِ سورس خطاست، نه skip. چیزهایی که پنل را مستقل می‌کنند:

| چیز | نقش |
| --- | --- |
| `seed/server.json` و `seed/client.json` | کپی `example/` داخل پنل؛ `gen.example_path()` وقتی ریپو نیست از همین‌ها می‌خواند، پس کانفیگ شروع و `selftest.py` بدون سورس C هم کار می‌کند. |
| `VERSION` | نسخه‌ی پنل، مستقل از هسته؛ در سایدبار نشان داده می‌شود (`PANEL_VERSION` فقط override). |
| `LICENSE` / `CHANGELOG.md` / `GUIDE.md` | مجوز (MIT + OFL فونت‌ها)، تغییرات و راهنمای کامل. |
| `static/fonts/` | فونت خودمیزبان؛ بدون CDN (بخش [فونت و فایل ثابت](#فونت-و-فایل-ثابت)). |
| `deploy/injspoof-panel.service` | واحد systemd پنل؛ هیچ ارجاعی به هسته ندارد. |

در این حالت صفحه‌ی «هسته» می‌گوید روی این ماشین هسته‌ای نیست — که درست است — و
بقیه‌ی کارها (ثبت نود، کانفیگ، reload، تاریخچه، نمودار) کامل کار می‌کند.

## کار install.sh با هسته

* فقط اگر نبودند، از مدیر بسته‌ی توزیع نصب می‌کند (apt / dnf / pacman):
  `python3` + `venv`؛ و وقتی هسته هم نصب می‌شود `gcc`/`make`/`libcap`
  (با `--fastpath` یک ردیف `clang`/`libbpf`/`libxdp` هم اضافه می‌شود). هیچ
  دست‌ی به PHP، MySQL، nginx، دامنه یا نام کاربری دیتابیس نمی‌زند.
* **هسته** را با `make` build می‌کند (اول `FASTPATH=1`، اگر درایور/ابزارش نبود
  build قابل‌حمل AF_PACKET)، باینری را در `/usr/local/bin/injspoof` می‌گذارد و
  `setcap cap_net_raw[,cap_bpf,cap_net_admin]+ep` ست می‌کند.
* برای instance (پیش‌فرض همان role) کانفیگ شروع می‌سازد — از `example/` ریپو،
  و اگر پنل مستقل است از `seed/` خودش — با `api.token` تصادفی، نام کارت شبکه و
  MAC gateway واقعی همان ماشین، و فایل‌های
  `/etc/injspoof/<instance>.{json,conf}` و wrapper را می‌چیند.
* قواعد بستن پاسخ کرنل (RST/ICMP) را از همان کانفیگ تولید می‌کند:
  `/etc/injspoof/firewall/<instance>.nft.sh` با زنجیره‌های per-instance
  (`out_<instance>` و `raw_<instance>` و `nft flush chain` برای اعمال idempotent)،
  پس دو instance روی یک ماشین همدیگر را پاک نمی‌کنند.
* helper ریشه‌پای `/usr/local/libexec/injspoof-nodectl` +
  `/etc/sudoers.d/injspoof-panel` را نصب می‌کند تا پنل بدون root بودن بتواند
  همان instanceهای ثبت‌شده را کنترل کند.
* نود محلی را در `panel.db` ثبت می‌کند (`register.py`) — با کاربر سرویس، نه root،
  تا مالکیت دیتابیس درست بماند. در پایان سلامت پنل را با یک درخواست HTTP چک
  می‌کند؛ سلامت API نود را فقط وقتی که هسته واقعاً بالا رفته باشد.

## واحدهای systemd و سرویس هسته

سه واحد نصب و enable می‌شوند:

| واحد | کار |
| --- | --- |
| `injspoof@<instance>` | خودِ هسته؛ از wrapper و EnvironmentFile‌ی instance اجرا می‌شود |
| `injspoof-firewall@<instance>` | با هر restart قواعد `nft` را می‌چیند تا کرنل RST نزند |
| `injspoof-panel` | پنل، با کاربر بی‌اختیار `injspoof-panel` |

```bash
systemctl status  injspoof@server
systemctl start   injspoof@server          # یا --start-node هنگام نصب
systemctl restart injspoof@server
systemctl status  injspoof-firewall@server
journalctl -u injspoof@server -u injspoof-panel -f
```

> واحد `injspoof@<instance>` نصب و enable می‌شود ولی راه نمی‌افتد، مگر
> `--start-node` بدهید — چون تا peer سمت مقابل تنظیم نشده، بالا آمدنش فقط drop
> تولید می‌کند. بعداً از صفحه‌ی «هسته» یا با `systemctl start` روشنش کنید.
> واحد هسته عمداً `NoNewPrivileges` ندارد: آن گزینه file-capability را بی‌اثر
> می‌کند و `setcap` روی باینری را بیهوده.

## گزینه های نصب

| گزینه | کار |
| --- | --- |
| `--role=server\|client` | نقش هسته‌ی این ماشین (پیش‌فرض server) |
| `--instance=NAME` | نام instance در `injspoof@NAME` (پیش‌فرض همان role) |
| `--api-bind=HOST:PORT` | `api.bind` کانفیگ شروع (پیش‌فرض `127.0.0.1:9090`؛ برای client `9091`) |
| `--src=DIR` | مسیر ریپو (پیش‌فرض پوشه‌ی والد `panel/`) |
| `--with-core` | هسته اجباری است؛ نبودن سورس = خطا (پیش‌فرض: خودکار — اگر سورس بود نصب می‌شود، نبود پنل تنها می‌ماند) |
| `--fastpath` | build با `FASTPATH=1` و capabilityهای BPF/NET_ADMIN |
| `--start-node` | پس از نصب، سرویس هسته را روشن کن (پیش‌فرض خاموش) |
| `--restart-node` | در `--update` سرویس هسته را هم restart کن |
| `--allow-update` | دکمه‌ی «به‌روزرسانی از پنل» را روشن می‌کند |
| `--no-core` / `--core-only` | فقط پنل / فقط هسته |
| `--host=` `--port=` `--prefix=` `--user=` | آدرس و مسیر و کاربر پنل |
| `--no-enable` | بچیند ولی start نکند |
| `--update` | کد را نو و سرویس‌ها را restart می‌کند (کانفیگ و db دست‌نخورده) |
| `--uninstall` | سرویس‌ها و فایل‌های سیستمی را برمی‌دارد؛ کانفیگ و `panel.db` می‌مانند (`--purge-binary` باینری را هم حذف می‌کند) |

## مسیرها

| چیز | مسیر |
| --- | --- |
| باینری هسته | `/usr/local/bin/injspoof` (با `setcap`) |
| نسخه‌ی build | `/etc/injspoof/build-info` |
| کانفیگ هسته | `/etc/injspoof/<instance>.json` (۰۶۴۰، گروه همان کاربر سرویس) |
| بکاپ کانفیگ روی دیسک | `/etc/injspoof/history/` |
| فهرست instanceها | `/etc/injspoof/instances.cfg` |
| اسکریپت فایروال | `/etc/injspoof/firewall/<instance>.nft.sh` |
| helper کنترل هسته | `/usr/local/libexec/injspoof-nodectl` + `/etc/sudoers.d/injspoof-panel` |
| state مشترک install/helper | `/etc/injspoof-panel/state.conf` |
| کد پنل | `/opt/injspoof-panel` |
| مستند پنل روی سرور | `/opt/injspoof-panel/{README.md,GUIDE.md,CHANGELOG.md,LICENSE}` (`systemctl cat injspoof-panel` هم همان `Documentation=` را دارد) |
| دیتابیس پنل (نودها، تاریخچه، pairها) | `/var/lib/injspoof-panel/panel.db` |
| تنظیمات و رمز | `/etc/injspoof-panel/panel.env` |
| لاگ | `journalctl -u injspoof@server -u injspoof-panel -f` |

## مرز امنیت کنترل هسته

پنل root نیست. هر کاری که به ریشه نیاز دارد از راه
`sudo -n /usr/local/libexec/injspoof-nodectl <cmd> <instance>` انجام می‌شود و
sudoers فقط همان کاربر و فقط همان مسیر را می‌پذیرد. helper هم:

* نام واحد systemd را خودش می‌سازد (`injspoof@<instance>`)؛ پنل نمی‌تواند هر
  واحدی را restart کند.
* `instance` باید هم الگوی `[A-Za-z0-9_.@-]` را رد کند، هم در `instances.cfg`
  ثبت باشد، هم wrapper و EnvironmentFile و کانفیگش روی دیسک باشد.
* `info` همان instance نود انتخابی را گزارش می‌کند، نه همیشه اولین ثبت‌شده.
* `firewall-apply` فقط متن تولیدشده توسط خود پنل را می‌پذیرد (تیتر
  `injspoof kernel-response blocker` و خطوط فقط `nft`/`iptables`/کامنت/`echo`).
* `config-write` قبل از نوشتن، نسخه‌ی قبلی را در `/etc/injspoof/history/`
  می‌گذارد و فایل را با `0640` و گروه کاربر سرویس می‌نویسد (گروه از
  `state.conf` خوانده می‌شود، پس `--user=custom` هم درست کار می‌کند).
* `update` فقط در مسیر ریپوی ثبت‌شده در `/etc/injspoof-panel/state.conf` و فقط
  با `git pull --ff-only` کار می‌کند، و آن هم تنها اگر نصب با `--allow-update`
  شده باشد.

## به روز رسانی و حذف

هسته + پنل (نصب از ریپو):

```bash
cd /opt/injspoof-src && git pull && sudo bash panel/install.sh --update
```

فقط پنل، روی نصب مستقل (اول `git pull` اگر sparse clone کرده‌اید؛ اگر پوشه را
کپی کرده‌اید، فایل‌های تازه را جای قبلی بگذارید):

```bash
cd /srv/injspoof-panel && sudo bash install.sh --no-core
```

```bash
sudo bash panel/install.sh --uninstall          # کانفیگ و panel.db می‌مانند
sudo bash panel/install.sh --uninstall --purge-binary
```

`.venv`، `panel.db` و `panel.env` (پس رمزها و نودهای ثبت‌شده) حفظ می‌شوند؛ کانفیگ
هسته‌ی روی دیسک هم دست‌نخورده می‌ماند. فقط کد و وابستگی‌ها نو و سرویس‌ها
restart می‌شوند. اگر نصب `--allow-update` شده باشد، همان کار از دکمه‌ی
«به‌روزرسانی» در صفحه‌ی «هسته» هم انجام می‌شود.

---

# بخش ۲: پنل

## صفحه های پنل

* **داشبورد زنده** — انتخاب نود، KPIها، سه نمودار (pps، B/s، drop)، جدول علل
  drop با نرخ لحظه‌ای، سنجه‌ی استخر IP مبدأ، syscallها، شاخص‌های لاگ/reload و
  دکمه‌های hot/hard reload.
* **نودها** — ثبت `api_url` و توکن هر نود، تست اتصال، وضعیت زنده، pps لحظه‌ای،
  ورود تاریخچه و حذف. تیک «هسته‌ی این نود روی همین ماشین اجرا می‌شود» + نام
  instance، برچسب **محلی** و دکمه‌ی «هسته» را فعال می‌کند.
* **هسته** — درِ همان بخش ۱ از داخل مرورگر: وضعیت نصب (باینری، capability، نسخه‌ی
  build، واحد systemd، اسکریپت فایروال، مسیر کانفیگ)، شروع/توقف/restart/وضعیت،
  `daemon-reload`، لاگ journalctl، پیش‌نمایش و دانلود و اعمال قواعد فایروال،
  نوشتن کانفیگ دیسک (با گیت اعتبارسنجی و بکاپ history)، برگرداندن کانفیگ
  زنده‌ی نود روی دیسک، و به‌روزرسانی (فقط اگر نصب با `--allow-update` بوده باشد).
  اگر helper روی این ماشین نباشد، صفحه به‌جای دکمه‌ها همان خط نصب را نشان می‌دهد.
* **ویرایشگر کانفیگ** — «خواندن از نود»، ویرایش درختی (افزودن/حذف کلید و عنصر
  آرایه) یا خام، «اعتبارسنجی»، «اعمال روی نود» با انتخاب `hot` / `hard` /
  بدون reload، و «تاریخچه».
* **ویزارد جفت کانفیگ** — مشخصات مشترک، سمت سرور، سمت کلاینت، forwarderها؛
  پیش‌نمایش چهار فایل، ذخیره، دانلود ZIP، و اعمال روی نودهای ثبت‌شده.

## دسترسی از بیرون

پنل پیش‌فرض فقط روی `127.0.0.1:8088` می‌نشیند. برای دیدنش از بیرون، تانل SSH
بزنید (نه باز کردن پورت):

```bash
ssh -L 8088:127.0.0.1:8088 root@IP-سرور
```

بعد در مرورگر خودتان: `http://127.0.0.1:8088`

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

## فونت و فایل ثابت

پنل برای رندر شدن به هیچ چیز بیرونی وصل نمی‌شود — نه CDN، نه گوگل فونتس.
`static/style.css` با `@font-face` از `static/fonts/` می‌خواند:

| فایل | وزن‌ها | کار |
| --- | --- | --- |
| `Vazirmatn-{Regular,Medium,SemiBold,Bold}.woff2` | 400 / 500 / 600 / 700 | متن فارسی UI؛ همان چهار وزنی که stylesheet استفاده می‌کند |
| `JetBrainsMono-{Regular,Bold}.woff2` | 400 / 700 | JSON، لاگ، مسیرها و جدول‌های عددی (LTR) |
| `OFL.txt`، `OFL-JetBrainsMono.txt` | — | متن کامل SIL Open Font License هر دو فونت |

`templates/base.html` وزن Regular را `preload` می‌کند تا در نخستین paint متن
پرش نکند، و `app.py` هم `font/woff2` را به MIME ثبت می‌کند (چند توزیع
`/etc/mime.types`شان این پسوند را ندارد و وگرنه `application/octet-stream`
می‌شود). `install.sh` در پایان نصب، URL فونت را هم با curl چک می‌کند.

اگر فونت عوض می‌کنید دو قاعده را نگه دارید — `selftest.py` همین‌ها را اجباری
می‌کند: هر `url()` باید به `fonts/…` محلی اشاره کند و هر `font-weight` که CSS
می‌خواهد باید face خودش را داشته باشد.

## تست

* `python selftest.py` — 65 بررسی بدون شبکه؛ منطق اعتبارسنج، ویزارد، لینتر
  هم‌راستایی، قواعد فایروال per-instance، کانفیگ شروعِ install.sh، قرارداد
  `core.py` با helper، مهاجرت ستون‌های `is_local`/`core_instance` در `db.py`،
  قرارداد `install.sh` با `injspoof-nodectl` (گروه کانفیگ، مالکیت `panel.db`،
  `--core-only` بدون venv)، خودمیزبان بودن فونت‌ها (face محلی، فایل واقعی woff2،
  نبودِ هر ارجاع بیرونی، پوشش وزن‌ها) و مستقل بودن پنل (fallback به `seed/`،
  `VERSION`/`LICENSE`/`GUIDE.md` کنار کد، بخشیدنِ نبودن سورس هسته).
* `python mock_api.py --mode server --port 9090 --token devtoken --load-example`
  یک API injspoof جعلی کامل می‌دهد (هر 8 endpoint + احراز Bearer) تا پنل روی
  ماشین بدون Linux هم قابل آزمایش باشد.
* `python mock_nodectl.py info server`
  جای helper ریشه‌پای لینوکس را می‌گیرد: همان KEY=valueها و همان دستور ها، ولی
  هیچ systemctl/nft واقعی اجرا نمی‌کند و وضعیت را در `panel/.mock-nodectl/`
  نگه می‌دارد. برای دیدن صفحه‌ی «هسته» با داده‌ی کامل:

  ```bash
  INJSPOOF_SUDO=python3 INJSPOOF_NODECTL=$PWD/panel/mock_nodectl.py python3 panel/run.py
  ```

* `python e2e_test.py` — 38 بررسی سرتاسری؛ با پنل و دو mock بالا، مسیرهای
  نوشتنی واقعی را می‌زند: اعمال کانفیگ، hot reload، گیت اعتبارسنجی، rollback از
  تاریخچه، push ویزارد، بررسی هم‌راستایی روی داده‌ی زنده، و اینکه کنترل سرویس
  به نود غیرمحلی رد می‌شود.

```bash
python panel/mock_api.py --mode server --port 9090 --token devtoken --load-example &
python panel/mock_api.py --mode client --port 9091 --token devtoken --load-example &
python panel/run.py &
python panel/e2e_test.py
```

## امنیت

* پنل را روی `0.0.0.0` باز نکنید. `PANEL_HOST` پیش‌فرض `127.0.0.1` است و
  دسترسی بیرونی فقط با تانل SSH یا یک reverse proxy با احراز هویت منطقی است.
* برای هر نود یک `api.token` بلند و تصادفی بگذارید:
  `openssl rand -hex 32`.
* اگر API نود روی `0.0.0.0` bind شده، هر کسی که به آن پورت برسد می‌تواند
  `PUT /api/v1/config` و `POST /api/v1/reload` بزند. صفحه‌ی «نودها» این حالت را
  یادآوری می‌کند.
* توکن‌ها هیچ‌وقت به مرورگر نمی‌روند: همه‌ی تماس‌ها با نود از سمت پایتون (پروکسی
  داخلی `/api/*`) انجام می‌شود و رکورد نود در `/api/core/*` هم بدون `api_token`
  سریال‌سازی می‌شود.
* اگر پنل را بیرون از ماشین نود اجرا می‌کنید، `PANEL_PASSWORD` را حتماً پر کنید
  و ترجیحاً بین دو ماشین TLS بگذارید.
* `panel.db` شامل آدرس و **توکن** نودهاست؛ مجوز `0750` روی
  `/var/lib/injspoof-panel` و `0640` روی `panel.env` گذاشته می‌شود.
* کنترل هسته از همان مسیر باریک بخش ۱ می‌آید: sudoers فقط
  `injspoof-panel → /usr/local/libexec/injspoof-nodectl` را می‌پذیرد و helper
  فقط instanceهای ثبت‌شده در `/etc/injspoof/instances.cfg` را؛ جزئیات در
  «مرز امنیت کنترل هسته».

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

## ساختار پوشه panel

```
panel/
  app.py                Flask + روت‌ها + نخ نمونه‌بردار + روت‌های /api/core/*
  core.py               پوسته‌ی calls به helper (sudo -n injspoof-nodectl …)
  db.py                 SQLite (nodes / pairs / config_history / settings)
  schema.py             اعتبارسنج + لینتر هم‌راستایی جفت (منطبق بر src/server.c)
  gen.py                تولید جفت کانفیگ + کانفیگ شروع + اسکریپت nftables/iptables
  injclient.py          کلاینت API نود (health/info/stats/PUT/reload)
  register.py           ثبت نود محلی در panel.db هنگام نصب
  install.sh            build + چیدن هسته و پنل روی لینوکس (venv + systemd + sudoers)
  mock_api.py           API جعلی injspoof برای تست روی هر سیستم‌عامل
  mock_nodectl.py       جای helper لینوکس برای تست صفحه‌ی «هسته» روی ویندوز
  run.py                اجرای توسعه
  selftest.py           65 بررسی منطقی بدون شبکه
  e2e_test.py           38 بررسی سرتاسری روی HTTP
  requirements.txt      flask + gunicorn
  VERSION               نسخه‌ی پنل (مستقل از هسته) — در سایدبار نمایش داده می‌شود
  LICENSE               MIT برای کد پنل + یادداشت OFL برای فونت‌ها
  CHANGELOG.md          تغییرات نسخه‌ها
  README.md             همین فایل (مرجع ساختار و گزینه‌ها)
  GUIDE.md              راهنمای کامل: نصب، اولین تونل، عملیات، عیب‌یابی
  seed/                 کپی example/ تا پنل بدون ریپوی C هم کانفیگ شروع بسازد
    server.json  client.json
  static/
    style.css           تم روشن RTL + @font-face های محلی
    app.js              منطق صفحه‌ها (window.PB: dash/nodes/core/nodeForm/editor/pair/history)
    fonts/              Vazirmatn (4 وزن) + JetBrains Mono (2 وزن) + متن OFL شان
  deploy/
    injspoof@.service               واحد template هسته (یک instance = یک سرویس)
    injspoof-firewall@.service      بستن RST/ICMP کرنل با هر restart
    injspoof-panel.service          پنل با کاربر injspoof-panel
    injspoof-nodectl                helper ریشه‌پای کنترل هسته (+ sudoers.d)
  templates/            base + dashboard + nodes + node_form + core + editor + pair + history + login
```
