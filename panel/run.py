"""
run.py — اجرای پنل در محیط توسعه

    python run.py                      # http://127.0.0.1:8088
    PANEL_PORT=9000 python run.py

در پروداکشن لینوکسی به‌جای این فایل از gunicorn/systemd استفاده کنید
(اسکریپت install.sh هر دو را می‌چیند). reloader عمداً خاموش است تا نخ
نمونه‌بردار (Collector) دوباره ساخته نشود.
"""

import os

from app import APP

if __name__ == "__main__":
    host = os.environ.get("PANEL_HOST", "127.0.0.1")
    port = int(os.environ.get("PANEL_PORT", "8088"))
    debug = os.environ.get("PANEL_DEBUG", "") == "1"
    APP.run(host=host, port=port, debug=debug, use_reloader=False, threaded=True)
