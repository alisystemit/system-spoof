"""
injclient.py — کلاینت HTTP API نود injspoof

همه‌ی مسیرها از src/api.c:527-542 برداشته شده‌اند:
  GET  /api/v1/health | info | stats | stats/traffic | stats/pool | stats/log
       | config | metrics
  PUT  /api/v1/config
  POST /api/v1/reload?mode=hot|hard
احراز هویت: Authorization: Bearer <token> (src/api.c:204).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

API_VERSION_PATH = "/api/v1"


class NodeError(Exception):
    """خطای عمومی تماس با نود."""


class NodeUnreachable(NodeError):
    pass


class NodeAuth(NodeError):
    pass


class NodeAPI(NodeError):
    def __init__(self, status, message):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.message = message


class InjClient:
    def __init__(self, base_url, token, timeout=5.0):
        self.base_url = (base_url or "").rstrip("/")
        self.token = token or ""
        self.timeout = timeout

    # ---------------- transport ----------------
    def _req(self, method, path, body=None, content_type="application/json",
             raw=False):
        url = self.base_url + path
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method)
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        if data is not None:
            req.add_header("Content-Type", content_type)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = resp.read()
                status = resp.status
        except urllib.error.HTTPError as exc:
            payload = exc.read() or b""
            status = exc.code
            text = payload.decode("utf-8", "replace")
            if status in (401, 403):
                raise NodeAuth(f"توکن API پذیرفته نشد (HTTP {status})") from exc
            raise NodeAPI(status, text[:400] or exc.reason) from exc
        except (urllib.error.URLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise NodeUnreachable(f"اتصال به {url} برقرار نشد: {reason}") from exc

        if raw:
            return payload.decode("utf-8", "replace")
        if not payload:
            return {}
        try:
            parsed = json.loads(payload.decode("utf-8", "replace"))
        except json.JSONDecodeError as exc:
            raise NodeError(f"پاسخ نود JSON معتبر نیست: {exc}") from exc
        if status >= 400 and isinstance(parsed, dict):
            raise NodeAPI(status, parsed.get("error", "unknown"))
        return parsed

    # ---------------- endpoints ----------------
    def health(self):
        return self._req("GET", f"{API_VERSION_PATH}/health")

    def info(self):
        return self._req("GET", f"{API_VERSION_PATH}/info")

    def stats(self):
        return self._req("GET", f"{API_VERSION_PATH}/stats")

    def stats_traffic(self):
        return self._req("GET", f"{API_VERSION_PATH}/stats/traffic")

    def stats_pool(self):
        return self._req("GET", f"{API_VERSION_PATH}/stats/pool")

    def stats_log(self):
        return self._req("GET", f"{API_VERSION_PATH}/stats/log")

    def metrics_text(self):
        return self._req("GET", f"{API_VERSION_PATH}/metrics", raw=True)

    def get_config(self):
        return self._req("GET", f"{API_VERSION_PATH}/config")

    def put_config(self, config_dict_or_text):
        if isinstance(config_dict_or_text, (dict, list)):
            body = json.dumps(config_dict_or_text, indent=2, ensure_ascii=False)
        else:
            body = str(config_dict_or_text)
        return self._req("PUT", f"{API_VERSION_PATH}/config",
                         body=body.encode("utf-8"))

    def reload(self, mode="hot"):
        if mode not in ("hot", "hard"):
            raise ValueError("mode باید hot یا hard باشد")
        return self._req("POST", f"{API_VERSION_PATH}/reload?mode={mode}", body=b"")

    def probe(self):
        """بهداشت کامل: health + info + خلاصه‌ی stats برای صفحه‌ی تست اتصال."""
        info = self.info()
        stats = self.stats()
        return {"info": info, "stats": stats, "health": self.health()}


def parse_prometheus(text):
    """متن Prometheus را به dict ساده تبدیل می‌کند (برای نمایش سریع)."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, value = line.partition(" ")
        try:
            out[name] = float(value)
        except ValueError:
            continue
    return out
