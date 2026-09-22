"""通知/导出的基地址解析回归测试（utils/public_url.py）。

用法（在 backend 目录下）：
    python -m pytest tests/test_public_url.py -v
    python tests/test_public_url.py

为什么要有它：
  1. **通知的读者是另一个人**：链接必须是"别人也点得开"的地址，所以 PUBLIC_BASE_URL 必须
     优先于"操作人此刻访问的地址"（实测踩过：本机 127.0.0.1:5173 的链接发给了外部同事）；
  2. **导出反过来**：文件由操作人自己下载，用"他此刻访问的地址"永远是对的 —— 两套语义
     混用就会有一处是错的，所以两个函数各钉一遍；
  3. **静默配错最贵**：PUBLIC_BASE_URL 配成 http:// 或内网 IP 时，服务端一切正常、
     只有收件人点不开；这里钉住"必须打 WARNING"，让问题在日志里可见。
"""

from __future__ import annotations

import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.utils import public_url  # noqa: E402


class _Req:
    """最小请求替身：只要 headers.get 与 base_url 两件事（与 FastAPI Request 同形态）。"""

    def __init__(self, referer: str | None = None, origin: str | None = None,
                 base: str = "http://testserver/"):
        self.headers = {"referer": referer, "origin": origin}
        self.base_url = base


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:  # noqa: D102
        self.messages.append(record.getMessage())


class _env:
    """临时改环境变量（用 with），退出时恢复原值。"""

    def __init__(self, **kv):
        self.kv = kv
        self.saved: dict[str, str | None] = {}

    def __enter__(self):
        for k, v in self.kv.items():
            self.saved[k] = os.environ.get(k)
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return self

    def __exit__(self, *exc):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return False


def _capture():
    h = _Capture()
    public_url.logger.addHandler(h)
    return h


def _uncapture(h):
    public_url.logger.removeHandler(h)


# ============ 1. 通知：显式配置优先，且归一尾斜杠 ============
def test_public_url_prefers_explicit_config():
    with _env(PUBLIC_BASE_URL="https://sdlc.vesync.cn/", CORS_ORIGINS="http://other:5173"):
        # 带尾斜杠 → 去掉（否则拼出 https://sdlc.vesync.cn//vulnerabilities/...）
        assert public_url.public_base_url(_Req(referer="http://localhost:5173/")) == \
            "https://sdlc.vesync.cn"


def test_expressly_configured_url_is_used_even_without_request():
    """重置密码那条通知拿不到 request 上下文，也必须能拿到对外地址。"""
    with _env(PUBLIC_BASE_URL="https://sdlc.vesync.cn"):
        assert public_url.public_base_url(None) == "https://sdlc.vesync.cn"


# ============ 2. 通知：没配时才退回请求上下文 / CORS ============
def test_public_url_falls_back_to_request_then_cors():
    with _env(PUBLIC_BASE_URL=None, CORS_ORIGINS="https://cors.example.com,https://x"):
        # 有 request → 用操作人访问的地址（Referer 优先）
        assert public_url.public_base_url(_Req(referer="https://sdlc.vesync.cn/some/page")) == \
            "https://sdlc.vesync.cn"
        # 没 request → CORS_ORIGINS 第一条
        assert public_url.public_base_url(None) == "https://cors.example.com"


def test_public_url_empty_when_nothing_configured():
    with _env(PUBLIC_BASE_URL=None, CORS_ORIGINS=None):
        assert public_url.public_base_url(None) == ""


# ============ 3. 导出：与通知相反，永远用"操作人此刻的地址" ============
def test_export_url_ignores_public_base_url():
    with _env(PUBLIC_BASE_URL="https://sdlc.vesync.cn"):
        # 导出文件由操作人自己下载 —— 他从本机导出就该是本机链接
        assert public_url.resolve_request_base_url(_Req(referer="http://localhost:5173/page")) == \
            "http://localhost:5173"
        # Referer 缺失时退到 Origin
        assert public_url.resolve_request_base_url(_Req(origin="http://127.0.0.1:8001")) == \
            "http://127.0.0.1:8001"
        # 都没有 → 请求自身的 scheme://host
        assert public_url.resolve_request_base_url(_Req()) == "http://testserver"


# ============ 4. 配错要能看见（否则只有收件人点不开，服务端毫无痕迹） ============
def test_http_config_and_internal_fallback_warn():
    h = _capture()
    try:
        with _env(PUBLIC_BASE_URL="http://sdlc.vesync.cn"):
            assert public_url.public_base_url(None) == "http://sdlc.vesync.cn"
        assert any("不是 https" in m for m in h.messages), h.messages

        h.messages.clear()
        with _env(PUBLIC_BASE_URL=None, CORS_ORIGINS=None):
            public_url.public_base_url(_Req(referer="http://127.0.0.1:5173/"))
        assert any("内网/本机地址" in m for m in h.messages), h.messages
    finally:
        _uncapture(h)


def test_normal_https_config_does_not_warn():
    h = _capture()
    try:
        with _env(PUBLIC_BASE_URL="https://sdlc.vesync.cn"):
            public_url.public_base_url(None)
        assert h.messages == [], h.messages
    finally:
        _uncapture(h)


def test_is_internal_host():
    for host in ("localhost", "127.0.0.1", "10.1.2.3", "192.168.1.9", "172.16.0.5", "::1"):
        assert public_url.is_internal_host(host), host
    for host in ("sdlc.vesync.cn", "sdlc.example.com", "8.8.8.8", ""):
        assert not public_url.is_internal_host(host), host


# ============ 运行器 ============
def _main() -> int:
    cases = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in cases:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(cases) - failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_main())
