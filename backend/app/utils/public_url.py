"""平台地址解析：给"别人"看的链接该用哪个基地址。

这里有**两种语义**，混用就会出错，所以刻意分成两个函数：

  · ``public_base_url()`` — 飞书通知 / 卡片按钮用。
    读者是**另一个人**（被指派的研发、被重置密码的同事），必须是别人也点得开的地址：
    显式配置 ``PUBLIC_BASE_URL`` 优先（生产配成对外域名，如 https://sdlc.vesync.cn），
    没配才退回"操作人此刻访问的地址"，并在解析出内网/本机地址时打 WARNING
    —— 实测踩过：本机 127.0.0.1:5173 的链接发给了外部同事，现象是"他点不开"。

  · ``resolve_request_base_url()`` — CSV / Word 导出里的超链接用。
    文件由**操作人自己**下载，用"他此刻访问的地址"永远是对的
    （多域名 / 内外网双入口都能自适应）。

⚠️ 配置生效条件：``PUBLIC_BASE_URL`` 是**容器环境变量**（compose 的 env_file 注入），
改完 .env 必须 ``docker compose up -d --force-recreate sdlc`` 才会生效 ——
只 ``restart`` 拿到的仍是旧值（env_file 在容器创建时就固化了，实测踩过）。
"""
from __future__ import annotations

import logging
import os
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

# 只在本机/内网可达的主机名与网段（粗判即可：目的是"提醒配置错了"，不是做安全判定）
_INTERNAL_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "::1")
_INTERNAL_PREFIXES = ("127.", "10.", "192.168.", "172.1", "172.2", "172.3")


def _cors_first() -> str:
    """CORS_ORIGINS 的第一条（部署时配置的前端白名单，生产就是对外域名）。"""
    cors = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
    return cors[0].rstrip("/") if cors else ""


def is_internal_host(host: str) -> bool:
    """主机名是否只在本机/内网可达。"""
    h = (host or "").lower()
    return h in _INTERNAL_HOSTS or h.startswith(_INTERNAL_PREFIXES)


def resolve_request_base_url(request) -> str:
    """**导出用**：操作人此刻访问的平台地址。

    优先级：
      1. ``Referer``：导出必然发生在平台页面上（axios 的 blob 请求同源带 Referer），
         取它的 origin 就是用户此刻访问的地址 —— 多域名 / 内外网双入口都自适应；
      2. ``Origin``：部分客户端/代理会带（跨域 XHR 一定带）；
      3. ``CORS_ORIGINS`` 的第一条：部署时配置的前端白名单；
      4. 请求自身的 scheme://host：前端由 FastAPI 托管（同源）时一定正确。

    为什么不写死域名：同一份代码要跑在本地、内网、多套部署环境上，写死必然有一处是错的。
    """
    for raw in (request.headers.get("referer"), request.headers.get("origin")):
        if not raw:
            continue
        try:
            parts = urlsplit(raw)
            if parts.scheme and parts.netloc:
                return f"{parts.scheme}://{parts.netloc}"
        except Exception:  # noqa: BLE001
            continue
    cors = _cors_first()
    if cors:
        return cors
    return str(request.base_url).rstrip("/")


def public_base_url(request=None) -> str:
    """**通知用**：收件人（另一个人）也点得开的平台地址。

    ``PUBLIC_BASE_URL`` 优先；没配时退回请求上下文（有 request）或 CORS_ORIGINS 第一条。
    拿到内网/本机地址时打 WARNING —— 页面上的现象是"收件人点链接打不开"，
    这条日志把原因直接指到配置上。
    """
    explicit = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")
    if explicit:
        # 配了 http:// 也要提醒：飞书卡片按钮在生产会因"不安全"被浏览器拦/降级，
        # 而这类问题在服务端日志里毫无痕迹（只在收件人的手机上表现出来），所以提前喊一声。
        if not explicit.startswith("https://"):
            logger.warning(
                "PUBLIC_BASE_URL 不是 https（当前 %s）—— 飞书卡片按钮指向 http 会被浏览器"
                "判为不安全（生产已启用 HTTPS 强制跳转，点开也会被跳走）。建议改成 https://",
                explicit,
            )
        return explicit

    base = resolve_request_base_url(request) if request is not None else _cors_first()
    if not base:
        return ""
    try:
        host = (urlsplit(base).hostname or "").lower()
    except Exception:  # noqa: BLE001
        host = ""
    if is_internal_host(host):
        logger.warning(
            "通知里的链接是内网/本机地址（%s）—— 收件人在别的网络下点不开。"
            "生产环境请配置 PUBLIC_BASE_URL=https://<对外域名>",
            base,
        )
    return base
