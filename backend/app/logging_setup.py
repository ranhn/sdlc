"""应用日志初始化（给业务模块的 INFO 日志开个出入口）。

## 为什么需要它

Python 的 root logger 默认只处理 WARNING 及以上 —— 业务模块里的 ``logger.info(...)``
**全部被丢掉**。而运维最常问的恰恰是这些 INFO：

  · ``飞书通知已发送（漏洞 #12 漏洞已驳回 → 冉海南）→ ou_xxx``
  · ``飞书通知发送失败（漏洞 #12 …）→ ou_xxx：飞书返回 400（…）``
  · ``飞书流转通知跳过：reporter #7（手工账号）无 open_id``
  · ``飞书同步: 用户 总数 1608, 新建 0, …, 停用 2``

现象是：日志里只有 uvicorn 的访问日志，"这条通知到底发出去没有""他为什么没收到"
在日志里完全查不到 —— 实测踩过：为了确认一条通知是否送达，只能另写脚本同步重发一次。

## 做法

- 给 root logger 配一个 stderr handler；**uvicorn 自己的 logger 不受影响**
  （它自带 handler 且不向 root 传播，格式保持原样）；
- 级别可用 ``LOG_LEVEL`` 覆盖（排查用 DEBUG，生产降噪用 WARNING），默认 INFO；
- **幂等**：``main.py`` 与 ``app_entry.py`` 两条启动路径都会经过它，重复调用只生效一次；
- 不覆盖已被接管的场合：root 已有 handler（例如被外部日志平台配置过）时只调级别。
"""
from __future__ import annotations

import logging
import os
import threading

_LOCK = threading.Lock()
_done = False

# 含时间/级别/模块名 —— 排查时要能一眼看出"是哪条链路打的"
DEFAULT_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"

# 会刷屏的第三方库：httpx 每次请求都打一条 INFO，接了 LLM/飞书之后会把业务日志淹掉
_NOISY_LOGGERS = ("httpx", "httpcore")


def setup_logging() -> None:
    """初始化应用日志（幂等，可重复调用）。"""
    global _done
    with _LOCK:
        if _done:
            return
        _done = True

        level_name = (os.getenv("LOG_LEVEL") or "INFO").strip().upper()
        level = getattr(logging, level_name, None)
        if not isinstance(level, int):      # 写错（如 LOG_LEVEL=infoo）→ 回落到 INFO
            level = logging.INFO

        root = logging.getLogger()
        if root.handlers:
            # 已经被配置过（容器平台/外部日志配置）→ 只调整级别，不抢它的 handler
            root.setLevel(level)
        else:
            logging.basicConfig(level=level, format=DEFAULT_FORMAT)

        for name in _NOISY_LOGGERS:
            logging.getLogger(name).setLevel(max(level, logging.WARNING))
