"""轻量进程内滑动窗口限流器。

**部署约束（务必阅读）**：本实现为**进程内**状态（``self._hits`` 保存在内存），
仅适用于**单机单 worker** 场景（即本项目默认部署形态：uvicorn 默认单 worker /
docker-compose 后端单实例）。

- 若以 ``uvicorn --workers N``（N>1）或 gunicorn 多 worker 启动，各 worker 有独立的
  限流计数，会导致限流**失效**（总限额变成 N 倍）。
- 多 worker / 多机水平扩容前，必须先替换为 Redis 集中式限流（接口可保持不变）。
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque


class RateLimiter:
    """按 key（如 IP）做滑动窗口限流。

    Args:
        max_requests: 窗口内允许的最大请求数。
        window_seconds: 窗口时长（秒）。
    """

    def __init__(self, max_requests: int, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, Deque[float]] = defaultdict(deque)

    def set_config(self, max_requests: int, window_seconds: int | None = None) -> None:
        """运行时更新限流参数（可在应用启动后按配置覆盖默认值）。"""
        self.max_requests = max_requests
        if window_seconds is not None:
            self.window_seconds = window_seconds

    def allow(self, key: str) -> bool:
        """判断 key 当前是否允许请求，并记录一次访问。"""
        now = time.monotonic()
        q = self._hits[key]
        # 清除窗口外的记录
        while q and now - q[0] >= self.window_seconds:
            q.popleft()
        if len(q) >= self.max_requests:
            return False
        q.append(now)
        return True


rate_limiter = RateLimiter(max_requests=5)
