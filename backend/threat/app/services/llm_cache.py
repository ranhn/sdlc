"""LLM 响应缓存。

以（model, seed, system_prompt, user_prompt, json_schema）的 SHA-256 为键，
将 LLM 的 JSON 输出落盘到 SQLite。相同输入在缓存有效期内直接命中，
从而保证"同一份需求文档多次分析结果字节级一致"，并省去重复 API 调用。
"""
from __future__ import annotations

import contextvars
import hashlib
import json
import logging
import sqlite3
import threading
import time
from pathlib import Path

from ..config import settings

from app.utils import network_clock as nc

logger = logging.getLogger(__name__)
_LOCAL = threading.local()

# 收集"当前建模 run"产生的缓存键，用于删除结果时精准失效对应缓存。
# 用 contextvars 而非 threading.local，避免 asyncio 下多个建模任务交错污染。
_run_cache_keys: contextvars.ContextVar[set[str]] = contextvars.ContextVar(
    "llm_run_cache_keys", default=set()
)


class LLMCache:
    """基于 SQLite 的进程内可复用响应缓存。

    线程安全：每个线程独立连接；写操作加进程级锁，避免 SQLite 写冲突。
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        db_path = db_path or Path(__file__).resolve().parents[2] / "data" / "llm_cache.sqlite"
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        """线程本地连接，避免跨线程共享 sqlite3.Connection。"""
        if not hasattr(_LOCAL, "conn"):
            conn = sqlite3.connect(str(self.db_path), timeout=30)
            conn.row_factory = sqlite3.Row
            conn.execute(
                """CREATE TABLE IF NOT EXISTS llm_cache (
                       k TEXT PRIMARY KEY,
                       v TEXT NOT NULL,
                       ts REAL NOT NULL
                   )"""
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_llm_cache_ts ON llm_cache(ts)")
            _LOCAL.conn = conn
        return _LOCAL.conn

    def _init_db(self) -> None:
        with self._lock:
            self._conn().commit()

    @staticmethod
    def build_key(
        system_prompt: str,
        user_prompt: str,
        model: str,
        seed: int,
        json_schema: dict | None = None,
        images_hash: str | None = None,
        temperature: float | None = None,
    ) -> str:
        """构造缓存键：模型 + 种子 + temperature + 完整 prompt + 约束 schema（+ 多模态图片内容哈希）。"""
        h = hashlib.sha256()
        h.update(model.encode("utf-8", "ignore"))
        h.update(str(seed).encode())
        # temperature 也纳入 key：改温度配置后不应再命中旧缓存（采样行为已不同）
        h.update(f"|t={temperature}".encode())
        h.update(system_prompt.encode("utf-8", "ignore"))
        h.update(user_prompt.encode("utf-8", "ignore"))
        if json_schema is not None:
            h.update(json.dumps(json_schema, sort_keys=True, ensure_ascii=False).encode("utf-8", "ignore"))
        if images_hash:
            # 图片内容哈希：同一份文档提取出的图片字节一致 → 命中缓存，结果可复现；
            # 换图/图片被重新编码 → 哈希不同 → miss，重新生成。
            h.update(b"|img|")
            h.update(images_hash.encode("utf-8", "ignore"))
        return h.hexdigest()

    def get(self, key: str) -> dict | None:
        """命中且未过期则返回缓存值，否则 None。"""
        if not settings.llm_cache_enabled:
            return None
        try:
            row = self._conn().execute("SELECT v, ts FROM llm_cache WHERE k=?", (key,)).fetchone()
        except sqlite3.Error:
            return None
        if not row:
            return None
        if nc.epoch() - row["ts"] > settings.llm_cache_ttl_seconds:
            return None
        try:
            return json.loads(row["v"])
        except (json.JSONDecodeError, TypeError):
            return None

    def set(self, key: str, value: dict) -> None:
        """写入缓存（幂等，覆盖旧值）。

        写失败必须**看得见**：老实现把 ``sqlite3.Error`` 静默吞掉，却仍然把这个键
        记进"本次 run 用过的缓存键"，于是结果里看着有 N 个键、库里可能只落了 N-1 条
        —— 下次同输入必然 miss、白跑一轮模型，表现就是"同一份输入两次结果不一样"
        （09-18 实际发生过：威胁识别那一步 32KB 的响应没落盘，第二遍重调模型，
        威胁数 75 → 72）。
        现在：失败 → warning + 重试一次；两次都失败 → error 日志，且**不记录该键**
        （没写进库里就没有"将来需要失效"的东西，记进去只会误导排查）。
        """
        if not settings.llm_cache_enabled:
            return
        try:
            payload = json.dumps(value, ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            logger.warning("LLM 响应缓存序列化失败，跳过写入 key=%s: %s", key[:12], exc)
            return
        for attempt in (1, 2):
            try:
                with self._lock:
                    conn = self._conn()
                    conn.execute(
                        "INSERT OR REPLACE INTO llm_cache(k, v, ts) VALUES (?,?,?)",
                        (key, payload, nc.epoch()),
                    )
                    conn.commit()
                # 写成功才记录：供删除结果时精准失效
                _run_cache_keys.get().add(key)
                return
            except sqlite3.Error as exc:
                # 不阻断主流程，但留痕：缓存拿不到就只能重跑模型，
                # 而模型在本项目配置下（reasoning 模型、温度走默认）不保证复现
                logger.warning(
                    "LLM 响应缓存写入失败（第 %d/2 次）key=%s: %s", attempt, key[:12], exc
                )
                time.sleep(0.05)
        logger.error(
            "LLM 响应缓存写入最终失败，本次不再记录该键（下次同输入会重新调用模型）key=%s",
            key[:12],
        )

    def remove_keys(self, keys: list[str]) -> int:
        """删除指定缓存键，返回删除条数。

        用于「删除建模结果时，精准失效该结果对应输入的缓存」。
        """
        if not keys:
            return 0
        try:
            with self._lock:
                cur = self._conn().executemany(
                    "DELETE FROM llm_cache WHERE k=?", [(k,) for k in keys]
                )
                self._conn().commit()
                return cur.rowcount
        except sqlite3.Error:
            return 0

    def clear(self) -> int:
        """清空缓存，返回删除条数（用于调试/管理）。"""
        with self._lock:
            cur = self._conn().execute("DELETE FROM llm_cache")
            self._conn().commit()
            return cur.rowcount


# 全局单例（进程内共享，线程安全）
_cache = LLMCache()


def get_llm_cache() -> LLMCache:
    return _cache


def record_cache_key(key: str) -> None:
    """把本次建模 run 访问过的缓存键记录下来。

    不仅 ``set()`` 新写入的键需要记录，**命中**（``get`` 直接返回）的键
    也必须记录——否则"某次建模全部命中缓存"时收集到的键为空，
    删除该结果后将无法精准失效对应缓存。
    """
    if key:
        _run_cache_keys.get().add(key)


def begin_cache_run() -> None:
    """开始收集当前建模 run 的缓存键（contextvars，并发任务间隔离）。"""
    _run_cache_keys.set(set())


def end_cache_run() -> list[str]:
    """结束收集，返回本次建模 run 产生的缓存键列表。"""
    keys = list(_run_cache_keys.get())
    _run_cache_keys.set(set())
    return keys
