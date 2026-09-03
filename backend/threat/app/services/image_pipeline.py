"""图片管道：合并、压缩、截断图片 data URI 列表，供 LLM 多模态调用。

职责单一：所有"图片进 LLM 之前"的处理都集中在这里，方便统一调参 / 调策略。
模块内函数都是同步的，便于在 task 协程里直接调用。
"""
from __future__ import annotations

import hashlib
import logging
from typing import Iterable

logger = logging.getLogger(__name__)

# ---- 全局默认上限（与前端 InputPanel.vue 中的常量保持一致） ----
# 总字节上限：约 8MB（data URI 含 base64 膨胀系数 ≈ 4/3 → 原始图约 6MB）
DEFAULT_MAX_TOTAL_BYTES = 8 * 1024 * 1024
# 单张字节上限：约 3MB（防止单张超 4MB 的图）
DEFAULT_MAX_SINGLE_BYTES = 3 * 1024 * 1024
# 张数上限：避免 prompt 中图片列表过长（影响 LLM 注意力与延迟）
DEFAULT_MAX_COUNT = 20


def _hash_image(uri: str) -> str:
    """对 data URI 字符串做 SHA-1 哈希（去重用）。"""
    return hashlib.sha1((uri or "").encode("utf-8", "ignore")).hexdigest()


def merge_image_data_uris(
    *groups: Iterable[str] | None,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_single_bytes: int = DEFAULT_MAX_SINGLE_BYTES,
    max_count: int = DEFAULT_MAX_COUNT,
) -> tuple[list[str], int, int]:
    """合并多组图片 data URI，按 (单张上限 / 总字节上限 / 张数上限) 截断并去重。

    Args:
        *groups: 任意个图片 data URI 列表（如 attachments、pasted_images）。
            会按入参顺序拼接，**前面的组优先级更高**（先被保留）。
        max_total_bytes: 合并后所有图片总字节上限。
        max_single_bytes: 单张图片字节上限（超过则丢弃）。
        max_count: 最多保留张数。

    Returns:
        (merged, truncated_count, dedup_count)
        - merged: 合并后保留的图片 data URI 列表
        - truncated_count: 被截断/丢弃的图片张数
        - dedup_count: 被去重掉（重复哈希）的图片张数
    """
    seen_hashes: set[str] = set()
    merged: list[str] = []
    truncated = 0
    deduped = 0
    total = 0

    for grp in groups:
        if not grp:
            continue
        for uri in grp:
            if not uri or not isinstance(uri, str):
                continue
            if len(uri) > max_single_bytes:
                truncated += 1
                continue
            h = _hash_image(uri)
            if h in seen_hashes:
                deduped += 1
                continue
            if total + len(uri) > max_total_bytes:
                truncated += 1
                continue
            if len(merged) >= max_count:
                truncated += 1
                continue
            seen_hashes.add(h)
            merged.append(uri)
            total += len(uri)

    if truncated or deduped:
        logger.info(
            "merge_image_data_uris: kept=%d truncated=%d deduped=%d total_bytes=%d",
            len(merged), truncated, deduped, total,
        )
    return merged, truncated, deduped


def validate_image_byte_budget(
    images: Iterable[str] | None,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> int:
    """校验图片列表的总字节数是否超限。返回实际总字节数（供调用方报错/截断）。

    设计目标：把"图片超 8MB"这种隐性限制转成显式 400/413 错误，
    避免悄悄传给 LLM 后被某些网关直接 5xx 拒。
    """
    if not images:
        return 0
    total = 0
    for u in images:
        if isinstance(u, str):
            total += len(u)
    if total > max_total_bytes:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=413,
            detail=(
                f"图片字节总量 {total} 超过上限 {max_total_bytes}（约 {max_total_bytes // 1024 // 1024}MB）。"
                "请减少图片张数或压缩后再提交。"
            ),
        )
    return total
