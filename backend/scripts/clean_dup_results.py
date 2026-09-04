"""清理同一 owner 在 60 秒窗口内产生的双结果（保留威胁数更多的一条）。

现象：之前 in-flight 去重未上线时，1 秒内双击会导致后端跑两次 LLM，
      生成两个独立 result_id。两条结果同时出现在历史列表里，组件/数据流/威胁
      都不一致，给用户造成困扰。

用法（在仓库根目录执行）：
    python backend/scripts/clean_dup_results.py
    # 或带参数
    python backend/scripts/clean_dup_results.py --window 60 --dry-run

依赖：脚本直接读 backend/data/results/*.json，
      不依赖 FastAPI / 任何服务进程。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

# 与 backend/threat/app/services/result_store.py 的 _RESULT_ID_RE 保持一致
import re

from app.utils import network_clock as nc
_RESULT_ID_RE = re.compile(r"^[0-9A-Za-z-]{16,40}$")

# 结果文件目录（与 result_store.RESULTS_DIR 一致）
RESULTS_DIR = (
    Path(__file__).resolve().parents[1]
    / "threat"
    / "data"
    / "results"
)


def _load(p: Path) -> dict | None:
    try:
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"  ⚠ 读取 {p.name} 失败: {e}", file=sys.stderr)
        return None


def _threat_count(rec: dict) -> int:
    """从结果里提取威胁数（threatCount > sum(threats) > 0）。"""
    stats = rec.get("stats") or {}
    if isinstance(stats.get("threatCount"), int):
        return int(stats["threatCount"])
    diagrams = ((rec.get("model") or {}).get("detail") or {}).get("diagrams") or []
    total = 0
    for d in diagrams:
        for c in d.get("cells") or []:
            total += len(c.get("threats") or [])
    return total


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--window", type=int, default=60, help="同指纹去重窗口（秒），默认 60")
    ap.add_argument("--dry-run", action="store_true", help="只看，不删")
    args = ap.parse_args()

    if not RESULTS_DIR.exists():
        print(f"❌ 结果目录不存在: {RESULTS_DIR}")
        return 1

    cutoff = nc.epoch() - args.window
    records: list[dict] = []
    for p in sorted(RESULTS_DIR.glob("*.json")):
        if p.name.startswith("."):
            continue
        rec = _load(p)
        if not rec:
            continue
        records.append({"path": p, "rec": rec})

    if not records:
        print(f"ℹ 结果目录 {RESULTS_DIR} 无记录")
        return 0

    # 按 (owner_username, input_fingerprint) 分组
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for item in records:
        rec = item["rec"]
        key = (
            rec.get("owner_username") or "",
            rec.get("input_fingerprint") or "",
        )
        # 仅当窗口期内 + 有 fingerprint 才纳入去重候选
        if rec.get("created_at", 0) >= cutoff and key[1]:
            groups[key].append(item)

    if not groups:
        print(f"ℹ 窗口期 {args.window}s 内无同 owner+fp 的重复结果（已有指纹结果数 = 0）")
        print(
            "  说明：in-flight 去重已在 2026-09-03 上线，"
            "新提交会自动去重；本脚本主要用于清理上线前产生的双结果。"
        )
        return 0

    deleted = 0
    kept = 0
    for key, items in groups.items():
        if len(items) < 2:
            continue
        # 按威胁数降序；威胁数相同按 created_at 升序（保留先创建的）
        items.sort(
            key=lambda x: (
                -_threat_count(x["rec"]),
                x["rec"].get("created_at", 0),
            )
        )
        keep = items[0]
        victims = items[1:]
        owner, fp = key
        print(f"\n📦 owner={owner!r} fp={fp!r} 共 {len(items)} 条，保留 1 条、删除 {len(victims)} 条：")
        for i, it in enumerate(items):
            rec = it["rec"]
            mark = "✅ 保留" if it is keep else "🗑 删除"
            print(
                f"  {mark}: {rec.get('id')} | "
                f"created_at={rec.get('created_at'):.0f} | "
                f"threats={_threat_count(rec)} | "
                f"title={rec.get('title')!r}"
            )
        for v in victims:
            if args.dry_run:
                print(f"  (dry-run) 跳过删除: {v['path']}")
                continue
            try:
                v["path"].unlink()
                deleted += 1
            except OSError as e:
                print(f"  ⚠ 删除失败 {v['path']}: {e}", file=sys.stderr)
        kept += 1

    print(
        f"\n{'[DRY-RUN] ' if args.dry_run else ''}处理完成："
        f"保留 {kept} 组，删除 {deleted} 条。"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
