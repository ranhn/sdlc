#!/usr/bin/env python3
"""清理 LLM 缓存 SQLite 中过期的记录。

用法：
    python3 scripts/cleanup_cache.py --days 30           # 默认路径
    python3 scripts/cleanup_cache.py --db <path> --days 7  # 自定义路径

实现细节：
    - 自动探测每个表的"时间列"（列名包含 time/date/created/expire/updated/at）
    - 删除该列值早于截止时间的记录
    - 执行 VACUUM 回收磁盘空间
"""
import argparse
import os
import sqlite3
from datetime import datetime, timedelta


def cleanup_llm_cache(db_path: str, days: int) -> int:
    if not os.path.exists(db_path):
        print(f"[SKIP] 缓存文件不存在: {db_path}")
        return 0

    print(f"[INFO] 清理 {db_path} 中超过 {days} 天的记录")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    print(f"[INFO] 发现表: {tables}")

    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    total_deleted = 0

    for table in tables:
        if table.startswith("sqlite_"):
            continue
        try:
            cursor.execute(f"PRAGMA table_info({table})")
            columns = [row[1] for row in cursor.fetchall()]

            # 找第一个时间列
            time_cols = [
                c for c in columns
                if any(k in c.lower() for k in ("time", "date", "created", "expire", "updated", "_at"))
            ]
            if not time_cols:
                print(f"  [SKIP] {table}: 未找到时间列")
                continue

            time_col = time_cols[0]
            cursor.execute(
                f"DELETE FROM {table} WHERE {time_col} < ?",
                (cutoff,),
            )
            deleted = cursor.rowcount
            total_deleted += deleted
            if deleted > 0:
                print(f"  [OK] {table}.{time_col}: 删除 {deleted} 条")
        except Exception as e:
            print(f"  [FAIL] {table}: {e}")

    conn.commit()

    # VACUUM 必须在连接关闭前执行
    try:
        conn.execute("VACUUM")
        print("[OK] VACUUM 完成，磁盘空间已回收")
    except Exception as e:
        print(f"[WARN] VACUUM 失败: {e}")

    conn.close()

    # 显示清理后大小
    new_size = os.path.getsize(db_path) / 1024
    print(f"[INFO] 清理后大小: {new_size:.1f} KB")
    return total_deleted


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="清理 LLM 缓存 SQLite")
    parser.add_argument("--days", type=int, default=30, help="清理超过多少天的记录")
    parser.add_argument("--db", type=str, default=None, help="缓存数据库路径")
    args = parser.parse_args()

    if args.db:
        db_path = args.db
    else:
        db_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "backend", "threat", "data", "llm_cache.sqlite")
        )

    total = cleanup_llm_cache(db_path, args.days)
    print(f"[DONE] 共清理 {total} 条过期记录")
