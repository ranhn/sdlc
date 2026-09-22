"""飞书每周定时同步的判定逻辑回归测试（app/scheduler.py）。

用法（在 backend 目录下）：
    python -m pytest tests/test_weekly_sync.py -v
    python tests/test_weekly_sync.py

为什么要有它：定时任务的坑都集中在"判定"上，而且**错了不会报错** —— 表现是
"周一早上没同步""同步跑了两遍""半夜莫名其妙跑了一次"。这里把判定掰成纯函数
（plan_weekly_run）逐条钉住：

  1. 时区：容器是 UTC，需求是"周一早上八点"= **北京时间**；目标小时小于 8 时
     换算顺序反了会跨到前一天（算错一整天），所以专门钉一条 hour=3 的用例；
  2. 漏跑要补：晚到当天晚上、甚至周日才起来检查，也应该把本周那次补上；
  3. 不能重复跑：本周已经同步过（含**手动**同步）就不再跑；
  4. 开关：FEISHU_SYNC_WEEKLY=0 一律不跑。
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import scheduler  # noqa: E402
from app.database import Base  # noqa: E402
from app.models import OperationLog  # noqa: E402
from app.routers import feishu as feishu_router  # noqa: E402
from app.security import write_operation_log  # noqa: E402

CST = scheduler.CST
# 2026-09-21 是周一（2026-09-22 为周二）
MON = datetime(2026, 9, 21, tzinfo=CST)


def _utc(dt: datetime) -> datetime:
    """北京时间 → naive UTC（库里存的就是 naive UTC）。"""
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def _plan(now: datetime, last: datetime | None = None, *,
          enabled: bool = True, weekday: int = 1, hour: int = 8):
    return scheduler.plan_weekly_run(_utc(now), _utc(last) if last else None,
                                     enabled=enabled, weekday=weekday, hour=hour)


def _make_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


# ============ 1. 时区换算 ============
def test_target_time_is_beijing_monday_8am():
    """周一 08:00（北京）= 周一 00:00 UTC。"""
    target = scheduler.weekly_target_utc(_utc(datetime(2026, 9, 23, 15, tzinfo=CST)),
                                         weekday=1, hour=8)
    assert target == datetime(2026, 9, 21, 0, 0), target


def test_target_hour_below_8_does_not_shift_the_day():
    """目标小时小于 8（如凌晨 3 点北京时间 = 前一天 19:00 UTC）必须仍属本周一。

    这条专治"先在 UTC 里算小时再减偏移"的写法：那样子 3 点会算成周一 19:00 UTC
    （其实是周一 03:00 + 8h 的错位），整次判定就会差一天。
    """
    target = scheduler.weekly_target_utc(_utc(datetime(2026, 9, 23, 15, tzinfo=CST)),
                                         weekday=1, hour=3)
    assert target == datetime(2026, 9, 20, 19, 0), target      # 周日 19:00 UTC = 周一 03:00 北京


def test_target_follows_configured_weekday():
    """配置成周日（7）时，目标落在本周日而不是周一。"""
    target = scheduler.weekly_target_utc(_utc(datetime(2026, 9, 23, 9, tzinfo=CST)),
                                         weekday=7, hour=8)
    assert target == datetime(2026, 9, 27, 0, 0), target       # 2026-09-27 是周日


# ============ 2. 到点前不跑、到点跑 ============
def test_does_not_run_before_target():
    ok, why = _plan(datetime(2026, 9, 21, 7, 59, tzinfo=CST))
    assert ok is False and "未到" in why, why


def test_runs_at_target():
    ok, why = _plan(datetime(2026, 9, 21, 8, 0, tzinfo=CST))
    assert ok is True, why


def test_runs_later_same_week_as_catch_up():
    """当天晚上/本周内才起来检查也要补上（进程重启、机器休眠都会错过整点）。"""
    for when in (datetime(2026, 9, 21, 20, 30, tzinfo=CST),
                 datetime(2026, 9, 26, 11, 0, tzinfo=CST)):     # 周六
        ok, why = _plan(when)
        assert ok is True, f"{when}: {why}"


# ============ 3. 本周跑过就不跑（手动也算） ============
def test_skips_when_already_synced_this_week():
    ok, why = _plan(datetime(2026, 9, 21, 9, 0, tzinfo=CST),
                    datetime(2026, 9, 21, 8, 30, tzinfo=CST))
    assert ok is False and "本周已同步" in why, why


def test_manual_sync_counts_as_done():
    """有人周一早上已经手动点过同步 → 定时任务不再重复拉一遍 1600 人。"""
    ok, why = _plan(datetime(2026, 9, 21, 10, 0, tzinfo=CST),
                    datetime(2026, 9, 21, 8, 5, tzinfo=CST))
    assert ok is False, why


def test_last_week_sync_does_not_block_this_week():
    ok, why = _plan(datetime(2026, 9, 21, 8, 1, tzinfo=CST),
                    datetime(2026, 9, 20, 23, 0, tzinfo=CST))   # 上周日同步的
    assert ok is True, why


def test_next_monday_before_target_waits_again():
    """下周一 07:59：上周已跑过 → 还没到点，本轮不跑。"""
    ok, why = _plan(datetime(2026, 9, 28, 7, 59, tzinfo=CST),
                    datetime(2026, 9, 21, 8, 1, tzinfo=CST))
    assert ok is False and "未到" in why, why


# ============ 4. 开关与配置解析 ============
def test_disabled_by_env():
    ok, why = _plan(datetime(2026, 9, 21, 12, 0, tzinfo=CST), enabled=False)
    assert ok is False and "已关闭" in why, why


def test_env_parsing_uses_defaults_on_garbage():
    saved = {k: os.environ.get(k) for k in ("FEISHU_SYNC_WEEKLY", "FEISHU_SYNC_WEEKDAY", "FEISHU_SYNC_HOUR")}
    try:
        os.environ.pop("FEISHU_SYNC_WEEKLY", None)
        assert scheduler.weekly_enabled() is True          # 默认开
        os.environ["FEISHU_SYNC_WEEKLY"] = "0"
        assert scheduler.weekly_enabled() is False
        os.environ["FEISHU_SYNC_WEEKDAY"] = "9"            # 越界 → 回默认周一
        os.environ["FEISHU_SYNC_HOUR"] = "abc"             # 非数字 → 回默认 8 点
        assert scheduler.target_weekday() == 1
        assert scheduler.target_hour() == 8
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# ============ 5. "最近一次同步"取自操作日志（手动/定时都算） ============
def test_last_sync_reads_operation_log():
    db = _make_db()
    db.add_all([
        OperationLog(username="admin", action="login", module="auth"),
        OperationLog(username="admin", action="feishu_sync", module="admin",
                     created_at=datetime(2026, 9, 21, 0, 5)),
        OperationLog(username="定时任务", action="feishu_sync", module="admin",
                     created_at=datetime(2026, 9, 28, 0, 5)),
        OperationLog(username="admin", action="feishu_sync_weekly", module="admin",
                     created_at=datetime(2026, 10, 5, 0, 5)),
    ])
    db.commit()
    assert scheduler._last_sync_at(db) == datetime(2026, 10, 5, 0, 5)
    assert scheduler._last_sync_at(_make_db()) is None      # 空库 → None（从没同步过）


def test_timed_task_writes_named_audit_row():
    """定时任务没有登录用户：审计日志要落成"定时任务"，而不是 anonymous。"""
    db = _make_db()
    write_operation_log(db, None, "feishu_sync", "admin", "飞书同步（定时任务）: 用户 总数 10",
                        username="定时任务")
    row = db.query(OperationLog).first()
    assert row.username == "定时任务", row.username
    assert row.user_id is None, row.user_id
    # 不传 username 时保持原行为
    write_operation_log(db, None, "x", "y", "z")
    assert db.query(OperationLog).order_by(OperationLog.id.desc()).first().username == "anonymous"


# ============ 6. 手动与定时互斥 ============
def test_concurrent_sync_is_rejected():
    """锁被占住时，第二个同步入口必须拿到 SyncInProgress（手动→409，定时→跳过）。"""

    async def _run():
        async with feishu_router.SYNC_LOCK:
            try:
                await feishu_router.run_feishu_sync(None, None, trigger="定时任务")
            except feishu_router.SyncInProgress:
                return True
            return False

    assert asyncio.run(_run()) is True


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
