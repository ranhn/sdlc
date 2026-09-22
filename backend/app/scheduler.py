"""进程内定时任务：目前只有「每周一早上八点自动同步飞书通讯录」。

## 为什么自己写一个循环，而不是上 APScheduler / 系统 cron

  · 不想为一件小事加依赖（`pip install apscheduler` 还要重建镜像）；
  · 系统 cron 要登服务器加一行、且容器内外两套时间口径容易搞错；
  · 单进程 uvicorn（见 backend/Dockerfile 的 CMD）+ 一个 asyncio 循环足够，随代码一起发布。
  ⚠️ 前提是**单 worker**：若将来改成 `uvicorn --workers N`，每个进程都会起一个循环 →
     必须把这里挪到独立进程或系统 cron，否则会 N 倍重复同步。

## 四个刻意的设计（都是踩过或容易踩的坑）

1. **时区按北京时间**：容器里是 UTC，而需求是"周一早上八点"= 北京时间。
   中国没有夏令时，所以用固定 UTC+8 偏移即可 —— 也不用 `ZoneInfo("Asia/Shanghai")`
   （slim 镜像可能没装 tzdata，那样会直接抛异常）。
2. **漏跑要补**：不是"睡到下周一点再醒"（进程重启、机器休眠、deps 更新都会错过），
   而是**每 30 分钟醒一次**判断"本周的目标时刻已过、且本周还没同步过" → 晚一点也能补上。
3. **不重复跑**：以**同步记录**为准（操作日志里本周目标时刻之后的 `feishu_sync`）——
   内存标记一重启就丢，会出现同一小时跑两遍。顺带一个好处：**手动同步也算数**
   （有人在周一早上已经点过同步，定时任务就不再重复跑一遍 1600 人）。
4. **与手动同步互斥**：共用 feishu.run_feishu_sync 里那把锁；抢不到就跳过本轮，
   30 分钟后再看（定时任务宁可晚点，也不和正在跑的手动同步抢飞书接口配额）。
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# 北京时间固定偏移（中国无夏令时）
CST = timezone(timedelta(hours=8))

# 检查间隔：30 分钟。比"睡到点"笨，但能补上重启/晚点 —— 一周只跑一次的任务，
# 多醒几次的代价可以忽略。
CHECK_INTERVAL_SECONDS = 30 * 60

# 操作日志里算作"同步过"的动作（手动与定时都在这两个里）
SYNC_ACTIONS = ("feishu_sync", "feishu_sync_weekly")


def _env_flag(name: str, default: bool = True) -> bool:
    """读布尔型环境变量：1/true/yes/on 为真，0/false/no/off 为假，未设置取默认。"""
    raw = (os.getenv(name) or "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def weekly_enabled() -> bool:
    """定时同步总开关，默认开（FEISHU_SYNC_WEEKLY=0 可关）。"""
    return _env_flag("FEISHU_SYNC_WEEKLY", True)


def target_weekday() -> int:
    """目标星期几（ISO：1=周一 … 7=周日），默认 1。"""
    try:
        v = int(os.getenv("FEISHU_SYNC_WEEKDAY", "1") or 1)
    except ValueError:
        v = 1
    return v if 1 <= v <= 7 else 1


def target_hour() -> int:
    """目标小时（**北京时间** 0-23），默认 8。"""
    try:
        v = int(os.getenv("FEISHU_SYNC_HOUR", "8") or 8)
    except ValueError:
        v = 8
    return v if 0 <= v <= 23 else 8


def weekly_target_utc(now_utc: datetime, *, weekday: int, hour: int) -> datetime:
    """本周的目标时刻，返回**naive UTC**（与库里 naive UTC 的时间口径一致，便于比较）。

    注意换算顺序：先在**北京时间**里算出"本周 X 点"，再减 8 小时换成 UTC ——
    若反过来（先在 UTC 里算小时再减偏移），目标小时小于 8 时会跨到前一天，算错一整天。
    """
    now_cst = now_utc.replace(tzinfo=timezone.utc).astimezone(CST)
    monday_cst = (now_cst - timedelta(days=now_cst.isoweekday() - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0,
    )
    target_cst = monday_cst + timedelta(days=weekday - 1, hours=hour)
    return target_cst.astimezone(timezone.utc).replace(tzinfo=None)


def plan_weekly_run(now_utc: datetime, last_sync_utc: datetime | None, *,
                    enabled: bool, weekday: int, hour: int) -> tuple[bool, str]:
    """纯函数：这一轮该不该跑 + 原因（原因写进日志，便于回答"为什么没跑"）。

    Args:
        now_utc: 当前时间（naive UTC 或带时区都行）
        last_sync_utc: 最近一次**成功同步**的时间（naive UTC；None = 从没同步过）
        enabled / weekday / hour: 开关与目标时刻（北京时间）

    Returns:
        (should_run, reason)
    """
    if not enabled:
        return False, "定时同步已关闭（FEISHU_SYNC_WEEKLY=0）"

    target = weekly_target_utc(now_utc, weekday=weekday, hour=hour)
    now_naive = now_utc.replace(tzinfo=None) if now_utc.tzinfo else now_utc
    if now_naive < target:
        return False, f"未到本周目标时刻（{target} UTC）"

    if last_sync_utc is not None:
        last = last_sync_utc.replace(tzinfo=None) if last_sync_utc.tzinfo else last_sync_utc
        if last >= target:
            # 手动同步也算数：有人已经同步过，就不重复跑一遍 1600 人
            return False, f"本周已同步过（最近一次 {last}）"
    return True, "到点且本周未同步"


def _last_sync_at(db) -> datetime | None:
    """最近一次同步的时间（手动/定时都算）。查不到返回 None。"""
    from .models import OperationLog

    row = (
        db.query(OperationLog.created_at)
        .filter(OperationLog.action.in_(SYNC_ACTIONS))
        .order_by(OperationLog.created_at.desc())
        .first()
    )
    return row[0] if row else None


async def _tick() -> None:
    """跑一轮判断；该跑就跑一次同步。任何异常都只记日志，不让循环断掉。"""
    from .database import SessionLocal
    from .routers import feishu as feishu_router

    if not (feishu_router._get_config()["app_id"] and feishu_router._get_config()["app_secret"]):
        return  # 没接飞书：静默（配了 App 凭证后下一轮自然生效）

    db = SessionLocal()
    try:
        should, reason = plan_weekly_run(
            datetime.utcnow(), _last_sync_at(db),
            enabled=weekly_enabled(), weekday=target_weekday(), hour=target_hour(),
        )
        if not should:
            logger.debug("定时同步跳过：%s", reason)
            return
        logger.info("定时同步开始（%s）：每周 %s 日 %02d:00（北京时间）",
                    reason, target_weekday(), target_hour())
        result = await feishu_router.run_feishu_sync(db, None, trigger="定时任务")
        logger.info(
            "定时同步完成：部门 %s（新建 %s / 匹配 %s），用户 总数 %s / 新建 %s / 更新 %s / 停用 %s / 失败 %s",
            result.dept_total, result.dept_created, result.dept_matched,
            result.total, result.created, result.updated, result.deactivated, result.failed,
        )
    except feishu_router.SyncInProgress:
        # 有人正在手动同步：这轮跳过，30 分钟后再看（不抢飞书接口）
        logger.info("定时同步跳过：已有一次同步正在进行")
    except Exception as exc:  # noqa: BLE001 —— 定时任务绝不能把进程带崩
        logger.warning("定时同步失败（下轮会重试）：%s", exc)
    finally:
        db.close()


async def weekly_feishu_sync_loop() -> None:
    """常驻循环（在 app 启动时用 asyncio.create_task 起）。"""
    logger.info(
        "飞书定时同步已启动：每周 %s 的 %02d:00（北京时间）检查一次；开关 FEISHU_SYNC_WEEKLY=%s",
        target_weekday(), target_hour(), "on" if weekly_enabled() else "off",
    )
    while True:
        try:
            await _tick()
        except Exception as exc:  # noqa: BLE001 —— 兜底，保证循环活着
            logger.warning("定时同步检查异常：%s", exc)
        await asyncio.sleep(CHECK_INTERVAL_SECONDS)
