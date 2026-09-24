# -*- coding: utf-8 -*-
"""基线需求到期提醒：每天固定时刻给负责人发一条飞书卡片（循环注册见 app_entry.py）。

## 为什么需要它
需求上挂着 `due_date`、列表里也有「已逾期」红标 —— 但那要**有人打开这一页**才看得见。
基线评估的负责人多半是研发，不会每天来刷；等逾期了才被安全同学发现，这一轮就白排了。
所以由系统提前 N 天私聊提醒本人，并顺手把"进度 / 合规率 / 不通过数"带上 ——
他点开就知道还剩多少、有没有卡点。

## 三条刻意的约束
1. **只提醒未完成的需求**：`done` 的不再打扰；没填截止日期的也不猜（宁可不发）。
2. **同一个需求每天最多一条**：以**操作日志**为准（内存标记一重启就丢，日志才是可靠记录 ——
   与周同步同一套路；顺带的好处是手动触发也计入去重，不会"手动发过、定时又发一遍"）。
3. **提醒绝不反过来影响业务**：发送走后台线程、异常只记日志（与其它通知一致）。

## 时间口径
全部按**北京时间**判断"今天"（中国无夏令时，用固定 +8 偏移，不依赖 tzdata ——
与 app/scheduler.py 同一套做法）。`due_date` 只比**日期部分**：它存的就是用户选的那一天
00:00（前端 value-format），与页面显示的 `due_date.slice(0, 10)` 同口径 ——
在这里做时区换算反而会把"9/30 到期"算成 9/29。
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import date, datetime, time, timedelta, timezone

logger = logging.getLogger(__name__)

# 北京时间固定偏移（中国无夏令时；与 app/scheduler.py 保持一致）
CST_OFFSET = timedelta(hours=8)

# 操作日志里的动作名：去重靠它（"今天是否已经提醒过这个需求"）
DUE_ACTION = "baseline_due_notice"

# 每 30 分钟醒一次：比"睡到点"笨，但进程重启 / 机器休眠都不会漏掉今天的提醒
CHECK_INTERVAL_SECONDS = 30 * 60


def _flag(name: str, default: bool = True) -> bool:
    raw = (os.getenv(name) or "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def _num(name: str, default: int, lo: int, hi: int) -> int:
    try:
        val = int(os.getenv(name, str(default)) or default)
    except ValueError:
        val = default
    return val if lo <= val <= hi else default


def due_enabled() -> bool:
    """提醒总开关，默认开（BASELINE_DUE_NOTIFY=0 可关）。"""
    return _flag("BASELINE_DUE_NOTIFY", True)


def due_hour() -> int:
    """每天几点之后开始提醒（**北京时间** 0-23），默认 9。"""
    return _num("BASELINE_DUE_HOUR", 9, 0, 23)


def due_days() -> int:
    """提前几天开始提醒（0 = 只在当天提醒；含已逾期），默认 3。"""
    return _num("BASELINE_DUE_DAYS", 3, 0, 60)


def days_left(due_date, today: date) -> int | None:
    """截止日期距今天还有几天（负数 = 已逾期）；没填截止日期返回 None。"""
    if not due_date:
        return None
    day = due_date.date() if isinstance(due_date, datetime) else due_date
    return (day - today).days


def pick_due(reqs, today: date, *, days: int):
    """挑出该提醒的需求：**未完成 + 有截止日期 + 剩余天数 <= N**（含已逾期）。

    返回 [(需求, 剩余天数)]，按紧急程度排序（已逾期 / 最先到期的在前）——
    一次提醒里若有多个需求，负责人的注意力应该先落在最急的那个上。
    """
    out: list[tuple[object, int]] = []
    for req in reqs:
        if (req.status or "in_progress") == "done":
            continue                        # 已完成的不再打扰
        left = days_left(req.due_date, today)
        if left is None:
            continue                        # 没填截止日期：不猜、不打扰
        if left <= days:
            out.append((req, left))
    out.sort(key=lambda pair: pair[1])
    return out


def _cst_today(now_utc: datetime) -> date:
    return (now_utc + CST_OFFSET).date()


def _cst_day_start_utc(today: date) -> datetime:
    """今天 00:00（北京时间）对应的 **naive UTC** —— 与库里时间同口径，可直接比较。"""
    return datetime.combine(today, time.min) - CST_OFFSET


def _sent_today(db, req_id: int, since_utc: datetime) -> bool:
    """今天是否已经给这个需求发过提醒（日志里找带 `req#<id> |` 标记的那条）。"""
    from .models import OperationLog

    marker = f"req#{req_id} |"
    rows = (
        db.query(OperationLog.detail)
        .filter(OperationLog.action == DUE_ACTION, OperationLog.created_at >= since_utc)
        .all()
    )
    return any((row[0] or "").startswith(marker) for row in rows)


def build_card(*, system_name: str, req_name: str, due_text: str, left: int,
               bound: int, assessed: int, compliance: float, fail_count: int,
               base_url: str) -> dict:
    """到期提醒卡片（纯函数，便于单测断言文案与按钮）。"""
    from .routers import feishu as fe

    overdue = left < 0
    when = f"已逾期 {abs(left)} 天" if overdue else ("今天到期" if left == 0 else f"还剩 {left} 天")
    elements: list[dict] = [
        fe.text_div(f"**{system_name}** 的基线评估等你收尾：{when}"),
        fe.fields_div(
            f"**需求**：{req_name}",
            f"**截止**：{due_text}",
            f"**已评估**：{assessed}/{bound}",          # 「做了多少」
            f"**合规率**：{compliance}%（通过 ÷ 应评）",  # 「做对多少」——两者口径写清楚，别混
            f"**不通过**：{fail_count} 项",
            f"**{'已逾期' if overdue else '进行中'}**：" + ("请尽快推进并补上依据" if fail_count else "按计划推进即可"),
        ),
    ]
    if base_url:
        elements += [{"tag": "hr"},
                     fe.primary_button("打开安全基线页", f"{base_url.rstrip('/')}/baseline")]
    elements.append(fe.note_div("每天最多提醒一次；完成评估后自动停止"))
    return {
        "config": {"wide_screen_mode": True},
        "header": {"template": "red" if overdue else "orange",
                   "title": {"tag": "plain_text",
                             "content": "基线评估已逾期" if overdue else "基线评估即将到期"}},
        "elements": elements,
    }


def tick(db, *, now: datetime | None = None, days: int | None = None,
         dry_run: bool = False) -> dict:
    """扫一遍该提醒的需求并发送；返回本轮统计（手动接口直接把这份统计返回给页面）。

    Args:
        db: 会话
        now: 当前时间（测试注入用，naive UTC）
        days: 覆盖"提前几天"（不传取 BASELINE_DUE_DAYS）
        dry_run: 只算要发给谁，**不发消息、不写日志**（上线前自检 / 排查用）
    """
    from .models import AssetSystem, BaselineRequirement, User
    from .routers import baseline as br
    from .routers import feishu as fe
    from .security import write_operation_log
    from .utils.public_url import public_base_url

    now = now or datetime.utcnow()
    today = _cst_today(now)
    days = due_days() if days is None else days
    day_start = _cst_day_start_utc(today)

    reqs = db.query(BaselineRequirement).all()
    picked = pick_due(reqs, today, days=days)
    result: dict = {"today": today.isoformat(), "days": days, "enabled": due_enabled(),
                    "notify_ready": fe.notify_enabled(), "dry_run": dry_run,
                    "due": len(picked), "sent": 0, "skipped": 0, "details": []}
    if not picked:
        return result

    cache: dict = {}          # 绑定范围（按"类型组合"缓存）
    scache: dict = {}         # 系统已有结论（按 system_id 缓存）—— 与上面分开，别混用同一个字典
    base_url = public_base_url()
    for req, left in picked:
        item: dict = {"id": req.id, "requirement": req.name, "days_left": left}
        if not due_enabled():
            item["skip"] = "提醒已关闭（BASELINE_DUE_NOTIFY=0）"
        elif not fe.notify_enabled():
            item["skip"] = "飞书通知未启用（未配 App 凭证或 FEISHU_NOTIFY=0）"
        elif _sent_today(db, req.id, day_start):
            item["skip"] = "今天已提醒过"
        else:
            owner = db.query(User).filter(User.id == req.owner_id).first() if req.owner_id else None
            open_id = (owner.feishu_open_id or "").strip() if owner else ""
            if not owner:
                item["skip"] = "需求没有负责人"
            elif not open_id:
                item["skip"] = f"负责人 {owner.full_name or owner.username} 无飞书 open_id（手工账号）"
            else:
                system = db.query(AssetSystem).filter(AssetSystem.id == req.system_id).first()
                bound_ids = br._bound_items(db, req.type_keys, cache)
                status_map = br._system_status(db, req.system_id, scache)
                cnt = br._counts(bound_ids, status_map)
                rate = br._rates(len(bound_ids), cnt)
                assessed = cnt["pass"] + cnt["fail"] + cnt["na"]
                card = build_card(
                    system_name=system.name if system else f"系统#{req.system_id}",
                    req_name=req.name or "基线评估",
                    due_text=req.due_date.strftime("%Y-%m-%d") if req.due_date else "—",
                    left=left, bound=len(bound_ids), assessed=assessed,
                    compliance=rate["compliance"], fail_count=cnt["fail"],
                    base_url=base_url,
                )
                if not dry_run:
                    fe.send_in_background(open_id, "interactive", card,
                                          tag=f"基线需求#{req.id} 到期提醒 → {owner.full_name or owner.username}")
                    write_operation_log(
                        db, None, DUE_ACTION, "baseline",
                        f"req#{req.id} | {system.name if system else req.system_id} / "
                        f"{req.name} | 剩余 {left} 天",
                        username="系统定时任务",
                    )
                item["to"] = owner.full_name or owner.username
                item["assessed"] = f"{assessed}/{len(bound_ids)}"
                item["compliance"] = rate["compliance"]
                item["fail"] = cnt["fail"]
                result["sent"] += 1
                result["details"].append(item)
                continue
        result["skipped"] += 1
        result["details"].append(item)
    return result


async def _tick() -> None:
    """跑一轮（由常驻循环调用）。任何异常都只记日志，绝不让循环断掉。"""
    from .database import SessionLocal

    if not due_enabled():
        return
    now = datetime.utcnow()
    if (now + CST_OFFSET).hour < due_hour():
        return                                  # 还没到今天的提醒时刻（默认 9:00 北京时间）

    db = SessionLocal()
    try:
        # tick 是同步的、只做几次查询 + 把发送丢进后台线程，不会长时间占住事件循环
        stat = tick(db, now=now)
        if stat["due"]:
            logger.info("基线到期提醒：待提醒 %s 条，已发 %s 条，跳过 %s 条",
                        stat["due"], stat["sent"], stat["skipped"])
    except Exception as exc:  # noqa: BLE001 —— 定时任务绝不能把进程带崩
        logger.warning("基线到期提醒失败（下轮会重试）：%s", exc)
    finally:
        db.close()


async def daily_due_loop() -> None:
    """常驻循环（app 启动时用 asyncio.create_task 起）。"""
    logger.info("基线到期提醒已启动：每天 %02d:00（北京时间）后提醒一次；开关 BASELINE_DUE_NOTIFY=%s",
                due_hour(), "on" if due_enabled() else "off")
    while True:
        try:
            await _tick()
        except Exception as exc:  # noqa: BLE001 —— 兜底，保证循环活着
            logger.warning("基线到期提醒检查异常：%s", exc)
        await asyncio.sleep(CHECK_INTERVAL_SECONDS)
