"""数据大盘 /overview 的 KPI 口径回归。

为什么要有它：
  1. 首页第 6 张卡从「平均修复时长」换成了「待确认」（取 status == pending 的数量）——
     这是首页上唯一"需要人去推动"的数字，口径必须与状态机/漏洞列表一致；
  2. 「平均修复时长」原来只认 fixed_at（研发点「修复完成」那一刻）：
     被驳回 / 直接关闭的漏洞没有 fixed_at → 全被排除在样本外；一套环境里若没人走过
     finish_fix，样本数就是 0，卡片恒显示 0h —— 看起来像"修复飞快"，用户反馈"没意义"。
     现在与趋势图「修复」线同口径：fixed_at → closed_at → 流转记录里进入终态的时间，
     分母也改成真正有时间的条数。下面几条把"包含被驳回的漏洞""无样本为 0"都钉住。

用法（在 backend 目录下）：python tests/test_dashboard_overview.py
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI                            # noqa: E402
from fastapi.testclient import TestClient              # noqa: E402
from sqlalchemy import create_engine                   # noqa: E402
from sqlalchemy.orm import sessionmaker                # noqa: E402
from sqlalchemy.pool import StaticPool                 # noqa: E402

from app.database import Base, get_db                  # noqa: E402
from app.models import Role, User, Vuln, VulnFlow      # noqa: E402
from app.routers import dashboard as dashboard_router  # noqa: E402
from app.security import get_current_user              # noqa: E402
from app.utils import network_clock as nc              # noqa: E402

CURRENT: dict = {}


def _setup():
    # check_same_thread=False + StaticPool：TestClient 在独立线程里发请求，内存库必须共享连接
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    role = Role(name="超级管理员", code="admin")
    db.add(role)
    db.flush()
    db.add(User(username="admin", password_hash="x", full_name="系统管理员",
                role_id=role.id, is_active=True))
    db.commit()
    user = db.query(User).filter(User.username == "admin").first()

    api = FastAPI()
    api.include_router(dashboard_router.router)
    api.dependency_overrides[get_db] = lambda: db
    api.dependency_overrides[get_current_user] = lambda: user
    return db, user, TestClient(api)


def _vuln(db, user, status, *, days_ago=10, fixed_days_ago=None, closed_days_ago=None,
          severity="high", created_at=None, fixed_at=None, closed_at=None):
    """建一条漏洞。时间既能给"相对今天几天前"，也能给**绝对时刻** ——
    环比基数改成自然月边界后，"3 天前"这种相对值在月初会落进上个月、月末落进本月，
    测试会随运行日期飘；凡是被基数判定用到的行一律用绝对取点（见 _prev_month）。"""
    now = nc.utcnow()
    v = Vuln(
        title=f"漏洞 {status}", severity=severity, status=status, reporter_id=user.id,
        created_at=created_at or (now - timedelta(days=days_ago)),
        fixed_at=fixed_at or (now - timedelta(days=fixed_days_ago)
                              if fixed_days_ago is not None else None),
        closed_at=closed_at or (now - timedelta(days=closed_days_ago)
                                if closed_days_ago is not None else None),
    )
    db.add(v)
    db.commit()
    return v


def _month_start() -> datetime:
    """本月 1 号 00:00 —— 环比基数的取点（「上月末收盘」那一刻）。"""
    now = nc.utcnow()
    return datetime(now.year, now.month, 1)


def _prev_month(offset_days: int = 10) -> datetime:
    """本月 1 号往前 offset_days 天 —— 必定落在**上个月**里（与"今天是几号"无关）。"""
    return _month_start() - timedelta(days=offset_days)


def test_pending_card_counts_first_step_backlog():
    """「待确认」= 状态为 pending 的漏洞数（与状态机 / 漏洞列表同口径）。"""
    db, user, client = _setup()
    for st in ("pending", "pending", "confirmed", "fixing", "retest", "fixed", "closed", "rejected"):
        _vuln(db, user, st)

    o = client.get("/api/dashboard/overview").json()
    assert o["pending"] == 2, f"待确认应为 2，实际 {o['pending']}"
    assert o["retest"] == 1, o
    assert o["total"] == 8, o
    # 未修复 = 待确认2 + 已确认1 + 修复中1 = 4
    # 已修复 = 待复测1 + 已修复1 + 已关闭1 + 已驳回1 = 4（两张卡互补：4 + 4 = 8 = 总数）
    assert o["unfixed"] == 4, o
    assert o["fixed_total"] == 4, o


def test_avg_fix_hours_includes_rejected_and_closed_not_only_fixed_at():
    """平均修复时长必须包含**被驳回 / 直接关闭**的漏洞（它们没有 fixed_at）。

    旧实现只看 fixed_at：本用例 3 条已闭环漏洞里只有 1 条有 fixed_at，
    旧口径会算成 48h（只有 1 条样本），甚至环境里全无 fixed_at 时直接显示 0h。
    """
    db, user, client = _setup()
    _vuln(db, user, "fixed", days_ago=10, fixed_days_ago=8)        # 2 天 = 48h
    _vuln(db, user, "closed", days_ago=10, closed_days_ago=6)      # 4 天 = 96h
    rej = _vuln(db, user, "rejected", days_ago=10)                 # 无时间列 → 靠流转记录
    db.add(VulnFlow(vuln_id=rej.id, from_status="pending", to_status="rejected",
                    operator_name="x", comment="误报",
                    created_at=nc.utcnow() - timedelta(days=5)))   # 5 天 = 120h
    db.commit()
    _vuln(db, user, "pending", days_ago=1)                          # 未闭环 → 不进样本

    o = client.get("/api/dashboard/overview").json()
    # 样本 3 条：(48 + 96 + 120) / 3 = 88.0
    assert o["avg_fix_hours"] == 88.0, f"应为 88.0（含被驳回那条），实际 {o['avg_fix_hours']}"


def test_avg_fix_hours_is_zero_without_closed_vulns():
    """没有已闭环漏洞时是 0（前端已不再把它当"时长"展示，卡片换成了「待确认」）。"""
    db, user, client = _setup()
    _vuln(db, user, "pending", days_ago=3)

    o = client.get("/api/dashboard/overview").json()
    assert o["avg_fix_hours"] == 0, o
    assert o["pending"] == 1, o


def test_snapshot_prev_month_is_the_base_for_all_cards():
    """首页六张卡的"较上月"基数 = **上月末收盘**：/overview 的 snapshot_prev_month。

    三个坑：① 基数那一刻还不存在的漏洞不能算进去；② 当时还没修好的不算已修复；
    ③ 「待确认」要看"当时有没有离开第一步"——离开时间取自确认/驳回那次流转记录。
    """
    db, user, client = _setup()
    v1 = _vuln(db, user, "pending", created_at=_prev_month(20), severity="high")      # 一直是待确认
    v2 = _vuln(db, user, "confirmed", created_at=_prev_month(20), severity="critical")  # 本月才确认 → 当时仍待确认
    v3 = _vuln(db, user, "confirmed", created_at=_prev_month(20), severity="low")       # 上月已确认 → 当时已离开
    # v2/v3 的"离开第一步"时间靠流转记录（与线上一致：确认时写 from_status=pending）
    db.add(VulnFlow(vuln_id=v2.id, from_status="pending", to_status="confirmed",
                    operator_name="x", comment="确认", created_at=nc.utcnow()))
    db.add(VulnFlow(vuln_id=v3.id, from_status="pending", to_status="confirmed",
                    operator_name="x", comment="确认", created_at=_prev_month(15)))
    db.commit()
    _vuln(db, user, "pending", created_at=nc.utcnow(), severity="critical")   # 本月才创建
    # 老数据（种子/导入）只有一条 from_status=None 的流转：不能因此把它永远算成"待确认"
    v4 = _vuln(db, user, "confirmed", created_at=_prev_month(20), severity="low")
    db.add(VulnFlow(vuln_id=v4.id, from_status=None, to_status="confirmed",
                    operator_name="x", comment="种子导入", created_at=_prev_month(12)))
    db.commit()

    o = client.get("/api/dashboard/overview").json()
    snap = o["snapshot_prev_month"]
    assert snap["total"] == 4, snap           # 排除"本月才创建"那条
    assert snap["unfixed"] == 4, snap         # 一条都还没修好
    assert snap["repaired"] == 0, snap
    assert snap["severity"] == 2, snap        # 当时未修复里的严重/高危：high + critical
    assert snap["pending"] == 2, snap         # v1 一直待确认 + v2 当时还没确认（v3 已离开）
    assert snap["rate"] == 0.0, snap          # 基数为 0 → 前端对「已修复率」显示破折号

    # 前端就是这么算的（六张卡统一"较上月"）
    assert o["total"] - snap["total"] == 1, o
    assert o["unfixed"] - snap["unfixed"] == 1, o
    assert (o["critical"] + o["high"]) - snap["severity"] == 1, o
    # 现在的待确认只有 2 条（v1 + 本月那条；v2/v3 已确认）→ 与上月基数持平
    assert (o["pending"] or 0) - snap["pending"] == 0, o


def test_snapshot_prev_month_feeds_rate_gap_in_points():
    """已修复率卡的第二行 = 与上月的**绝对差（百分点）**，不是相对涨跌。

    用户口径：上月 90%、本月 95% → 「+5%」（而不是把 +5.6% 的相对涨幅写上去）。
    这条特意用 90% → 95%：相对算法给 +5.6、绝对差给 +5 —— 两个数不同，
    测试才钉得住（用 100% → 50% 那种用例两种算法都会得到 −50，等于没测）。
    """
    db, user, client = _setup()
    # 上月收盘：10 条里 9 条已修好 → 90%
    for i in range(10):
        closed = i < 9
        _vuln(db, user, "closed" if closed else "pending", created_at=_prev_month(30),
              closed_at=_prev_month(20) if closed else None, severity="low")
    # 本月新增 10 条并全部修好 → 现在 19 / 20 = 95%
    for _ in range(10):
        _vuln(db, user, "fixed", created_at=nc.utcnow(), fixed_at=nc.utcnow(), severity="low")

    o = client.get("/api/dashboard/overview").json()
    s = o["snapshot_prev_month"]
    assert s["total"] == 10 and s["repaired"] == 9, s
    assert s["rate"] == 90.0, s
    assert o["total"] == 20 and o["fixed_total"] == 19, o
    assert o["fix_rate"] == 95.0, o
    # 前端算的是绝对差：95 − 90 = +5（相对涨跌会得到 +5.6，是另一个数）
    assert o["fix_rate"] - s["rate"] == 5.0, o


def test_month_base_boundary_is_month_start():
    """基数边界 = **本月 1 号 00:00**（上月末收盘）：上月发生的事算上月，本月发生的事算本月。

    回归点：这个基数以前是"now − 30 天"—— 一个每小时都在漂的滚动窗口，卡片上却写着
    「较上月」。真实数据下两种口径能差一倍（+9 对 +5、+158.8% 对 +29.4%）。
    这条把边界钉死：上月最后一天修好的要计入、本月 1 号当天修好的不计入、
    本月 1 号当天创建的漏洞也不能出现在基数里。
    """
    db, user, client = _setup()
    start = _month_start()
    # ① 上月最后一天修好 → 基数里算"已修复"
    _vuln(db, user, "fixed", created_at=start - timedelta(days=20),
          fixed_at=start - timedelta(days=1), severity="low")
    # ② 本月 1 号当天才修好 → 基数里仍算"未修复"（那一刻之前它是欠着的）
    _vuln(db, user, "fixed", created_at=start - timedelta(days=20),
          fixed_at=start + timedelta(minutes=1), severity="high")
    # ③ 本月 1 号当天创建 → 基数里根本不该存在
    _vuln(db, user, "pending", created_at=start + timedelta(minutes=1), severity="critical")

    snap = client.get("/api/dashboard/overview").json()["snapshot_prev_month"]
    assert snap["total"] == 2, snap          # ① + ②（③ 那一刻还不存在）
    assert snap["repaired"] == 1, snap       # 只有 ①
    assert snap["unfixed"] == 1, snap        # ② 当时还没修好
    assert snap["severity"] == 1, snap       # ② 当时未修复里唯一的高危
    assert snap["rate"] == 50.0, snap        # 1 / 2


def test_cards_are_complementary_so_they_add_up():
    """未修复 + 已修复 = 漏洞总数 —— 首页两张卡必须**严格互补**（本次改口径的全部目的）。

    回归点：旧口径「未闭环 = 非终态」（含已修复/待复测），与「已修复」在"已修复未关闭"
    上重叠，真实库上出现 `9 + 8 = 17 > 总数 16`，读者第一反应是"数字算错了"。
    现在按"修好 / 没修好"划分，加法天然成立；率卡也必须与这两张卡同源
    （否则 50% 与"已修复 8 / 总数 16"又会各说各话）。
    """
    db, user, client = _setup()
    for st in ("pending", "confirmed", "fixing", "retest", "fixed", "closed", "rejected"):
        _vuln(db, user, st)
    db.commit()

    o = client.get("/api/dashboard/overview").json()
    assert o["total"] == 7, o
    assert o["unfixed"] == 3, f"未修复应为 3（待确认/已确认/修复中），实际 {o['unfixed']}"
    # 「待复测」属于已修复：它 = 研发已经修好了、等验收
    assert o["fixed_total"] == 4, f"已修复应为 4（含待复测），实际 {o['fixed_total']}"
    assert o["unfixed"] + o["fixed_total"] == o["total"], f"加法必须平：{o}"
    assert o["fix_rate"] == round(o["fixed_total"] / o["total"] * 100, 1), o
    # 「待确认」是「未修复」的子集（页面上标注了，避免被当成并列项相加）
    assert o["pending"] <= o["unfixed"], o


def test_distribution_and_top_cover_all_vulns():
    """等级 / 类型分布与系统排行统计**全部**漏洞 —— 各扇区之和 = 漏洞总数。

    回归点：这两处曾按"未修复"统计，于是饼图加起来只有 6、而首页总数是 16，
    只能在标题里补「（未修复）」解释；用户要求展示全量数据。
    """
    db, user, client = _setup()
    for st in ("pending", "confirmed", "fixing", "retest", "fixed", "closed", "rejected"):
        _vuln(db, user, st, severity="high")
    db.commit()

    d = client.get("/api/dashboard/distribution").json()
    assert sum(i["value"] for i in d["by_severity"]) == 7, d
    assert sum(i["value"] for i in d["by_category"]) == 7, d

    t = client.get("/api/dashboard/top").json()
    assert sum(s["count"] for s in t["top_systems"]) == 7, t


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
