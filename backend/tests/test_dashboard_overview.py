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
from datetime import timedelta

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
          severity="high"):
    now = nc.utcnow()
    v = Vuln(
        title=f"漏洞 {status}", severity=severity, status=status, reporter_id=user.id,
        created_at=now - timedelta(days=days_ago),
        fixed_at=now - timedelta(days=fixed_days_ago) if fixed_days_ago is not None else None,
        closed_at=now - timedelta(days=closed_days_ago) if closed_days_ago is not None else None,
    )
    db.add(v)
    db.commit()
    return v


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


def test_snapshot_30d_is_the_month_base_for_all_cards():
    """首页六张卡的"较上月"基数：都来自 /overview 的 snapshot_30d（前端只做减法/除法）。

    三个坑：① "30 天前还不存在"的漏洞不能算进去；② 当时还没关闭的不算已闭环；
    ③ 「待确认」要看"当时有没有离开第一步"——离开时间取自确认/驳回那次流转记录。
    """
    db, user, client = _setup()
    v1 = _vuln(db, user, "pending", days_ago=40, severity="high")       # 一直是待确认
    v2 = _vuln(db, user, "confirmed", days_ago=40, severity="critical")  # 10 天前才确认 → 当时仍待确认
    v3 = _vuln(db, user, "confirmed", days_ago=40, severity="low")       # 35 天前已确认 → 当时已离开
    # v2/v3 的"离开第一步"时间靠流转记录（与线上一致：确认时写 from_status=pending）
    db.add(VulnFlow(vuln_id=v2.id, from_status="pending", to_status="confirmed",
                    operator_name="x", comment="确认",
                    created_at=nc.utcnow() - timedelta(days=10)))
    db.add(VulnFlow(vuln_id=v3.id, from_status="pending", to_status="confirmed",
                    operator_name="x", comment="确认",
                    created_at=nc.utcnow() - timedelta(days=35)))
    db.commit()
    _vuln(db, user, "pending", days_ago=3, severity="critical")         # 30 天前还不存在
    # 老数据（种子/导入）只有一条 from_status=None 的流转：不能因此把它永远算成"待确认"
    v4 = _vuln(db, user, "confirmed", days_ago=40, severity="low")
    db.add(VulnFlow(vuln_id=v4.id, from_status=None, to_status="confirmed",
                    operator_name="x", comment="种子导入",
                    created_at=nc.utcnow() - timedelta(days=38)))
    db.commit()

    o = client.get("/api/dashboard/overview").json()
    snap = o["snapshot_30d"]
    assert snap["total"] == 4, snap           # 排除"3 天前才创建"那条
    assert snap["unfixed"] == 4, snap         # 一条都还没修好
    assert snap["repaired"] == 0, snap
    assert snap["severity"] == 2, snap        # 当时未修复里的严重/高危：high + critical
    assert snap["pending"] == 2, snap         # v1 一直待确认 + v2 当时还没确认（v3 已离开）
    assert snap["rate"] == 0.0, snap          # 当月基数为 0 → 前端对「已修复率」显示破折号

    # 前端就是这么算的（六张卡统一"较上月"）
    assert o["total"] - snap["total"] == 1, o
    assert o["unfixed"] - snap["unfixed"] == 1, o
    assert (o["critical"] + o["high"]) - snap["severity"] == 1, o
    # 现在的待确认只有 2 条（v1 + 3 天前那条；v2/v3 已确认）→ 与上月基数持平
    assert (o["pending"] or 0) - snap["pending"] == 0, o


def test_snapshot_30d_feeds_month_over_month_rate_change():
    """闭环率卡的第二行是"较上月的百分比涨跌"（**相对变化**，不是百分点）。

    必须用相对变化时，分母为 0 就没有意义 —— 这种情形由前端显示破折号（见 Dashboard.vue）。
    """
    db, user, client = _setup()
    # 40 天前创建、35 天前闭环 → 30 天前它已经闭环（当时的闭环率 = 100%）
    _vuln(db, user, "closed", days_ago=40, closed_days_ago=35, severity="low")
    _vuln(db, user, "pending", days_ago=3, severity="high")     # 本月新增、未闭环

    o = client.get("/api/dashboard/overview").json()
    s30 = o["snapshot_30d"]
    assert s30["total"] == 1, s30
    assert s30["rate"] == 100.0, s30
    # 现在 1/2 = 50.0%，相对上月 100% → −50%
    assert o["fix_rate"] == 50.0, o
    assert round((o["fix_rate"] - s30["rate"]) / s30["rate"] * 100, 1) == -50.0, o


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
