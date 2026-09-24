"""首页「漏洞趋势」的口径回归：未修复存量线 + 粒度自适应 + 全部历史。

两条线（已修复 / 未修复存量）共用**同一个事件**（修好那一刻）：它 +1、存量 −1，
所以永远互补、加法一定平 —— 终点必然等于首页「未修复」卡片。

为什么要有它（每条都对应改动时发现的具体问题）：
  1. /trend 原来固定按日，且 `span = max(1, days)` 把 days=0 变成"只看 1 天" ——
     前端选「全部」时实际只有近 30 天（`trendRange.value || undefined` 又把 0 丢了）。
     现在 days<=0 = 全部历史，跨度大时自动按周/月聚合（近一年 365 个刻度必然糊成一团）；
  2. 新增「未修复存量」= 期初余额 + 累计新增 − 累计**已修复**。两个坑：
     · **期初余额**不算 → 窗口选短时曲线从 0 起步，看着像"欠债突然暴涨"；
     · 若两条线各用各的事件（历史实现：已修复线按"进入终态"、存量线按"关闭/驳回"），
       同一页必然对不上（真实库上出现过"卡片 8、曲线 7"）。

用法（在 backend 目录下）：python tests/test_dashboard_trend.py
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


def _vuln(db, user, status, *, days_ago=10, fixed_days_ago=None, closed_days_ago=None):
    now = nc.utcnow()
    v = Vuln(
        title=f"漏洞 {status}", severity="high", status=status, reporter_id=user.id,
        created_at=now - timedelta(days=days_ago),
        fixed_at=now - timedelta(days=fixed_days_ago) if fixed_days_ago is not None else None,
        closed_at=now - timedelta(days=closed_days_ago) if closed_days_ago is not None else None,
    )
    db.add(v)
    db.commit()
    return v


def test_trend_unfixed_balance_includes_opening_balance():
    """存量 = 期初余额 + 累计新增 − 累计已修复；窗口选短了老漏洞也不能"消失"。

    「已修复」线（含待复测 / 已修复 / 已关闭 / 已驳回）与「未修复存量」共用**同一个事件**
    （修好那一刻）：它 +1、存量 −1 —— 所以两条线永远互补，加法一定平。
    """
    db, user, client = _setup()
    _vuln(db, user, "pending", days_ago=10)
    _vuln(db, user, "confirmed", days_ago=10)
    _vuln(db, user, "fixed", days_ago=10, fixed_days_ago=5)      # 10 天前创建、5 天前"已修复"

    rows = client.get("/api/dashboard/trend?days=30").json()
    assert sum(r["created"] for r in rows) == 3, rows
    assert sum(r["repaired"] for r in rows) == 1, f"「已修复」线：{rows}"
    assert rows[-1]["unfixed"] == 2, f"3 新增 − 1 已修复 = 2，实际 {rows[-1]}"
    # 互补关系：累计已修复 + 期末存量 = 累计新增
    assert sum(r["repaired"] for r in rows) + rows[-1]["unfixed"] == \
        sum(r["created"] for r in rows), rows

    # 只看最近 2 天：窗口内既无新增也无修复，但期初余额必须带进来（仍是 2，而不是 0）
    rows2 = client.get("/api/dashboard/trend?days=2").json()
    assert sum(r["created"] for r in rows2) == 0, rows2
    assert sum(r["repaired"] for r in rows2) == 0, rows2
    assert rows2[-1]["unfixed"] == 2, f"窗口外的老漏洞不能凭空消失：{rows2}"


def test_trend_final_unfixed_equals_overview_card():
    """存量线的终点必须等于首页「未修复」卡片 —— 同一页两个数字不能打架。

    这里的坑：只要两条线用了两套不同的事件（历史实现就是），同页必然对不上
    （真出现过"卡片 8、曲线 7"）。现在两条线共用"修好那一刻"，天然相等。
    """
    db, user, client = _setup()
    _vuln(db, user, "pending", days_ago=10)
    _vuln(db, user, "fixed", days_ago=10, fixed_days_ago=6)          # 已修复、未关闭
    _vuln(db, user, "closed", days_ago=10, closed_days_ago=5)        # 真正了结
    rej = _vuln(db, user, "rejected", days_ago=10)                   # 驳回：靠流转记录定时
    db.add(VulnFlow(vuln_id=rej.id, from_status="pending", to_status="rejected",
                    operator_name="x", comment="误报",
                    created_at=nc.utcnow() - timedelta(days=4)))
    db.commit()

    o = client.get("/api/dashboard/overview").json()
    rows = client.get("/api/dashboard/trend?days=30").json()
    assert o["unfixed"] == 1, o                     # 只剩 pending（其余 3 条都已修好）
    assert rows[-1]["unfixed"] == o["unfixed"], \
        f"曲线终点 {rows[-1]['unfixed']} 必须等于「未修复」卡片 {o['unfixed']}"
    # 已修复 = fixed + closed + rejected = 3；且 已修复 + 未修复 = 总数
    assert sum(r["repaired"] for r in rows) == 3, rows
    assert sum(r["repaired"] for r in rows) + o["unfixed"] == o["total"], o


def test_trend_days_zero_means_all_history():
    """days=0 = 全部历史（原来被 max(1, days) 变成"只看 1 天"）。"""
    db, user, client = _setup()
    _vuln(db, user, "pending", days_ago=400)     # 一年前
    _vuln(db, user, "pending", days_ago=3)

    rows = client.get("/api/dashboard/trend?days=0").json()
    assert sum(r["created"] for r in rows) == 2, "选「全部」必须包含一年前那条"
    # 跨度一年多 → 自动按月聚合：桶数远小于 400，且标签是"X月"
    assert 12 <= len(rows) <= 20, f"应自动按月聚合，实际 {len(rows)} 个桶"
    assert rows[-1]["date"].endswith("月"), rows[-1]

    # 近一个月仍按日：30 个桶，一年前那条不进窗口，但期初余额要算上
    rows30 = client.get("/api/dashboard/trend?days=30").json()
    assert len(rows30) == 30, rows30
    assert sum(r["created"] for r in rows30) == 1, rows30
    assert rows30[-1]["unfixed"] == 2, rows30


def test_trend_all_history_picks_bucket_by_real_span():
    """选「全部」时按**真实跨度**选自适应粒度（不是固定按月）。

    回归点：原来 days<=0 直接写死按月 —— 平台只有 40 天数据时，整张图只有两个点
    连成一条斜线，看起来像"暴跌"、也看不出任何趋势（用户反馈"全部的趋势图有问题"）。
    现在跨度 ≤92 天按日、≤400 按周、更久按月，与其它区间同一套规则。
    """
    db, user, client = _setup()
    _vuln(db, user, "pending", days_ago=40)
    _vuln(db, user, "pending", days_ago=3)

    rows = client.get("/api/dashboard/trend?days=0").json()
    assert len(rows) >= 39, f"40 天历史应按日聚合，实际 {len(rows)} 个桶"
    assert not rows[-1]["date"].endswith("月"), rows[-1]

    # 显式指定粒度仍然有效（可选 日/周/月）
    weeks = client.get("/api/dashboard/trend?days=0&bucket=week").json()
    assert 5 <= len(weeks) <= 8, f"40 天按周 ≈ 6 个桶，实际 {len(weeks)}"


def test_trend_bucket_is_adaptive_and_overridable():
    """近半年按周（否则 180 个 x 轴刻度必然糊），也可以显式指定粒度。"""
    db, user, client = _setup()
    _vuln(db, user, "pending", days_ago=100)

    weeks = client.get("/api/dashboard/trend?days=180").json()
    assert 20 <= len(weeks) <= 30, f"近半年应按周聚合（约 26 个桶），实际 {len(weeks)}"
    assert sum(r["created"] for r in weeks) == 1, weeks

    days = client.get("/api/dashboard/trend?days=180&bucket=day").json()
    assert len(days) == 180, f"显式传 bucket=day 应按日，实际 {len(days)}"


def test_trend_empty_returns_empty_list():
    """没有任何漏洞时返回空列表（前端据此不画线，而不是报错）。"""
    db, user, client = _setup()
    assert client.get("/api/dashboard/trend?days=30").json() == []


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
