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


def test_pending_card_counts_first_step_backlog():
    """「待确认」= 状态为 pending 的漏洞数（与状态机 / 漏洞列表同口径）。"""
    db, user, client = _setup()
    for st in ("pending", "pending", "confirmed", "fixing", "retest", "fixed", "closed", "rejected"):
        _vuln(db, user, st)

    o = client.get("/api/dashboard/overview").json()
    assert o["pending"] == 2, f"待确认应为 2，实际 {o['pending']}"
    assert o["retest"] == 1, o
    assert o["total"] == 8, o
    # 未关闭（不含 draft）：pending2 + confirmed1 + fixing1 + retest1 + fixed1 = 6
    assert o["open"] == 6, o


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
