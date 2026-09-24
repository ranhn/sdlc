# -*- coding: utf-8 -*-
"""基线需求到期提醒（app/baseline_reminder.py）回归测试。

用法（在 backend 目录下）：
    python tests/test_baseline_due.py

为什么要有它：提醒是**发出去就收不回**的动作 —— 发错人、重复轰炸、或者因为飞书报错
把业务搞挂，代价都比没有提醒大。这里钉住五件事：
  1. 挑人口径：未完成 + 有截止日期 + 剩余天数 <= N（含已逾期），以及"已完成/没填日期"不发；
  2. **同一个需求每天最多一条**（靠操作日志去重，重启也不会重复发）；
  3. 三类必然跳过：没有负责人、负责人没 open_id（手工账号）、飞书未启用；
  4. dry_run 只算不发、不写日志（上线前自检用）；
  5. 手动接口的权限（仅管理员/安全专家）。

测试**不发真实请求**：把 feishu.send_in_background（唯一发送出口）换成本地记录函数，
并把 notify_enabled 显式置真（本机 .env 可能没配凭证，否则"跳过"分支永远测不出来）。
"""
from __future__ import annotations

import json
import os
import sys
from datetime import date, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI                            # noqa: E402
from fastapi.testclient import TestClient              # noqa: E402
from sqlalchemy import create_engine                   # noqa: E402
from sqlalchemy.orm import sessionmaker                # noqa: E402
from sqlalchemy.pool import StaticPool                 # noqa: E402

from app import baseline_reminder as reminder          # noqa: E402
from app.database import Base, get_db                  # noqa: E402
from app.models import (                               # noqa: E402
    AssetSystem,
    BaselineCategory,
    BaselineItem,
    BaselineRequirement,
    Role,
    User,
)
from app.routers import baseline as baseline_router    # noqa: E402
from app.routers import feishu                          # noqa: E402
from app.security import get_current_user              # noqa: E402

CURRENT: dict = {}
SENT: list[dict] = []


def _capture(receive_id, msg_type, content, *, tag=""):
    SENT.append({"to": receive_id, "msg_type": msg_type, "content": content, "tag": tag})


def _setup():
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    admin_role = Role(name="超级管理员", code="admin")
    dev_role = Role(name="开发", code="dev")
    db.add_all([admin_role, dev_role])
    db.flush()

    # 负责人分两类：有飞书 open_id 的（能收到）/ 手工账号（没有 open_id，必须跳过）
    with_feishu = User(username="dev1", password_hash="x", full_name="有飞书",
                       role_id=dev_role.id, is_active=True, feishu_open_id="ou_dev1")
    no_feishu = User(username="dev2", password_hash="x", full_name="手工账号",
                     role_id=dev_role.id, is_active=True, feishu_open_id=None)
    secops = User(username="sec1", password_hash="x", full_name="安全专家",
                  role_id=dev_role.id, is_active=True)      # 权限测试用（非 write role）
    admin = User(username="admin", password_hash="x", full_name="管理员",
                 role_id=admin_role.id, is_active=True)
    db.add_all([with_feishu, no_feishu, secops, admin])
    db.commit()
    db.add(AssetSystem(name="A系统"))
    db.commit()

    api = FastAPI()
    api.include_router(baseline_router.router)
    api.dependency_overrides[get_db] = lambda: db
    api.dependency_overrides[get_current_user] = lambda: CURRENT["user"]

    SENT.clear()
    feishu.notify_enabled = lambda: True
    feishu.send_in_background = _capture
    return db, TestClient(api)


def _req(db, *, owner, days, status="in_progress", with_items=True):
    """建一条需求：截止 = 今天 ± days 天（按北京时间算"今天"，与模块同口径）。"""
    today = reminder._cst_today(datetime.utcnow())
    system = db.query(AssetSystem).first()
    if with_items:
        # 分类名/编码按 (baseline_type, code) 唯一 → 每个用例造的模块要各自唯一
        tag = uuid4().hex[:6]
        cat = BaselineCategory(name=f"分类-{tag}", code=f"cat_{tag}",
                               baseline_type="backend_dev", sort=0)
        db.add(cat)
        db.flush()
        for i in range(4):
            db.add(BaselineItem(category_id=cat.id, name=f"检查项{i}", sort=i,
                                description="要求", check_method="manual"))
        db.commit()
    req = BaselineRequirement(
        system_id=system.id, name=f"需求-{days}", baseline_types=json.dumps(["backend_dev"]),
        owner_id=owner.id if owner else None, status=status,
        due_date=datetime.combine(today + timedelta(days=days), datetime.min.time()),
    )
    db.add(req)
    db.commit()
    return req


# ============ 1. 纯函数：挑人与剩余天数 ============
def test_days_left_and_pick_due():
    """剩余天数按"日期"算；挑选规则 = 未完成 + 有日期 + 剩余 <= N（含已逾期）。"""
    today = date(2026, 9, 24)
    assert reminder.days_left(datetime(2026, 9, 24, 0, 0), today) == 0
    assert reminder.days_left(datetime(2026, 9, 30, 0, 0), today) == 6
    assert reminder.days_left(datetime(2026, 9, 20, 0, 0), today) == -4      # 已逾期
    assert reminder.days_left(None, today) is None

    def req(st, due):
        return SimpleNamespace(status=st, due_date=due)

    reqs = [
        req("in_progress", datetime(2026, 9, 25)),   # 还剩 1 天 → 发
        req("in_progress", datetime(2026, 9, 27)),   # 还剩 3 天 → 发（边界）
        req("in_progress", datetime(2026, 9, 28)),   # 还剩 4 天 → 不发
        req("in_progress", None),                    # 没填截止 → 不发
        req("done", datetime(2026, 9, 20)),          # 已完成 → 不发（哪怕已逾期）
        req("in_progress", datetime(2026, 9, 10)),   # 已逾期 14 天 → 发
    ]
    picked = reminder.pick_due(reqs, today, days=3)
    assert [p[1] for p in picked] == [-14, 1, 3], picked   # 最急的排最前
    assert len(picked) == 3


# ============ 2. 卡片文案（口径要写清楚）============
def test_card_text_and_button():
    card = reminder.build_card(system_name="A系统", req_name="A-基线评估",
                               due_text="2026-09-30", left=2, bound=54, assessed=12,
                               compliance=58.1, fail_count=5, base_url="https://x.test")
    text = json.dumps(card, ensure_ascii=False)
    assert card["header"]["title"]["content"] == "基线评估即将到期", text
    assert "还剩 2 天" in text and "A系统" in text, text
    # 「做了多少」与「做对多少」分开写（这两个数字并排最容易混）
    assert "已评估" in text and "12/54" in text, text
    assert "合规率" in text and "58.1%" in text, text
    assert "https://x.test/baseline" in text, text
    assert card["header"]["template"] == "orange", text

    late = reminder.build_card(system_name="A", req_name="B", due_text="2026-09-01", left=-3,
                               bound=4, assessed=0, compliance=0.0, fail_count=0,
                               base_url="")
    late_text = json.dumps(late, ensure_ascii=False)
    assert late["header"]["template"] == "red", late_text
    assert "已逾期 3 天" in late_text, late_text
    assert "button" not in late_text, "拿不到平台地址时不要留死链"   # base_url 空 → 不放按钮


# ============ 3. 真的发 / 一天只发一次 / 跳过分类 ============
def test_tick_sends_once_per_day():
    db, _ = _setup()
    owner = db.query(User).filter(User.username == "dev1").first()
    req = _req(db, owner=owner, days=1)

    stat = reminder.tick(db, days=3)
    assert stat["due"] == 1 and stat["sent"] == 1, stat
    assert SENT and SENT[0]["to"] == "ou_dev1", SENT
    assert SENT[0]["msg_type"] == "interactive", SENT

    # 再跑一次：今天已经发过 → 跳过（去重靠操作日志，进程重启也有效）
    SENT.clear()
    stat2 = reminder.tick(db, days=3)
    assert stat2["due"] == 1 and stat2["sent"] == 0, stat2
    assert stat2["details"][0]["skip"] == "今天已提醒过", stat2
    assert SENT == [], "已经提醒过就不该再发"

    # 换一天（模拟次日）→ 又能发
    stat3 = reminder.tick(db, days=3, now=datetime.utcnow() + timedelta(days=1))
    assert stat3["sent"] == 1, stat3
    assert len(SENT) == 1, SENT
    assert req.id  # 保持引用（避免 linter 认为变量未用）


def test_tick_skips_without_owner_open_id_and_when_disabled():
    db, _ = _setup()
    manual = db.query(User).filter(User.username == "dev2").first()
    _req(db, owner=manual, days=1)
    stat = reminder.tick(db, days=3)
    assert stat["sent"] == 0 and stat["skipped"] == 1, stat
    assert "open_id" in stat["details"][0]["skip"], stat
    assert SENT == []

    # 没有负责人
    _req(db, owner=None, days=1)
    stat2 = reminder.tick(db, days=3)
    assert any(d.get("skip") == "需求没有负责人" for d in stat2["details"]), stat2

    # 飞书未启用：一条都不发
    feishu.notify_enabled = lambda: False
    SENT.clear()
    stat3 = reminder.tick(db, days=3)
    assert stat3["sent"] == 0 and SENT == [], stat3
    assert "未启用" in stat3["details"][0]["skip"], stat3


def test_dry_run_sends_nothing_and_writes_no_log():
    """dry_run：只算"会发给谁"，不发消息、不写日志（否则试跑一次就把当天额度用掉了）。"""
    db, _ = _setup()
    owner = db.query(User).filter(User.username == "dev1").first()
    _req(db, owner=owner, days=2)

    stat = reminder.tick(db, days=3, dry_run=True)
    assert stat["sent"] == 1 and stat["dry_run"] is True, stat
    assert stat["details"][0]["to"] == "有飞书", stat
    assert SENT == [], "dry_run 不该真发"

    from app.models import OperationLog
    assert db.query(OperationLog).filter(OperationLog.action == reminder.DUE_ACTION).count() == 0
    # 试跑之后正式跑仍然会发（dry_run 不占用"今天已提醒"）
    assert reminder.tick(db, days=3)["sent"] == 1


# ============ 4. 手动接口的权限 ============
def test_notify_endpoint_requires_secops():
    db, client = _setup()
    owner = db.query(User).filter(User.username == "dev1").first()
    _req(db, owner=owner, days=1)

    CURRENT["user"] = db.query(User).filter(User.username == "sec1").first()   # dev 角色
    assert client.post("/api/baseline/requirements/notify-due").status_code == 403

    CURRENT["user"] = db.query(User).filter(User.username == "admin").first()
    r = client.post("/api/baseline/requirements/notify-due?dry_run=true")
    assert r.status_code == 200, r.text
    assert r.json()["due"] == 1, r.text
    assert SENT == [], "dry_run 不该真发"


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
