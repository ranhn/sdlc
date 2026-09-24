"""基线「全部通过」批量接口（POST /baseline/requirements/{id}/bulk-result）的回归。

批量操作最容易犯两个错，都在这里钉住：
  1. **把已有结论顺手覆盖掉** —— 尤其"不通过"，那是有依据的判断，不是"还没填"；
  2. **越权** —— 只校验角色、不校验"这条基线在不在本需求绑定范围内"，
     拿到别人的 item_id 就能改（单条接口当初就是为了这个才加了需求上下文）。

用法（在 backend 目录下）：python tests/test_baseline_bulk.py
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI                            # noqa: E402
from fastapi.testclient import TestClient              # noqa: E402
from sqlalchemy import create_engine                   # noqa: E402
from sqlalchemy.orm import sessionmaker                # noqa: E402
from sqlalchemy.pool import StaticPool                 # noqa: E402

from app.baseline_catalog import TYPE_KEYS             # noqa: E402
from app.database import Base, get_db                  # noqa: E402
from app.models import (                               # noqa: E402
    AssetSystem, BaselineCategory, BaselineItem, BaselineRequirement, BaselineResult, Role, User,
)
from app.routers import baseline as baseline_router    # noqa: E402
from app.security import get_current_user              # noqa: E402

CURRENT: dict = {}


def _setup():
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    role = Role(name="超级管理员", code="admin")
    dev_role = Role(name="开发", code="dev")
    db.add_all([role, dev_role])
    db.flush()
    owner = User(username="owner", password_hash="x", full_name="负责人",
                 role_id=role.id, is_active=True)
    other = User(username="other", password_hash="x", full_name="路人",
                 role_id=dev_role.id, is_active=True)
    db.add_all([owner, other])
    db.commit()
    owner = db.query(User).filter(User.username == "owner").first()
    other = db.query(User).filter(User.username == "other").first()

    api = FastAPI()
    api.include_router(baseline_router.router)
    api.dependency_overrides[get_db] = lambda: db
    api.dependency_overrides[get_current_user] = lambda: CURRENT["user"]
    return db, owner, other, TestClient(api)


def _fixture(db, owner):
    """一个系统 + 一条绑定 TYPE_KEYS[0] 的需求，含 5 个检查项。"""
    system = AssetSystem(name="A系统")
    db.add(system)
    db.flush()
    btype = TYPE_KEYS[0]
    cat = BaselineCategory(name="分类A", code="cat_a", baseline_type=btype, sort=0)
    db.add(cat)
    db.flush()
    items = []
    for i in range(5):
        it = BaselineItem(category_id=cat.id, name=f"检查项{i}", sort=i,
                          description="要求", check_method="manual")
        db.add(it)
        items.append(it)
    db.commit()
    req = BaselineRequirement(system_id=system.id, name="A-基线评估",
                              baseline_types=json.dumps([btype]), owner_id=owner.id,
                              status="in_progress")
    db.add(req)
    db.commit()
    return system, btype, items, req


def _results(db, system):
    return {r.item_id: r.status for r in
            db.query(BaselineResult).filter(BaselineResult.system_id == system.id).all()}


def test_bulk_fills_only_pending_and_never_overwrites_existing():
    """只填未评估的：已有的「不通过」「通过」原样保留（这是批量操作的安全底线）。"""
    db, owner, other, client = _setup()
    CURRENT["user"] = owner
    system, btype, items, req = _fixture(db, owner)
    db.add_all([
        BaselineResult(system_id=system.id, item_id=items[0].id, status="fail"),
        BaselineResult(system_id=system.id, item_id=items[1].id, status="pass"),
    ])
    db.commit()

    r = client.post(f"/api/baseline/requirements/{req.id}/bulk-result",
                    json={"baseline_type": btype, "status": "pass"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["changed"] == 3, body          # 3 项待评估被填
    assert body["skipped"] == 2, body          # fail + pass 各跳过 1
    assert body["total"] == 5, body

    got = _results(db, system)
    assert got[items[0].id] == "fail", "「不通过」绝不能被批量覆盖"
    assert got[items[1].id] == "pass", got
    assert all(got[i.id] == "pass" for i in items[2:]), got


def test_bulk_rejects_type_outside_requirement_scope():
    """越权防护：只校验角色不够 —— 未绑定的基线类型必须 400（与单条接口同一道闸）。"""
    db, owner, other, client = _setup()
    CURRENT["user"] = owner
    system, btype, items, req = _fixture(db, owner)
    unbound = [k for k in TYPE_KEYS if k != btype][0]

    r = client.post(f"/api/baseline/requirements/{req.id}/bulk-result",
                    json={"baseline_type": unbound, "status": "pass"})
    assert r.status_code == 400, r.text
    assert "绑定范围" in r.json()["detail"], r.text
    assert _results(db, system) == {}, "被拒绝的请求不该写任何结论"


def test_bulk_allows_pass_and_na_but_not_fail():
    """批量只允许「通过 / 不适用」；「不通过」必须逐项写依据。

    一次给一整组塞同一句理由（"按要求整改"），等于把"依据"变成套话 —— 那正是合规
    检查最怕的东西。标"不适用"是常见的正当批量场景（如这套系统没有固件）。
    """
    db, owner, other, client = _setup()
    CURRENT["user"] = owner
    system, btype, items, req = _fixture(db, owner)

    r = client.post(f"/api/baseline/requirements/{req.id}/bulk-result",
                    json={"baseline_type": btype, "status": "fail"})
    assert r.status_code == 400, r.text
    assert "逐项" in r.json()["detail"], r.text
    assert _results(db, system) == {}, "被拒绝的批量不该写任何结论"

    r = client.post(f"/api/baseline/requirements/{req.id}/bulk-result",
                    json={"baseline_type": btype, "status": "na"})
    assert r.status_code == 200 and r.json()["changed"] == 5, r.text
    assert set(_results(db, system).values()) == {"na"}


def test_bulk_requires_owner_or_write_role():
    """权限与单条评估一致：管理员/安全专家，或该需求负责人本人；其他人 403。"""
    db, owner, other, client = _setup()
    system, btype, items, req = _fixture(db, owner)
    CURRENT["user"] = other
    r = client.post(f"/api/baseline/requirements/{req.id}/bulk-result",
                    json={"baseline_type": btype, "status": "pass"})
    assert r.status_code == 403, r.text
    assert _results(db, system) == {}


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
