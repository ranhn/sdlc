"""指派留痕（漏洞详情「状态流转」时间线）的回归测试。

用法（在 backend 目录下）：
    python -m pytest tests/test_vuln_assign_flow.py -v
    python tests/test_vuln_assign_flow.py

为什么要有它：
    用户反馈"每次指派的记录应该在下面打印出来"—— 指派接口此前只写了操作日志，
    而详情页「状态流转」区块读的是 GET /api/vulns/{id}/flows，那里一条指派都没有。
    本测试打的就是**用户实际看到的那条链路**：
      · 首次指派      → 出现「指派负责人：X」；
      · 换人          → 出现「变更负责人：X → Y」；
      · 编辑里改负责人 → 同样留痕，并注明"（编辑时变更）"；
      · 清空负责人     → 出现「取消指派：X → 未指派」；
      · 没动负责人的编辑 → **不得**往时间线里刷记录。
    另外锁定"from == to == 当前状态"这一约定：前端据此把这类条目渲染成
    单个状态 + 说明，而不是"待确认 → 待确认"这种没信息量的箭头。
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI                            # noqa: E402
from fastapi.testclient import TestClient              # noqa: E402
from sqlalchemy import create_engine                   # noqa: E402
from sqlalchemy.orm import sessionmaker                # noqa: E402
from sqlalchemy.pool import StaticPool                 # noqa: E402

from app.database import Base, get_db                  # noqa: E402
from app.models import Role, User, Vuln                # noqa: E402
from app.routers import vulns as vulns_router          # noqa: E402
from app.security import get_current_user              # noqa: E402

CURRENT: dict = {}


def _setup():
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    admin_role = Role(name="超级管理员", code="admin")
    dev_role = Role(name="研发人员", code="dev")
    db.add_all([admin_role, dev_role])
    db.flush()
    db.add(User(username="admin", password_hash="x", full_name="管理员",
                role_id=admin_role.id, is_active=True))
    db.add(User(username="dev1", password_hash="x", full_name="研发小王",
                role_id=dev_role.id, is_active=True))
    db.add(User(username="dev2", password_hash="x", full_name="研发小李",
                role_id=dev_role.id, is_active=True))
    db.commit()

    api = FastAPI()
    api.include_router(vulns_router.router)
    api.dependency_overrides[get_db] = lambda: db
    api.dependency_overrides[get_current_user] = lambda: CURRENT["user"]
    return db, TestClient(api)


def _user(db, username: str) -> User:
    return db.query(User).filter(User.username == username).first()


def _new_vuln(client) -> int:
    r = client.post("/api/vulns", json={
        "title": "测试漏洞：指派留痕",
        "severity": "low",
        "description": "回归测试用",
        "api_endpoint": "/api/test/assign-flow",
    })
    assert r.status_code in (200, 201), r.text
    return r.json()["id"]


def _flows(client, vid: int) -> list[dict]:
    r = client.get(f"/api/vulns/{vid}/flows")
    assert r.status_code == 200, r.text
    return r.json()


def test_assign_writes_flow_record() -> None:
    """首次指派 / 换人 / 清空，都要在 flows 里留下人话记录。"""
    db, client = _setup()
    CURRENT["user"] = _user(db, "admin")
    vid = _new_vuln(client)
    dev1 = _user(db, "dev1")
    dev2 = _user(db, "dev2")

    # ① 首次指派
    r = client.post(f"/api/vulns/{vid}/assign", json={"assignee_id": dev1.id})
    assert r.status_code == 200, r.text
    items = _flows(client, vid)
    assert items[-1]["comment"].startswith("指派负责人："), items[-1]
    assert "研发小王" in items[-1]["comment"], items[-1]
    assert items[-1]["operator_name"] == "管理员"

    # ② 换人
    r = client.post(f"/api/vulns/{vid}/assign", json={"assignee_id": dev2.id})
    assert r.status_code == 200, r.text
    last = _flows(client, vid)[-1]
    assert last["comment"].startswith("变更负责人："), last
    assert "研发小王" in last["comment"] and "研发小李" in last["comment"], last

    # ③ 清空（走编辑接口，指派接口要求 assignee_id 必填）
    r = client.patch(f"/api/vulns/{vid}", json={"assignee_id": None})
    assert r.status_code == 200, r.text
    last = _flows(client, vid)[-1]
    assert last["comment"].startswith("取消指派："), last
    assert "未指派" in last["comment"], last


def test_assign_flow_keeps_status_unchanged() -> None:
    """指派不改状态：from == to == 当前状态（前端据此渲染单个状态 + 说明）。"""
    db, client = _setup()
    CURRENT["user"] = _user(db, "admin")
    vid = _new_vuln(client)
    assert client.post(f"/api/vulns/{vid}/assign",
                       json={"assignee_id": _user(db, "dev1").id}).status_code == 200
    last = _flows(client, vid)[-1]
    assert last["from_status"] == last["to_status"] == "pending", last


def test_assign_via_edit_is_recorded_but_plain_edit_is_not() -> None:
    """编辑里改负责人要留痕（注明"编辑时变更"）；没动负责人的编辑不得刷屏。"""
    db, client = _setup()
    CURRENT["user"] = _user(db, "admin")
    vid = _new_vuln(client)
    dev1 = _user(db, "dev1")

    before = len(_flows(client, vid))
    # ① 只改标题：时间线不得新增
    r = client.patch(f"/api/vulns/{vid}", json={"title": "改个标题"})
    assert r.status_code == 200, r.text
    assert len(_flows(client, vid)) == before, "没动负责人的编辑不应写流转记录"

    # ② 编辑里改负责人：要留痕
    r = client.patch(f"/api/vulns/{vid}", json={"assignee_id": dev1.id})
    assert r.status_code == 200, r.text
    items = _flows(client, vid)
    assert len(items) == before + 1, items
    assert items[-1]["comment"].endswith("（编辑时变更）"), items[-1]
    assert "研发小王" in items[-1]["comment"], items[-1]


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        fn()
        print(f"  PASS  {fn.__name__}")
    print(f"\n{len(tests)} tests passed")
