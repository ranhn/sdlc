"""漏洞状态机 · 端到端回归测试（每个动作打一遍接口）。

用法（在 backend 目录下）：
    python -m pytest tests/test_vuln_state_machine.py -v
    python tests/test_vuln_state_machine.py

为什么要有它：
    「修复完成」「关闭」两个动作曾经因为生成时间戳的写法错误
    （`__import__("datetime").nc.utcnow()` —— datetime 模块上根本没有 nc 属性）
    而**必崩 500**，但没有任何测试覆盖"点这些按钮"，所以一直没被发现，
    只能等用户在页面上点到才暴露。这个测试把整条链路（含时间戳落库）打一遍：
      · 每个动作都能走通、状态按预期推进；
      · fixed_at / closed_at 真的写进库（它们不在接口响应里，必须查库断言）；
      · 状态不允许的动作要被拦成 403，而不是 500。
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
    db.commit()

    api = FastAPI()
    api.include_router(vulns_router.router)
    api.dependency_overrides[get_db] = lambda: db
    api.dependency_overrides[get_current_user] = lambda: CURRENT["user"]
    return db, TestClient(api)


def _new_vuln(client) -> int:
    r = client.post("/api/vulns", json={
        "title": "测试漏洞：状态机全流程",
        "severity": "low",
        "description": "回归测试用",
        "api_endpoint": "/api/test/state-machine",
    })
    assert r.status_code in (200, 201), r.text
    return r.json()["id"]


def test_full_state_machine_flow_has_no_500():
    """提交 → 确认 → 修复中 → 修复完成 → 复测通过 → 关闭，每一步都必须成功。"""
    db, client = _setup()
    CURRENT["user"] = db.query(User).filter(User.username == "admin").first()
    vid = _new_vuln(client)

    steps = [("confirm", "confirmed"), ("start_fix", "fixing"),
             ("finish_fix", "retest"), ("pass_retest", "fixed"), ("close", "closed")]
    for action, expect in steps:
        r = client.post(f"/api/vulns/{vid}/action/{action}", json={"comment": "回归"})
        assert r.status_code == 200, f"{action} 返回 {r.status_code}: {r.text}"
        assert r.json()["status"] == expect, f"{action} 后状态是 {r.json()['status']}"


def test_finish_fix_and_close_write_timestamps():
    """fixed_at / closed_at 必须真的写进库 —— 它们不在响应里，只能查库验证。"""
    db, client = _setup()
    CURRENT["user"] = db.query(User).filter(User.username == "admin").first()
    vid = _new_vuln(client)
    for action in ("confirm", "start_fix", "finish_fix"):
        assert client.post(f"/api/vulns/{vid}/action/{action}", json={}).status_code == 200
    db.expire_all()
    v = db.get(Vuln, vid)
    assert v.fixed_at is not None, "修复完成没写 fixed_at"
    assert v.reviewer_id is not None, "修复完成没记复测人"

    assert client.post(f"/api/vulns/{vid}/action/pass_retest", json={}).status_code == 200
    assert client.post(f"/api/vulns/{vid}/action/close", json={}).status_code == 200
    db.expire_all()
    assert db.get(Vuln, vid).closed_at is not None, "关闭没写 closed_at"


def test_illegal_action_returns_403_not_500():
    """状态不允许的动作要拦成 403（不是 500）；研发也不能替安全专家确认。"""
    db, client = _setup()
    CURRENT["user"] = db.query(User).filter(User.username == "admin").first()
    vid = _new_vuln(client)          # 当前 pending
    r = client.post(f"/api/vulns/{vid}/action/close", json={})
    assert r.status_code == 403, f"期望 403，实际 {r.status_code}: {r.text}"

    CURRENT["user"] = db.query(User).filter(User.username == "dev1").first()
    r2 = client.post(f"/api/vulns/{vid}/action/confirm", json={})
    assert r2.status_code == 403, f"研发不应能确认，实际 {r2.status_code}"


def test_ignore_action_is_gone():
    """ignore 动作已删除：状态机里不存在，API 调它会被拦成 403 且状态不变。

    为什么删：页面上从来没有"忽略"入口，库里也没有该状态的数据，留着它就等于
    留了一条"能把漏洞改成页面看不到、也筛不出来"的暗道。
    """
    from app.state_machine import ACTION_RULES, TRANSITIONS

    assert "ignore" not in ACTION_RULES, "状态机里还有 ignore 动作"
    assert "ignore" not in TRANSITIONS, "状态机里还有 ignore 的流转目标"

    db, client = _setup()
    CURRENT["user"] = db.query(User).filter(User.username == "admin").first()
    vid = _new_vuln(client)
    r = client.post(f"/api/vulns/{vid}/action/ignore", json={})
    assert r.status_code == 403, f"期望 403，实际 {r.status_code}: {r.text}"
    db.expire_all()
    assert db.get(Vuln, vid).status == "pending", "被拒绝的动作竟然改了状态"
    # 历史数据兼容：状态常量与中文名保留，老数据仍显示「已忽略」
    from app.state_machine import STATUS_NAMES, VulnState
    assert STATUS_NAMES.get(VulnState.IGNORED) == "已忽略"


def test_reject_records_reason():
    """驳回要落 rejection_reason，并记进流转（详情页靠它显示驳回原因）。"""
    db, client = _setup()
    CURRENT["user"] = db.query(User).filter(User.username == "admin").first()
    vid = _new_vuln(client)
    r = client.post(f"/api/vulns/{vid}/reject", json={"reason": "误报，环境问题"})
    assert r.status_code == 200, r.text
    db.expire_all()
    v = db.get(Vuln, vid)
    assert v.status == "rejected" and v.rejection_reason == "误报，环境问题"


# ============ 负责人（修复人）权限：确认 / 驳回 / 转派 ============
# 背景：修复人页面（前端「漏洞修复」）只显示"指派给我"的漏洞，但此前 confirm/reject
# 只对 admin|secops 开放、assign 也只对 admin|secops 开放 —— 修复人在自己页面上既
# 确认不了也驳回不了，遇到"不该我修"也没有转派入口。现在按**负责人本人**最小放开，
# 下面这几条把"放开了什么"和"没放开什么"都钉住。
def _assign(client, vid: int, assignee_id: int) -> None:
    """管理员把漏洞指派给某人（走真实接口，顺带覆盖 assign 自己的权限判定）。"""
    r = client.post(f"/api/vulns/{vid}/assign", json={"assignee_id": assignee_id})
    assert r.status_code == 200, r.text


def _users(db):
    return (db.query(User).filter(User.username == "admin").first(),
            db.query(User).filter(User.username == "dev1").first())


def test_assignee_can_confirm_own_vuln():
    """被指派的修复人能对自己负责的漏洞「确认」（此前只有 admin/secops 能确认）。"""
    db, client = _setup()
    admin, dev = _users(db)
    CURRENT["user"] = admin
    vid = _new_vuln(client)              # pending
    _assign(client, vid, dev.id)

    CURRENT["user"] = dev
    r = client.post(f"/api/vulns/{vid}/action/confirm", json={"comment": "已确认，安排修复"})
    assert r.status_code == 200, f"负责人应能确认，实际 {r.status_code}: {r.text}"
    assert r.json()["status"] == "confirmed"


def test_assignee_can_reject_own_vuln():
    """负责人能驳回自己负责的漏洞，驳回原因照常落库（"误报"是修复人最常见的结论）。"""
    db, client = _setup()
    admin, dev = _users(db)
    CURRENT["user"] = admin
    vid = _new_vuln(client)
    _assign(client, vid, dev.id)

    CURRENT["user"] = dev
    r = client.post(f"/api/vulns/{vid}/reject", json={"reason": "误报：测试环境未部署该接口"})
    assert r.status_code == 200, f"负责人应能驳回，实际 {r.status_code}: {r.text}"
    db.expire_all()
    v = db.get(Vuln, vid)
    assert v.status == "rejected"
    assert v.rejection_reason == "误报：测试环境未部署该接口"


def test_assignee_can_transfer_assignment():
    """负责人可把漏洞**转派**给别人（页面上那个「指派」按钮），转派后不再归自己。"""
    db, client = _setup()
    admin, dev = _users(db)
    dev2 = User(username="dev2", password_hash="x", full_name="研发小李",
                role_id=dev.role_id, is_active=True)
    db.add(dev2)
    db.commit()

    CURRENT["user"] = admin
    vid = _new_vuln(client)
    _assign(client, vid, dev.id)

    CURRENT["user"] = dev
    r = client.post(f"/api/vulns/{vid}/assign", json={"assignee_id": dev2.id})
    assert r.status_code == 200, f"负责人应能转派，实际 {r.status_code}: {r.text}"
    db.expire_all()
    assert db.get(Vuln, vid).assignee_id == dev2.id, "转派后负责人没变"


def test_assignee_privilege_is_scoped_to_own_vuln():
    """负责人特权**只对自己负责的漏洞**生效：别人的漏洞仍 403（三条动作一起验）。"""
    db, client = _setup()
    admin, dev = _users(db)
    CURRENT["user"] = admin
    vid = _new_vuln(client)              # 不指派给任何人
    _assign(client, vid, admin.id)       # 挂到管理员名下，确保"有主但不是 dev"

    CURRENT["user"] = dev
    for path, payload in ((f"/api/vulns/{vid}/action/confirm", {}),
                          (f"/api/vulns/{vid}/reject", {"reason": "误报"}),
                          (f"/api/vulns/{vid}/assign", {"assignee_id": dev.id})):
        r = client.post(path, json=payload)
        assert r.status_code == 403, f"{path} 应 403，实际 {r.status_code}: {r.text}"
    db.expire_all()
    assert db.get(Vuln, vid).status == "pending", "被拒的动作竟然改了状态"


def test_unassigned_vuln_grants_no_assignee_power():
    """**没人负责**的漏洞不产生任何"负责人特权"。

    这条钉的是最容易写错的实现细节：`v.assignee_id is None` 时若只做 `==` 比较
    （或忘了判空），"无主漏洞"就会被判成"人人都是负责人"，等于把确认/驳回/转派
    开给全站。_is_assignee 里必须同时判 assignee_id 非空。
    """
    db, client = _setup()
    admin, dev = _users(db)
    CURRENT["user"] = admin
    vid = _new_vuln(client)              # assignee_id 为 None

    CURRENT["user"] = dev
    r1 = client.post(f"/api/vulns/{vid}/action/confirm", json={})
    r2 = client.post(f"/api/vulns/{vid}/reject", json={"reason": "误报"})
    r3 = client.post(f"/api/vulns/{vid}/assign", json={"assignee_id": admin.id})
    assert (r1.status_code, r2.status_code, r3.status_code) == (403, 403, 403), \
        f"无主漏洞竟给出负责人权限：{r1.status_code},{r2.status_code},{r3.status_code}"


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
