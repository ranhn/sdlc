"""人员管理接口回归测试：编辑用户 + 提权防护 + 列表字段。

用法（在 backend 目录下）：
    python -m pytest tests/test_user_admin.py -v
    python tests/test_user_admin.py

为什么要有它：
  1. **列表字段**：`UserOut` 少一个字段，前端就整列显示"—"（"最近同步"列就这么哑了
     很久 —— `last_synced_at` 一直没在响应里），字段级回归必须锁住；
  2. **提权路径**：安全专家能改超级管理员账号、或能把自己/别人提升成超级管理员，
     都属于越权，必须在接口层挡住；
  3. **自锁死**：把系统里最后一个超级管理员降级 = 没人能再管理用户与角色，必须拦住；
  4. **少传字段不能清数据**：编辑接口只改传了的字段，没传的保持原样。
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
from app.models import Department, Role, User          # noqa: E402
from app.routers import admin as admin_router          # noqa: E402
from app.security import get_current_user              # noqa: E402

CURRENT: dict = {}          # 当前登录用户（用例里切换）


def _setup():
    # check_same_thread=False + StaticPool：TestClient 在独立线程里跑请求，
    # 内存库必须跨线程共享同一个连接，否则报"SQLite objects created in a thread…"
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    roles = {}
    for name, code in (("超级管理员", "admin"), ("安全专家", "secops"), ("普通权限", "user")):
        r = Role(name=name, code=code)
        db.add(r)
        roles[code] = r
    dept = Department(name="安全部")
    db.add(dept)
    db.flush()
    db.add_all([
        User(username="admin", password_hash="x", full_name="系统管理员",
             role_id=roles["admin"].id, is_active=True),
        User(username="secops1", password_hash="x", full_name="安全运营",
             role_id=roles["secops"].id, is_active=True),
        User(username="Tracy.Yang", password_hash="x", full_name="杨翠", en_name="Tracy.Yang",
             email="tracy.yang@vesync.com", role_id=roles["user"].id, department_id=dept.id,
             feishu_open_id="ou_tracy", is_active=True, must_change_password=True),
    ])
    db.commit()

    api = FastAPI()
    api.include_router(admin_router.router)
    api.dependency_overrides[get_db] = lambda: db
    api.dependency_overrides[get_current_user] = lambda: CURRENT["user"]
    return db, roles, dept, TestClient(api)


def test_list_users_exposes_sync_fields():
    """列表必须带 feishu_open_id 与 last_synced_at（否则前端"最近同步"列与飞书标签永远是空）。"""
    db, roles, dept, client = _setup()
    CURRENT["user"] = db.query(User).filter(User.username == "admin").first()
    rows = client.get("/api/users").json()
    fields = set(rows[0].keys())
    assert "last_synced_at" in fields, fields
    assert "feishu_open_id" in fields, fields
    assert "department_name" in fields, fields
    tracy = next(r for r in rows if r["username"] == "Tracy.Yang")
    assert tracy["feishu_open_id"] == "ou_tracy"
    assert tracy["department_name"] == "安全部"
    # 手工账号没有飞书字段
    assert next(r for r in rows if r["username"] == "admin")["feishu_open_id"] is None


def test_update_user_changes_role_and_keeps_untouched_fields():
    db, roles, dept, client = _setup()
    CURRENT["user"] = db.query(User).filter(User.username == "admin").first()
    tracy = db.query(User).filter(User.username == "Tracy.Yang").first()

    r = client.put(f"/api/users/{tracy.id}", json={"role_id": roles["secops"].id})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["role_code"] == "secops" and body["role_name"] == "安全专家"
    # 没传的字段保持原样（接口只改传了的字段）
    assert body["email"] == "tracy.yang@vesync.com"
    assert body["full_name"] == "杨翠"
    # 姓名/邮箱/部门也能改
    r2 = client.put(f"/api/users/{tracy.id}", json={"full_name": "杨小翠", "email": ""})
    assert r2.status_code == 200 and r2.json()["full_name"] == "杨小翠"
    assert r2.json()["email"] is None       # 显式传空 → 清空邮箱


# ============ 一键重置为初始口令 + 飞书私信通知本人 ============
def _stub_feishu(*, enabled=True, send_error=None, sent=None):
    """把飞书发送换成本地替身（不发真实请求），返回 (恢复函数, sent 列表)。

    显式控制 notify_enabled：本机 .env 里可能配了真实飞书凭证，那会让"未启用飞书"
    这条分支测不出来（会真的尝试发送）。
    """
    fe = admin_router.feishu_notify
    orig_enabled, orig_send = fe.notify_enabled, fe.send_and_wait
    box = sent if sent is not None else []

    def _send(receive_id, msg_type, content):
        if send_error is not None:
            raise send_error
        box.append({"to": receive_id, "msg_type": msg_type, "content": content})
        return {"message_id": "om_test"}

    fe.notify_enabled = lambda: enabled
    fe.send_and_wait = _send

    def restore():
        fe.notify_enabled, fe.send_and_wait = orig_enabled, orig_send

    return restore, box


def _card_text(card) -> str:
    """卡片 JSON 里所有文案拍平（断言关键字用，不绑死结构）。"""
    out: list[str] = []

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "content" and isinstance(v, str):
                    out.append(v)
                else:
                    walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(card)
    return "\n".join(out)


def test_reset_password_sets_default_and_notifies_via_feishu():
    """重置 = 口令恢复默认值 + 强制首登改密 + 当场把账号口令私信给本人。"""
    from app.security import verify_password

    db, roles, dept, client = _setup()
    CURRENT["user"] = db.query(User).filter(User.username == "admin").first()
    tracy = db.query(User).filter(User.username == "Tracy.Yang").first()
    restore, sent = _stub_feishu()
    try:
        r = client.post(f"/api/users/{tracy.id}/reset-password")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["notified"] is True, body
        assert body["password"] == "Aa123456", body
    finally:
        restore()

    db.refresh(tracy)
    assert verify_password("Aa123456", tracy.password_hash), "口令没重置成默认值"
    assert tracy.must_change_password is True, "重置后应强制首登改密"

    assert len(sent) == 1, f"应发 1 条，实际 {len(sent)}"
    assert sent[0]["to"] == "ou_tracy", sent[0]
    assert sent[0]["msg_type"] == "interactive", "应发卡片"
    text = _card_text(sent[0]["content"])
    assert "Tracy.Yang" in text and "Aa123456" in text, text


def test_reset_password_reports_when_account_has_no_feishu():
    """手工账号（无 open_id）：照样重置，但如实回报"没发出去 + 原因"，并回传口令。"""
    from app.security import verify_password

    db, roles, dept, client = _setup()
    CURRENT["user"] = db.query(User).filter(User.username == "admin").first()
    secops = db.query(User).filter(User.username == "secops1").first()   # 无 feishu_open_id
    restore, sent = _stub_feishu()
    try:
        r = client.post(f"/api/users/{secops.id}/reset-password")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["notified"] is False and body["error"], body
        assert "飞书" in body["error"], body
        assert body["password"] == "Aa123456", "失败时也要把口令回给管理员（便于线下告知）"
    finally:
        restore()

    assert sent == [], "没有 open_id 不该尝试发送"
    db.refresh(secops)
    assert verify_password("Aa123456", secops.password_hash), "重置本身必须成功"


def test_reset_password_surfaces_feishu_failure_but_keeps_reset():
    """飞书侧报错（权限没开等）：错误原样回报给管理员，但**重置已经生效**。"""
    from fastapi import HTTPException

    from app.security import verify_password

    db, roles, dept, client = _setup()
    CURRENT["user"] = db.query(User).filter(User.username == "admin").first()
    tracy = db.query(User).filter(User.username == "Tracy.Yang").first()
    restore, sent = _stub_feishu(
        send_error=HTTPException(status_code=502, detail="飞书发消息失败：code=230006 Bot ability"))
    try:
        r = client.post(f"/api/users/{tracy.id}/reset-password")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["notified"] is False, body
        assert "230006" in (body["error"] or ""), body
    finally:
        restore()

    assert sent == []
    db.refresh(tracy)
    assert verify_password("Aa123456", tracy.password_hash), "通知失败不该回滚密码重置"
    assert tracy.must_change_password is True


def test_reset_password_permissions():
    """权限与自锁：非管理员 403、secops 不能重置管理员、不能重置自己。"""
    db, roles, dept, client = _setup()
    admin = db.query(User).filter(User.username == "admin").first()
    secops = db.query(User).filter(User.username == "secops1").first()
    tracy = db.query(User).filter(User.username == "Tracy.Yang").first()
    restore, sent = _stub_feishu()
    try:
        CURRENT["user"] = tracy                      # 普通权限
        assert client.post(f"/api/users/{tracy.id}/reset-password").status_code == 403

        CURRENT["user"] = secops                     # secops 动 admin
        assert client.post(f"/api/users/{admin.id}/reset-password").status_code == 403

        CURRENT["user"] = admin                      # 重置自己
        assert client.post(f"/api/users/{admin.id}/reset-password").status_code == 400
    finally:
        restore()
    assert sent == [], f"被拦下的请求不该发消息：{sent}"


def test_empty_update_is_noop():
    db, roles, dept, client = _setup()
    CURRENT["user"] = db.query(User).filter(User.username == "admin").first()
    tracy = db.query(User).filter(User.username == "Tracy.Yang").first()
    before = client.get("/api/users").json()
    r = client.put(f"/api/users/{tracy.id}", json={})
    assert r.status_code == 200
    after = client.get("/api/users").json()
    assert before == after, "空请求不该改动任何数据"


def test_secops_cannot_touch_admin_nor_escalate():
    db, roles, dept, client = _setup()
    CURRENT["user"] = db.query(User).filter(User.username == "secops1").first()
    admin_row = db.query(User).filter(User.username == "admin").first()
    tracy = db.query(User).filter(User.username == "Tracy.Yang").first()

    # 安全专家不能改超级管理员账号
    r = client.put(f"/api/users/{admin_row.id}", json={"full_name": "改名试试"})
    assert r.status_code == 403 and "超级管理员" in r.json()["detail"], r.text
    # 安全专家不能把别人提升为超级管理员
    r2 = client.put(f"/api/users/{tracy.id}", json={"role_id": roles["admin"].id})
    assert r2.status_code == 403 and "提升" in r2.json()["detail"], r2.text
    # 但可以正常改普通账号的角色（例如设为安全专家）
    r3 = client.put(f"/api/users/{tracy.id}", json={"role_id": roles["secops"].id})
    assert r3.status_code == 200, r3.text


def test_cannot_demote_the_last_admin():
    """把最后一个超级管理员降级 = 系统再没人能管用户/角色，必须拦住。"""
    db, roles, dept, client = _setup()
    CURRENT["user"] = db.query(User).filter(User.username == "secops1").first()
    # 先造第二个 admin，验证"有人兜底时允许降级"，避免规则写死成"admin 永远不能降级"
    admin_row = db.query(User).filter(User.username == "admin").first()
    backup = User(username="admin2", password_hash="x", full_name="备胎管理员",
                  role_id=roles["admin"].id, is_active=True)
    db.add(backup)
    db.commit()

    CURRENT["user"] = db.query(User).filter(User.username == "admin2").first()
    r = client.put(f"/api/users/{admin_row.id}", json={"role_id": roles["user"].id})
    assert r.status_code == 200, r.text          # 还有 admin2 兜底 → 允许

    # 现在只剩 admin2 一个超管了，降级它必须被拒
    r2 = client.put(f"/api/users/{backup.id}", json={"role_id": roles["user"].id})
    assert r2.status_code == 400 and "至少" in r2.json()["detail"], r2.text


def test_update_missing_user_returns_404():
    db, roles, dept, client = _setup()
    CURRENT["user"] = db.query(User).filter(User.username == "admin").first()
    assert client.put("/api/users/99999", json={"full_name": "x"}).status_code == 404


# ============ 人员下拉（/users/pick）的权限边界 ============
def test_user_pick_open_to_any_logged_in_user_but_users_stays_admin_only():
    """人员下拉对**任何已登录用户**开放，而全量人员列表仍然只给 admin/secops。

    背景：漏洞的负责人可以是任何同事，所以"能指派"的人必须能列出全部人员 —— 而"能指派"的人里
    包含**修复人本人**（他可以在「漏洞修复」页把自己负责的漏洞转派给同事）。此前
    /users/pick 上有 require_admin：研发只拿到按钮、拿不到数据源，点开「指派」弹窗一片空白
    （前端又是空 catch，看不出是 403）—— 这就是实测踩到的现象。
    这里同时钉住"放宽的只有这一份 3 字段数据"：邮箱/角色/部门/飞书 id 仍锁在 /users 里。
    """
    db, roles, dept, client = _setup()
    tracy = db.query(User).filter(User.username == "Tracy.Yang").first()   # 普通权限
    CURRENT["user"] = tracy

    r = client.get("/api/users/pick")
    assert r.status_code == 200, f"普通用户应能读人员下拉，实际 {r.status_code}: {r.text}"
    rows = r.json()
    # 必须能选到任何人（含 admin/secops —— 负责人不按角色限制）
    assert {"admin", "secops1", "Tracy.Yang"} <= {u["username"] for u in rows}, rows
    # 只暴露 3 个字段：多一个字段就是多一份顺带泄露
    assert set(rows[0].keys()) == {"id", "username", "full_name"}, rows[0]

    # 反过来：带邮箱/角色/部门/飞书 id 的全量列表仍 403 —— 放宽的只有下拉这一个接口
    assert client.get("/api/users").status_code == 403, "全量人员列表不该对普通用户开放"


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
