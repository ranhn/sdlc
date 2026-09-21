"""登录接口回归：必须返回用户 id。

用法（在 backend 目录下）：
    python tests/test_auth_login.py

为什么值得单测：`Token` 里漏掉 id 时，接口照样 200、页面也不报错 —— 只是所有
"这条记录是不是我的"判断**静默失效**。实测表现就是：把漏洞指派给研发后，他的
「漏洞修复」页看不到「确认 / 驳回」按钮（isAssignee 永远为 false），排查起来毫无线索。
"""

from __future__ import annotations

import os
import sys

# ⚠️ 必须在导入 app.* 之前设好 SECRET_KEY：security.py 在 import 时就读取它，
# 为空时 create_access_token 会直接抛错（登录 500）。
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-login-regression-32chars")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI                            # noqa: E402
from fastapi.testclient import TestClient              # noqa: E402
from sqlalchemy import create_engine                   # noqa: E402
from sqlalchemy.orm import sessionmaker                # noqa: E402
from sqlalchemy.pool import StaticPool                 # noqa: E402

from app.database import Base, get_db                  # noqa: E402
from app.models import Role, User                      # noqa: E402
from app.routers import auth as auth_router            # noqa: E402
from app.security import hash_password                 # noqa: E402


def _setup():
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    role = Role(name="研发人员", code="dev")
    db.add(role)
    db.flush()
    db.add(User(username="dev1", password_hash=hash_password("Aa123456"),
                full_name="研发小王", role_id=role.id, is_active=True,
                must_change_password=True))
    db.commit()

    api = FastAPI()
    api.include_router(auth_router.router)
    api.dependency_overrides[get_db] = lambda: db
    return db, TestClient(api)


def test_login_returns_user_id_and_flags():
    """登录响应必须带 id（前端判断"是不是我负责的/我提交的"全靠它）。"""
    db, client = _setup()
    r = client.post("/api/auth/login", data={"username": "dev1", "password": "Aa123456"})
    assert r.status_code == 200, r.text
    body = r.json()
    dev = db.query(User).filter(User.username == "dev1").first()
    assert body.get("id") == dev.id, f"登录没返回 id（或不对）：{body}"
    assert body["username"] == "dev1"
    assert body["role"] == "dev"
    assert body["must_change_password"] is True, "首登必改密标记要带出来（前端要靠它弹改密框）"
    assert body["access_token"]


def test_login_rejects_wrong_password():
    """密码错误仍然 401（别为了加字段把校验改坏）。"""
    db, client = _setup()
    r = client.post("/api/auth/login", data={"username": "dev1", "password": "wrong-password"})
    assert r.status_code == 401, r.text


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
