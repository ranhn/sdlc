# -*- coding: utf-8 -*-
"""控制模块（基线分类）维护接口回归：新增 / 改名 / 删除 + 重名与删除的边界。

用法（在 backend 目录下）：python tests/test_baseline_category.py

为什么要有它：分类此前只有 GET + POST —— **建错名字只能留着**（检查项能改能删，分类动不了）。
补上改名/删除时有三个坑，都在这里钉住：
  1. 重名只在**同一基线内**算冲突（DB 唯一约束就是 (baseline_type, name)）；
     旧代码查的是全局重名 → "后端开发基线叫了『日志审计』，安全需求基线就不能叫"；
  2. **分类下还有检查项时不许删**：删条目会连带删掉各系统的评估结论（不可逆的取证数据），
     必须让使用者自己决定这些条目去哪；
  3. 权限与其它模板维护一致：仅管理员/安全专家。
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
from app.models import (                               # noqa: E402
    AssetSystem,
    BaselineCategory,
    BaselineItem,
    BaselineResult,
    Role,
    User,
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
    admin_role = Role(name="超级管理员", code="admin")
    dev_role = Role(name="普通", code="user")
    db.add_all([admin_role, dev_role])
    db.flush()
    db.add_all([
        User(username="admin", password_hash="x", full_name="管理员",
             role_id=admin_role.id, is_active=True),
        User(username="Tracy.Yang", password_hash="x", full_name="普通用户",
             role_id=dev_role.id, is_active=True),
    ])
    db.commit()
    db.add(AssetSystem(name="A系统"))
    db.commit()

    api = FastAPI()
    api.include_router(baseline_router.router)
    api.dependency_overrides[get_db] = lambda: db
    api.dependency_overrides[get_current_user] = lambda: CURRENT["user"]
    return db, TestClient(api)


def _u(db, name):
    return db.query(User).filter(User.username == name).first()


def _cat(db, name, btype="backend_dev", items=0):
    cat = BaselineCategory(name=name, code=f"c_{name}", baseline_type=btype, sort=0)
    db.add(cat)
    db.flush()
    for i in range(items):
        db.add(BaselineItem(category_id=cat.id, name=f"{name}-项{i}", sort=i,
                            check_method="manual"))
    db.commit()
    return cat


def test_create_category_auto_code_and_per_type_dup():
    """新增：内部编码自动生成（页面不让用户填）；重名只在同一基线内算冲突。"""
    db, client = _setup()
    CURRENT["user"] = _u(db, "admin")

    r = client.post("/api/baseline/categories", json={"name": "日志审计", "baseline_type": "backend_dev"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["name"] == "日志审计" and body["code"], body       # code 自动生成
    assert body["baseline_type"] == "backend_dev", body

    # 同基线重名 → 400
    r2 = client.post("/api/baseline/categories", json={"name": "日志审计", "baseline_type": "backend_dev"})
    assert r2.status_code == 400, r2.text
    assert "已存在" in r2.json()["detail"], r2.text

    # 另一个基线里的同名模块 → 允许（两条基线本来就各有一套模块名）
    r3 = client.post("/api/baseline/categories", json={"name": "日志审计", "baseline_type": "security_requirement"})
    assert r3.status_code == 201, r3.text


def test_update_category_rename_and_dup_guard():
    """改名：同基线重名要拦；改名**不影响已有检查项与评估结论**（结论挂在 item_id 上）。"""
    db, client = _setup()
    CURRENT["user"] = _u(db, "admin")
    a = _cat(db, "账号安全", items=2)
    b = _cat(db, "密码策略")
    item_ids = [i.id for i in db.query(BaselineItem).filter(BaselineItem.category_id == a.id).all()]

    r = client.put(f"/api/baseline/categories/{a.id}", json={"name": "身份与账号安全"})
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "身份与账号安全", r.json()

    r2 = client.put(f"/api/baseline/categories/{a.id}", json={"name": b.name})
    assert r2.status_code == 400, r2.text
    assert "已有" in r2.json()["detail"], r2.text

    # 名称变了，条目与结论都还在
    assert [i.id for i in db.query(BaselineItem).filter(BaselineItem.category_id == a.id).all()] == item_ids
    listed = client.get("/api/baseline/items?baseline_type=backend_dev").json()
    assert any(i["category_name"] == "身份与账号安全" for i in listed), listed


def test_delete_category_refuses_when_items_exist():
    """分类下还有检查项 → 拒绝删除（删条目会连带删掉评估结论，那是不可逆的取证数据）。"""
    db, client = _setup()
    CURRENT["user"] = _u(db, "admin")
    cat = _cat(db, "接口安全", items=2)
    item = db.query(BaselineItem).filter(BaselineItem.category_id == cat.id).first()
    db.add(BaselineResult(system_id=1, item_id=item.id, status="pass", evidence="ok"))
    db.commit()

    r = client.delete(f"/api/baseline/categories/{cat.id}")
    assert r.status_code == 400, r.text
    assert "检查项" in r.json()["detail"], r.text
    assert db.query(BaselineItem).filter(BaselineItem.category_id == cat.id).count() == 2

    # 把条目挪到别的模块（移动不影响结论）→ 这次能删，且结论仍在
    other = _cat(db, "其它模块")
    for it in db.query(BaselineItem).filter(BaselineItem.category_id == cat.id).all():
        assert client.put(f"/api/baseline/items/{it.id}",
                          json={"category_id": other.id}).status_code == 200
    assert client.delete(f"/api/baseline/categories/{cat.id}").status_code == 204
    assert db.query(BaselineCategory).filter(BaselineCategory.id == cat.id).first() is None
    assert db.query(BaselineResult).filter(BaselineResult.item_id == item.id).count() == 1, \
        "挪模块不该动结论"

    # 不存在的分类 → 404
    assert client.delete("/api/baseline/categories/999999").status_code == 404


def test_category_write_requires_secops():
    """权限与其它模板维护一致：普通用户连改带删一律 403。"""
    db, client = _setup()
    cat = _cat(db, "数据安全")
    CURRENT["user"] = _u(db, "Tracy.Yang")
    assert client.post("/api/baseline/categories",
                       json={"name": "新模块", "baseline_type": "backend_dev"}).status_code == 403
    assert client.put(f"/api/baseline/categories/{cat.id}", json={"name": "改名"}).status_code == 403
    assert client.delete(f"/api/baseline/categories/{cat.id}").status_code == 403


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
