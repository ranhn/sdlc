"""基线需求（范围绑定）回归测试：分母口径、不适用计入、范围校验、权限。

用法（在 backend 目录下）：
    python -m pytest tests/test_baseline_requirement.py -v
    python tests/test_baseline_requirement.py

为什么要有它：
  1. **分母口径**：这是整件事的核心 —— 合规率必须只按"本需求绑定的基线"算。老口径把
     全库条目当分母（系统数 × 全部条目数），没做过基线的系统也在拉低整体数字，且这个
     数字回答不了"谁欠账"。这里钉住"只绑后端时，分母就是后端的 2 条"。
  2. **不适用计入分母**：`合规率 = 通过 ÷ 应评`（需求方口径）。曾有一版把 na 从分母剔除
     （怕标了 na 反而拉低数字），现按"应评即分母"。测试里同时断言"不等于旧口径的值"。
  3. **范围校验**：负责人（研发）可以自评，但**只能动本需求绑定范围内的条目** —— 放开
     权限时最怕的就是顺手把"任意检查项"也放开了。
  4. **解绑不删结论**：结论属于系统（baseline_result），不属于某条需求；解绑再绑回来
     不该要求重填。删需求同理。
  5. **去重**：同一系统两条需求都绑同一个基线时，概览不能把同一检查项算两遍。
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

from app.baseline_catalog import BASELINE_TYPES        # noqa: E402
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

CURRENT: dict = {}          # 当前登录用户（用例里切换）

# 测试数据：安全需求基线 3 条（1 分类 2 条 + 1 分类 1 条）、后端开发基线 2 条、
# APP 开发基线**故意留空**（0 条）—— 用来钉住"空基线不能让接口 500 / 不能算成 100%"
ITEMS = {
    "security_requirement": [("账号安全", "禁用默认账号"), ("账号安全", "权限最小化"),
                             ("密码策略", "密码复杂度")],
    "backend_dev": [("接口安全", "接口鉴权"), ("接口安全", "越权校验")],
}


def _setup():
    # check_same_thread=False + StaticPool：TestClient 在独立线程里发请求，
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
    db.flush()
    db.add_all([
        User(username="admin", password_hash="x", full_name="系统管理员",
             role_id=roles["admin"].id, is_active=True),
        User(username="secops1", password_hash="x", full_name="安全运营",
             role_id=roles["secops"].id, is_active=True),
        User(username="Tracy.Yang", password_hash="x", full_name="杨翠",
             role_id=roles["user"].id, is_active=True),
        User(username="Alan.Li", password_hash="x", full_name="李阿蓝",
             role_id=roles["user"].id, is_active=True),
    ])
    db.add_all([AssetSystem(name="H业务"), AssetSystem(name="订单系统")])
    db.flush()

    for btype, rows in ITEMS.items():
        cats: dict[str, BaselineCategory] = {}
        for idx, (cat_name, item_name) in enumerate(rows):
            cat = cats.get(cat_name)
            if not cat:
                cat = BaselineCategory(name=cat_name, code=f"{btype}_{idx}",
                                       baseline_type=btype, sort=idx)
                db.add(cat)
                db.flush()
                cats[cat_name] = cat
            db.add(BaselineItem(category_id=cat.id, name=item_name, severity="high",
                                check_method="manual", is_required=True, sort=idx))
    db.commit()

    api = FastAPI()
    api.include_router(baseline_router.router)
    api.dependency_overrides[get_db] = lambda: db
    api.dependency_overrides[get_current_user] = lambda: CURRENT["user"]
    return db, client_of(api)


def client_of(api):
    return TestClient(api)


def _users(db):
    return {u.username: u for u in db.query(User).all()}


def _create(db, client, system_name="H业务", types=("backend_dev",), **extra):
    """建一条需求（默认绑后端开发基线），返回响应体。"""
    system = db.query(AssetSystem).filter(AssetSystem.name == system_name).first()
    payload = {"system_id": system.id, "baseline_types": list(types)}
    payload.update(extra)
    r = client.post("/api/baseline/requirements", json=payload)
    return r


# ============ 1. 类型目录 ============
def test_types_returns_all_five_with_counts():
    """5 个类型都要返回（含 0 条的空基线），并带上条目/分类数。"""
    db, client = _setup()
    CURRENT["user"] = _users(db)["admin"]
    rows = client.get("/api/baseline/types").json()
    assert [r["key"] for r in rows] == list(BASELINE_TYPES), rows
    by = {r["key"]: r for r in rows}

    assert by["security_requirement"]["item_count"] == 3, by["security_requirement"]
    assert by["security_requirement"]["category_count"] == 2, by["security_requirement"]
    assert by["backend_dev"]["item_count"] == 2, by["backend_dev"]
    # 空基线照样返回（0 条 = 这批 Excel 还没导入，前端据此置灰）
    assert by["app_dev"]["item_count"] == 0, by["app_dev"]
    assert by["app_dev"]["label"] == BASELINE_TYPES["app_dev"]


# ============ 2. 分母口径 ============
def test_denominator_is_bound_scope_only():
    """只绑后端开发基线 → 分母是那 2 条，不把安全需求基线的 3 条算进去。"""
    db, client = _setup()
    CURRENT["user"] = _users(db)["admin"]

    body = _create(db, client, types=["backend_dev"]).json()
    assert body["bound_items"] == 2, body
    assert body["compliance"] == 0.0 and body["progress"] == 0.0, body
    assert body["pending_count"] == 2, body
    assert body["baseline_labels"] == [BASELINE_TYPES["backend_dev"]], body

    # 再绑上安全需求 → 分母变成 2 + 3
    r2 = client.put(f"/api/baseline/requirements/{body['id']}",
                    json={"baseline_types": ["backend_dev", "security_requirement"]})
    assert r2.status_code == 200, r2.text
    assert r2.json()["bound_items"] == 5, r2.json()
    # 归一后按目录顺序（安全需求在前），前端分组顺序依赖它
    assert r2.json()["baseline_types"] == ["security_requirement", "backend_dev"], r2.json()


def test_na_counts_in_compliance_denominator():
    """1 通过 / 1 不通过 / 1 不适用 → 合规率 33.3（**不适用也算分母**），进度 100。

    口径变更（需求方要求）：`合规率 = 通过 ÷ 应评`。旧版把"不适用"从分母剔除以避免
    "标了 na 反而拉低数字"，现在按"应评即分母" —— 标了不适用的条目同样没通过。
    """
    db, client = _setup()
    CURRENT["user"] = _users(db)["admin"]
    req = _create(db, client, types=["security_requirement"]).json()

    items = client.get(f"/api/baseline/requirements/{req['id']}/items").json()
    assert len(items) == 3, items
    for item, status in zip(items, ("pass", "fail", "na")):
        r = client.put(f"/api/baseline/requirements/{req['id']}/items/{item['item_id']}",
                       json={"status": status, "evidence": "证据"})
        assert r.status_code == 200, r.text

    row = client.get("/api/baseline/requirements").json()[0]
    assert (row["pass_count"], row["fail_count"], row["na_count"]) == (1, 1, 1), row
    assert row["pending_count"] == 0, row
    assert row["progress"] == 100.0, row
    # 分母 = 应评 3 → 1/3 = 33.3（旧口径 1/2 = 50.0，这里明确把它排除掉）
    assert row["compliance"] == 33.3, row
    assert row["compliance"] != 50.0, "「不适用」要计入合规率分母（现行口径）"


def test_empty_baseline_does_not_break_rates():
    """绑了一个 0 条目的基线：bound_items=0，不能除零 500，也不该算成 100%。"""
    db, client = _setup()
    CURRENT["user"] = _users(db)["admin"]
    r = _create(db, client, types=["app_dev"])
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["bound_items"] == 0, body
    assert body["compliance"] == 0.0 and body["progress"] == 0.0, body


# ============ 3. 详情只给绑定范围内的条目 ============
def test_items_only_from_bound_baselines():
    db, client = _setup()
    CURRENT["user"] = _users(db)["admin"]
    req = _create(db, client, types=["backend_dev"]).json()

    items = client.get(f"/api/baseline/requirements/{req['id']}/items").json()
    assert len(items) == 2, items
    assert {i["baseline_type"] for i in items} == {"backend_dev"}, items
    assert all(i["baseline_label"] == BASELINE_TYPES["backend_dev"] for i in items), items
    assert all(i["status"] == "pending" for i in items), items
    assert all(i["category_name"] == "接口安全" for i in items), items

    # 未绑定的基线：传了也只返回空（不是"顺手给全库"）
    assert client.get(f"/api/baseline/requirements/{req['id']}/items",
                      params={"baseline_type": "security_requirement"}).json() == []
    # 范围内按基线过滤正常
    only = client.get(f"/api/baseline/requirements/{req['id']}/items",
                      params={"baseline_type": "backend_dev"}).json()
    assert len(only) == 2, only


# ============ 4. 权限与范围约束 ============
def test_owner_can_evaluate_only_within_scope():
    """研发（需求负责人）能自评，但只能动本需求绑定的条目；别人的需求一律 403。"""
    db, client = _setup()
    users = _users(db)
    CURRENT["user"] = users["admin"]
    req = _create(db, client, types=["backend_dev"],
                  owner_id=users["Tracy.Yang"].id).json()
    other_req = _create(db, client, system_name="订单系统", types=["security_requirement"],
                        owner_id=users["Alan.Li"].id).json()

    mine = client.get(f"/api/baseline/requirements/{req['id']}/items").json()
    in_scope = mine[0]["item_id"]

    # 范围内 → 允许（研发自评）
    CURRENT["user"] = users["Tracy.Yang"]
    r = client.put(f"/api/baseline/requirements/{req['id']}/items/{in_scope}",
                   json={"status": "pass", "evidence": "已配置"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "pass"

    # 不在这条需求范围内（安全需求基线的条目，且是别人的需求）
    outsider = client.get("/api/baseline/items", params={"baseline_type": "security_requirement"})
    outside_id = outsider.json()[0]["id"]
    r2 = client.put(f"/api/baseline/requirements/{req['id']}/items/{outside_id}",
                    json={"status": "pass"})
    assert r2.status_code == 400 and "范围" in r2.json()["detail"], r2.text

    # 别人负责的需求（哪怕条目同属后端基线）
    r3 = client.put(f"/api/baseline/requirements/{other_req['id']}/items/{in_scope}",
                    json={"status": "pass"})
    assert r3.status_code == 403, r3.text

    # 非负责人也不能建/改/删需求
    assert client.post("/api/baseline/requirements",
                       json={"system_id": 1, "baseline_types": ["backend_dev"]}).status_code == 403
    assert client.put(f"/api/baseline/requirements/{req['id']}",
                      json={"name": "改名"}).status_code == 403
    assert client.delete(f"/api/baseline/requirements/{req['id']}").status_code == 403


# ============ 5. 改绑定 / 删需求都不动已有结论 ============
def test_rebinding_and_delete_keep_existing_results():
    db, client = _setup()
    CURRENT["user"] = _users(db)["admin"]
    req = _create(db, client, types=["backend_dev"]).json()
    items = client.get(f"/api/baseline/requirements/{req['id']}/items").json()
    first_id = items[0]["item_id"]
    client.put(f"/api/baseline/requirements/{req['id']}/items/{first_id}",
               json={"status": "pass", "evidence": "已配置"})

    # 解绑后端基线（换成安全需求）→ 结论保留在库，切回来还在
    assert client.put(f"/api/baseline/requirements/{req['id']}",
                      json={"baseline_types": ["security_requirement"]}).status_code == 200
    back = client.put(f"/api/baseline/requirements/{req['id']}",
                      json={"baseline_types": ["backend_dev"]}).json()
    assert back["pass_count"] == 1, back
    assert back["compliance"] == 50.0, back          # 1/2

    # 删需求：只删范围，不删结论
    assert client.delete(f"/api/baseline/requirements/{req['id']}").status_code == 204
    assert db.query(BaselineResult).count() == 1, "删需求不该连带删除评估结论"


# ============ 6. 概览去重 ============
def test_overview_dedupes_shared_baselines():
    """同一系统两条需求都绑后端基线：同一检查项在概览里只算一次。"""
    db, client = _setup()
    CURRENT["user"] = _users(db)["admin"]
    a = _create(db, client, types=["backend_dev"]).json()
    _create(db, client, types=["backend_dev"], name="H业务-后端基线-复评")

    items = client.get(f"/api/baseline/requirements/{a['id']}/items").json()
    client.put(f"/api/baseline/requirements/{a['id']}/items/{items[0]['item_id']}",
               json={"status": "pass"})

    ov = client.get("/api/baseline/requirements/overview").json()
    assert ov["requirement_count"] == 2, ov
    assert ov["system_count"] == 1, ov
    assert ov["bound_items"] == 2, ov          # 2 条需求 × 2 条后端检查项，去重后仍是 2
    assert ov["pass_count"] == 1, ov
    assert ov["compliance"] == 50.0, ov        # 1/2，重复需求不会把它压成 1/4


# ============ 7. 入参校验 ============
def test_create_validation():
    db, client = _setup()
    CURRENT["user"] = _users(db)["admin"]

    # 系统不存在
    assert client.post("/api/baseline/requirements",
                       json={"system_id": 99999, "baseline_types": ["backend_dev"]}).status_code == 404
    # 空绑定
    r = _create(db, client, types=[])
    assert r.status_code == 400 and "至少" in r.json()["detail"], r.text
    # 未知类型
    r2 = _create(db, client, types=["backend_dev", "OOPS"])
    assert r2.status_code == 400 and "OOPS" in r2.json()["detail"], r2.text
    # 负责人不存在
    r3 = _create(db, client, types=["backend_dev"], owner_id=99999)
    assert r3.status_code == 400, r3.text

    # 名称留空 → 自动生成「<系统名>-基线评估」
    body = _create(db, client, types=["backend_dev"]).json()
    assert body["name"] == "H业务-基线评估", body
    assert body["status"] == "in_progress", body
    assert body["system_name"] == "H业务", body

    # 编辑：状态非法 / 空名称 / 空绑定都被挡
    rid = body["id"]
    assert client.put(f"/api/baseline/requirements/{rid}",
                      json={"status": "whatever"}).status_code == 400
    assert client.put(f"/api/baseline/requirements/{rid}",
                      json={"name": "   "}).status_code == 400
    assert client.put(f"/api/baseline/requirements/{rid}",
                      json={"baseline_types": []}).status_code == 400
    # 需求不存在
    assert client.put("/api/baseline/requirements/99999", json={"name": "x"}).status_code == 404
    assert client.get("/api/baseline/requirements/99999/items").status_code == 404
    assert client.delete("/api/baseline/requirements/99999").status_code == 404


def test_update_can_close_and_clear_due_date():
    db, client = _setup()
    CURRENT["user"] = _users(db)["admin"]
    req = _create(db, client, types=["backend_dev"], due_date="2026-10-31T00:00:00").json()
    assert req["due_date"].startswith("2026-10-31"), req

    r = client.put(f"/api/baseline/requirements/{req['id']}",
                   json={"status": "done", "due_date": None})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "done", r.json()
    assert r.json()["due_date"] is None, "显式传 null 应清除截止日期"

    # 只改名字时，其它字段保持原样（只改传了的字段）
    r2 = client.put(f"/api/baseline/requirements/{req['id']}", json={"name": "改名了"})
    assert r2.json()["name"] == "改名了" and r2.json()["status"] == "done", r2.json()


# ============ 8. 每个基线各自的进度 ============
def test_per_baseline_breakdown():
    """整体"75 项里做了 8 项"看不出问题在哪 —— 每条基线要有自己的进度与计数。

    场景：绑「安全需求基线(3)」+「后端开发基线(2)」，只在后端那条上评 1 条通过：
      · 后端开发：total 2 / 通过 1 / 未评估 1 / 进度 50%
      · 安全需求：total 3 / 通过 0 / 未评估 3 / 进度 0%
      · 整体：bound 5 / 通过 1 / 进度 20%
    列表卡与详情面板都靠这份数据画进度条，所以顺序（目录顺序）也钉住。
    """
    db, client = _setup()
    CURRENT["user"] = _users(db)["admin"]
    req = _create(db, client, types=["security_requirement", "backend_dev"]).json()
    assert [b["type"] for b in req["baselines"]] == ["security_requirement", "backend_dev"], req["baselines"]
    assert [b["total"] for b in req["baselines"]] == [3, 2], req["baselines"]
    assert [b["label"] for b in req["baselines"]] == ["安全需求基线", "后端开发安全基线"], req["baselines"]
    assert req["bound_items"] == 5, req

    items = client.get(f"/api/baseline/requirements/{req['id']}/items").json()
    backend_item = next(i for i in items if i["baseline_type"] == "backend_dev")
    client.put(f"/api/baseline/requirements/{req['id']}/items/{backend_item['item_id']}",
               json={"status": "pass"})

    row = client.get("/api/baseline/requirements").json()[0]
    by = {b["type"]: b for b in row["baselines"]}
    assert by["backend_dev"]["pass_count"] == 1, by["backend_dev"]
    assert by["backend_dev"]["progress"] == 50.0, by["backend_dev"]
    assert by["backend_dev"]["pending_count"] == 1, by["backend_dev"]
    assert by["security_requirement"]["pass_count"] == 0, by["security_requirement"]
    assert by["security_requirement"]["progress"] == 0.0, by["security_requirement"]
    assert row["pass_count"] == 1 and row["progress"] == 20.0, row      # 1/5

    # 概览只做汇总，不受单基线拆分影响；另外要给出"按系统"的行（首页那张卡用）
    ov = client.get("/api/baseline/requirements/overview").json()
    assert ov["bound_items"] == 5 and ov["pass_count"] == 1, ov
    assert [s["system_name"] for s in ov["systems"]] == ["H业务"], ov["systems"]
    assert ov["systems"][0]["compliance"] == 20.0, ov["systems"][0]        # 1/5
    assert ov["systems"][0]["bound_items"] == 5, ov["systems"][0]


def test_overview_lists_systems_worst_first():
    """两个系统：一个做满、一个没动 —— 概览要按系统列出，且**最差的排最前**。

    首页的「安全基线整体合规率」卡就是按这个顺序画的：直接看到谁欠账，
    而不是只给一个整体百分比（整体 50% 说不出问题在谁身上）。
    """
    db, client = _setup()
    CURRENT["user"] = _users(db)["admin"]
    a = _create(db, client, system_name="H业务", types=["backend_dev"]).json()
    _create(db, client, system_name="订单系统", types=["backend_dev"])
    for it in client.get(f"/api/baseline/requirements/{a['id']}/items").json():
        client.put(f"/api/baseline/requirements/{a['id']}/items/{it['item_id']}",
                   json={"status": "pass"})

    ov = client.get("/api/baseline/requirements/overview").json()
    assert ov["system_count"] == 2, ov
    rows = {s["system_name"]: s for s in ov["systems"]}
    assert rows["H业务"]["compliance"] == 100.0 and rows["H业务"]["progress"] == 100.0, rows["H业务"]
    assert rows["订单系统"]["compliance"] == 0.0 and rows["订单系统"]["pending_count"] == 2, rows["订单系统"]
    assert ov["systems"][0]["system_name"] == "订单系统", ov["systems"]
    # 整体仍是"按系统去重后汇总"：2 条通过 ÷ (2 系统 × 2 项) = 50%
    assert ov["pass_count"] == 2 and ov["bound_items"] == 4, ov
    assert ov["compliance"] == 50.0, ov


def test_overview_systems_empty_when_no_requirements():
    """没有任何需求时也要返回结构一致的 systems: []（前端不必做存在性判断）。"""
    db, client = _setup()
    CURRENT["user"] = _users(db)["admin"]
    ov = client.get("/api/baseline/requirements/overview").json()
    assert ov["systems"] == [] and ov["system_count"] == 0, ov


def test_item_edit_keeps_existing_results():
    """编辑检查项：改名/改要求**不动评估结论**（结论挂在 item_id 上，不挂在名字上）。

    回归点：此前只有"新增 + 删除"，改个错别字只能删了重建 —— 而删除会连带删掉所有系统
    在该检查项上的评估结论（前端确认弹窗里就这么写的）。改名是零风险操作，不该走那条路。
    """
    db, client = _setup()
    CURRENT["user"] = _users(db)["admin"]
    req = _create(db, client, types=["backend_dev"]).json()          # 2 条检查项
    item = db.query(BaselineItem).filter(BaselineItem.name == "接口鉴权").first()
    assert client.put(f"/api/baseline/requirements/{req['id']}/items/{item.id}",
                      json={"status": "fail", "evidence": "越权可访问"}).status_code == 200

    r = client.put(f"/api/baseline/items/{item.id}",
                   json={"name": "接口鉴权（改名）", "description": "新的要求",
                         "check_method": "manual"})
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "接口鉴权（改名）", r.json()

    # 结论还在：1 不通过 / 2 项
    assert db.query(BaselineResult).filter(BaselineResult.item_id == item.id).count() == 1
    row = client.get("/api/baseline/requirements").json()[0]
    assert (row["pass_count"], row["fail_count"]) == (0, 1), row
    assert row["compliance"] == 0.0, row
    # 需求详情里显示的是新名字（前端表格直接读 item_name）
    items = client.get(f"/api/baseline/requirements/{req['id']}/items").json()
    assert any(i["item_name"] == "接口鉴权（改名）" for i in items), items


def test_check_method_only_manual():
    """「自动」检查方式被显式拒绝：没有任何代码在读 check_method。

    回归点：库里曾提供「自动」选项，但挂了"自动"的检查项照样要人工点结论（模板库那列
    因此常年只有"人工"一个值）。留着它 = 对着界面承诺一个不存在的自动化。
    """
    db, client = _setup()
    CURRENT["user"] = _users(db)["admin"]
    cat = db.query(BaselineCategory).filter(BaselineCategory.baseline_type == "backend_dev").first()
    r = client.post("/api/baseline/items",
                    json={"category_id": cat.id, "name": "自动项", "check_method": "automated"})
    assert r.status_code == 400, r.text
    assert "人工" in r.json()["detail"], r.text
    # 不传 check_method（默认 manual）正常建
    r = client.post("/api/baseline/items", json={"category_id": cat.id, "name": "人工项"})
    assert r.status_code == 201, r.text


def test_fail_needs_evidence_and_pending_resets():
    """两条硬要求：**「不通过」必须留依据**、**结论可以撤回（重置为未评估）**。

    为什么钉在这：① 一条"不通过"没有说明，研发不知道改什么、审计问不出所以然 ——
    结论可以下，但必须带着理由下；② 手滑点错只能被另一个结论顶替（等于逼人编一个
    结论出来），所以要有"回到未评估"这条正路。
    """
    db, client = _setup()
    CURRENT["user"] = _users(db)["admin"]
    req = _create(db, client, types=["backend_dev"]).json()
    item = db.query(BaselineItem).filter(BaselineItem.name == "接口鉴权").first()
    url = f"/api/baseline/requirements/{req['id']}/items/{item.id}"

    # 不通过：缺说明 / 只有空白 → 400；都不该写库
    assert client.put(url, json={"status": "fail"}).status_code == 400
    assert client.put(url, json={"status": "fail", "evidence": "   "}).status_code == 400
    assert db.query(BaselineResult).filter(BaselineResult.item_id == item.id).count() == 0

    r = client.put(url, json={"status": "fail", "evidence": "未开启鉴权，要求 9/30 前整改"})
    assert r.status_code == 200, r.text
    assert r.json()["evidence"].startswith("未开启鉴权"), r.json()

    # 重置为未评估：状态、说明、评估人、评估时间一并清空（不能留下"半截结论")
    r = client.put(url, json={"status": "pending"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "pending", body
    assert not body["evidence"] and not body["checked_at"], body
    row = db.query(BaselineResult).filter(BaselineResult.item_id == item.id).first()
    assert (row.status, row.evidence, row.checker_id) == ("pending", None, None), row
    # 页面上回到"未评估"：本需求 2 条都未评估
    assert client.get("/api/baseline/requirements").json()[0]["pending_count"] == 2
    # 「通过」不需要说明，仍然一键可存
    assert client.put(url, json={"status": "pass"}).status_code == 200


def test_export_requirement_csv():
    """导出 CSV = 能送审的台账：每条带结论 + 依据 + 评估人 + 时间，未评估的也要在。"""
    db, client = _setup()
    CURRENT["user"] = _users(db)["admin"]
    req = _create(db, client, types=["backend_dev"]).json()
    item = db.query(BaselineItem).filter(BaselineItem.name == "接口鉴权").first()
    client.put(f"/api/baseline/requirements/{req['id']}/items/{item.id}",
               json={"status": "fail", "evidence": "未开启鉴权"})

    r = client.get(f"/api/baseline/requirements/{req['id']}/export")
    assert r.status_code == 200, r.text
    assert "attachment" in r.headers.get("content-disposition", ""), r.headers
    text = r.content.decode("utf-8-sig")          # 去 BOM 后按普通文本断言
    assert text.splitlines()[0] == \
        "系统,需求,基线,控制模块,检查项,要求,评估结果,说明与证据,评估人,评估时间", text[:200]
    assert "不通过" in text and "未开启鉴权" in text, text
    assert "未评估" in text, "另一条没评过的也必须出现在台账里（导出是全量，不跟页面筛选）"
    assert "H业务" in text, text                   # 每行都带系统/需求，便于多份文件合并后筛选

    # 权限与评估一致：普通用户且非负责人 → 403
    CURRENT["user"] = _users(db)["Tracy.Yang"]
    assert client.get(f"/api/baseline/requirements/{req['id']}/export").status_code == 403
    # 只支持 csv（不静默给一个别的格式）
    CURRENT["user"] = _users(db)["admin"]
    assert client.get(f"/api/baseline/requirements/{req['id']}/export?fmt=docx").status_code == 400


def test_item_edit_requires_secops():
    """改检查项属模板维护：与新增/删除同一道权限闸（普通权限 403）。"""
    db, client = _setup()
    CURRENT["user"] = _users(db)["Tracy.Yang"]
    item = db.query(BaselineItem).first()
    assert client.put(f"/api/baseline/items/{item.id}",
                      json={"name": "随便改"}).status_code == 403


# ============ 10. 全部评完自动收口 ============
def test_autoclose_when_all_assessed():
    """全部评完 → 需求自动置为「已完成」。

    为什么是自动：进度 100% 却还挂着"进行中"，看的人不知道到底算不算完；此前在行上补了
    一个「已评完 · 标记完成」的提示 —— 那是同一个动作的**第二个入口**（页面上两个"标记完成"）。
    现在系统收口，行上只留一个状态词。

    同时钉住"只单向收口"：撤销一条结论不会把已完成的需求自动拉回进行中
    （「重新开启」是人的决定，系统不抢）。
    """
    db, client = _setup()
    CURRENT["user"] = _users(db)["admin"]
    req = _create(db, client, types=["backend_dev"]).json()          # 2 条检查项
    items = (db.query(BaselineItem)
             .join(BaselineCategory, BaselineItem.category_id == BaselineCategory.id)
             .filter(BaselineCategory.baseline_type == "backend_dev")
             .order_by(BaselineItem.id).all())
    assert len(items) == 2, items
    url = f"/api/baseline/requirements/{req['id']}/items"

    # 只评了 1 条：还没完，仍是进行中
    assert client.put(f"{url}/{items[0].id}", json={"status": "pass"}).status_code == 200
    assert client.get("/api/baseline/requirements").json()[0]["status"] == "in_progress"

    # 最后一条评完 → 自动已完成
    assert client.put(f"{url}/{items[1].id}", json={"status": "pass"}).status_code == 200
    row = client.get("/api/baseline/requirements").json()[0]
    assert row["status"] == "done", row
    assert row["progress"] == 100.0, row

    # 撤销一条：进度回落，但状态不回退（单向收口）
    assert client.put(f"{url}/{items[1].id}", json={"status": "pending"}).status_code == 200
    again = client.get("/api/baseline/requirements").json()[0]
    assert again["progress"] < 100 and again["status"] == "done", again


def test_autoclose_via_bulk_and_ignores_empty_scope():
    """批量评完也收口；但**一条基线都没绑**（应评 0）不算做完 —— 免得建完需求就自封完成。"""
    db, client = _setup()
    CURRENT["user"] = _users(db)["admin"]

    req = _create(db, client, types=["backend_dev"]).json()
    r = client.post(f"/api/baseline/requirements/{req['id']}/bulk-result",
                    json={"baseline_type": "backend_dev", "status": "pass"})
    assert r.status_code == 200, r.text
    assert r.json()["auto_done"] is True, r.text
    assert client.get("/api/baseline/requirements").json()[0]["status"] == "done"

    # 空范围（app_dev 在测试数据里故意留空）：直接调收口函数，必须拒绝
    from app.routers.baseline import _autoclose_if_done
    empty = _create(db, client, types=["app_dev"]).json()
    assert empty["bound_items"] == 0, empty
    assert empty["status"] == "in_progress", empty
    from app.models import BaselineRequirement
    obj = db.query(BaselineRequirement).filter(BaselineRequirement.id == empty["id"]).first()
    assert _autoclose_if_done(db, obj, None) is False, "应评 0 项不算做完"


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
