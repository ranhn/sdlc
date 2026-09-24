"""漏洞筛选 · 端到端回归测试（列表接口 / 导出接口 / 报告范围描述）。

用法（在 backend 目录下）：
    python -m pytest tests/test_vuln_filters.py -v
    python tests/test_vuln_filters.py

为什么要有它：
    筛选栏上每加/改一个条件，实际牵动**三处**：
      1. 列表接口 `GET /api/vulns`        —— 页面上看到什么
      2. 导出接口 `GET /api/vulns/export` —— "导出当前筛选结果"拿到什么
      3. `_describe_scope()`              —— Word 报告封面写的是什么范围
    少接一处就会出现两种很难当场发现的事故：
      · 页面筛出 2 条，点导出却拿到全部 15 条（导出按钮写的是"全部筛选结果"）；
      · 报告封面写着"全部漏洞"，实际只含某个大类 —— 报告一旦外发，读者无法判断范围。

    另外特别锁住两个容易踩的点：
      · **来源 = 内部**（is_external=False）也是一个筛选条件，不能用 `if is_external:` 写成
        "假值当没传"，否则"仅内部"的报告会被描述成"全部漏洞"；
      · **大类为空的历史数据**不该被任何大类筛出来（也不该在大类筛选下凭空出现）。
"""

from __future__ import annotations

import csv
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI                            # noqa: E402
from fastapi.testclient import TestClient              # noqa: E402
from sqlalchemy import create_engine                   # noqa: E402
from sqlalchemy.orm import sessionmaker                # noqa: E402
from sqlalchemy.pool import StaticPool                 # noqa: E402

from app.database import Base, get_db                  # noqa: E402
from app.models import Role, User                      # noqa: E402
from app.routers import vulns as vulns_router          # noqa: E402
from app.routers.vulns import _describe_scope          # noqa: E402
from app.security import get_current_user              # noqa: E402

CURRENT: dict = {}

# 固定数据：3 条有分类 + 1 条"大类为空"的历史数据
FIXTURES = [
    {"title": "SQL 注入", "vuln_category": "注入类", "vuln_type": "SQL注入",
     "severity": "high", "is_external": False},
    {"title": "越权查询", "vuln_category": "访问控制", "vuln_type": "越权",
     "severity": "high", "is_external": True},
    {"title": "信息泄露", "vuln_category": "信息泄露", "vuln_type": "信息泄露",
     "severity": "low", "is_external": False},
    {"title": "未分类历史数据", "severity": "medium"},   # 没有 vuln_category
]


def _setup():
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    admin_role = Role(name="超级管理员", code="admin")
    db.add(admin_role)
    db.flush()
    db.add(User(username="admin", password_hash="x", full_name="管理员",
                role_id=admin_role.id, is_active=True))
    db.commit()
    CURRENT["user"] = db.query(User).filter(User.username == "admin").first()

    api = FastAPI()
    api.include_router(vulns_router.router)
    api.dependency_overrides[get_db] = lambda: db
    api.dependency_overrides[get_current_user] = lambda: CURRENT["user"]
    return db, TestClient(api)


def _seed(client) -> None:
    for fx in FIXTURES:
        # api_endpoint 是提交漏洞的必填项（页面上也校验），这里给个占位值
        payload = {"description": "回归测试用", "api_endpoint": "/api/test/filter", **fx}
        r = client.post("/api/vulns", json=payload)
        assert r.status_code in (200, 201), r.text


def _titles(resp) -> list[str]:
    """取筛选结果里的标题（列表接口是分页响应，条目在 items 里）。"""
    return sorted(v["title"] for v in resp.json()["items"])


def _csv_titles(resp) -> list[str]:
    rows = list(csv.reader(io.StringIO(resp.content.decode("utf-8-sig"))))
    return sorted(row[1] for row in rows[1:])


# ============ 列表接口 ============

def test_list_filters_by_category():
    """按一级大类筛选：只出该类，其它类不混进来。"""
    _, client = _setup()
    _seed(client)
    assert _titles(client.get("/api/vulns", params={"vuln_category": "注入类"})) == ["SQL 注入"]
    assert _titles(client.get("/api/vulns", params={"vuln_category": "访问控制"})) == ["越权查询"]
    # 筛选值是大类标签本身，不是二级子类
    assert client.get("/api/vulns", params={"vuln_category": "SQL注入"}).json()["items"] == []


def test_uncategorized_rows_never_leak_into_category_filter():
    """大类为空的历史数据：不带筛选能看到，带任何大类筛选都不出现（不会"凭空冒出"）。"""
    _, client = _setup()
    _seed(client)
    assert client.get("/api/vulns").json()["total"] == 4
    for cat in ("注入类", "访问控制", "信息泄露", "其他"):
        assert "未分类历史数据" not in _titles(
            client.get("/api/vulns", params={"vuln_category": cat})
        )


def test_list_filters_by_external():
    """来源筛选：外部 / 内部 都要能筛，且都不等于"全部"。

    注意"内部"包含**未分类的历史数据** —— is_external 落库是 False 而不是 NULL，
    所以只筛外部才是"少数派"，不能反过来以为内部只有显式标了内部的那两条。
    """
    _, client = _setup()
    _seed(client)
    assert _titles(client.get("/api/vulns", params={"is_external": "true"})) == ["越权查询"]
    assert _titles(client.get("/api/vulns", params={"is_external": "false"})) == [
        "SQL 注入", "信息泄露", "未分类历史数据",
    ]
    assert len(client.get("/api/vulns").json()) == 4


def test_category_combines_with_other_filters():
    """多个筛选条件是取交集，不是互相覆盖。"""
    _, client = _setup()
    _seed(client)
    # 注入类 + 高危 → 命中；注入类 + 低危 → 空
    assert _titles(client.get("/api/vulns",
                              params={"vuln_category": "注入类", "severity": "high"})) == ["SQL 注入"]
    assert client.get("/api/vulns",
                      params={"vuln_category": "注入类", "severity": "low"}).json()["items"] == []


def test_multi_value_filters_for_dashboard_drill_down():
    """首页 KPI 卡片钻取传的是**多值**：severity=critical,high、status=pending,confirmed,...

    单值过滤做不到"严重 + 高危"这种组合；多值走 IN，而单值行为必须与以前完全一致
    （前端等级下拉、历史调用方都还在用单值）。
    """
    _, client = _setup()
    _seed(client)     # high×2（SQL 注入 / 越权查询）、low×1、medium×1，全部为 pending

    assert _titles(client.get("/api/vulns", params={"severity": "high,low"})) == [
        "SQL 注入", "信息泄露", "越权查询"]
    # 单值行为不变
    assert _titles(client.get("/api/vulns", params={"severity": "low"})) == ["信息泄露"]

    # 多状态（首页「未闭环」那一串）× 多等级 = 取交集
    assert _titles(client.get("/api/vulns", params={
        "severity": "high,low",
        "status": "pending,confirmed,fixing,retest,fixed"}) ) == [
        "SQL 注入", "信息泄露", "越权查询"]
    assert _titles(client.get("/api/vulns", params={
        "severity": "high,low", "status": "closed,rejected"})) == []


def test_multi_value_severity_applies_to_export_too():
    """导出必须与列表同口径，否则钻取后点导出会得到 0 条（"critical,high" 被当成一个等级）。"""
    _, client = _setup()
    _seed(client)
    exp = client.get("/api/vulns/export", params={"fmt": "csv", "severity": "high,low"})
    assert _csv_titles(exp) == ["SQL 注入", "信息泄露", "越权查询"]


def test_describe_scope_multi_severity_uses_chinese_names():
    """报告封面要把多等级翻成中文，不能写成"等级：critical,high"（报告一旦外发就改不了）。"""
    db, _ = _setup()
    text = _describe_scope(db, severity="critical,high")
    assert "严重" in text and "高危" in text, text
    assert "critical" not in text, text


# ============ 导出接口 ============

def test_export_honours_category_and_source():
    """导出必须和列表同口径 —— 否则"导出当前筛选结果"会多导出。"""
    _, client = _setup()
    _seed(client)
    exp = lambda **p: client.get("/api/vulns/export", params={"fmt": "csv", **p})  # noqa: E731

    assert _csv_titles(exp()) == ["SQL 注入", "信息泄露", "未分类历史数据", "越权查询"]
    assert _csv_titles(exp(vuln_category="注入类")) == ["SQL 注入"]
    assert _csv_titles(exp(is_external="true")) == ["越权查询"]
    assert _csv_titles(exp(is_external="false")) == ["SQL 注入", "信息泄露", "未分类历史数据"]
    assert _csv_titles(exp(vuln_category="注入类", is_external="false")) == ["SQL 注入"]
    assert _csv_titles(exp(vuln_category="注入类", is_external="true")) == []


# ============ 分页 ============

def test_list_is_paginated_and_reports_total():
    """服务端分页：total 是筛选后的总数（与分页参数无关），items 只有当前页。

    分页最容易出的两类 bug 都在这里锁住：
      · 同一条数据出现在两页里 / 某条数据永远翻不到（排序不稳定或 offset 算错）；
      · total 跟着 page 变，导致前端页数跳来跳去。
    """
    _, client = _setup()
    _seed(client)

    p1 = client.get("/api/vulns", params={"page": 1, "page_size": 2}).json()
    assert p1["total"] == 4 and p1["page"] == 1 and p1["page_size"] == 2, p1
    assert len(p1["items"]) == 2

    p2 = client.get("/api/vulns", params={"page": 2, "page_size": 2}).json()
    assert p2["total"] == 4 and len(p2["items"]) == 2, p2
    ids1 = {v["id"] for v in p1["items"]}
    ids2 = {v["id"] for v in p2["items"]}
    assert not (ids1 & ids2), f"两页出现重复数据：{ids1 & ids2}"
    assert len(ids1 | ids2) == 4, "有数据在两页之外（永远翻不到）"

    # 超出范围的页：items 为空但 total 不变（前端靠 total 才能收敛回最后一页）
    p9 = client.get("/api/vulns", params={"page": 9, "page_size": 2}).json()
    assert p9["items"] == [] and p9["total"] == 4, p9


def test_pagination_happens_after_filtering():
    """分页必须作用在筛选之后：total 是筛选命中的条数，不是全表条数。"""
    _, client = _setup()
    _seed(client)
    p1 = client.get("/api/vulns", params={"is_external": "false", "page": 1, "page_size": 2}).json()
    assert p1["total"] == 3, f"内部提交共 3 条，total 却是 {p1['total']}（按全表算了？）"
    assert len(p1["items"]) == 2
    p2 = client.get("/api/vulns", params={"is_external": "false", "page": 2, "page_size": 2}).json()
    assert p2["total"] == 3 and len(p2["items"]) == 1, p2


def test_page_size_is_capped():
    """page_size 有上限：不能用一个参数把全量拉回去（那分页就白做了）。"""
    _, client = _setup()
    _seed(client)
    assert client.get("/api/vulns", params={"page_size": 9999}).status_code == 422
    assert client.get("/api/vulns", params={"page": 0}).status_code == 422


# ============ 报告范围描述 ============

def test_scope_desc_mentions_category_and_source():
    """Word 报告封面要写清"这批数据是怎么筛出来的"，且不能把"仅内部"写成"全部漏洞"。"""
    db, _ = _setup()
    assert _describe_scope(db, vuln_category="注入类") == "漏洞大类：注入类"
    assert _describe_scope(db, is_external=True) == "来源：外部报告"
    # ⚠️ False 是"只要内部提交"，必须写出来；以前用 `if is_external:` 判断的话这里会漏
    assert _describe_scope(db, is_external=False) == "来源：内部提交"
    # 没传来源时不提来源（否则每份报告都凭空多一句）
    assert "来源" not in _describe_scope(db)
    desc = _describe_scope(db, status="fixed", severity="high",
                           vuln_category="访问控制", is_external=True)
    assert desc == "状态：已修复 · 等级：高危 · 漏洞大类：访问控制 · 来源：外部报告", desc


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
