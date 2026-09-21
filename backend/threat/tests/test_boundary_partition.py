"""信任边界成员分区的回归测试。

用法（在 backend/threat 目录下）：
    python -m pytest tests/test_boundary_partition.py -v
    python tests/test_boundary_partition.py          # 无 pytest 时直接跑

为什么要有它：
    用户反馈「图中好像只有一个边界，却显示有 3 个边界」。根因是边界成员**各自
    独立推断**：边界名/描述里都有「数据 / 服务」这类泛化词时，每个边界各自选中
    同一批内网节点 → 成员包围盒完全一样 → 多个虚线框叠成一个，而计数仍是多个。

    修法是把成员分配改成**分区**（每个组件只属于一个边界）。本文件锁住分区语义：
      1. 互斥：没有组件同时属于两个边界（这是"框叠在一起"的根因）；
      2. 实义优先：与第三方外部实体相连的组件归第三方边界；边界名与组件名有
         实义重合的归该边界；仅有「服务 / 数据」这类泛化词重合不算；
      3. 同角色重复的边界只有一个拿到成员，其余的成员为空（前端对空边界不绘制
         也不计数，计数才与画面一致）；
      4. 确定性：同输入必得同结果（布局可复现是硬要求）。
"""

from __future__ import annotations

import importlib
import os
import sys
import time as _time
import types
from datetime import datetime

_THREAT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 轻量加载：威胁建模服务的模块会 `from app.utils import network_clock`（SDLC 宿主），
# 真实时钟导入即触发 NTP 校准，测试里塞一个最小替身即可（详见
# test_dfd_lifecycle_consistency.py 的说明）。
if "app" not in sys.modules:
    _app_pkg = types.ModuleType("app")
    _app_pkg.__path__ = []
    _utils_pkg = types.ModuleType("app.utils")
    _utils_pkg.__path__ = []
    _clock = types.ModuleType("app.utils.network_clock")
    _clock.now = datetime.now
    _clock.utcnow = datetime.utcnow
    _clock.epoch = _time.time
    _clock.offset_seconds = lambda: 0.0
    _clock.to_utc_aware = lambda dt: dt
    sys.modules["app"] = _app_pkg
    sys.modules["app.utils"] = _utils_pkg
    sys.modules["app.utils.network_clock"] = _clock

_pkg = types.ModuleType("threatlite")
_pkg.__path__ = [os.path.join(_THREAT, "app")]
sys.modules["threatlite"] = _pkg

MB = importlib.import_module("threatlite.services.model_builder")


def _comp(cid, name, ctype="process", lifecycle=None):
    return {"id": cid, "name": name, "type": ctype, "lifecycle": lifecycle}


def _flow(fid, src, tgt, name="流"):
    return {"id": fid, "name": name, "sourceId": src, "targetId": tgt}


def _partition(components, flows, layer_of=None):
    builder = MB.ThreatModelBuilder()
    comp_type = {c["id"]: c["type"] for c in components}
    comp_by_id = {c["id"]: c for c in components}
    layers = layer_of or {c["id"]: 0 for c in components}
    return builder._partition_boundary_members(comp_by_id, comp_type, flows, layers)


def _as_sets(members: dict) -> dict:
    return {k: set(v) for k, v in members.items()}


# ---------------------------------------------------------------------------
# 1. 互斥（用户反馈的直接根因）
# ---------------------------------------------------------------------------
def test_members_are_a_partition_no_component_in_two_boundaries() -> None:
    """任何组件最多属于一个边界 —— 否则两个边界会长成一模一样。"""
    comps = [
        _comp("b1", "手机端应用与公网侧信任边界", "trustboundary"),
        _comp("b2", "健康云服务侧信任边界", "trustboundary"),
        _comp("b3", "第三方平台接口信任边界", "trustboundary"),
        _comp("a1", "智能手环", "actor"),
        _comp("p1", "手机端 App"),
        _comp("p2", "健康数据中心"),
        _comp("p3", "异常告警服务"),
        _comp("s1", "健康时序数据库", "datastore"),
        _comp("x1", "Twilio 通知平台", "actor"),
    ]
    flows = [_flow("f1", "a1", "p1"), _flow("f2", "p1", "p2"),
             _flow("f3", "p2", "s1"), _flow("f4", "p3", "x1")]
    members = _partition(comps, flows)
    seen: dict[str, str] = {}
    for bid, ids in members.items():
        for cid in ids:
            assert cid not in seen, f"组件 {cid} 同时属于 {seen[cid]} 与 {bid}"
            seen[cid] = bid
    # actor 不进任何边界（DFD 语义：外部实体在边界之外）
    assert "a1" not in seen and "x1" not in seen


def test_role_keywords_are_read_from_name_not_description() -> None:
    """角色判定只看边界**名字**：描述里满是"数据/服务"时不能把所有边界归成一类。"""
    builder = MB.ThreatModelBuilder()
    assert builder._boundary_role("手机端应用与公网侧信任边界") == "edge"
    assert builder._boundary_role("健康云服务侧信任边界") == "service"
    assert builder._boundary_role("第三方平台接口信任边界") == "third"
    assert builder._boundary_role("数据存储层信任边界") == "store"
    assert builder._boundary_role("某个说不清的边界") == "other"


# ---------------------------------------------------------------------------
# 2. 实义重合与第三方归属
# ---------------------------------------------------------------------------
def test_third_party_boundary_claims_integration_component() -> None:
    """与第三方外部实体直接相连的组件，归第三方边界（而不是被"服务"抢走）。"""
    comps = [
        _comp("b1", "健康云服务侧信任边界", "trustboundary"),
        _comp("b2", "第三方平台接口信任边界", "trustboundary"),
        _comp("p1", "健康数据中心"),
        _comp("p2", "异常告警服务"),          # → Twilio（第三方）
        _comp("x1", "Twilio / SES 通知平台", "actor"),
    ]
    flows = [_flow("f1", "p2", "x1")]
    members = _partition(comps, flows)
    assert members["b2"] == ["p2"], members
    assert members["b1"] == ["p1"], members


def test_real_name_overlap_wins_but_generic_word_does_not() -> None:
    """边界名与组件名的**实义**重合优先；只有「服务」这类泛化词重合不算。"""
    comps = [
        _comp("b1", "IM 与人工审批侧信任边界", "trustboundary"),
        _comp("b2", "多智能体服务侧信任边界", "trustboundary"),
        _comp("p1", "审批服务"),              # 与 b1 有"审批"实义重合
        _comp("p2", "诊断 Agent"),            # 与 b2 无重合 → 落服务侧
    ]
    members = _partition(comps, [_flow("f1", "p1", "p2")])
    assert members["b1"] == ["p1"], members
    assert members["b2"] == ["p2"], members


def test_client_side_boundary_takes_client_and_entry() -> None:
    """公网/用户侧边界：客户端类组件 + 最浅层入口（网关）归它。"""
    comps = [
        _comp("b1", "手机端应用与公网侧信任边界", "trustboundary"),
        _comp("b2", "健康云服务侧信任边界", "trustboundary"),
        _comp("p1", "手机端 App / H5 看板"),
        _comp("p2", "云网关"),
        _comp("p3", "健康数据中心"),
    ]
    flows = [_flow("f1", "p1", "p2"), _flow("f2", "p2", "p3")]
    members = _partition(comps, [_flow("f1", "p1", "p2"), _flow("f2", "p2", "p3")],
                         layer_of={"b1": 0, "b2": 0, "p1": 3, "p2": 1, "p3": 2})
    assert set(members["b1"]) == {"p1", "p2"}, members
    assert members["b2"] == ["p3"], members


# ---------------------------------------------------------------------------
# 3. 空边界与确定性
# ---------------------------------------------------------------------------
def test_duplicate_role_boundaries_keep_only_one_populated() -> None:
    """两个同角色边界（如两个"服务侧"）：只有代表边界有成员，另一个为空。

    空边界前端不绘制也不计数 —— 这正是"显示 3 个、只看到 1 个"的收口点。
    """
    comps = [
        _comp("b1", "健康云服务侧信任边界", "trustboundary"),
        _comp("b2", "多智能体服务侧信任边界", "trustboundary"),
        _comp("p1", "健康数据中心"),
    ]
    members = _partition(comps, [])
    assert members["b1"] == ["p1"], members
    assert members["b2"] == [], members


def test_partition_is_deterministic() -> None:
    comps = [
        _comp("b1", "手机端应用与公网侧信任边界", "trustboundary"),
        _comp("b2", "健康云服务侧信任边界", "trustboundary"),
        _comp("b3", "第三方平台接口信任边界", "trustboundary"),
        _comp("p1", "手机端 App"), _comp("p2", "云网关"), _comp("p3", "健康数据中心"),
        _comp("p4", "异常告警服务"), _comp("s1", "健康时序数据库", "datastore"),
        _comp("x1", "Twilio 通知平台", "actor"),
    ]
    flows = [_flow("f1", "p1", "p2"), _flow("f2", "p2", "p3"),
             _flow("f3", "p3", "s1"), _flow("f4", "p4", "x1")]
    assert _partition(comps, flows) == _partition(comps, flows)


# ---------------------------------------------------------------------------
# 4. 真实模型：三个边界必须是三组不同成员，几何才会分开
# ---------------------------------------------------------------------------
# 取自真实结果 20260920-145812-e3df0a（用户截图那份：12 节点 / 3 个边界）。
_REAL_COMPONENTS = [
    ("手机端应用与公网侧信任边界", "trustboundary"),
    ("第三方平台接口信任边界", "trustboundary"),
    ("健康云服务侧信任边界", "trustboundary"),
    ("Apple HealthKit / Google Fit", "actor"),
    ("Twilio / SES 通知平台", "actor"),
    ("智能健康手环", "actor"),
    ("手机端 App / H5 看板", "process"),
    ("云网关", "process"),
    ("健康数据中心", "process"),
    ("异常告警服务", "process"),
    ("OTA 服务", "process"),
    ("H5 静态资源 CDN / OSS", "datastore"),
    ("原始健康数据对象存储", "datastore"),
    ("健康时序数据库", "datastore"),
    ("手机端本地缓存", "datastore"),
]
_REAL_FLOW_PAIRS = [
    ("手机端 App / H5 看板", "手机端本地缓存"),
    ("健康时序数据库", "健康数据中心"),
    ("云网关", "手机端 App / H5 看板"),
    ("OTA 服务", "手机端 App / H5 看板"),
    ("健康数据中心", "原始健康数据对象存储"),
    ("手机端 App / H5 看板", "OTA 服务"),
    ("手机端 App / H5 看板", "云网关"),
    ("智能健康手环", "手机端 App / H5 看板"),
    ("手机端 App / H5 看板", "智能健康手环"),
    ("异常告警服务", "Twilio / SES 通知平台"),
    ("H5 静态资源 CDN / OSS", "手机端 App / H5 看板"),
    ("Apple HealthKit / Google Fit", "手机端 App / H5 看板"),
    ("健康数据中心", "异常告警服务"),
    ("云网关", "健康数据中心"),
    ("健康数据中心", "健康时序数据库"),
    ("手机端 App / H5 看板", "Apple HealthKit / Google Fit"),
]


def _real_model() -> tuple[list[dict], list[dict]]:
    comps = [_comp(n, n, t) for n, t in _REAL_COMPONENTS]
    flows = [_flow(f"f{i}", s, t) for i, (s, t) in enumerate(_REAL_FLOW_PAIRS, 1)]
    return comps, flows


def test_real_model_boundaries_have_distinct_members_and_geometry() -> None:
    """三个边界必须各自拿到**不同**的成员，且几何不相同（用户反馈的回归）。"""
    comps, flows = _real_model()
    members = _partition(comps, flows)
    sets = {bid: frozenset(v) for bid, v in members.items()}
    assert len(set(sets.values())) == len(sets), f"存在成员完全相同的边界：{members}"
    assert all(sets.values()), f"存在空边界（会被前端隐藏，计数对不上）：{members}"

    # 几何：用真实布局算每个边界的容器矩形，必须互不相同
    builder = MB.ThreatModelBuilder()
    layout = builder._layout(comps, flows)
    boxes = {}
    for c in comps:
        if c["type"] != "trustboundary":
            continue
        pos = layout.get(c["id"]) or {}
        size = pos.get("containerSize") or {}
        boxes[c["name"]] = (round(size.get("width", 0)), round(size.get("height", 0)))
    assert len(set(boxes.values())) == len(boxes), f"边界几何完全相同：{boxes}"
    for name, (w, h) in boxes.items():
        assert w > 0 and h > 0, f"边界「{name}」几何为空：{w}x{h}"


def _build(components, flows):
    """跑一次完整装配（不含 LLM），拿到落库形态的模型。"""
    builder = MB.ThreatModelBuilder()
    return builder.build(
        {"title": "分区测试", "description": ""},
        {"title": "DFD", "description": ""},
        components, flows, [],
    )


def _diagram(model):
    return model["detail"]["diagrams"][0]


def test_build_persists_boundary_members_and_empty_flag() -> None:
    """装配期必须把分区结果落进 cell：data.boundaryMembers / boundaryEmpty。

    这两个字段是渲染器 / Word 报告 / 布局度量 / 前端画布 / 前端威胁下拉共用的
    **唯一事实源**。以前它们各自按"几何包含"重推，同一份结果出现三套口径
    （画布不画空边界、报告表里却编号列出、度量把空边界也数进去）。
    """
    comps, flows = _real_model()
    cells = _diagram(_build(comps, flows))["cells"]
    by_id = {c["id"]: c for c in cells}
    boundaries = [c for c in cells if c.get("shape") == "tm.BoundaryBox"]
    assert boundaries, "真实模型应产出信任边界"

    seen: dict[str, str] = {}
    for b in boundaries:
        data = b.get("data") or {}
        members = data.get("boundaryMembers")
        assert isinstance(members, list), f"边界缺少 boundaryMembers：{data.get('name')}"
        assert data.get("boundaryEmpty") is (not members), "boundaryEmpty 与成员不一致"
        for m in members:
            assert m in by_id, f"成员 {m} 不是本图的 cell"
            assert by_id[m].get("shape") != "tm.BoundaryBox", "边界不能把边界当成员"
            owner = seen.get(m)
            assert owner is None, f"cell {m} 同时属于 {owner} 与 {b['id']}"
            seen[m] = b["id"]

    # 真实模型三个边界都应有成员（否则会被前端隐藏、计数对不上）
    assert all((b.get("data") or {}).get("boundaryMembers") for b in boundaries), [
        ((b.get("data") or {}).get("name"), (b.get("data") or {}).get("boundaryMembers"))
        for b in boundaries
    ]


def test_empty_boundary_is_zero_sized_and_flagged() -> None:
    """成员为空的边界：零几何 + boundaryEmpty=true（前端不画、计数也不算）。"""
    comps = [
        _comp("b1", "健康云服务侧信任边界", "trustboundary"),
        _comp("b2", "多智能体服务侧信任边界", "trustboundary"),  # 同角色 → 无成员
        _comp("p1", "健康数据中心"),
        _comp("p2", "诊断 Agent"),
    ]
    cells = _diagram(_build(comps, [_flow("f1", "p1", "p2")]))["cells"]
    by_name = {(c.get("data") or {}).get("name"): c for c in cells
               if c.get("shape") == "tm.BoundaryBox"}
    empty = by_name["多智能体服务侧信任边界"]
    assert (empty.get("data") or {}).get("boundaryEmpty") is True
    assert empty["size"]["width"] == 0 and empty["size"]["height"] == 0
    filled = by_name["健康云服务侧信任边界"]
    assert (filled.get("data") or {}).get("boundaryEmpty") is False
    assert filled["size"]["width"] > 0


def test_report_and_metrics_share_the_same_boundary_facts() -> None:
    """Word 报告与布局度量必须和 cell 里的事实同源（同一份结果只允许一套口径）。

    回归的是用户能直接看到的矛盾：报告插图（PNG）里不画空边界，报告表格却把它
    编号成 TB2 并列出"包含元素 —、元素数 0"；度量又把边界数报成 2 个。
    """
    from threatlite.services.dfd_layout_metrics import count_drawable_boundaries
    from threatlite.services.result_exporter import _collect_elements

    comps = [
        _comp("b1", "健康云服务侧信任边界", "trustboundary"),
        _comp("b2", "多智能体服务侧信任边界", "trustboundary"),  # 空
        _comp("p1", "健康数据中心"),
        _comp("p2", "诊断 Agent"),
        _comp("s1", "健康时序数据库", "datastore"),
    ]
    model = _build(comps, [_flow("f1", "p1", "p2"), _flow("f2", "p1", "s1")])
    diagram = _diagram(model)

    cells = diagram["cells"]
    by_id = {c["id"]: c for c in cells}
    facts = {
        (b.get("data") or {}).get("name"): set((b.get("data") or {}).get("boundaryMembers") or [])
        for b in cells if b.get("shape") == "tm.BoundaryBox"
    }
    assert facts["多智能体服务侧信任边界"] == set(), facts

    elements = _collect_elements(model)
    assert len(elements["boundaries"]) == 1, (
        f"报告不应列出空边界：{[b['name'] for b in elements['boundaries']]}"
    )
    reported = elements["boundaries"][0]
    assert reported["name"] == "健康云服务侧信任边界"
    assert reported["members"], "报告里非空边界必须列出成员"
    assert set(reported["members"]) <= set(facts["健康云服务侧信任边界"]) | {
        elements["id_by_cell"].get(m) for m in facts["健康云服务侧信任边界"]
    }, "报告的成员编号必须来自同一份事实"

    # 度量与报告口径一致：边界数 = 可绘制的边界数（空边界不计）
    assert count_drawable_boundaries(diagram) == len(elements["boundaries"]) == 1


# ---------------------------------------------------------------------------
# 5. 容器几何：必须完整包住成员（Kahn 分层 与 生命周期泳道 两条路径都要）
# ---------------------------------------------------------------------------
# 回归的是「成员节点伸出信任边界框」。根因是两处叠加：
#   1) 容器矩形取成员**中心**的 min/max，右侧补 `_w_of(inner[-1])/2` —— 隐含
#      "最后一个成员最靠右且宽度等于基准宽"，实际成员宽度按名称 150~280px 动态变化；
#   2) 组装 cell 时用 `containerCenter - size/2` 反算左上角，而 containerCenter
#      传的是成员中心的**平均值**（注释写的是 bbox 中心）→ 框被整体平移。
# 用户可见性来自渲染端规则：前端 DfdGraph.boundaryLayout 与后端 dfd_renderer 都是
# 「内容 ± 26，垂直方向只缩不涨（Math.max/min 夹住模型矩形）」—— 模型框窄了/偏了
# 会被原样画出来，节点就压在虚线上。
_LIFECYCLE_KEYS = ["collect", "transit", "store", "process", "use", "exchange"]


def _real_model_with_lifecycle() -> tuple[list[dict], list[dict]]:
    """真实模型的泳道版：给非边界组件补上合法 lifecycle，触发泳道布局。"""
    comps, flows = _real_model()
    comps = [dict(c) for c in comps]
    for i, c in enumerate([c for c in comps if c["type"] != "trustboundary"]):
        c["lifecycle"] = _LIFECYCLE_KEYS[i % len(_LIFECYCLE_KEYS)]
    return comps, flows


def _rect(c: dict) -> tuple[float, float, float, float]:
    p, s = c.get("position") or {}, c.get("size") or {}
    x0, y0 = p.get("x", 0), p.get("y", 0)
    return x0, y0, x0 + s.get("width", 0), y0 + s.get("height", 0)


def _check_container_geometry(tag: str, comps: list[dict], flows: list[dict]) -> None:
    from threatlite.services.dfd_layout_metrics import evaluate

    model = _build(comps, flows)
    dia = _diagram(model)
    cells = dia["cells"]
    by_id = {c["id"]: c for c in cells}
    boxes = [c for c in cells if c.get("shape") == "tm.BoundaryBox"]
    assert boxes, f"{tag}: 真实模型应产出信任边界"

    # ⓿ 坐标合法性：**节点**必须落在正象限。
    # Kahn 布局去掉了"按边界数量预留宽度"之后，单节点层的锯齿偏移若不加夹取就会
    # 被推到画布外（负坐标）—— 这条守住那个边界条件。
    # 容器单元格不在校验范围：泳道布局内部按 55px 内边距重算容器 bbox（渲染端随后
    # 会收缩到内容 ± 26），成员贴边时容器可能到 -3px，属既有观感细节、不影响内容。
    for c in cells:
        if c.get("shape") in ("tm.Text", "tm.BoundaryBox"):
            continue
        p = c.get("position") or {}
        assert p.get("x", 0) >= 0 and p.get("y", 0) >= 0, (
            f"{tag}: 节点「{(c.get('data') or {}).get('name')}」坐标为负 "
            f"({p.get('x')}, {p.get('y')})"
        )

    for b in boxes:
        bx0, by0, bx1, by1 = _rect(b)
        members = (b.get("data") or {}).get("boundaryMembers") or []
        name = (b.get("data") or {}).get("name")
        # ① 每个成员必须完整落在容器框内
        for mid in members:
            c = by_id[mid]
            cx0, cy0, cx1, cy1 = _rect(c)
            assert cx0 >= bx0 - 0.5 and cy0 >= by0 - 0.5, (
                f"{tag}: 成员「{(c.get('data') or {}).get('name')}」左上越框（容器「{name}」）"
            )
            assert cx1 <= bx1 + 0.5 and cy1 <= by1 + 0.5, (
                f"{tag}: 成员「{(c.get('data') or {}).get('name')}」右下越框（容器「{name}」）"
            )
        # ② 容器必须覆盖成员**外框**的中心（防"框整体平移"，即 containerCenter 传成
        #    成员中心平均值那类错误）。这里只校验覆盖关系而**不要求严格等中心**：
        #    泳道布局在容器算完之后还会把框拉宽/延展到泳道带（见 _layout_lifecycle_lanes
        #    的"回收进泳道带"一段），等中心不成立是设计使然。
        if members:
            rects = [_rect(by_id[m]) for m in members]
            want_cx = (min(r[0] for r in rects) + max(r[2] for r in rects)) / 2
            want_cy = (min(r[1] for r in rects) + max(r[3] for r in rects)) / 2
            assert bx0 <= want_cx <= bx1, (
                f"{tag}: 容器「{name}」未覆盖成员外框中心 x（{want_cx:.1f} 不在 "
                f"[{bx0:.1f}, {bx1:.1f}]）"
            )
            assert by0 <= want_cy <= by1, (
                f"{tag}: 容器「{name}」未覆盖成员外框中心 y（{want_cy:.1f} 不在 "
                f"[{by0:.1f}, {by1:.1f}]）"
            )

    # ③ 度量口径（与渲染器同口径）：**真正的成员**不得越框。
    #    度量的 member_outside 按"中心在框内"判定，因此"非成员的中心恰好落进别人的
    #    容器框、且外框探出"也会被记一条 —— 那是"每行紧凑分带"（用户要求消除留白）
    #    带来的固有现象，不是成员越框。这里只对**确实是成员**的条目做断言。
    m = evaluate({"model": model})
    assert m is not None, f"{tag}: 度量模块无法评估该模型"
    member_ids = {
        mid for b in boxes for mid in (b.get("data") or {}).get("boundaryMembers") or []
    }
    real_outside = [
        item for item in m["member_outside"]
        if any((by_id[mid].get("data") or {}).get("name") in item for mid in member_ids)
    ]
    assert real_outside == [], f"{tag}: 成员越框 {real_outside}"
    # ④ 画布质量目标（与 dfd_layout_metrics 的"商业级基线"同口径）：
    #    长宽比 ≤2.6 / 利用率 ≥75% —— 两条布局路径都要达标。
    #    回归的是 Kahn 布局"某层 8 个节点、横向 2232px"导致长宽比 4.40 那种情况。
    assert m["canvas_aspect"] <= 2.6, (
        f"{tag}: 画布长宽比 {m['canvas_aspect']:.2f} 未达标（宽层折行是否失效？）"
    )
    assert m["fill_ratio"] >= 0.75, f"{tag}: 画布利用率 {m['fill_ratio']:.1%} 未达标"


def test_container_wraps_members_kahn_fallback_layout() -> None:
    """Kahn 分层布局（**回退路径**）：容器必须完整包住成员。

    注意：build() 现在会先做生命周期兜底推断（缺失时按类型 + 名字关键词补出来，
    于是走泳道布局），因此 Kahn 只在**兜底推断失败**时才被用到。这里把
    _ensure_lifecycles 置为恒等来模拟那条错误路径，保证回退布局自身也被守着 ——
    它是"推断失败也不崩"的安全网，值得留测试。
    """
    comps, flows = _real_model()
    orig = MB.ThreatModelBuilder._ensure_lifecycles
    MB.ThreatModelBuilder._ensure_lifecycles = lambda self, c, f: c  # type: ignore[assignment]
    try:
        _check_container_geometry("Kahn", comps, flows)
    finally:
        MB.ThreatModelBuilder._ensure_lifecycles = orig  # type: ignore[assignment]


def test_container_wraps_members_lifecycle_layout() -> None:
    """生命周期泳道布局：同一条不变量（两条路径共用 _boundary_container_box）。"""
    comps, flows = _real_model_with_lifecycle()
    _check_container_geometry("lane", comps, flows)


# ---------------------------------------------------------------------------
# 6. 跨边界标记必须与落盘的成员事实同源
# ---------------------------------------------------------------------------
def _check_flag_matches_members(tag: str, comps: list[dict], flows: list[dict]) -> None:
    dia = _diagram(_build(comps, flows))
    cells = dia["cells"]
    owner: dict[str, str] = {}
    for b in cells:
        if b.get("shape") != "tm.BoundaryBox":
            continue
        for mid in (b.get("data") or {}).get("boundaryMembers") or []:
            owner[mid] = b["id"]
    checked = 0
    for c in cells:
        if not (c.get("source") and c.get("target")):
            continue
        s = (c.get("source") or {}).get("cell")
        t = (c.get("target") or {}).get("cell")
        want = owner.get(s) != owner.get(t)
        got = bool((c.get("data") or {}).get("crossesTrustBoundary"))
        assert got == want, (
            f"{tag}: 流「{(c.get('data') or {}).get('name')}」的 crossesTrustBoundary="
            f"{got}，但按落盘成员应为 {want}"
        )
        checked += 1
    assert checked, f"{tag}: 没有可校验的数据流"


def test_build_does_not_recompute_boundary_membership() -> None:
    """跨边界标记只允许用**布局落盘的分区**，不得再另算一套。

    做法：把旧的独立推导替换成"会抛异常"，只要 build() 又去调用它，测试立刻红
    —— 这条比"断言结果一致"更有牙齿：结果一致可能是巧合（旧推导在 Kahn 路径上
    恰好与分区相同，我最初就是在 Kahn 路径上验证、才误判它没问题）。

    历史事故：泳道布局的分区按**泳道序号**当 layer 依据，旧推导按 **Kahn 拓扑分层**，
    两者对同一组件可能判到不同边界 → crossesTrustBoundary 与 cell.data.boundaryMembers
    不一致。实测用 5 份真实结构在当前代码上重建：42/120 条流不一致（模型2 20/38、
    模型3 10/19、模型1 9/26、模型5 3/16），表现为虚线/红方块画错、Word 报告
    "所属边界"列与图不符。修好后 10/10 重建全部一致。
    """
    comps, flows = _real_model_with_lifecycle()
    builder = MB.ThreatModelBuilder()

    def _boom(*_args, **_kwargs):
        raise AssertionError(
            "build() 不应再调用 _compute_boundary_membership —— "
            "跨边界标记必须来自布局落盘的分区（单一事实源）"
        )

    builder._compute_boundary_membership = _boom       # type: ignore[assignment]
    model = builder.build(
        {"title": "单一事实源", "description": ""},
        {"title": "DFD", "description": ""},
        comps, flows, [],
    )
    cells = _diagram(model)["cells"]
    assert any(c.get("shape") == "tm.BoundaryBox" for c in cells)


def test_kahn_fallback_layout_boundaries_do_not_overlap() -> None:
    """Kahn 布局：信任边界容器之间不得互相重叠（含"被整个包住"的情况）。

    回归的是避让只看**相邻一对**的缺陷：排序键是容器的最小 layer，
    （只对 Kahn 回退路径断言：泳道布局改用"每行紧凑分带"——用户反馈"飘逸"后
    选择观感优先——同一域在不同泳道的 x 区间不再对齐，跨泳道容器**可能**重叠，
    度量 boundary_overlap 会如实报出。紧凑与对齐是一对固有矛盾，不做硬断言。）
    [健康云(layer0), 手机端应用(layer1), 第三方平台接口(layer1)] 里
    (健康云, 第三方平台接口) 这对从未被比较 —— 后者 100% 落在前者内部，
    画布上两个虚线框叠成一个。现在改为与**所有已放置**的边界比较。
    """
    from threatlite.services.dfd_layout_metrics import evaluate

    comps, flows = _real_model()
    orig = MB.ThreatModelBuilder._ensure_lifecycles
    MB.ThreatModelBuilder._ensure_lifecycles = lambda self, c, f: c  # type: ignore[assignment]
    try:
        m = evaluate({"model": _build(comps, flows)})
    finally:
        MB.ThreatModelBuilder._ensure_lifecycles = orig  # type: ignore[assignment]
    assert m is not None
    assert m["boundary_overlap"] == [], f"边界容器互相重叠：{m['boundary_overlap']}"


def test_crosses_boundary_flag_matches_persisted_members_both_layouts() -> None:
    """crossesTrustBoundary（虚线/红方块/主图分层的依据）必须由落盘成员唯一决定。

    这条不变量此前是**两套推导**：落盘 boundaryMembers 走分区算法，而流的
    crossesTrustBoundary 由另一段复刻的拓扑分层 + 关键词推断算出 —— 存量结果上
    实测 40%（48/120）的流与最终几何对不上。
    """
    comps, flows = _real_model()
    _check_flag_matches_members("Kahn", comps, flows)
    lane_comps, lane_flows = _real_model_with_lifecycle()
    _check_flag_matches_members("lane", lane_comps, lane_flows)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        fn()
        print(f"  PASS  {fn.__name__}")
    print(f"\n{len(tests)} tests passed")
