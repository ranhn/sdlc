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


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        fn()
        print(f"  PASS  {fn.__name__}")
    print(f"\n{len(tests)} tests passed")
