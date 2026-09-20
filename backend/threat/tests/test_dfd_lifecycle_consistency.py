"""DFD「组件类型 ↔ 数据生命周期阶段」自洽性回归测试。

用法（在 backend/threat 目录下）：
    python -m pytest tests/test_dfd_lifecycle_consistency.py -v
    python tests/test_dfd_lifecycle_consistency.py          # 无 pytest 时直接跑

为什么要有它：
    用户反馈「审计服务怎么放到数据存储了」—— 一个 type=process 的服务被标成
    lifecycle=store，于是它和真正存数据的「审计记录库」并排出现在「数据存储」泳道里。
    根因有三层，任何一层单独修都挡不住：
      1. 提示词（document_analyzer 规范第 7 条）在 delete 阶段举例「归档服务」，
         没讲清"存储阶段只属于存储类组件"→ 模型把"负责留存审计记录的服务"也归为 store；
      2. 确定性兜底（dfd_reviewer._normalize_roles）里有一条"只有入边的组件 → store"，
         把汇点型**服务**（审计 / 报表 / 通知服务）直接送进存储泳道；
      3. 全链路没有"类型 ↔ 阶段"一致性约束，process 标 store 一路放行。
    本测试把"服务不得落进存储泳道"固化成断言，防止以后退回去。
"""

from __future__ import annotations

import importlib
import os
import sys
import time as _time
import types
from datetime import datetime

_THREAT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_APP = os.path.join(_THREAT, "app")

# ---------------------------------------------------------------------------
# 轻量加载被测模块
# ---------------------------------------------------------------------------
# 为什么不直接 `from app.services import ...`：
#   · 威胁建模服务的部分模块会 `from app.utils import network_clock`（app = SDLC
#     宿主应用），拉起宿主意味着 FastAPI / DB 配置全要就绪，测试不再独立；
#   · 真实 network_clock 模块导入即触发 NTP 校准（网络依赖 + 拖慢测试）。
# 所以这里塞一个最小替身，再把 `threat/app` 挂成一个假包的 __path__，
# 让模块内的相对导入（.llm_client / ..config）照常解析。
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
_pkg.__path__ = [_APP]
sys.modules["threatlite"] = _pkg

R = importlib.import_module("threatlite.services.dfd_reviewer")
A = importlib.import_module("threatlite.services.document_analyzer")
MB = importlib.import_module("threatlite.services.model_builder")

_LIFECYCLES = ("collect", "transit", "store", "process", "use", "exchange", "delete")
_TYPES = (
    "actor", "externalentity", "process",
    "datastore", "vectorstore", "trustboundary",
)


def _normalized_lifecycle(
    ctype: str,
    name: str,
    lifecycle: str | None,
    flows: list[dict] | None = None,
    cid: str = "c1",
) -> str | None:
    """跑一遍确定性归一化，返回该组件最终的 lifecycle。"""
    comps = [{"id": cid, "type": ctype, "name": name, "lifecycle": lifecycle}]
    out = R.DFDReviewer(llm=None)._normalize_roles(comps, flows or [])
    return out[0].get("lifecycle")


def _lane_of(comps: list[dict], flows: list[dict]) -> dict[str, str]:
    """跑真实泳道布局，返回 {组件名: 泳道标签}。"""
    builder = MB.ThreatModelBuilder()
    layout = builder._layout_lifecycle_lanes(comps, flows)
    bands = sorted(
        (b for b in layout.get("_lanes") or [] if isinstance(b, dict)),
        key=lambda b: b.get("y") or 0,
    )
    result: dict[str, str] = {}
    for c in comps:
        pos = layout.get(c["id"]) or {}
        y = pos.get("y")
        label = "(未匹配)"
        for b in bands:
            if y is not None and b["y"] <= y < b["y"] + b["height"]:
                label = str(b.get("label") or b.get("key") or "")
                break
        result[str(c.get("name"))] = label
    return result


# ---------------------------------------------------------------------------
# 1. 类型 × 阶段 的穷举矩阵：归一化结果必须永远自洽
# ---------------------------------------------------------------------------
def test_type_lifecycle_matrix_is_consistent() -> None:
    bad: list[tuple] = []
    for ctype in _TYPES:
        for lc in _LIFECYCLES:
            got = _normalized_lifecycle(ctype, "某服务组件", lc)
            if ctype == "trustboundary":
                ok = got in (None, "")                     # 容器不落阶段
            elif ctype in ("datastore", "vectorstore"):
                ok = got in ("store", "delete")            # 存储类只落存储/删除
            elif ctype in ("actor", "externalentity"):
                ok = got in ("collect", "exchange")        # 外部实体只在端点阶段
            else:
                ok = got not in ("store", "delete")        # 服务类绝不在存储阶段
            if not ok:
                bad.append((ctype, lc, got))
    assert not bad, f"归一化后仍存在类型↔阶段不自洽的组合：{bad}"


# ---------------------------------------------------------------------------
# 2. 用户反馈的原始 case：审计服务（process）被标 store
# ---------------------------------------------------------------------------
# 取自真实结果 20260920-115536-2bf8b7（多 Agent 运维平台）。
# 该次「审计服务（Audit）」在图上是个孤立节点（0 入 0 出）：审计相关的两条流是
# 「工具层 → 审计记录库」与「编排器 Agent → 审计记录库」，并不经过它。
# 结果文件里不保存 lifecycle，但它的 y 落在「数据存储」泳道、且没有任何边可让
# 拓扑兜底生效 —— 只能是 LLM 当次给它标了 store。
_AUDIT_FIXTURE_COMPS = [
    {"id": "审计服务（Audit）", "type": "process", "name": "审计服务（Audit）", "lifecycle": "store"},
    {"id": "审计记录库", "type": "datastore", "name": "审计记录库", "lifecycle": "store"},
    {"id": "工具层", "type": "process", "name": "工具层", "lifecycle": "exchange"},
    {"id": "运维人员", "type": "actor", "name": "运维人员", "lifecycle": "collect"},
]
_AUDIT_FIXTURE_FLOWS = [
    {"id": "f1", "sourceId": "工具层", "targetId": "审计记录库", "name": "工具调用审计"},
]


def test_audit_service_is_not_placed_in_storage_lane() -> None:
    fixed = R.DFDReviewer(llm=None)._normalize_roles(
        _AUDIT_FIXTURE_COMPS, _AUDIT_FIXTURE_FLOWS
    )
    by_name = {c["name"]: c for c in fixed}
    # 服务 → use（不是 store）；存储设施照旧 store
    assert by_name["审计服务（Audit）"]["lifecycle"] == "use", by_name["审计服务（Audit）"]
    assert by_name["审计记录库"]["lifecycle"] == "store"

    # 端到端：审计服务必须落在「数据使用」泳道，绝不能和「审计记录库」挤在数据存储
    lanes = _lane_of(fixed, _AUDIT_FIXTURE_FLOWS)
    assert lanes["审计服务（Audit）"] == "数据使用", lanes
    assert lanes["审计记录库"] == "数据存储", lanes


# ---------------------------------------------------------------------------
# 3. 汇点型服务：老规则把"只有入边的组件"兜底成 store（→ 存储泳道）
# ---------------------------------------------------------------------------
def test_sink_service_without_lifecycle_is_not_storage() -> None:
    flows = [
        {"id": "f1", "sourceId": "编排器", "targetId": "报表服务", "name": "上报"},
    ]
    comps = [
        {"id": "报表服务", "type": "process", "name": "报表服务", "lifecycle": None},
        {"id": "编排器", "type": "process", "name": "编排器", "lifecycle": "use"},
    ]
    fixed = R.DFDReviewer(llm=None)._normalize_roles(comps, flows)
    got = {c["name"]: c.get("lifecycle") for c in fixed}
    assert got["报表服务"] == "use", got      # 消费数据的服务，不是存储


def test_store_named_process_keeps_store() -> None:
    """"名字本身就是存储角色"的 process 例外：保留 store/delete。

    这类组件的 type 更该是 datastore，交给 AI 自查阶段去改 —— 归一化只做收敛，
    不在这里硬改类型（避免与 document_analyzer 的口径二次漂移）。
    """
    assert _normalized_lifecycle("process", "审计归档库", "store") == "store"
    assert _normalized_lifecycle("process", "会话缓存", "store") == "store"


# ---------------------------------------------------------------------------
# 4. 结构自检（喂给 AI 自省阶段的缺陷清单）要能看见这两类问题
# ---------------------------------------------------------------------------
def test_structural_defects_flag_type_lifecycle_mismatch() -> None:
    comps = [
        {"id": "c1", "type": "process", "name": "审计服务（Audit）", "lifecycle": "store"},
        {"id": "c2", "type": "datastore", "name": "审计记录库", "lifecycle": "store"},
        {"id": "c3", "type": "process", "name": "工具层", "lifecycle": "exchange"},
    ]
    flows = [{"id": "f1", "sourceId": "c3", "targetId": "c2", "name": "工具调用审计"}]
    defects = A._structural_defects(comps, flows)
    assert any("store/delete 只适用于" in d and "审计服务" in d for d in defects), defects


def test_structural_defects_flag_isolated_component() -> None:
    comps = [
        {"id": "c1", "type": "process", "name": "审计服务（Audit）", "lifecycle": "use"},
        {"id": "c2", "type": "datastore", "name": "审计记录库", "lifecycle": "store"},
        {"id": "c3", "type": "process", "name": "工具层", "lifecycle": "exchange"},
        {"id": "c4", "type": "trustboundary", "name": "服务侧边界", "lifecycle": ""},
    ]
    flows = [{"id": "f1", "sourceId": "c3", "targetId": "c2", "name": "工具调用审计"}]
    defects = A._structural_defects(comps, flows)
    assert any("孤立节点" in d and "审计服务" in d for d in defects), defects
    # 信任边界是容器，本来就不接流，不该被报成孤立组件
    assert not any("孤立节点" in d and "边界" in d for d in defects), defects


# ---------------------------------------------------------------------------
# 5. 真实模型的整体不变式：任何服务都不许出现在「数据存储」泳道
# ---------------------------------------------------------------------------
# 组件与流取自真实结果 20260920-115536-2bf8b7（15 组件 / 21 条流），用名字当 id。
_REAL_COMPONENTS = [
    ("长期记忆与向量库", "datastore"),
    ("审批服务", "process"),
    ("编排器 Agent", "process"),
    ("IM 平台与人工审批方", "actor"),
    ("告警接入服务", "process"),
    ("修复 Agent", "process"),
    ("可观测性平台", "actor"),
    ("工具层", "process"),
    ("Prometheus 与 Zabbix 告警源", "actor"),
    ("诊断 Agent", "process"),
    ("审计服务（Audit）", "process"),
    ("日志分析 Agent", "process"),
    ("审计记录库", "datastore"),
    ("K8s 集群与 API", "actor"),
    ("大模型服务", "process"),
]
_REAL_FLOW_PAIRS = [
    ("工具层", "K8s 集群与 API"),
    ("工具层", "可观测性平台"),
    ("诊断 Agent", "工具层"),
    ("IM 平台与人工审批方", "审批服务"),
    ("编排器 Agent", "诊断 Agent"),
    ("工具层", "审计记录库"),
    ("编排器 Agent", "日志分析 Agent"),
    ("编排器 Agent", "长期记忆与向量库"),
    ("诊断 Agent", "编排器 Agent"),
    ("编排器 Agent", "大模型服务"),
    ("审批服务", "IM 平台与人工审批方"),
    ("长期记忆与向量库", "编排器 Agent"),
    ("修复 Agent", "审批服务"),
    ("告警接入服务", "编排器 Agent"),
    ("日志分析 Agent", "编排器 Agent"),
    ("修复 Agent", "工具层"),
    ("日志分析 Agent", "工具层"),
    ("编排器 Agent", "审计记录库"),
    ("审批服务", "修复 Agent"),
    ("编排器 Agent", "修复 Agent"),
    ("Prometheus 与 Zabbix 告警源", "告警接入服务"),
]


def test_real_model_has_no_service_in_storage_lane() -> None:
    comps = [
        {"id": name, "type": ctype, "name": name, "lifecycle": None}
        for name, ctype in _REAL_COMPONENTS
    ]
    # 复刻当次 LLM 的标注：审计服务被标成 store（见文件头说明）
    for c in comps:
        if c["name"] == "审计服务（Audit）":
            c["lifecycle"] = "store"
    flows = [
        {"id": f"f{i}", "sourceId": s, "targetId": t, "name": f"流{i}"}
        for i, (s, t) in enumerate(_REAL_FLOW_PAIRS, 1)
    ]
    fixed = R.DFDReviewer(llm=None)._normalize_roles(comps, flows)
    lanes = _lane_of(fixed, flows)
    offenders = [
        f"{c['name']}({c['type']}) → {lanes[c['name']]}"
        for c in fixed
        if c["type"] == "process" and lanes[c["name"]] == "数据存储"
    ]
    assert not offenders, f"服务型组件落在「数据存储」泳道：{offenders}"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        fn()
        print(f"  PASS  {fn.__name__}")
    print(f"\n{len(tests)} tests passed")
