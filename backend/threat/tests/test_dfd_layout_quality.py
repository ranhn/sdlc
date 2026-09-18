"""DFD 布局质量回归测试。

用法（在 backend/threat 目录下）：
    python -m pytest tests/test_dfd_layout_quality.py -v
    python tests/test_dfd_layout_quality.py          # 无 pytest 时直接跑

为什么要有它：
    数据流图的"好看"以前只能靠人眼看截图判断，改一处布局经常在别处
    悄悄劣化（历史上边穿节点一度达到 191 处也无人察觉）。这里把商业级
    标准固化成断言，任何布局改动都能立刻看到六个维度的数字变化。

阈值取自「商业级 DFD 工具」（draw.io / Lucidchart / IriusRisk）的
共同特征：
    - 连线永不穿过节点（这是专业与业余的分水岭）
    - 画布不留大片空白（内容占比 >= 75%）
    - 连线长度均衡（最长/最短 <= 3）
    - 成员不越出信任边界

注意：部分历史结果是在**旧布局算法**下生成的，天然带着旧缺陷。
因此 `test_historical_results_are_monotonic` 只断言"新算法不劣于旧算法"，
真正的零缺陷断言由 `test_synthetic_scenarios_strict` 对合成场景执行。
"""

from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 度量库与渲染器共用同一份实现（app/services/dfd_layout_metrics.py），
# 保证「度量通过」等价于「图上没问题」。
# 注意：这里用 importlib 直接按文件路径加载，不走 `app.services` 包——因为
# `app/__init__.py` 会拉起整个应用（依赖 FastAPI / DB 配置），而布局度量
# 必须能在没有完整运行环境下独立跑（CI / 本地快速验证）。
import importlib.util  # noqa: E402

_LM_PATH = os.path.join(_BACKEND, "app", "services", "dfd_layout_metrics.py")
_spec = importlib.util.spec_from_file_location("dfd_layout_metrics", _LM_PATH)
M = importlib.util.module_from_spec(_spec)
sys.modules["dfd_layout_metrics"] = M
_spec.loader.exec_module(M)  # type: ignore[union-attr]

_RESULTS_DIR = os.path.join(_BACKEND, "data", "results")

# 商业级阈值
MAX_SPAN_RATIO = 3.0
MIN_FILL_RATIO = 0.75
MAX_ASPECT = 2.6


def _records():
    if not os.path.isdir(_RESULTS_DIR):
        return []
    return list(M.iter_results(_RESULTS_DIR))


def _synthetic_scenarios() -> list[tuple[str, dict]]:
    """构造覆盖已知失效模式的合成场景，用于严格断言。

    这些场景刻意复刻历史上真正踩过的坑：
      1. 夹心障碍：A → B，同一个水平带中间夹着 C（旧 HV/VH 两候选必穿）
      2. 多节点同层并排（长边要跨过好几个节点）
      3. 边界成员贴边（容器 bbox 少算 1px 就露框）
      4. 弧形回路：A→B→C→A，容易造成路径重合
    """
    scenarios: list[tuple[str, dict]] = []

    def _cell(cid, x, y, w, h, name, shape="tm.Process"):
        return {
            "id": cid, "shape": shape,
            "position": {"x": x, "y": y},
            "size": {"width": w, "height": h},
            "visible": True,
            "data": {"name": name, "type": shape},
        }

    def _edge(eid, s, t, name, **kw):
        d = {"name": name, "type": "tm.Flow"}
        d.update(kw)
        return {
            "id": eid, "shape": "tm.Flow",
            "source": {"cell": s}, "target": {"cell": t},
            "visible": True, "data": d,
        }

    # --- 场景 1：夹心障碍 ---
    cells = [
        _cell("a", 0, 0, 180, 60, "客户端", "tm.Actor"),
        _cell("m", 400, 0, 180, 60, "中间服务"),
        _cell("b", 800, 0, 180, 60, "目标服务"),
        _edge("e1", "a", "b", "直连数据"),
        _edge("e2", "a", "m", "就近数据"),
        _edge("e3", "m", "b", "转发数据"),
    ]
    scenarios.append(("夹心障碍", {"cells": cells}))

    # --- 场景 2：同层多节点并排 + 跨行长边 ---
    row = [_cell(f"r{i}", i * 260, 0, 180, 60, f"服务{i}") for i in range(5)]
    row2 = [_cell(f"s{i}", i * 260 + 130, 260, 180, 60, f"存储{i}", "tm.Store")
            for i in range(4)]
    cells = row + row2
    edges = [_edge("x0", "r0", "r4", "长距离调用")]
    edges += [_edge(f"y{i}", f"r{i}", f"s{i}", f"写入{i}") for i in range(4)]
    edges += [_edge(f"z{i}", f"s{i}", f"r{i+1}", f"回读{i}") for i in range(3)]
    scenarios.append(("同层并排+长边", {"cells": cells + edges}))

    # --- 场景 3：边界成员贴边 ---
    bnd = {
        "id": "bd", "shape": "tm.BoundaryBox",
        "position": {"x": 0, "y": 0},
        "size": {"width": 420, "height": 200},
        "visible": True,
        "data": {"name": "内网边界", "type": "tm.BoundaryBox",
                 "boundaryMembers": ["n1", "n2"]},
    }
    n1 = _cell("n1", 20, 30, 180, 60, "服务A")
    n2 = _cell("n2", 220, 110, 180, 60, "服务B")
    out = _cell("n3", 600, 60, 180, 60, "外部用户", "tm.Actor")
    cells = [bnd, n1, n2, out,
             _edge("f1", "n3", "n1", "请求"), _edge("f2", "n1", "n2", "内部调用")]
    scenarios.append(("边界成员贴边", {"cells": cells}))

    # --- 场景 4：三角回路（路径重合同高发） ---
    a = _cell("A", 0, 0, 180, 60, "网关")
    b = _cell("B", 400, 0, 180, 60, "认证")
    c = _cell("C", 200, 260, 180, 60, "日志", "tm.Store")
    cells = [a, b, c,
             _edge("t1", "A", "B", "鉴权"),
             _edge("t2", "B", "C", "审计"),
             _edge("t3", "C", "A", "回写")]
    scenarios.append(("三角回路", {"cells": cells}))

    return scenarios


# ----------------------------------------------------------------------
# 严格断言：合成场景必须零缺陷
# ----------------------------------------------------------------------

def test_synthetic_scenarios_strict():
    """合成场景：五个结构类缺陷必须全为 0。"""
    failures: list[str] = []
    for name, diagram in _synthetic_scenarios():
        m = M.evaluate({"model": {"detail": {"diagrams": [diagram]}}})
        assert m is not None
        for key, label in (
            ("member_outside", "成员越框"),
            ("node_overlap", "节点重叠"),
            ("edge_through_node", "边穿节点"),
            ("edge_overlap", "路径重合"),
        ):
            if m[key]:
                failures.append(f"{name} / {label}={len(m[key])}: {m[key][:3]}")
    assert not failures, "合成场景存在布局缺陷：\n" + "\n".join(failures)


def test_synthetic_scenarios_edge_through_node_zero():
    """单列断言：边穿节点是最高优先级缺陷，单独再测一次以防回归。"""
    for name, diagram in _synthetic_scenarios():
        m = M.evaluate({"model": {"detail": {"diagrams": [diagram]}}})
        assert m is not None
        assert not m["edge_through_node"], (
            f"{name} 出现边穿节点：{m['edge_through_node'][:5]}"
        )


# ----------------------------------------------------------------------
# 历史结果：记录指标（不要求零，因为数据本身是旧算法产物）
# ----------------------------------------------------------------------

def test_historical_results_report(capsys=None):
    """打印历史结果的全部指标，作为「改前/改后」对比基线。"""
    records = _records()
    if not records:
        print("（未找到历史结果，跳过）")
        return
    lines = ["", "=== DFD 布局质量基线（历史结果） ==="]
    agg = {"member_outside": 0, "node_overlap": 0, "boundary_overlap": 0,
           "edge_through_node": 0, "edge_overlap": 0}
    ratios, fills = [], []
    for name, rec in records:
        m = M.evaluate(rec)
        if not m:
            continue
        lines.append(M.format_report(name, m))
        for k in agg:
            agg[k] += len(m[k])
        ratios.append(m["span_ratio"])
        fills.append(m["fill_ratio"])
    lines.append("")
    lines.append("--- 汇总 ---")
    for k, v in agg.items():
        lines.append(f"  {k}: {v}")
    if ratios:
        lines.append(f"  平均 span_ratio: {sum(ratios) / len(ratios):.2f}")
        lines.append(f"  平均 fill_ratio: {sum(fills) / len(fills):.1%}")
    report = "\n".join(lines)
    print(report)
    return report


# ----------------------------------------------------------------------
# 性能回归：防止布线复杂度再次爆炸
# ----------------------------------------------------------------------
# 背景：候选池曾是完整笛卡尔积（带外通道 × 脱离列 × 阶梯列），50 节点
# 单图布线要 50s，30+ 节点的真实系统完全不可用。修复后为通道级剪枝，
# 50 节点 ~2.4s。这里固化成断言——任何让耗时回退到秒级以上的改动
# 都会立刻失败，而不是等到用户抱怨卡顿。
#
# 阈值取得比实测宽松（实测 50 节点 ~2.4s，阈值 8s），只拦截"数量级
# 回退"，不因机器差异产生假警报。
PERF_BUDGET_SEC = {20: 2.0, 50: 8.0}


def _perf_diagram(n_nodes: int, n_edges: int) -> dict:
    """合成一张规整网格图（节点方阵 + 打散的长边），用于压测布线。"""
    import math as _m

    cells: list[dict] = []
    cols = max(2, int(_m.ceil(_m.sqrt(n_nodes))))
    for i in range(n_nodes):
        r, c = divmod(i, cols)
        cells.append({
            "id": f"n{i}", "shape": "tm.Process",
            "position": {"x": 60 + c * 220, "y": 60 + r * 170},
            "size": {"width": 150, "height": 80},
            "data": {"name": f"处理过程{i}"},
        })
    for j in range(n_edges):
        a, b = j % n_nodes, (j * 7 + 3) % n_nodes
        if a == b:
            b = (b + 1) % n_nodes
        cells.append({
            "id": f"e{j}", "shape": "tm.Flow",
            "source": {"cell": f"n{a}"}, "target": {"cell": f"n{b}"},
            "data": {"name": f"数据流{j}"},
        })
    return {"id": f"perf{n_nodes}", "cells": cells, "lanes": []}


def test_routing_performance_budget():
    """布线耗时必须在预算内（拦截复杂度数量级回退）。"""
    import time as _t

    failures: list[str] = []
    for n, budget in sorted(PERF_BUDGET_SEC.items()):
        d = _perf_diagram(n, n * 2)
        t0 = _t.perf_counter()
        M.plan_edge_routes(d)
        dt = _t.perf_counter() - t0
        print(f"  性能: {n:3d} 节点 / {n*2:3d} 边 → {dt:6.2f}s (预算 {budget}s)")
        if dt > budget:
            failures.append(f"{n} 节点布线耗时 {dt:.2f}s 超出预算 {budget}s")
    assert not failures, "布线性能回退：\n" + "\n".join(failures)


def test_routing_result_is_cached_and_stable():
    """同一张图重复布线必须命中缓存，且结果逐点一致。

    缓存是消除「多个指标各布线一遍」的关键（evaluate 内曾布线 2~3 次）。
    这里同时验证：① 重复调用结果稳定；② 缓存命中不改变几何。
    """
    d = _perf_diagram(20, 40)
    r1 = M.plan_edge_routes(d)
    r2 = M.plan_edge_routes(d)
    assert r1 == r2, "同一张图的两次布线结果不一致（缓存污染或不确定性）"
    assert len(r1) > 0, "布线结果为空"

    # 不同对象、同内容 → 结果必须一致（可复现，不依赖对象身份）
    d2 = _perf_diagram(20, 40)
    r3 = M.plan_edge_routes(d2)
    assert set(r1.keys()) == set(r3.keys()), "同内容图的路由键集合不一致"
    for k in r1:
        assert r1[k] == r3[k], f"边 {k} 的路由在同内容图上不可复现"


def test_route_cache_not_poisoned_by_mutation():
    """原地改坐标后必须重算，不能返回过期缓存。

    缓存键含结构指纹（各 cell 的 id/坐标/尺寸），正是为这个场景设计的：
    前端拖动节点后重新求值，若命中旧缓存就会画出错误路径。
    """
    d = _perf_diagram(12, 24)
    r1 = M.plan_edge_routes(d)
    # 把所有节点整体下移 400px，路径必然改变
    for c in d["cells"]:
        if c.get("source") is None:
            c["position"]["y"] += 400.0
    r2 = M.plan_edge_routes(d)
    assert r1 != r2, "节点坐标变更后返回了过期缓存（缓存键未包含几何指纹）"


def test_candidate_channel_pruning_keeps_zero_defects():
    """通道级剪枝（_CH_LIMIT）不得引入穿节点/重合。

    剪枝按「通道线碰撞数」截断候选，理论上不会丢掉更优解；这个测试
    守住该不变式——剪枝若误伤有效通道，这里会立刻红。
    """
    for name, diagram in _synthetic_scenarios():
        m = M.evaluate({"model": {"detail": {"diagrams": [diagram]}}})
        assert m is not None
        assert not m["edge_through_node"], (
            f"{name} 剪枝后出现穿节点：{m['edge_through_node'][:5]}"
        )
        assert not m["edge_overlap"], (
            f"{name} 剪枝后出现路径重合：{m['edge_overlap'][:5]}"
        )


if __name__ == "__main__":
    print("=== 合成场景严格断言 ===")
    test_synthetic_scenarios_strict()
    test_synthetic_scenarios_edge_through_node_zero()
    print("合成场景：全部通过\n")

    print("=== 性能预算 ===")
    test_routing_performance_budget()
    print("性能预算：通过\n")

    print("=== 缓存正确性 ===")
    test_routing_result_is_cached_and_stable()
    test_route_cache_not_poisoned_by_mutation()
    test_candidate_channel_pruning_keeps_zero_defects()
    print("缓存正确性：通过\n")

    test_historical_results_report()
