"""数据流收敛（源头降噪）的回归测试。

守住三件事：
    1. 只合并"同向 + 同安全语义"的流，加密/公网语义不同、反向流都不许合；
    2. 合并**不丢威胁**（被合并流上的威胁改挂代表流，条数不变）；
    3. 结果确定（同输入两次一致、顺序稳定），且信息不丢（名字/描述/协议聚合）。

另附 P1 的"必要性排序"口径测试：公网/加密 > 落库 > 同域编排，且可复现。
跑法：python -m pytest tests/test_flow_convergence.py -v   或直接 python 本文件。
"""

from __future__ import annotations

import os
import sys

# 与运行时一致：backend/ 在 sys.path 上，威胁子应用以 threat.app.* 导入
# （子应用内部 `from app.utils import ...` 用的是 SDLC 宿主包）
_BACKEND_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from threat.app.services.document_analyzer import _flow_necessity_key  # noqa: E402
from threat.app.services.flow_convergence import converge_flows  # noqa: E402


def _flow(fid, src, tgt, name, desc="", **props):
    return {
        "id": fid,
        "sourceId": src,
        "targetId": tgt,
        "name": name,
        "description": desc,
        "properties": props,
    }


# ---------------------------------------------------------------------------
# 数据流预算（P1）：只度量不裁剪 —— 超预算必须在质量报告里可见
# ---------------------------------------------------------------------------
def _diagram(n_nodes: int, n_edges: int) -> dict:
    """手搭一份最小 DFD：n_nodes 个处理节点 + 1 个信任边界 + n_edges 条流。"""
    cells = [
        {"id": f"n{i}", "shape": "tm.Process",
         "position": {"x": i * 100, "y": 0}, "size": {"width": 80, "height": 60}}
        for i in range(n_nodes)
    ]
    cells.append({"id": "b1", "shape": "tm.BoundaryBox",
                  "position": {"x": 0, "y": 0}, "size": {"width": 900, "height": 200}})
    cells += [
        {"id": f"e{i}", "shape": "tm.Flow",
         "source": {"cell": f"n{i % n_nodes}"},
         "target": {"cell": f"n{(i + 1) % n_nodes}"},
         "data": {"name": f"流{i}"}}
        for i in range(n_edges)
    ]
    return {"cells": cells}


def test_flow_budget_ratio_and_report_flag():
    """预算口径 = 流数 / **非边界节点数**；超 1.5× 时报告要显式标出。

    为什么只度量不裁剪：裁流等于从模型里删元素、连带删掉挂在流上的威胁，
    而模型内容是用户资产、不可逆 —— 先让问题可见（日志 + 报告），取舍交给人。
    实测存量结果里最差的一份是 13 个非边界节点 / 38 条流 = 2.92×。
    """
    from threat.app.services.dfd_layout_metrics import evaluate, format_report

    def _m(n_nodes: int, n_edges: int) -> dict:
        rec = {"model": {"detail": {"diagrams": [_diagram(n_nodes, n_edges)]}}}
        got = evaluate(rec)
        assert got is not None, "度量模块无法评估最小图"
        return got

    ok = _m(n_nodes=10, n_edges=12)               # 1.2× 在预算内
    assert ok["flow_budget_ratio"] == 1.2, ok["flow_budget_ratio"]
    assert "预算<=1.5" in format_report("t", ok)
    assert "超预算" not in format_report("t", ok), "预算内不应出现超预算提示"

    over = _m(n_nodes=10, n_edges=30)             # 3.0× 超预算
    assert over["flow_budget_ratio"] == 3.0, over["flow_budget_ratio"]
    assert "超预算" in format_report("t", over), "超预算必须在报告里可见"


def test_merge_same_direction_same_semantics():
    flows = [
        _flow("f1", "A", "B", "上传体征数据", "手环体征经网关上传", protocol="HTTPS"),
        _flow("f2", "A", "B", "设备鉴权", "设备证书双向鉴权", protocol="MQTT"),
    ]
    merged, remap = converge_flows(flows)
    assert len(merged) == 1, f"同向同语义应合并为 1 条，实际 {len(merged)}"
    m = merged[0]
    assert "上传体征数据" in m["name"] and "设备鉴权" in m["name"], m["name"]
    assert "手环体征" in m["description"] and "双向鉴权" in m["description"]
    assert "HTTPS" in m["properties"]["protocol"] and "MQTT" in m["properties"]["protocol"]
    assert remap == {"f2": "f1"} or remap == {"f1": "f2"}, remap


def test_keep_when_security_semantics_differ():
    flows = [
        _flow("f1", "A", "B", "明文调用", isEncrypted=False),
        _flow("f2", "A", "B", "加密调用", isEncrypted=True),
    ]
    merged, remap = converge_flows(flows)
    assert len(merged) == 2, "加密语义不同不得合并（否则丢掉'这条是加密的'）"
    assert remap == {}


def test_keep_reverse_direction_apart():
    flows = [
        _flow("f1", "A", "B", "请求"),
        _flow("f2", "B", "A", "响应"),
    ]
    merged, remap = converge_flows(flows)
    assert len(merged) == 2, "反向流（请求/响应）必须保留两条平行线"
    assert remap == {}


def test_pass_through_dangling_and_self_loop():
    flows = [
        _flow("f1", "", "B", "缺源"),
        _flow("f2", "A", "A", "自环"),
        _flow("f3", "A", "B", "正常"),
    ]
    merged, remap = converge_flows(flows)
    assert len(merged) == 3 and remap == {}


def test_threats_are_preserved_by_remap():
    """模拟 model_builder.build() 的搬迁：威胁条数不变、都落到代表流上。"""
    flows = [
        _flow("f1", "A", "B", "上传体征数据"),
        _flow("f2", "A", "B", "设备鉴权"),
        _flow("f3", "B", "C", "落库"),
    ]
    merged, remap = converge_flows(flows)
    threats = [
        {"componentId": "f1", "title": "t1"},
        {"componentId": "f2", "title": "t2"},
        {"componentId": "f3", "title": "t3"},
    ]
    before = len(threats)
    for t in threats:
        new_id = remap.get(t["componentId"])
        if new_id:
            t["componentId"] = new_id
    assert len(threats) == before, "威胁条数必须守恒"
    live_ids = {f["id"] for f in merged}
    assert all(t["componentId"] in live_ids for t in threats), "威胁不能悬空"
    assert len({t["componentId"] for t in threats if t["componentId"] != "f3"}) == 1


def test_deterministic_and_order_stable():
    flows = [
        _flow("f1", "A", "B", "第一条长描述流", "描述很长" * 3),
        _flow("f2", "A", "B", "第二条"),
        _flow("f3", "C", "D", "另一对端点"),
    ]
    a = converge_flows(list(flows))
    b = converge_flows(list(flows))
    assert [f["id"] for f in a[0]] == [f["id"] for f in b[0]]
    assert a[1] == b[1]
    # 顺序稳定：合并后的代表流仍在原首次出现位置（元素编号不会漂）
    assert [f["id"] for f in a[0]] == ["f1", "f3"]


def test_necessity_key_orders_security_then_storage_then_internal():
    comps = {
        "actor1": {"id": "actor1", "type": "actor"},
        "svc": {"id": "svc", "type": "process"},
        "svc2": {"id": "svc2", "type": "process"},
        "db": {"id": "db", "type": "datastore"},
    }
    public_flow = _flow("f1", "actor1", "svc", "公网登录", protocol="HTTPS", isPublicNetwork=True)
    store_flow = _flow("f2", "svc", "db", "写入订单")
    internal_flow = _flow("f3", "svc", "svc2", "库存处理结果")
    keys = {
        "public": _flow_necessity_key(public_flow, comps),
        "store": _flow_necessity_key(store_flow, comps),
        "internal": _flow_necessity_key(internal_flow, comps),
    }
    assert keys["public"][:3] > keys["internal"][:3], keys
    assert keys["store"][:3] > keys["internal"][:3], keys
    # 确定性：同输入两次一致
    assert _flow_necessity_key(internal_flow, comps) == keys["internal"]


def _threat(cid, title, severity="Medium"):
    return {
        "componentId": cid,
        "title": title,
        "severity": severity,
        "type": "Spoofing",
        "description": "",
        "mitigation": "",
    }


def test_model_builder_converges_and_keeps_threats():
    """走一遍真实 build()：合并生效、威胁一条不丢、importance 已下发。"""
    from threat.app.services.model_builder import ThreatModelBuilder

    comps = [
        {"id": "c1", "type": "actor", "name": "用户", "lifecycle": "collect"},
        {"id": "c2", "type": "process", "name": "接入网关", "lifecycle": "transit"},
        {"id": "c3", "type": "process", "name": "业务服务", "lifecycle": "use"},
        {"id": "c4", "type": "datastore", "name": "订单数据库", "lifecycle": "store"},
    ]
    flows = [
        _flow("f1", "c1", "c2", "登录请求", "用户登录", isPublicNetwork=True, protocol="HTTPS"),
        _flow("f2", "c1", "c2", "设备鉴权", "设备证书鉴权", isPublicNetwork=True, protocol="MQTT"),
        _flow("f3", "c3", "c4", "写入订单"),
    ]
    threats = [
        _threat("f1", "T1-凭据泄露", "High"),
        _threat("f2", "T2-设备伪造", "Low"),
        _threat("f3", "T3-数据篡改", "Medium"),
    ]
    model = ThreatModelBuilder().build(
        summary={"title": "收敛验证系统", "description": "d"},
        diagram={"title": "数据流图", "diagramType": "STRIDE"},
        components=comps,
        flows=flows,
        threats=threats,
        methodology="STRIDE",
    )
    cells = model["detail"]["diagrams"][0]["cells"]
    flow_cells = [c for c in cells if c.get("shape") == "tm.Flow"]
    assert len(flow_cells) == 2, f"f1/f2 应合并，实际流 cell = {len(flow_cells)}"

    # 威胁保全：三条威胁一条不少，且两条都挂到了合并后的代表流上
    all_threats = [t for c in cells for t in (c.get("threats") or [])]
    assert len(all_threats) == 3, f"威胁条数应守恒，实际 {len(all_threats)}"
    merged = [c for c in flow_cells if "登录请求" in str(c["data"].get("name") or "")]
    assert merged, "合并后的代表流应保留（名字里含首条流的名字）"
    assert len(merged[0]["threats"]) == 2, "被合并流上的威胁应改挂到代表流"

    # importance 下发（后端唯一口径，前端只读）
    for c in flow_cells:
        assert c["data"].get("importance") in ("primary", "secondary"), c["data"]
    assert merged[0]["data"]["importance"] == "primary", "公网 + 高危威胁 → 重要流"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        fn()
        print(f"  PASS  {fn.__name__}")
    print(f"\n{len(tests)} tests passed")
