"""威胁模型构建器：将 DFD 元素与威胁整合为 Threat Dragon 兼容模型。

生成的 JSON 完全符合 threat-dragon-v2.schema.json，可直接被
OWASP Threat Dragon 打开编辑。
"""

from __future__ import annotations

import json
import logging
import math
import uuid
from typing import Any

logger = logging.getLogger(__name__)

# Threat Dragon 版本号（保持兼容）
TD_VERSION = "2.6.2"
# 默认模型 / 图编号
MODEL_ID = 0
# 模型结构常量（与 Threat Dragon 一致）
STRIDE_TYPE_NAMES = {
    "Spoofing": "Spoofing",
    "Tampering": "Tampering",
    "Repudiation": "Repudiation",
    "Information Disclosure": "Information Disclosure",
    "Denial of Service": "Denial of Service",
    "Elevation of Privilege": "Elevation of Privilege",
}

# 组件类型 -> Threat Dragon shape
SHAPE_MAP = {
    "actor": "tm.Actor",
    "process": "tm.Process",
    "datastore": "tm.Store",
    "externalentity": "tm.Actor",
    "trustboundary": "tm.BoundaryBox",
    "text": "tm.Text",
    # STRIDE-AI：AI 元素的渲染形状（X6 cell type）。
    # - 主动型（model/prompt/tool/agentconfig）→ tm.Process
    # - 存储型（vectorstore/trainingdata）→ tm.Store（语义上就是数据存储，
    #   在官方 TD 中也能正确匹配威胁类型）
    # data.type 单独保留为 TD-可识别的形状（用于威胁类型推断）；
    # AI 子类型放在 data.aiElementType，平台前端按此做 AI 视觉样式。
    "model": "tm.Process",
    "prompt": "tm.Process",
    "vectorstore": "tm.Store",
    "tool": "tm.Process",
    "trainingdata": "tm.Store",
    "agentconfig": "tm.Process",
}

# STRIDE-AI 元素的内部标识（写入 data.type 以便前端/威胁判定识别）
AI_ELEMENT_TYPE_TAG = {
    "model": "tm.Model",
    "prompt": "tm.Prompt",
    "vectorstore": "tm.VectorStore",
    "tool": "tm.Tool",
    "trainingdata": "tm.TrainingData",
    "agentconfig": "tm.AgentConfig",
}

# 数据生命周期泳道（与 output_schema.LIFECYCLE_ENUM 顺序一致）
# 布局时按此顺序自上而下分泳道展示，使数据流图呈现
# "采集 → 传输 → 存储 → 处理 → 使用 → 交换 → 删除"的生命周期结构。
LIFECYCLE_ORDER = ["collect", "transit", "store", "process", "use", "exchange", "delete"]
LIFECYCLE_LABELS = {
    "collect":  "数据采集",
    "transit":  "数据传输",
    "store":    "数据存储",
    "process":  "数据处理",
    "use":      "数据使用",
    "exchange": "数据交换",
    "delete":   "数据删除",
    # 兜底泳道：未标注生命周期的组件归入此泳道（排在最下方）
    "other": "其他 / 未标注",
}


class ThreatModelBuilder:
    """将分析结果整合为 Threat Dragon v2 兼容的威胁模型 JSON。"""

    # 布局常量
    NODE_WIDTH = 180
    NODE_HEIGHT = 60
    H_GAP = 60
    V_GAP = 40
    MARGIN = 40

    def __init__(self) -> None:
        self._counter = 1  # 威胁编号计数器
        self._arch_heights: dict[str, float] = {}  # 同泳道横向流的拱高堆叠（由 _layout_lifecycle_lanes 计算）

    def build(
        self,
        summary: dict[str, Any],
        diagram: dict[str, Any],
        components: list[dict[str, Any]],
        flows: list[dict[str, Any]],
        threats: list[dict[str, Any]],
        methodology: str = "STRIDE",
    ) -> dict[str, Any]:
        """构建完整的 Threat Dragon v2 威胁模型。

        Args:
            summary: 模型摘要信息。
            diagram: 图元数据。
            components: DFD 组件列表。
            flows: 数据流列表。
            threats: 威胁列表（每条含 componentId）。
            methodology: 威胁建模方法论，写入每条威胁的 modelType。

        Returns:
            符合 threat-dragon-v2.schema.json 的字典。
        """
        # 防御：LLM 偶发把 summary 输出成字符串而非对象。
        # 若如此则丢弃非法类型，避免下方 summary.get(...) 崩溃导致任务失败。
        if not isinstance(summary, dict):
            summary = {"title": "AI 生成的威胁模型", "description": ""}

        # 数据流去重：(sourceId, targetId, name) 完全相同的流只保留一条，
        # 避免 AI 重复生成同一条边导致连线与标签重叠
        flows = self._dedupe_flows(flows)

        # P3 修复：自动添加外层"业务系统边界"兜底。
        # 当模型没有任何 trustboundary 节点时，AI 偶尔会漏标，DFD 呈现
        # "一堆节点散在画布上、没有承载它们的容器"，前端用户看到的就是
        # "数据存储跑出框外"。此处自动补一个 outer trustboundary 包裹
        # 所有非 actor 节点，落地"我们规定的框"这一产品语义。
        if not any(c.get("type") == "trustboundary" for c in components):
            outer = self._build_outer_boundary(components)
            if outer is not None:
                components = list(components) + [outer]

        # 为每个组件分配位置（自动布局）
        layout = self._layout(components, flows)
        # 生命周期泳道元数据（无 lifecycle 字段时 _layout 不输出）
        lanes_meta = layout.pop("_lanes", None) if isinstance(layout, dict) else None

        # 组件 → 所属 trustboundary 的映射；用于计算每条数据流的「跨边界」语义。
        # 渲染层会把 crossesTrustBoundary===true 的边画成中虚线，与加密/公网形成
        # 三种视觉区分：实线绿(加密) / 实线橙(公网) / 中虚线灰黑(跨边界)。
        boundary_membership = self._compute_boundary_membership(components, flows)

        cells = []
        id_to_cell_id: dict[str, str] = {}
        # 元素类型映射（组件 + 数据流都纳入，供威胁挂载时判断类型）
        element_by_id: dict[str, str] = {c["id"]: c["type"] for c in components}
        for f in flows:
            element_by_id[f["id"]] = "dataflow"

        # 1. 创建组件 cells
        for i, comp in enumerate(components):
            cell = self._make_component_cell(comp, layout[comp["id"]], i)
            id_to_cell_id[comp["id"]] = cell["id"]
            cells.append(cell)

        # 2. 创建数据流 cells
        for flow in flows:
            cell = self._make_flow_cell(
                flow,
                id_to_cell_id[flow["sourceId"]],
                id_to_cell_id[flow["targetId"]],
                layout,
                boundary_membership=boundary_membership,
            )
            id_to_cell_id[flow["id"]] = cell["id"]
            cells.append(cell)

        # 3. 为威胁分派到对应组件 cell
        threats_by_comp: dict[str, list] = {}
        for t in threats:
            threats_by_comp.setdefault(t["componentId"], []).append(t)

        for cid, tlist in threats_by_comp.items():
            target = id_to_cell_id.get(cid)
            if not target:
                continue
            # 威胁可能挂在组件或数据流上，统一用 element_by_id 取类型
            elem_type = element_by_id.get(cid, "process")
            for cell in cells:
                if cell["id"] == target:
                    cell["data"]["hasOpenThreats"] = True
                    cell["threats"] = [
                        self._make_threat(t, elem_type, methodology)
                        for t in tlist
                    ]
                    break

        # 4. 组装模型
        title = summary.get("title", "AI 生成的威胁模型")
        model = {
            "version": TD_VERSION,
            "summary": {
                "title": title,
                "description": summary.get("description", ""),
                "id": MODEL_ID,
                "owner": summary.get("owner", "AI Threat Dragon"),
            },
            "detail": {
                "contributors": [{"name": "AI Threat Dragon"}],
                "reviewer": "",
                "diagramTop": 1,
                "threatTop": self._counter,
                "diagrams": [
                    {
                        "title": diagram.get("title", "数据流图"),
                        "diagramType": diagram.get("diagramType", "STRIDE"),
                        "id": 0,
                        "thumbnail": "",
                        "version": TD_VERSION,
                        "placeholder": "",
                        "description": diagram.get("description", ""),
                        "cells": cells,
                        **({"lanes": lanes_meta} if lanes_meta else {}),
                    }
                ],
            },
        }
        return model

    # ------------------------------------------------------------------
    # 自动布局
    # ------------------------------------------------------------------
    # 同一层内节点横向交错间隔，让横向流有独立通道
    _INTRALAYER_VARIANCE = 60  # 同层节点 X 抖动幅度（px）
    # 跨越 ≥2 层的长边在源/目标端点上下错位，让折角斜线明显
    _LONG_EDGE_VERTICAL_JITTER = 30

    def _dedupe_flows(self, flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """合并 (sourceId, targetId, name) 完全重复的数据流。

        LLM 生成的数据流偶尔会把同一条边重复输出多遍，导致图中出现
        重叠连线和重复标签。这里保留首条；带威胁的流不做去重，避免
        威胁因组件 id 被移除而悬空。
        """
        seen: dict[tuple[str, str, str], int] = {}
        merged: list[dict[str, Any]] = []
        for f in flows:
            if f.get("threats"):
                merged.append(f)
                continue
            key = (
                f.get("sourceId") or "",
                f.get("targetId") or "",
                f.get("name") or "",
            )
            if key not in seen:
                seen[key] = len(merged)
                merged.append(f)
            # 完全重复且无威胁 → 丢弃
        return merged

    def _build_outer_boundary(
        self, components: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        """P3 兜底：自动生成一个外层「业务系统边界」trustboundary。

        触发条件：components 里没有任何 trustboundary 节点。
        行为：构造一个占位 trustboundary，让 _layout 走容器化逻辑自动
        包裹所有非 actor 组件（process/datastore/AI 元素等），从而
        解决「数据存储节点跑出框外」的产品体验问题。

        返回的 boundary 不携带任何数据流（不与任何 component 直接相连），
        仅在视觉上提供外层容器语义。
        """
        has_internal = any(
            c.get("type") not in ("actor", "externalentity", "trustboundary", "text")
            for c in components
        )
        if not has_internal:
            return None
        bid = f"outer-boundary-{uuid.uuid4().hex[:8]}"
        return {
            "id": bid,
            "name": "业务系统边界",
            "type": "trustboundary",
            "description": "自动生成的外层业务系统边界，包裹所有内部组件（process/datastore/AI 元素等）",
            "properties": {"isTrustBoundary": True},
        }

    def _compute_boundary_membership(
        self,
        components: list[dict[str, Any]],
        flows: list[dict[str, Any]],
    ) -> dict[str, str]:
        """推断每个组件所属的信任边界，返回 {component_id: boundary_id}。

        用于「跨边界」数据流标记：当一条流的两端属于不同 trustboundary（或一
        端在边界内、一端在边界外）时，该流在 DFD 上以中虚线（'7 5'）渲染，
        与「加密流」「公网流」一起构成三种视觉语义。

        算法与 _layout() 内部的容器化逻辑保持一致：复用 Kahn 拓扑分层 +
        _infer_boundary_children 关键词推断；同一个组件在多个 boundary 的
        情况下，保留后命中者（实际几乎不会发生，因为 _infer_boundary_children
        会按类型/层语义互斥分配）。返回字典仅包含「至少属于一个 boundary」的
        组件；不在任何 boundary 内的组件不出现在结果里，由调用方用 .get(cid)
        拿到 None 表示「在边界外」。
        """
        if not components:
            return {}
        comp_by_id = {c["id"]: c for c in components}
        comp_type = {c["id"]: c.get("type", "process") for c in components}
        boundary_ids = [cid for cid, t in comp_type.items() if t == "trustboundary"]
        if not boundary_ids:
            return {}

        # 复刻 _layout() 里的 Kahn 拓扑分层（trustboundary 不参与），得到
        # 每个非边界组件的 layer，供 _infer_boundary_children 语义分组。
        in_degree: dict[str, int] = {c["id"]: 0 for c in components}
        children: dict[str, list] = {c["id"]: [] for c in components}
        for f in flows:
            src, tgt = f.get("sourceId"), f.get("targetId")
            if not src or not tgt:
                continue
            if src not in in_degree or tgt not in in_degree:
                continue
            children.setdefault(src, []).append(tgt)
            in_degree[tgt] += 1
        for cid in boundary_ids:
            in_degree[cid] = 10 ** 9

        layer_of: dict[str, int] = {}
        remaining = dict(in_degree)
        cur = [cid for cid, d in remaining.items() if d == 0]
        if not cur:
            cur = [cid for cid in in_degree if cid not in boundary_ids]
        no = 0
        while cur:
            cur.sort()
            for cid in cur:
                layer_of[cid] = no
            seen_this = set(cur)
            nxt = []
            for cid in cur:
                for child in children.get(cid, []):
                    remaining[child] -= 1
                    if remaining[child] <= 0 and child not in seen_this:
                        nxt.append(child)
                        seen_this.add(child)
            if not nxt:
                leftover = [cid for cid in remaining
                            if cid not in layer_of and cid not in boundary_ids]
                if leftover:
                    leftover.sort()
                    nxt = leftover
                else:
                    break
            cur = nxt
            no += 1
        for cid in in_degree:
            if cid not in layer_of and cid not in boundary_ids:
                layer_of[cid] = 0

        # 对每个 trustboundary 推断其包裹的组件；后写入的 boundary 会覆盖先前
        # 分配（实际场景几乎不会重叠，因为 _infer_boundary_children 走的是
        # 互斥的语义分组）。
        membership: dict[str, str] = {}
        for bid in boundary_ids:
            inner = self._infer_boundary_children(
                comp_by_id, comp_type, flows, bid, layer_of
            )
            for cid in inner:
                membership[cid] = bid
        return membership

    def _infer_boundary_children(
        self,
        comp_by_id: dict[str, Any],
        comp_type: dict[str, str],
        flows: list[dict[str, Any]],
        boundary_cid: str,
        layer_of: dict[str, int],
    ) -> list[str]:
        """推断某个信任边界应包裹的组件（确定性启发式）。

        策略：
        1. 用边界名字/描述中的关键词区分『存储侧 / 服务侧 / 用户侧』语义；
        2. 存储侧（数据库/缓存/日志…）→ 只含 datastore / vectorstore / trainingdata；
        3. 服务侧（内网/服务/后端/微服务…）→ 只含 process，且排除最上游(用户侧)浅层，
           取拓扑中间层的 process；
        4. 用户侧（公网/用户/前端/接入…）→ 只含 actor + 最上游浅层 process；
        5. 无关键词命中 → 兜底含全部非 boundary 组件。
        6. P3 兜底：outer boundary（id 以 'outer-boundary-' 开头）→ 包含所有
           非 actor 非 boundary 组件，作为「业务系统边界」的最外层容器。
        这样能避免『公网边界』误吞所有节点，边界之间互不重叠。
        """
        # P3 兜底：outer boundary 走全包分支，绕开关键词推断
        if str(boundary_cid).startswith("outer-boundary-"):
            return [
                cid for cid, t in comp_type.items()
                if t not in ("trustboundary", "actor", "externalentity", "text")
            ]

        name = str(comp_by_id.get(boundary_cid, {}).get("name") or "")
        desc = str(comp_by_id.get(boundary_cid, {}).get("description") or "")
        text = (name + " " + desc).lower()

        # 类型语义分组
        store_types = {"datastore", "vectorstore", "trainingdata", "store"}
        proc_types = {"process", "model", "prompt", "tool", "agentconfig"}
        actor_types = {"actor", "externalentity"}

        def _match_impl(*groups):
            kw_pool = {
                "store": ("数据库", "存储", "数据", "缓存", "db", "database",
                          "redis", "mysql", "日志", "es", "elastic", "消息",
                          "queue", "mq", "对象存储", "oss"),
                "proc": ("服务", "后端", "微服务", "内部", "api", "业务", "中台",
                         "网关", "核心", "内网"),
                "actor": ("公网", "用户", "外网", "前端", "浏览器", "web", "app",
                          "客户端", "移动端", "手机", "h5", "接入"),
            }
            return any(any(k.lower() in text for k in kw_pool[g]) for g in groups)

        matched_types: set[str] = set()
        if _match_impl("store"):
            matched_types |= store_types
        if _match_impl("proc"):
            matched_types |= proc_types
        if _match_impl("actor"):
            matched_types |= actor_types
        if not matched_types:
            matched_types = store_types | proc_types | actor_types

        candidates = [
            cid for cid, t in comp_type.items()
            if t in matched_types and t != "trustboundary"
        ]
        if not candidates:
            return []

        # 按拓扑层（layer_of）分组，区分 用户侧(浅层)/服务侧(中层)/存储侧(深层)
        layers = [layer_of.get(c, 0) for c in candidates]
        min_l, max_l = (min(layers), max(layers)) if layers else (0, 0)
        mid_l = (min_l + max_l) / 2.0

        # 只保留该边界语义对应的那一段节点：
        #   store → 深层（>= mid_l）；proc → 中层（>= min_l，避开最浅用户侧）；
        #   actor → 浅层（<= mid_l）。
        selected = []
        for c in candidates:
            t = comp_type.get(c)
            l = layer_of.get(c, 0)
            if t in store_types:
                if l >= mid_l - 0.5:
                    selected.append(c)
            elif t in proc_types:
                # 内网/服务侧边界包含 process。
                # 但最上游的『入口前端』process（layer 很浅、通常已归公网/用户侧边界）
                # 必须排除，否则内网边界会误吞公网边界，导致边界互相嵌套重叠。
                # 取 l >= min_l + 1.5 的中层及以下 process 作为服务侧核心。
                if matched_types & proc_types and l >= min_l + 1.5:
                    selected.append(c)
            else:  # actor / externalentity
                if l <= mid_l + 0.5:
                    selected.append(c)
        if not selected:
            selected = candidates

        # 公网/用户侧边界：把与之直接相邻的最浅层 process（如 Web 前端）一并纳入，
        # 使边界包裹『外部 actor + 入口前端』，而非只有空荡荡的外部实体。
        if matched_types & actor_types and not (matched_types & proc_types):
            shallow_procs = [
                c for c in comp_type
                if comp_type.get(c) in proc_types
                and layer_of.get(c, 0) <= min_l + 1.5
            ]
            shallow_procs.sort(
                key=lambda c: (layer_of.get(c, 0),
                               str(comp_by_id.get(c, {}).get("name") or ""))
            )
            selected = shallow_procs + selected

        # 信任边界不包裹外部 actor/外部实体（它们应在边界外，符合 DFD 语义）
        selected = [c for c in selected
                    if comp_type.get(c) not in actor_types]

        # 按"参与流数"降序（度越大越核心），保证确定性
        degree: dict[str, int] = {}
        for f in flows:
            for e in (f.get("sourceId"), f.get("targetId")):
                if e:
                    degree[e] = degree.get(e, 0) + 1
        selected.sort(
            key=lambda c: (-degree.get(c, 0),
                           layer_of.get(c, 0),
                           str(comp_by_id.get(c, {}).get("name") or ""))
        )
        return selected

    def _layout(
        self,
        components: list[dict[str, Any]],
        flows: list[dict[str, Any]],
    ) -> dict[str, dict]:
        """DFD 自动布局：Kahn 分层 + 横向铺开 + 信任边界容器化 + 链式防竖线。

        设计目标（满足『数据流不应是从上到下一条直线』）：
        1. 保留拓扑纵向分层（上游→下游），但同一层兄弟节点横向并排 → 分叉/汇聚自然呈现；
        2. 单节点链式层在水平方向蛇形偏移，避免整图退化成单列竖线；
        3. 信任边界（trustboundary）不作为普通节点占用顶层，而是按关键词推断
           内含组件后用 bbox 包裹成容器；
        4. 所有偏移/选择基于 stable_id 哈希与稳定排序，确定性可复现（漂移=0）。

        算法步骤：
        A. Kahn 拓扑分层（排除 trustboundary），得到每个实体节点的 layer；
        B. 每层节点按类型+名字排序，横向居中铺开；
        C. 链式防竖线：对连续单/双节点层施加蛇形横向锚点偏移；
        D. 信任边界内含推断 + bbox 容器化。
        """
        if not components:
            return {}

        # 生命周期泳道布局：当**至少一个非信任边界组件**带 lifecycle 字段（且值在白名单内）时启用。
        # 组件按 数据采集→传输→存储→处理→使用→交换→删除 分组排布，使数据流图呈现生命周期结构。
        #
        # P2-1 兜底：若所有 lifecycle 字段都是 None / "" / 不在白名单内（LLM 漏标或全标 other），
        # 则**回退**到主 Kahn 分层布局——避免 7+1 个 swimlane 中前 7 个全空、节点全挤 "other" lane。
        lifecycle_typed = [
            c for c in components
            if c.get("type") != "trustboundary"
            and (c.get("lifecycle") or "").strip().lower() in LIFECYCLE_LABELS
        ]
        if lifecycle_typed:
            layout_lanes = self._layout_lifecycle_lanes(components, flows)
            # P2-2 sanity check：扫描布局后节点 y，统计有多少节点**不**在任何 swimlane 矩形内
            # 仅做 warn 日志，**不**中断流程（让上游 dfd_reviewer 二次纠偏可观测）
            try:
                self._layout_sanity_check(components, layout_lanes)
            except Exception as _exc:  # noqa: BLE001
                logger.warning("layout sanity check 异常（不中断流程）: %s", _exc)
            return layout_lanes

        comp_by_id = {c["id"]: c for c in components}
        comp_type = {c["id"]: c.get("type", "process") for c in components}

        def _stable_rank(cid: str) -> tuple:
            import hashlib as _hashlib
            h = _hashlib.sha1(cid.encode("utf-8")).hexdigest()
            return (int(h[:8], 16),)

        boundary_ids = [cid for cid, t in comp_type.items() if t == "trustboundary"]

        # --- A. Kahn 拓扑分层（trustboundary 不参与，单独容器化） ---
        in_degree: dict[str, int] = {c["id"]: 0 for c in components}
        children: dict[str, list] = {c["id"]: [] for c in components}
        parents: dict[str, list] = {c["id"]: [] for c in components}
        for f in flows:
            src, tgt = f.get("sourceId"), f.get("targetId")
            if not src or not tgt:
                continue
            if src not in in_degree or tgt not in in_degree:
                continue
            children.setdefault(src, []).append(tgt)
            parents.setdefault(tgt, []).append(src)
            in_degree[tgt] += 1

        # 信任边界入度置高，确保不会进入拓扑层（避免挤占顶层）
        for cid in boundary_ids:
            in_degree[cid] = 10 ** 9

        layer_of: dict[str, int] = {}
        remaining = dict(in_degree)
        current_layer = [cid for cid, d in remaining.items() if d == 0]
        if not current_layer:
            current_layer = [cid for cid in in_degree if cid not in boundary_ids]
        cur_layer_no = 0
        while current_layer:
            current_layer.sort(key=_stable_rank)
            for cid in current_layer:
                layer_of[cid] = cur_layer_no
            visited_this_layer = set(current_layer)
            next_layer = []
            for cid in current_layer:
                for child in children.get(cid, []):
                    remaining[child] -= 1
                    if remaining[child] <= 0 and child not in visited_this_layer:
                        next_layer.append(child)
                        visited_this_layer.add(child)
            if not next_layer:
                leftover = [cid for cid in remaining if cid not in layer_of
                            and cid not in boundary_ids]
                if leftover:
                    leftover.sort(key=_stable_rank)
                    next_layer = leftover
                else:
                    break
            current_layer = next_layer
            cur_layer_no += 1

        for cid in in_degree:
            if cid not in layer_of and cid not in boundary_ids:
                layer_of[cid] = 0

        max_layer = max(layer_of.values()) if layer_of else 0
        layer_buckets: dict[int, list] = {i: [] for i in range(max_layer + 1)}
        for cid, lid in layer_of.items():
            layer_buckets[lid].append(cid)

        # --- B. 每层节点排序（actor/store 贴边，process 居中，boundary 兜底） ---
        def _group_key(cid: str) -> tuple:
            t = comp_type.get(cid, "process")
            name = comp_by_id.get(cid, {}).get("name", "") or ""
            type_pri = {
                "externalentity": 0, "actor": 0,
                "trustboundary": 4,
                "process": 2,
                "datastore": 3,
                "model": 2, "prompt": 2, "vectorstore": 2, "tool": 2,
                "trainingdata": 2, "agentconfig": 2,
                "text": 5,
            }.get(t, 2)
            return (type_pri, name, _stable_rank(cid))

        for lid in layer_buckets:
            layer_buckets[lid].sort(key=_group_key)

        # --- 布局参数 ---
        col_width = self.NODE_WIDTH + self.H_GAP
        per_layer_max = max((len(layer_buckets[l]) for l in layer_buckets), default=1)
        # 画布宽度：按最宽层铺开，并为信任边界容器与单节点层锯齿偏移留足横向空间
        # P1-2 同 lifecycle 布局：用 boundary 数量做横向预算（容器可达 1200px+）
        boundary_reserve_main = len(boundary_ids) * 240 + 240
        canvas_width = max(per_layer_max * col_width, self.NODE_WIDTH * 3) + self.MARGIN * 2 + boundary_reserve_main

        positions: dict[str, dict] = {}
        n_layers = max_layer + 1
        layer_gap = max(self.V_GAP * 1.6,
                        min(self.V_GAP * 3.2, 320 / max(1, n_layers) + self.V_GAP * 1.4))
        row_h = self.NODE_HEIGHT + layer_gap

        # --- C. 坐标分配：每层横向居中铺开 + 单节点层锯齿偏移 ---
        # 核心：兄弟节点（同层）横向并排，分叉/汇聚自然呈现。
        # 防竖线：当某层只有一个节点（链式路径上的中间节点）时，把它在水平方向
        # 左右交替偏移，使『A→B→C→…』不再是竖直一条线，而是左右锯齿 + 斜向边。
        # 偏移基于层号奇偶（确定性），多节点层保持居中。
        for lid in sorted(layer_buckets.keys()):
            nodes = layer_buckets[lid]
            n = len(nodes)
            if n == 0:
                continue
            layer_total_w = sum(
                self.NODE_WIDTH + (self.H_GAP if i > 0 else 0) for i in range(n)
            )
            start_x = (canvas_width - layer_total_w) / 2
            # 单节点层：左右锯齿偏移（防竖线）。偏移量适度，避免边过长/重叠。
            if n == 1 and n_layers >= 3:
                zig = (self.NODE_WIDTH * 0.85 + self.H_GAP * 0.5)
                start_x += zig if lid % 2 == 1 else -zig
            y = self.MARGIN + lid * row_h
            for col, cid in enumerate(nodes):
                positions[cid] = {
                    "x": start_x + col * col_width,
                    "y": y,
                    "layer": lid,
                }

        # --- D. 信任边界容器化：推断内含组件 → bbox 包裹 ---
        # 内含组件直接取其已分配的 position，计算 bbox 中心与尺寸（确定性）。
        boundary_inner: dict[str, list[str]] = {}
        for cid in boundary_ids:
            children_ids = self._infer_boundary_children(
                comp_by_id, comp_type, flows, cid, layer_of
            )
            # 只包裹已被布局（有 position）且非 boundary 的组件
            inner = [k for k in children_ids
                     if k in positions and comp_type.get(k) != "trustboundary"]
            if not inner:
                # 兜底：仍给一个可见的容器（与它数据流连通范围相关）
                xs_all = [positions[k]["x"] for k in positions
                          if comp_type.get(k) != "trustboundary"]
                if xs_all:
                    cx = (min(xs_all) + max(xs_all)) / 2 + self.NODE_WIDTH / 2
                    cy = self.MARGIN + (n_layers * row_h) / 2 + self.NODE_HEIGHT / 2
                    positions[cid] = {
                        "x": cx - 180, "y": cy - 60,
                        "layer": 0, "container": True,
                        "containerSize": {"width": 400, "height": 200},
                        "containerCenter": (cx, cy),
                    }
                    boundary_inner[cid] = []
                continue

            boundary_inner[cid] = inner
            xs = [positions[k]["x"] + self.NODE_WIDTH / 2 for k in inner]
            ys = [positions[k]["y"] + self.NODE_HEIGHT / 2 for k in inner]
            cx, cy = sum(xs) / len(xs), sum(ys) / len(ys)
            minx = min(xs) - self.H_GAP * 1.4
            maxx = max(xs) + self.H_GAP * 1.4 + self.NODE_WIDTH
            miny = min(ys) - self.V_GAP * 1.4
            maxy = max(ys) + self.V_GAP * 1.4 + self.NODE_HEIGHT
            positions[cid] = {
                "x": minx,
                "y": miny,
                "layer": min((layer_of.get(k, 0) for k in inner), default=0),
                "container": True,
                "containerSize": {
                    "width": max(260, maxx - minx),
                    "height": max(160, maxy - miny),
                },
                "containerCenter": (cx, cy),
            }

        # --- E. 信任边界垂直避让：不同边界容器互不重叠 ---
        # 信任边界是水平条带容器。若相邻边界的 y 区间重叠，把后一个边界
        # 连同其内含组件（children）整体下移，既消除容器重叠，又保持
        # children 始终位于容器内部。按 min layer 排序保证条带顺序稳定。
        _bd_order = sorted(
            [cid for cid in boundary_ids if cid in positions],
            key=lambda cid: positions[cid].get("layer", 0),
        )
        for i in range(1, len(_bd_order)):
            prev, cur = _bd_order[i - 1], _bd_order[i]
            pp, cp = positions[prev], positions[cur]
            p_h = pp.get("containerSize", {}).get("height", 0)
            c_h = cp.get("containerSize", {}).get("height", 0)
            p_bottom = pp["y"] + p_h
            c_top = cp["y"]
            # 垂直重叠且水平也重叠才避让（避免水平并排的边界被强行拉开）
            px0, px1 = pp["x"], pp["x"] + pp.get("containerSize", {}).get("width", 0)
            cx0, cx1 = cp["x"], cp["x"] + cp.get("containerSize", {}).get("width", 0)
            overlap_x = min(px1, cx1) - max(px0, cx0) > 10
            if overlap_x and c_top < p_bottom + self.V_GAP * 0.5:
                delta = (p_bottom + self.V_GAP * 0.5) - c_top
                # P2-3：children 推 delta 时不能越出所属 swimlane。
                # 取「所有 children 中最小剩余推幅」作为实际推幅，
                # 让 trustboundary 容器跟着 children 平移同样距离；
                # 若容器仍与 prev 重叠，由容器自身消化（children 永远留在 lane 内）。
                bounded_delta = delta
                for kid in boundary_inner.get(cur, []):
                    kp = positions.get(kid)
                    if not kp or "edge_jitter" in kp:
                        continue
                    k_lc = kp.get("lifecycle")
                    if k_lc in lane_top:
                        k_lane_top = lane_top[k_lc]
                        k_lane_bottom = k_lane_top + lane_h
                        # 距所属 lane 下边界的最大可推距离（保留 NODE_HEIGHT 不越界）
                        max_k = k_lane_bottom - kp["y"] - self.NODE_HEIGHT
                        if max_k < bounded_delta:
                            bounded_delta = max_k
                for kid in boundary_inner.get(cur, []):
                    kp = positions.get(kid)
                    if kp and "edge_jitter" not in kp:
                        positions[kid] = dict(kp, y=kp["y"] + bounded_delta)
                # 边界自身 y 及中心同步下移（与 children 等量）
                cp["y"] += bounded_delta
                cc = cp.get("containerCenter")
                if cc:
                    cp["containerCenter"] = (cc[0], cc[1] + bounded_delta)

        # --- 跨层长边抖动：让斜线/折角线明显（可选，保持轻微错位） ---
        for f in flows:
            src, tgt = f.get("sourceId"), f.get("targetId")
            if not src or not tgt:
                continue
            if src not in positions or tgt not in positions:
                continue
            lid_src = layer_of.get(src, 0)
            lid_tgt = layer_of.get(tgt, 0)
            if abs(lid_src - lid_tgt) >= 2:
                import hashlib as _hashlib
                h = int(_hashlib.sha1(("edge:" + f.get("id", "")).encode("utf-8")).hexdigest()[:4], 16)
                dy = ((h % 200) - 100) / 100.0 * self._LONG_EDGE_VERTICAL_JITTER
                positions[src] = dict(positions[src], edge_jitter=dy)
                positions[tgt] = dict(positions[tgt], edge_jitter=-dy)

        return positions

    # ------------------------------------------------------------------
    # 生命周期泳道布局
    # ------------------------------------------------------------------
    def _layout_lifecycle_lanes(
        self,
        components: list[dict[str, Any]],
        flows: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """生命周期泳道布局：组件按 数据采集→数据传输→数据存储→数据处理→数据使用→数据交换→数据删除 分泳道排布。

        当任一非信任边界组件带 lifecycle 字段时，由 _layout() 自动选用本布局
        替代 Kahn 分层拓扑，使 AI 生成的 DFD 呈现数据生命周期结构。

        设计要点：
        A. 非信任边界组件按 lifecycle 分桶（collect/transit/store/process/use/
           exchange/delete 及兜底 other），泳道按 LIFECYCLE_ORDER 自上而下排列；
        B. 每个泳道内的组件按参与流数降序 + 名字排序，单行横向居中铺开，
           同泳道组件共享同一 Y → 形成清晰的横向条带；
        C. 信任边界复用 _infer_boundary_children（把泳道序号当 layer 参与
           语义推断），再用 bbox 包裹成容器，跨泳道时自然纵向延展；
        D. 与 Kahn 布局一致：输出确定性坐标；泳道几何写入
           positions['_lanes'] 供前端绘制泳道背景与标签。
        """
        import hashlib as _hashlib

        comp_by_id = {c["id"]: c for c in components}
        comp_type = {c["id"]: c.get("type", "process") for c in components}
        boundary_ids = [cid for cid, t in comp_type.items() if t == "trustboundary"]

        def _stable_rank(cid: str) -> tuple:
            h = _hashlib.sha1(cid.encode("utf-8")).hexdigest()
            return (int(h[:8], 16),)

        # --- A. 按生命周期分桶（含兜底 other） ---
        lane_keys = list(LIFECYCLE_ORDER) + ["other"]
        lane_index = {k: i for i, k in enumerate(lane_keys)}
        buckets: dict[str, list[str]] = {k: [] for k in lane_keys}
        for c in components:
            if c.get("type") == "trustboundary":
                continue
            lc = (c.get("lifecycle") or "").strip().lower()
            bucket = lc if lc in buckets else "other"
            buckets[bucket].append(c["id"])

        # 每个组件所属泳道序号（供边界语义推断当 layer 用）
        lane_of: dict[str, int] = {}
        for k, ids in buckets.items():
            for cid in ids:
                lane_of[cid] = lane_index[k]

        # --- B. 泳道几何：单行横向居中铺开，泳道自上而下 ---
        degree: dict[str, int] = {}
        for f in flows:
            for e in (f.get("sourceId"), f.get("targetId")):
                if e:
                    degree[e] = degree.get(e, 0) + 1

        # --- B-pre. 跨泳道连接度：用于泳道内节点 y 错位（stagger） ---
        # in_from_above[cid] = 从比 cid 所在泳道更上方的节点流入的边数
        # out_to_below[cid]  = 从 cid 流出到比其所在泳道更下方的边数
        # 两者决定 y 偏移方向：纯入流节点偏 lane 上半、纯出流偏下半、双向居中。
        in_from_above: dict[str, int] = {}
        out_to_below: dict[str, int] = {}
        for f in flows:
            src, tgt = f.get("sourceId"), f.get("targetId")
            if not src or not tgt or src == tgt:
                continue
            s_lane = lane_of.get(src)
            t_lane = lane_of.get(tgt)
            if s_lane is None or t_lane is None or s_lane == t_lane:
                continue
            if s_lane < t_lane:  # src 在上、tgt 在下
                in_from_above[tgt] = in_from_above.get(tgt, 0) + 1
                out_to_below[src] = out_to_below.get(src, 0) + 1
            else:  # s_lane > t_lane → src 在下、tgt 在上
                in_from_above[src] = in_from_above.get(src, 0) + 1
                out_to_below[tgt] = out_to_below.get(tgt, 0) + 1

        visible = [k for k in lane_keys if buckets[k]]
        col_width = self.NODE_WIDTH + self.H_GAP
        per_lane_max = max((len(buckets[k]) for k in visible), default=1)
        # P1-2：跨多个 swimlane 的 trustboundary 容器实际宽度可达 1200px+，
        # 原来固定 +480 横向余量在 5 lane 场景下不够，fitView 后节点看起来散在
        # 一侧又超出右边界。改为：boundary 数量 * 240 + 240 给容器留 240 边距。
        # （容器本身在 _infer_boundary_children 里基于内含组件 bbox 包裹，
        # 此处不重算 bbox，只做粗略上限预算，节点仍按 swimlane 铺开）
        boundary_reserve = len(boundary_ids) * 240 + 240
        canvas_width = max(
            per_lane_max * col_width, self.NODE_WIDTH * 3
        ) + self.MARGIN * 2 + boundary_reserve

        lane_h = self.NODE_HEIGHT + self.V_GAP * 2
        lane_gap = self.V_GAP * 2.5  # 增加泳道间距，给跨泳道流与同泳道拱留出垂直空间
        lane_top: dict[str, float] = {}
        y = self.MARGIN
        for k in visible:
            lane_top[k] = y
            y += lane_h + lane_gap
        canvas_h = y - lane_gap + self.MARGIN

        # y 错位最大幅度 = (lane_h - NODE_HEIGHT) / 2 * 0.65
        # 留 35% 缓冲，确保节点 y 始终落在所属 swimlane 矩形内，
        # 既让线明显分散、又不会被 _layout_sanity_check 报警。
        max_y_offset = (lane_h - self.NODE_HEIGHT) / 2 * 0.65

        positions: dict[str, Any] = {}
        for k in visible:
            ids = buckets[k]
            ids.sort(
                key=lambda cid: (
                    -degree.get(cid, 0),
                    str(comp_by_id.get(cid, {}).get("name") or ""),
                    _stable_rank(cid),
                )
            )
            n = len(ids)
            total_w = sum(
                self.NODE_WIDTH + (self.H_GAP if i > 0 else 0) for i in range(n)
            )
            start_x = (canvas_width - total_w) / 2
            center_y = lane_top[k] + (lane_h - self.NODE_HEIGHT) / 2
            # 同 swimlane 内仅在节点数 ≥ 2 时启用 stagger，避免单节点偏移后视觉割裂
            for col, cid in enumerate(ids):
                if n >= 2:
                    in_n = in_from_above.get(cid, 0)
                    out_n = out_to_below.get(cid, 0)
                    total = in_n + out_n
                    if total > 0:
                        # -1（纯入流→偏上）~ +1（纯出流→偏下），0 = 居中
                        y_off = (out_n - in_n) / total * max_y_offset
                    else:
                        # 孤立节点仍居中，不偏移
                        y_off = 0.0
                else:
                    y_off = 0.0
                positions[cid] = {
                    "x": start_x + col * col_width,
                    "y": center_y + y_off,
                    "layer": lane_index[k],
                    "lifecycle": k,
                }

        # --- B+. 同泳道横向流的拱高预分配 ---
        # 当同一泳道内 ≥2 条同向流时，需要在不同高度堆叠拱顶，避免
        # 多条流叠在同一水平线造成视觉混乱。每个泳道按方向（左→右、
        # 右→左）分桶后，依次叠加 0*step、1*step、2*step …
        arch_heights: dict[str, float] = {}
        step = self.NODE_HEIGHT * 0.55 + self.V_GAP * 0.5
        flows_by_lane: dict[str, list[tuple[str, int, int]]] = {}
        for f in flows:
            sid = f.get("sourceId") or ""
            tid = f.get("targetId") or ""
            ps_f, pt_f = positions.get(sid), positions.get(tid)
            if not ps_f or not pt_f or sid == tid:
                continue
            if ps_f.get("layer") != pt_f.get("layer"):
                continue
            sx_c = ps_f["x"] + self.NODE_WIDTH / 2
            tx_c = pt_f["x"] + self.NODE_WIDTH / 2
            if abs(sx_c - tx_c) < 1:
                continue
            lane = ps_f.get("lifecycle") or ""
            flows_by_lane.setdefault(lane, []).append(
                (f.get("id") or "", int(sx_c), int(tx_c))
            )
        for _lane, flist in flows_by_lane.items():
            flist.sort(key=lambda t: (t[1], t[2], t[0]))
            # 把同方向（左→右、右→左）的流集中，分别在 lane 上下两侧堆叠
            above: list[tuple[str, int, int]] = [
                t for t in flist if t[2] > t[1]
            ]
            below: list[tuple[str, int, int]] = [
                t for t in flist if t[2] <= t[1]
            ]
            for grp_sign, grp in ((-1, above), (1, below)):
                for i, (fid, _a, _b) in enumerate(grp):
                    # 每 2 条流共享同一高度，错位堆叠
                    level = i // 2
                    arch_heights[fid] = grp_sign * level * step
        self._arch_heights = arch_heights

        # --- C. 信任边界容器化（泳道序号作为 layer 参与语义推断） ---
        boundary_inner: dict[str, list[str]] = {}
        for cid in boundary_ids:
            children_ids = self._infer_boundary_children(
                comp_by_id, comp_type, flows, cid, lane_of
            )
            inner = [
                k
                for k in children_ids
                if k in positions and comp_type.get(k) != "trustboundary"
            ]
            if not inner:
                xs_all = [
                    positions[k]["x"]
                    for k in positions
                    if comp_type.get(k) != "trustboundary"
                ]
                if xs_all:
                    cx = (min(xs_all) + max(xs_all)) / 2 + self.NODE_WIDTH / 2
                    cy = canvas_h / 2 + self.NODE_HEIGHT / 2
                    positions[cid] = {
                        "x": cx - 180,
                        "y": cy - 60,
                        "layer": 0,
                        "container": True,
                        "containerSize": {"width": 400, "height": 200},
                        "containerCenter": (cx, cy),
                    }
                    boundary_inner[cid] = []
                continue

            boundary_inner[cid] = inner
            xs = [positions[k]["x"] + self.NODE_WIDTH / 2 for k in inner]
            ys = [positions[k]["y"] + self.NODE_HEIGHT / 2 for k in inner]
            cx, cy = sum(xs) / len(xs), sum(ys) / len(ys)
            minx = min(xs) - self.H_GAP * 1.4
            maxx = max(xs) + self.H_GAP * 1.4 + self.NODE_WIDTH
            miny = min(ys) - self.V_GAP * 1.4
            maxy = max(ys) + self.V_GAP * 1.4 + self.NODE_HEIGHT
            positions[cid] = {
                "x": minx,
                "y": miny,
                "layer": min((lane_of.get(k, 0) for k in inner), default=0),
                "container": True,
                "containerSize": {
                    "width": max(260, maxx - minx),
                    "height": max(160, maxy - miny),
                },
                "containerCenter": (cx, cy),
            }

        # --- D. 信任边界垂直避让（与 Kahn 布局一致） ---
        _bd_order = sorted(
            [cid for cid in boundary_ids if cid in positions],
            key=lambda cid: positions[cid].get("layer", 0),
        )
        for i in range(1, len(_bd_order)):
            prev, cur = _bd_order[i - 1], _bd_order[i]
            pp, cp = positions[prev], positions[cur]
            p_h = pp.get("containerSize", {}).get("height", 0)
            c_h = cp.get("containerSize", {}).get("height", 0)
            p_bottom = pp["y"] + p_h
            c_top = cp["y"]
            px0, px1 = pp["x"], pp["x"] + pp.get("containerSize", {}).get("width", 0)
            cx0, cx1 = cp["x"], cp["x"] + cp.get("containerSize", {}).get("width", 0)
            overlap_x = min(px1, cx1) - max(px0, cx0) > 10
            if overlap_x and c_top < p_bottom + self.V_GAP * 0.5:
                delta = (p_bottom + self.V_GAP * 0.5) - c_top
                # P2-3：children 推 delta 时不能越出所属 swimlane。
                # 取「所有 children 中最小剩余推幅」作为实际推幅，
                # 让 trustboundary 容器跟着 children 平移同样距离；
                # 若容器仍与 prev 重叠，由容器自身消化（children 永远留在 lane 内）。
                bounded_delta = delta
                for kid in boundary_inner.get(cur, []):
                    kp = positions.get(kid)
                    if not kp or "edge_jitter" in kp:
                        continue
                    k_lc = kp.get("lifecycle")
                    if k_lc in lane_top:
                        k_lane_top = lane_top[k_lc]
                        k_lane_bottom = k_lane_top + lane_h
                        max_k = k_lane_bottom - kp["y"] - self.NODE_HEIGHT
                        if max_k < bounded_delta:
                            bounded_delta = max_k
                for kid in boundary_inner.get(cur, []):
                    kp = positions.get(kid)
                    if kp and "edge_jitter" not in kp:
                        positions[kid] = dict(kp, y=kp["y"] + bounded_delta)
                # 边界自身 y 及中心同步下移（与 children 等量）
                cp["y"] += bounded_delta
                cc = cp.get("containerCenter")
                if cc:
                    cp["containerCenter"] = (cc[0], cc[1] + bounded_delta)

        # --- E. 泳道元数据（供前端绘制泳道背景与标签） ---
        positions["_lanes"] = [
            {
                "key": k,
                "label": LIFECYCLE_LABELS.get(k, "其他 / 未标注"),
                "x": self.MARGIN,
                "y": lane_top[k],
                "width": max(0, canvas_width - self.MARGIN * 2),
                "height": lane_h,
            }
            for k in visible
        ]
        return positions

    def _layout_sanity_check(
        self,
        components: list[dict[str, Any]],
        layout: dict[str, Any],
    ) -> None:
        """P2-2：扫描生命周期布局后节点 y 坐标，统计有多少节点中心**不**在任一 swimlane 矩形内。

        仅做 warn 日志（不中断流程），让上游 dfd_reviewer 二次纠偏可观测。
        异常标准：节点中心 y 偏离最近的 swimlane 区间 > lane_h / 2。
        """
        lanes = layout.get("_lanes") or []
        if not lanes:
            return  # Kahn 主布局无 swimlane，跳过
        lane_ranges = [
            (float(ln["y"]), float(ln["y"]) + float(ln["height"]))
            for ln in lanes
        ]
        lane_h = lanes[0]["height"] if lanes else 0
        threshold = max(lane_h / 2.0, 50.0)  # 至少 50px 容忍
        outliers: list[tuple[str, float, str]] = []
        for c in components:
            cid = c["id"]
            pos = layout.get(cid)
            if not isinstance(pos, dict) or "x" not in pos:
                continue
            cy = float(pos.get("y", 0)) + self.NODE_HEIGHT / 2
            # 找最近 lane
            best_dist = min((min(abs(cy - lo), abs(cy - hi)) for lo, hi in lane_ranges), default=0)
            if best_dist > threshold:
                outliers.append((cid, cy, c.get("name", "")))
        if outliers:
            preview = ", ".join(f"{n}({cid} y={y:.0f})" for cid, y, n in outliers[:5])
            logger.warning(
                "DFD 布局有 %d 个节点 y 偏离最近 swimlane > %dpx（threshold=lane_h/2）：%s%s",
                len(outliers), int(threshold),
                preview,
                "..." if len(outliers) > 5 else "",
            )

    # ------------------------------------------------------------------
    # 组件 cell 生成
    # ------------------------------------------------------------------
    def _make_component_cell(
        self,
        comp: dict[str, Any],
        pos: dict[str, float],
        idx: int,
    ) -> dict[str, Any]:
        """生成一个组件 cell（节点）。"""
        ctype = comp["type"]
        props = comp.get("properties", {})
        is_boundary = ctype in ("trustboundary",) or props.get(
            "isTrustBoundary", False
        )
        shape = "tm.BoundaryBox" if is_boundary else SHAPE_MAP.get(
            ctype, "tm.Process"
        )
        # STRIDE-AI：AI 元素渲染形状 (X6 cell type) 用 tm.Process/tm.Store，
        # data.type 同步使用 TD-可识别的形状（让官方 TD 的
        # getThreatTypesByElement 能正确推断威胁类型），AI 子类型放在
        # data.aiElementType，平台前端按此字段做 AI 视觉样式（图标/边框）。
        cell_data_type = shape
        ai_element_type = AI_ELEMENT_TYPE_TAG.get(ctype)
        data = {
            "name": comp.get("name", ""),
            "description": comp.get("description", ""),
            "type": cell_data_type,
            "hasOpenThreats": False,
            "outOfScope": False,
            "isTrustBoundary": is_boundary,
        }
        if ai_element_type:
            data["aiElementType"] = ai_element_type
        # 加入组件属性（Threat Dragon 兼容）
        data.update(self._normalize_properties(props))
        width, height = self.NODE_WIDTH, self.NODE_HEIGHT
        if is_boundary:
            # 自适应尺寸：根据内含组件 bbox
            csize = pos.get("containerSize") if pos else None
            if csize:
                width, height = csize["width"], csize["height"]
                # trustboundary 中心对齐"内含组件 bbox 中心"
                cx, cy = pos.get("containerCenter", (pos["x"] + self.NODE_WIDTH / 2,
                                                     pos["y"] + self.NODE_HEIGHT / 2))
                # 把 x/y 反算为左上角
                pos = dict(pos)
                pos["x"] = cx - width / 2
                pos["y"] = cy - height / 2
            else:
                width, height = self.NODE_WIDTH + 40, self.NODE_HEIGHT + 40
        cell = {
            "id": str(uuid.uuid4()),
            "shape": shape,
            "zIndex": idx,
            "position": {"x": pos["x"], "y": pos["y"]},
            "size": {"width": width, "height": height},
            "visible": True,
            "data": data,
            "threats": [],
            "attrs": {
                "body": {
                    "stroke": "#000000",
                    "strokeWidth": 2,
                    "strokeDasharray": "10 5" if is_boundary else None,
                }
            },
        }
        return cell

    def _make_flow_cell(
        self,
        flow: dict[str, Any],
        source_cell_id: str,
        target_cell_id: str,
        layout: dict[str, dict],
        boundary_membership: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """生成一个数据流 cell（边）。"""
        props = flow.get("properties", {})
        # 跨信任边界判断：两端属于不同 trustboundary（None 表示在所有 boundary
        # 之外）。两端都在边界外 → 不跨；同一 boundary → 不跨；一边内一边外
        # 或分别在不同 boundary → 跨。前端拿到这个标记后会把边画成中虚线
        # '7 5'，与加密(实线绿)/公网(实线橙)共同构成三种语义区分。
        src_comp_id = flow.get("sourceId")
        tgt_comp_id = flow.get("targetId")
        bm = boundary_membership or {}
        src_b = bm.get(src_comp_id) if src_comp_id else None
        tgt_b = bm.get(tgt_comp_id) if tgt_comp_id else None
        crosses_trust_boundary = src_b != tgt_b
        data = {
            "name": flow.get("name", ""),
            "description": flow.get("description", ""),
            "type": "tm.Flow",
            "hasOpenThreats": False,
            "outOfScope": False,
            "isBidirectional": False,
            "protocol": props.get("protocol", ""),
            "isEncrypted": bool(props.get("isEncrypted", False)),
            "isPublicNetwork": bool(props.get("isPublicNetwork", False)),
            "crossesTrustBoundary": bool(crosses_trust_boundary),
        }
        cell = {
            "id": str(uuid.uuid4()),
            "shape": "tm.Flow",
            "zIndex": 1000,
            "source": {"cell": source_cell_id},
            "target": {"cell": target_cell_id},
            "visible": True,
            "data": data,
            "threats": [],
            "attrs": {
                "line": {
                    "stroke": "#000000",
                    "strokeWidth": 1,
                    "targetMarker": {"name": "block"},
                }
            },
        }
        # 数据流交叉感：为跨层 / 横向长边生成斜向折点（vertices）
        #  X6 默认正交路由会把这些顶点当作必经折点，形成斜线 + 折角 + 横向穿越。
        vertices = self._make_flow_vertices(flow, layout, self._arch_heights)
        if vertices:
            cell["vertices"] = vertices
        return cell

    def _make_flow_vertices(
        self,
        flow: dict[str, Any],
        layout: dict[str, dict],
        arch_heights: dict[str, float] | None = None,
    ) -> list[dict[str, float]]:
        """为数据流生成斜向 / 折角路由点，制造"交叉穿越"视觉效果。

        规则：
        - 源/目标同一层（横向流）：中点向上/下垂直拱起，让横向流彼此交错穿越；
        - 源/目标不同层：在中点处把路径拉向一侧（斜向），使跨层流呈现斜线折角，
          并尽量避让中间层节点。
        所有偏移基于 stable_id 哈希，确定性可复现。
        """
        import hashlib as _hashlib

        src, tgt = flow.get("sourceId"), flow.get("targetId")
        if not src or not tgt:
            return []
        ps, pt = layout.get(src), layout.get(tgt)
        if not ps or not pt:
            return []
        # 节点中心
        sx = ps["x"] + self.NODE_WIDTH / 2
        sy = ps["y"] + self.NODE_HEIGHT / 2
        tx = pt["x"] + self.NODE_WIDTH / 2
        ty = pt["y"] + self.NODE_HEIGHT / 2

        h = int(_hashlib.sha1(("flow:" + str(flow.get("id", ""))).encode("utf-8")).hexdigest()[:4], 16)
        sign = 1.0 if (h % 2) == 0 else -1.0
        # 归一化随机 0.15~0.85，用于控制拱起/斜拉方向与幅度
        r = 0.25 + (h % 1000) / 1000.0 * 0.5

        midx = (sx + tx) / 2
        midy = (sy + ty) / 2

        src_layer = ps.get("layer", 0)
        tgt_layer = pt.get("layer", 0)

        # 水平距离 / 垂直距离
        dx = tx - sx
        dy = ty - sy

        if src_layer == tgt_layer:
            # 同泳道横向流：『单向扁平拱』+ 反向流分到上下两侧天然不交叉。
            # 拱高按同泳道堆叠预分配（arch_heights[flow_id]），同向多流错位
            # 堆叠避免相互重叠；未分配时回落默认拱高。
            side = -1.0 if dx > 0 else 1.0  # 左→右上方拱，右→左下方拱
            base_arch = self.NODE_HEIGHT * 0.7 + self.V_GAP * 0.6
            stacked = (arch_heights or {}).get(flow.get("id"))
            if stacked is None:
                arch = base_arch
            else:
                arch = base_arch + abs(stacked)
            arch_y = sy + side * arch
            return [
                {"x": sx + dx * 0.30, "y": arch_y},
                {"x": sx + dx * 0.70, "y": arch_y},
            ]

        # 跨泳道纵向流：源在源泳道内的横向序号决定偏移方向，避免多源-多
        # 目的发散/汇聚时所有线汇聚到同一中点区域。
        src_lane_nodes = sorted(
            [cid for cid, pos in layout.items()
             if isinstance(pos, dict) and pos.get("layer") == src_layer and "x" in pos],
            key=lambda cid: layout[cid]["x"],
        )
        try:
            src_idx = src_lane_nodes.index(src)
        except ValueError:
            src_idx = 0
        sign = 1.0 if src_idx % 2 == 0 else -1.0
        pull = sign * min(self.NODE_WIDTH * 0.45, max(self.V_GAP * 0.8, abs(dy) * 0.16))
        return [
            {"x": midx + pull, "y": midy - abs(dy) * 0.18},
            {"x": midx + pull * 0.6, "y": midy + abs(dy) * 0.05},
        ]

    def _normalize_properties(self, props: dict[str, Any]) -> dict[str, Any]:
        """规范化组件属性到 Threat Dragon 兼容字段。"""
        normalized = {}
        bool_keys = [
            "handlesCardPayment",
            "handlesGoodsOrServices",
            "isALog",
            "isBidirectional",
            "isEncrypted",
            "isPublicNetwork",
            "isSigned",
            "isTrustBoundary",
            "isWebApplication",
            "providesAuthentication",
            "storesCredentials",
            "storesInventory",
            # STRIDE-AI 新增 AI 属性
            "isLLMService",
            "hasRAG",
            "hasTools",
            "isVectorStore",
            "isSystemPrompt",
            "storesTrainingData",
            "handlesHealthData",
        ]
        for key in bool_keys:
            if key in props:
                normalized[key] = bool(props[key])
        # 字符串属性
        for key in ("privilegeLevel", "protocol"):
            if props.get(key):
                normalized[key] = str(props[key])
        return normalized

    def _make_threat(
        self, t: dict[str, Any], component_type: str, methodology: str = "STRIDE"
    ) -> dict[str, Any]:
        """生成一条 Threat Dragon 兼容的威胁记录。

        modelType 反映威胁建模方法论（STRIDE/CIA/CIADIE/LINDDUN/PLOT4ai/EOP），
        与官方 schema 的 modelType 字段对齐。cwe / references / outOfScope 为
        AI 附加元数据（官方 v2 schema 会忽略未知字段，不影响官方 Threat Dragon
        打开与编辑，同时前端可展示）。
        """
        number = self._counter
        self._counter += 1
        # threat.modelType 是官方 TD 用 getThreatTypesByElement / 翻译映射的
        # 关键字段。STRIDE-AI 是平台扩展方法论，官方 TD 不识别，会让新
        # 建威胁的下拉退化为『全部方法论混合』。这里把 STRIDE-AI 映射
        # 为最接近的官方方法论 STRIDE（AI 特有的威胁类型仍可通过
        # threat.type 字段正确显示），并用 aiExtension 字段让平台前端
        # 识别并显示 STRIDE-AI 标签。
        model_type = methodology if methodology in (
            "STRIDE", "CIA", "CIADIE", "LINDDUN", "PLOT4ai", "EOP"
        ) else "STRIDE"
        if methodology == "STRIDE-AI":
            model_type = "STRIDE"
        threat = {
            "title": t.get("title", "未命名威胁"),
            "type": t.get("type", "Information Disclosure"),
            "status": t.get("status", "Open"),
            "severity": t.get("severity", "Medium"),
            "score": t.get("score", ""),
            "description": t.get("description", ""),
            "mitigation": t.get("mitigation", ""),
            "modelType": model_type,
            "number": number,
            "threatId": str(uuid.uuid4()),
        }
        if methodology == "STRIDE-AI":
            threat["aiExtension"] = True  # 平台前端用它显示 STRIDE-AI 标签
        # 附加元数据：仅当存在时写入，保持 schema 干净
        if t.get("cwe"):
            threat["cwe"] = t["cwe"]
        if t.get("references"):
            threat["references"] = t["references"]
        # DREAD 评级（STRIDE-AI）：保留五维评分与总分
        if isinstance(t.get("dread"), dict):
            threat["dread"] = t["dread"]
            threat["dreadScore"] = t.get("dreadScore", sum(t["dread"].values()))
        # outOfScope（范围管理）默认 False
        threat["outOfScope"] = bool(t.get("outOfScope", False))
        return threat

    def to_json(self, model: dict[str, Any]) -> str:
        """将模型序列化为 JSON 字符串。"""
        return json.dumps(model, ensure_ascii=False, indent=2)
