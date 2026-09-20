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

from .flow_convergence import converge_flows
from .methodology import normalize_methodology

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


def recompute_layout_hints(diagram: dict) -> None:
    """重算 diagram.layoutHints 里的 route 与 labelX/labelY（**原地更新**）。

    这是 layoutHints 几何的**唯一重算入口**：建模（ThreatModelBuilder.build）
    与用户编辑后（result_store.update_layout / rename_element）都必须走
    这里。为什么必须存在：布局提示是按「节点坐标」计算的派生数据——
    坐标一动，route 与标签落点即全部失效。历史上 update_layout 只写
    坐标不重算 route，刷新页面后节点在新位置、折线还是老坐标的，
    X6 在「新锚点 → 老折线」之间画出斜线段，整图连线乱成一团。

    实现说明：
    - route：dfd_layout_metrics.plan_edge_routes（与导出/度量同源）；
    - 标签落点：dfd_spec.place_edge_labels（与导出 PNG 同源），
      labelT/labelOffset 沿用 hints 里的既有值（它们由布局期
      _label_hints 生成，只与节点对关系有关，坐标变化不影响）；
    - crossOffset/labelT/labelOffset 等布局期提示原样保留，只覆盖
      route/labelX/labelY 三个几何字段。
    """
    cells = diagram.get("cells") or []
    if not cells:
        return
    from . import dfd_layout_metrics as _lm
    from . import dfd_spec as _spec

    flow_cell_ids = {
        c["id"]: str((c.get("data") or {}).get("flowId"))
        for c in cells
        if c.get("source") and c.get("target") and (c.get("data") or {}).get("flowId")
    }
    if not flow_cell_ids:
        return

    hints = diagram.get("layoutHints")
    if not isinstance(hints, dict):
        hints = {}
        diagram["layoutHints"] = hints

    # 1) 重算全部边的正交路由
    routes_by_cell = _lm.plan_edge_routes({"cells": cells})

    # 2) 重算边标签最终落点（避让障碍 = 所有可见节点矩形，含边界容器）
    node_boxes: list[tuple[float, float, float, float]] = []
    for c in cells:
        if c.get("source") and c.get("target"):
            continue
        if c.get("visible") is False:
            continue
        p = c.get("position") or {}
        s = c.get("size") or {}
        x, y = float(p.get("x", 0.0)), float(p.get("y", 0.0))
        node_boxes.append((
            x, y,
            x + float(s.get("width", 180.0)),
            y + float(s.get("height", 60.0)),
        ))

    cell_by_id = {c.get("id"): c for c in cells}
    items: list[dict[str, Any]] = []
    for cell_id, pts in routes_by_cell.items():
        fid = flow_cell_ids.get(cell_id)
        if not fid or len(pts) < 2:
            continue
        cell = cell_by_id.get(cell_id)
        if cell is None:
            continue
        name = str(((cell.get("data") or {}).get("name")) or "").strip()
        if not name:
            continue
        old = hints.get(str(fid)) or {}
        t = float(old.get("labelT", 0.5))
        off = float(old.get("labelOffset", 0.0))
        ax, ay = _spec.point_on_polyline(pts, t, off)
        items.append({
            "key": str(fid), "text": name,
            "x": ax, "y": ay - _spec.LABEL_FONT_SIZE / 2.0,
        })
    # 彩色/语义边先占位（与两端「先灰后彩」绘制顺序一致）
    order = {str((c.get("data") or {}).get("flowId")): i for i, c in enumerate(cells)}
    items.sort(key=lambda it: order.get(it["key"], 0))
    try:
        label_xy = _spec.place_edge_labels(items, node_boxes)
    except Exception:
        label_xy = {}

    # 3) 写回：plan_edge_routes 的键是 cell id，hints 的键是 flowId
    for cell_id, pts in routes_by_cell.items():
        fid = flow_cell_ids.get(cell_id)
        if not fid or len(pts) < 2:
            continue
        h = hints.setdefault(str(fid), {})
        h["route"] = [[int(round(p[0])), int(round(p[1]))] for p in pts]
    for fid, xy in label_xy.items():
        h = hints.setdefault(str(fid), {})
        h["labelX"] = round(float(xy[0]), 1)
        h["labelY"] = round(float(xy[1]), 1)


class ThreatModelBuilder:
    """将分析结果整合为 Threat Dragon v2 兼容的威胁模型 JSON。"""

    # 布局常量
    NODE_WIDTH = 180        # 基准宽度（同时也是最小宽度）
    NODE_HEIGHT = 60
    H_GAP = 60              # 节点水平间距（基准，实际按宽度动态放大）
    V_GAP = 40
    MARGIN = 40

    # ---- 画布横向铺开（对齐 dfd_layout_metrics 的"商业级长宽比"口径） ----
    # 泳道布局天然是纵向堆叠，画布容易"瘦高"（实测 6 泳道 ≈ 1130×1420）。
    # 前端按**内容**等比适配后（缩放比由高度决定），左右两侧会各剩一大块
    # 空白，观感是"组件全挤在画布中间一条窄带里"。
    # 因此在内容允许的范围内把画布横向撑到目标长宽比，并让每行节点
    # **等距铺开**（不再是死居中 + 固定 60px 间距），把组件、实体、连线
    # 分布到整块画布上。
    CANVAS_ASPECT_TARGET = 1.45   # 目标宽高比（横版，落在 4:3 ~ 16:9 之间）
    H_GAP_SPREAD_MAX = 4.5        # 同行节点最大间距 = H_GAP × 该系数

    # ---- D1: 动态节点宽度参数 ----
    # 节点标签由前端按 12px 字号渲染在节点内，宽度不足时文字会溢出/被裁切；
    # 而布局若统一按 NODE_WIDTH=180 排布，长名称节点（AI 组件名常达 20+ 字）
    # 实际渲染宽度会超出预留槽位 → 相邻节点在画布上互相重叠。
    # 这里按字符类别估算渲染宽度，让布局预留与真实渲染一致。
    NODE_WIDTH_MIN = 150
    NODE_WIDTH_MAX = 280
    # CJK/全角字符按 1.0em、ASCII 按 0.55em 估算；再留左右内边距与
    # 右侧威胁徽标（最多 2 字符 + 圆形底）所需空间。
    _CHAR_W_CJK = 12.0      # 12px 字号下 CJK 字符近似宽度
    _CHAR_W_ASCII = 6.6     # 12px 字号下 ASCII 字符近似宽度
    _NODE_PAD_X = 34.0      # 左右内边距合计（前端标签有 padding）
    _BADGE_RESERVE = 22.0   # 威胁数徽标预留宽度（右上角）

    def __init__(self) -> None:
        self._counter = 1  # 威胁编号计数器
        # D1: cell_id -> 布局宽度。由 _layout* 在分桶后统一计算，供后续
        # bbox/画布宽度/间距计算复用，避免各处重复估算导致不一致。
        self._node_w: dict[str, float] = {}
        # D1: 当前布局的泳道间距（跨泳道流错位需要读它来定位"缝隙"）
        self._lane_gap: float = 0.0
        # D2: cell_id(流) -> {"crossOffset": float, ...}，跨泳道流的过道错位提示
        self._cross_hints: dict[str, dict[str, float]] = {}
        # D2: 布局坐标快照（_group_cross_flows 需要读源/目标节点中心 x）
        self._layout_positions: dict[str, dict[str, Any]] = {}
        # D5: cell_id(流) -> {"labelT": float, "labelOffset": float}，边标签锚点提示
        self._label_hints: dict[str, dict[str, float]] = {}

    def _group_cross_flows(
        self, flows: list[dict[str, Any]], lane_of: dict[str, int]
    ) -> dict[tuple[int, int], list[tuple[str, float, float]]]:
        """D2: 把跨泳道流按 (源泳道序号, 目标泳道序号) 分组。

        Returns:
            {(src_lane, tgt_lane): [(flow_id, 源节点中心x, 目标节点中心x), ...]}
            仅包含「两端都已分泳道且泳道不同」的流。
        """
        groups: dict[tuple[int, int], list[tuple[str, float, float]]] = {}
        for f in flows:
            fid = f.get("id") or ""
            sid, tid = f.get("sourceId") or "", f.get("targetId") or ""
            if not fid or not sid or not tid or sid == tid:
                continue
            s_lane, t_lane = lane_of.get(sid), lane_of.get(tid)
            if s_lane is None or t_lane is None or s_lane == t_lane:
                continue
            ps, pt = self._layout_positions.get(sid), self._layout_positions.get(tid)
            if not ps or not pt:
                continue
            sx = ps["x"] + self._w_of(sid) / 2
            tx = pt["x"] + self._w_of(tid) / 2
            groups.setdefault((s_lane, t_lane), []).append((fid, sx, tx))
        return groups

    def _estimate_text_width(self, text: str) -> float:
        """估算一段文字在 12px 字号下的渲染宽度（px）。

        仅做布局预算使用，不追求与浏览器逐像素一致：宁可略宽（留白）
        也不能偏窄（偏窄 = 相邻节点重叠，正是要修的问题）。
        """
        if not text:
            return 0.0
        w = 0.0
        for ch in text:
            # CJK / 全角标点走宽字符宽度，其余按 ASCII 估算
            w += self._CHAR_W_CJK if ord(ch) > 0x2E80 else self._CHAR_W_ASCII
        return w

    def _compute_node_widths(self, components: list[dict[str, Any]]) -> None:
        """D1: 为每个组件预计算布局宽度，写入 self._node_w。

        规则：
        - 普通组件：按名称估算宽度 + 内边距 + 徽标预留，clamp 到 [MIN, MAX]；
          名称较长的再按高度限制折行（前端 label 会自动折行，最多约 2 行），
          因此宽度上限不必无限放大。
        - 信任边界（容器）：宽度由内含组件 bbox 决定，不在此计算，保持 NODE_WIDTH。

        必须在调用 _layout() 之前执行，且每次布局都要重算（组件名可能被
        AI 纠偏/用户重命名）。
        """
        self._node_w = {}
        for c in components:
            cid = c.get("id")
            if not cid:
                continue
            if c.get("type") == "trustboundary":
                self._node_w[cid] = float(self.NODE_WIDTH)
                continue
            name = str(c.get("name") or "")
            # AI 子类型标签（前端渲染为 "[AgentConfig]" 形式）也会占宽
            ai_tag = AI_ELEMENT_TYPE_TAG.get(c.get("type") or "")
            if ai_tag:
                name += f" [{ai_tag.replace('tm.', '')}]"
            text_w = self._estimate_text_width(name)
            w = text_w + self._NODE_PAD_X
            if text_w > 0:
                w += self._BADGE_RESERVE
            w = max(self.NODE_WIDTH_MIN, min(self.NODE_WIDTH_MAX, w))
            # 对齐到 10px 网格，坐标更整齐、fitView 后观感更稳
            self._node_w[cid] = float(int(w / 10) * 10)

    def _w_of(self, cid: str) -> float:
        """取组件的布局宽度（未预计算时回退基准宽度）。"""
        return self._node_w.get(cid, float(self.NODE_WIDTH))

    def _row_width(self, ids: list[str], gap: float | None = None) -> float:
        """一行节点的总宽度（含节点间 gap）。"""
        if not ids:
            return 0.0
        g = self.H_GAP if gap is None else gap
        return sum(self._w_of(cid) for cid in ids) + g * (len(ids) - 1)

    def _row_positions(self, ids: list[str], start_x: float, gap: float | None = None) -> list[float]:
        """一行节点的逐节点 x 坐标（按各自宽度累加）。"""
        g = self.H_GAP if gap is None else gap
        xs: list[float] = []
        cur = start_x
        for cid in ids:
            xs.append(cur)
            cur += self._w_of(cid) + g
        return xs

    def _spread_row_positions(self, ids: list[str], canvas_width: float) -> list[float]:
        """一行节点在泳道内**等距铺开**后的 x 坐标。

        与 _row_positions（固定 H_GAP + 整体居中）的区别：把「泳道可用宽度 −
        节点总宽」按 n-1 等分当成间距，让同一行的组件分布到整条泳道上，而不是
        挤在画布中间一小段里。

        两个约束：
          · 间距不小于 H_GAP（保证不重叠、不挤在一起）；
          · 间距不超过 H_GAP × H_GAP_SPREAD_MAX —— 节点稀疏到看不出相互关系
            反而更难读，宁可让这一行短一点、由泳道底色把它托住；
          · 单节点行保持居中（只有一个元素时"铺开"没有语义）。
        """
        if not ids:
            return []
        n = len(ids)
        span = max(0.0, canvas_width - self.MARGIN * 2)
        total = sum(self._w_of(cid) for cid in ids)
        if n == 1:
            return [self.MARGIN + max(0.0, (span - total) / 2.0)]
        gap = min(
            self.H_GAP * self.H_GAP_SPREAD_MAX,
            max(self.H_GAP, (span - total) / (n - 1)),
        )
        row_w = total + gap * (n - 1)
        start = self.MARGIN + max(0.0, (span - row_w) / 2.0)
        return self._row_positions(ids, start, gap)


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

        # 数据流收敛：同向 + 同安全语义的流合并为一条（避免连线与标签重叠）。
        # 返回的 id 映射用于把被合并流上的威胁**改挂**到代表流（威胁一条不丢）。
        flows, flow_id_remap = self._dedupe_flows(flows)
        if flow_id_remap:
            moved = 0
            for t in threats:
                new_id = flow_id_remap.get(str(t.get("componentId") or ""))
                if new_id:
                    t["componentId"] = new_id
                    moved += 1
            logger.info(
                "威胁迁移：%d 条威胁从被合并的数据流改挂到代表流（总数不变=%d）",
                moved, len(threats),
            )

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

        # 3.2 数据流「重要性」标记：后端下发、前端只读，三处口径统一
        #   primary  = 跨信任边界 | 加密 | 公网 | 挂 high|critical 威胁
        #   secondary= 无安全语义的纯编排流（收敛后应很少）
        # 与 dfd_layout_metrics._flow_is_primary 同口径；前端"主图/全部"优先读它，
        # 不再各自推导（老逻辑见 DfdGraph.flowIsImportant，仅作老模型兜底）。
        primary_n = 0
        flow_cells = [c for c in cells if c.get("shape") == "tm.Flow"]
        for cell in flow_cells:
            data = cell.setdefault("data", {})
            high = any(
                str((t or {}).get("severity") or "").lower() in ("high", "critical")
                for t in (cell.get("threats") or [])
            )
            is_primary = bool(
                data.get("crossesTrustBoundary")
                or data.get("isEncrypted")
                or data.get("isPublicNetwork")
                or high
            )
            data["importance"] = "primary" if is_primary else "secondary"
            if is_primary:
                primary_n += 1
        logger.info(
            "数据流分层：重要流 %d 条 / 次要流 %d 条（共 %d）",
            primary_n, len(flow_cells) - primary_n, len(flow_cells),
        )

        # 3.5/3.6 layoutHints 几何（route + 标签落点）统一由模块级
        # recompute_layout_hints 在 diagram 组装后重算——用户编辑
        # （update_layout / rename_element）也走同一入口，保证
        # 「坐标一动、线与标签同步重算」，不再出现老 route 画在新坐标上的
        # 斜线乱图（历史事故见 recompute_layout_hints 文档串）。

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
                        # D2/D5：布局期算出的「跨泳道过道错位」与「边标签锚点」提示。
                        # route/labelX/labelY 随后由 recompute_layout_hints 统一补齐；
                        # 键为 flow 的原始业务 id（与 cell.data.flowId 对应），
                        # 而非随机生成的 cell.id，避免前端需要额外反查映射。
                        **({"layoutHints": self._layout_hints_payload(flows)}),
                    }
                ],
            },
        }
        # 统一几何重算入口：补 route 与 labelX/labelY（唯一真源）
        recompute_layout_hints(model["detail"]["diagrams"][0])
        # P3：泳道内顺序微调（以**真实布线交叉数**为目标，严格变好才接受）；
        # 有接受才需要再重算一次几何（route/label 跟着新坐标走）。
        _polish = self._polish_lane_order(model["detail"]["diagrams"][0])
        if _polish["accepted"]:
            recompute_layout_hints(model["detail"]["diagrams"][0])
            logger.info(
                "泳道内顺序微调：接受 %d/%d 次相邻交换，交叉 %d → %d 处",
                _polish["accepted"], _polish["evals"],
                _polish["before"], _polish["after"],
            )
        return model

    # ------------------------------------------------------------------
    # P3：泳道内顺序微调（以真实布线交叉数为目标）
    # ------------------------------------------------------------------
    # 为什么这条路值得走：此前两次"看图直觉"的优化都被实测否掉 —— 布线代价函数
    # 加交叉项（真实 62→65 处）、邻居重心法重排（62→70 处），见 dfd_layout_metrics
    # 里的实测记录。它们的共同问题是拿**代理指标**当目标（直线交叉 / 位置估计）。
    # 这里改成：相邻两个节点交换位置 → 真的重新布线 → 数真实交叉处数，
    # **只有严格变少才接受** ⇒ 数学上不可能让结果变差（与交叉局部重路由同一套准则）。
    # 实测潜力（4 份真实结果，单步最好的一对交换）：51→22、135→115、62→34、62→34。
    #
    # 约束：允许跨边界交换（实测"只允许同边界内交换"会把最大收益挡掉：某张图
    # 一步就能 62→34，限制后只降到 59）。做法是交换后把"移动后仍应包住该节点"的
    # 边界矩形**只增不减**地撑开 —— 边界成员集合不变、成员不会越框，而边界框
    # 在渲染端本来就会按成员重算（画布/导出都按内容收缩），所以撑大无副作用。
    # 每次评估同时检查：交叉严格变少、且成员越框/节点重叠/边界重叠都不新增。
    # 预算：只处理 ≤ _POLISH_MAX_EDGES 条边的图，最多 _POLISH_MAX_EVALS 次评估。
    #
    # 为什么**不用**墙上时间做预算：一开始加了"最多 4 秒"，结果同一份输入在快慢
    # 不同的机器上停在不同的评估点 → 布局不可复现（回归测试 test_lane_order_polish
    # _never_worse 直接报"微调结果不可复现"）。计数预算才是确定的：同输入必得同结果。
    # 24 次评估 ≈ 最坏 5 秒（真实 13~16 组件图的每次评估约 0.2s），建模要跑几分钟，
    # 这点开销可以忽略。
    _POLISH_MAX_EVALS = 24
    _POLISH_MAX_EDGES = 40

    def _polish_lane_order(self, diagram: dict[str, Any]) -> dict[str, int]:
        """泳道内相邻节点交换的局部爬山（目标是真实布线交叉数）。

        Returns:
            {"evals": 评估次数, "accepted": 接受次数, "before": 原交叉, "after": 新交叉}
        """
        from . import dfd_layout_metrics as _lm

        empty = {"evals": 0, "accepted": 0, "before": 0, "after": 0}
        cells = diagram.get("cells") or []
        lanes = diagram.get("lanes") or []
        if not cells or not lanes:
            return empty
        if len(_lm.edge_cells(diagram)) > self._POLISH_MAX_EDGES:
            return empty  # 大图不做：每次评估都是一次全量布线

        nodes = _lm.node_cells(diagram)
        if len(nodes) < 2:
            return empty
        bounds = [c for c in cells if c.get("shape") == "tm.BoundaryBox"]

        def _rect(c: dict) -> tuple[float, float, float, float]:
            return _lm.rect_of(c)

        # 泳道分组：节点按 x 升序，组成"可交换的相邻对"
        groups: list[list[dict]] = []
        for lane in lanes:
            ly0 = float(lane.get("y", 0.0))
            ly1 = ly0 + float(lane.get("height", 0.0))
            inside = []
            for c in nodes:
                r = _rect(c)
                cy = (r[1] + r[3]) / 2.0
                if ly0 <= cy <= ly1:
                    inside.append(c)
            if len(inside) >= 2:
                inside.sort(key=lambda c: (float((c.get("position") or {}).get("x", 0.0)),
                                           str(c.get("id") or "")))
                groups.append(inside)
        if not groups:
            return empty

        def _grow_boundaries_for(cell: dict) -> list[tuple[dict, dict, dict]]:
            """把"包着该节点"的边界矩形撑到能容纳它（只增不减）。

            返回被改过的 [(边界 cell, 原 position, 原 size)]，不接受时整体还原。
            """
            r = _rect(cell)
            cx, cy = (r[0] + r[2]) / 2.0, (r[1] + r[3]) / 2.0
            touched: list[tuple[dict, dict, dict]] = []
            for b in bounds:
                br = _rect(b)
                if not (br[0] <= cx <= br[2] and br[1] <= cy <= br[3]):
                    continue  # 该节点不在这个边界里（成员集合不变，不扩无关边界）
                new = (min(br[0], r[0]), min(br[1], r[1]), max(br[2], r[2]), max(br[3], r[3]))
                if new == br:
                    continue
                old_pos = dict(b.get("position") or {})
                old_size = dict(b.get("size") or {})
                touched.append((b, old_pos, old_size))
                b["position"] = {**old_pos, "x": new[0], "y": new[1]}
                b["size"] = {**old_size, "width": new[2] - new[0], "height": new[3] - new[1]}
            return touched

        def _violations() -> tuple[int, int, int]:
            return (len(_lm.metric_member_outside(diagram)),
                    len(_lm.metric_node_overlap(diagram)),
                    len(_lm.metric_boundary_overlap(diagram)))

        before = _lm.metric_edge_crossing(diagram)
        # 基线缺陷数（历史模型可能本来就有成员越框）：只要求交换**不新增**缺陷，
        # 而不是要求归零 —— 否则存量模型一个交换都做不了
        base_viol = _violations()
        if base_viol != (0, 0, 0):
            logger.info("泳道顺序微调：基线已有缺陷 %s，仅承诺不新增", base_viol)
        best = before
        evals = accepted = 0
        improved = True
        while improved:
            improved = False
            for group in groups:
                for a, b in zip(group, group[1:]):
                    if evals >= self._POLISH_MAX_EVALS:
                        break
                    pa = dict(a.get("position") or {})
                    pb = dict(b.get("position") or {})
                    ax, bx = pa.get("x"), pb.get("x")
                    if ax is None or bx is None or abs(float(ax) - float(bx)) < 1.0:
                        continue
                    a["position"] = {**pa, "x": bx}
                    b["position"] = {**pb, "x": ax}
                    touched = _grow_boundaries_for(a) + _grow_boundaries_for(b)
                    cross = _lm.metric_edge_crossing(diagram)
                    evals += 1
                    if cross < best and _violations() <= base_viol:
                        best = cross
                        accepted += 1
                        improved = True
                    else:  # 不接受 → 节点位置与被动过的边界几何整体还原
                        a["position"] = pa
                        b["position"] = pb
                        for bcell, old_pos, old_size in touched:
                            bcell["position"] = old_pos
                            bcell["size"] = old_size
                if evals >= self._POLISH_MAX_EVALS:
                    break
            if evals >= self._POLISH_MAX_EVALS:
                break
        return {"evals": evals, "accepted": accepted, "before": before, "after": best}

    def _layout_hints_payload(
        self,
        flows: list[dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        """D2/D5: 布局期的「过道错位/标签参数」提示，键为 flow 原始业务 id。

        只生成与**节点关系**相关的提示（crossOffset/labelT/labelOffset）；
        几何字段（route/labelX/labelY）由模块级 recompute_layout_hints
        统一计算并写回——建模与用户编辑后重算走同一条路径。

        前端在 cell.data.flowId 上能拿到同一个 id，因此可直接查表：
            hints[cell.data.flowId] -> {
                route, labelX, labelY,          ← recompute_layout_hints 填
                crossOffset, labelT, labelOffset, ← 这里填
            }
        """
        payload: dict[str, dict[str, Any]] = {}
        for f in flows:
            fid = f.get("id")
            if not fid:
                continue
            hint: dict[str, Any] = {}
            cross = self._cross_hints.get(fid)
            if cross and abs(cross.get("crossOffset", 0.0)) > 0.1:
                hint["crossOffset"] = cross["crossOffset"]
            lab = self._label_hints.get(fid)
            if lab and (
                abs(lab.get("labelT", 0.5) - 0.5) > 0.01
                or abs(lab.get("labelOffset", 0.0)) > 0.01
            ):
                hint["labelT"] = lab["labelT"]
                hint["labelOffset"] = lab["labelOffset"]
            if hint:
                payload[str(fid)] = hint
        return payload

    # ------------------------------------------------------------------
    # 自动布局
    # ------------------------------------------------------------------
    # 同一层内节点横向交错间隔，让横向流有独立通道
    _INTRALAYER_VARIANCE = 60  # 同层节点 X 抖动幅度（px）
    # 跨越 ≥2 层的长边在源/目标端点上下错位，让折角斜线明显
    _LONG_EDGE_VERTICAL_JITTER = 30

    def _dedupe_flows(
        self, flows: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], dict[str, str]]:
        """收敛数据流：同向 + 同安全语义的重复流合并为一条。

        委托 ``flow_convergence.converge_flows``（键 = 源/目标/加密/公网）。
        返回 (合并后的流, {被合并 id: 代表 id})，后者用于把威胁改挂到代表流上。

        与老实现的差别：老实现只合并 (sourceId, targetId, name) 三者全同的流，
        且"带威胁的流不敢合并"（怕威胁悬空）——于是同一条通道上「上传体征数据」
        与「设备鉴权」两条平行线永远留着。现在用 id 重映射解决悬空问题，
        **合并不丢威胁**成为硬约束（build() 里执行搬迁）。
        """
        merged, remap = converge_flows(flows)
        if remap:
            logger.info(
                "数据流收敛：%d → %d 条，%d 条同向同语义流被合并（威胁改挂代表流）",
                len(flows or []), len(merged), len(remap),
            )
        return merged, remap

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
        boundary_inner: dict[str, list[str]] = {}
        for bid in boundary_ids:
            boundary_inner[bid] = self._infer_boundary_children(
                comp_by_id, comp_type, flows, bid, layer_of
            )
        # 存储兜底：无存储关键词命中的边界名会把存储留在所有边界外
        self._dispatch_orphan_stores(boundary_inner, comp_by_id)
        for bid, inner in boundary_inner.items():
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

    def _dispatch_orphan_stores(
        self,
        boundary_inner: dict[str, list[str]],
        comp_by_id: dict[str, Any],
    ) -> None:
        """把未被任何信任边界认领的存储类组件并入「成员最多的边界」（就地修改）。

        触发场景：LLM 产出的边界名是「服务侧内网边界」「客户端执行区」这类
        不含存储关键词的名字——_infer_boundary_children 按关键词互斥分组时，
        数据库/缓存/日志/消息队列等存储组件一个边界都进不去，几何上被留在
        所有边界框之外：DFD 上存储裸奔在边界外，报告「所属边界」列整列为空。

        存储几乎总是部署在内网服务侧，因此兜底目标取成员最多的边界
        （成员最多 ≈ 服务侧主边界；并列取 id 最小者，保证确定性）。
        必须在边界 bbox 计算之前调用，容器几何才会真正把存储包进去。
        """
        store_types = {"datastore", "vectorstore", "trainingdata", "store"}
        claimed = {cid for inner in boundary_inner.values() for cid in inner}
        orphans = [
            cid for cid, c in comp_by_id.items()
            if str(c.get("type", "")).lower() in store_types and cid not in claimed
        ]
        if not orphans or not boundary_inner:
            return
        target = max(sorted(boundary_inner), key=lambda b: len(boundary_inner[b]))
        boundary_inner[target] = list(boundary_inner[target]) + orphans

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

        # D1: 先按组件名预计算各自布局宽度，后续所有间距/bbox/画布宽度
        # 都通过 _w_of() 取真实宽度，避免长名称节点互相重叠。
        self._compute_node_widths(components)

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
        # D1: 每层宽度按节点真实宽度累加（该分支同样存在长名称节点重叠问题）
        per_layer_w = {
            l: self._row_width(layer_buckets[l]) for l in layer_buckets
        }
        per_layer_max = max(per_layer_w.values(), default=self.NODE_WIDTH)
        # 画布宽度：按最宽层铺开，并为信任边界容器与单节点层锯齿偏移留足横向空间
        # P1-2 同 lifecycle 布局：用 boundary 数量做横向预算（容器可达 1200px+）
        boundary_reserve_main = len(boundary_ids) * 240 + 240
        canvas_width = max(per_layer_max, self.NODE_WIDTH * 3) + self.MARGIN * 2 + boundary_reserve_main

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
            layer_total_w = self._row_width(nodes)
            start_x = (canvas_width - layer_total_w) / 2
            # 单节点层：左右锯齿偏移（防竖线）。偏移量适度，避免边过长/重叠。
            if n == 1 and n_layers >= 3:
                zig = (self._w_of(nodes[0]) * 0.85 + self.H_GAP * 0.5)
                start_x += zig if lid % 2 == 1 else -zig
            y = self.MARGIN + lid * row_h
            x_list = self._row_positions(nodes, start_x)
            for col, cid in enumerate(nodes):
                positions[cid] = {
                    "x": x_list[col],
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
            boundary_inner[cid] = [
                k for k in children_ids
                if k in positions and comp_type.get(k) != "trustboundary"
            ]
        # 存储兜底：孤儿存储并入成员最多的边界（须在 bbox 计算前，
        # 容器几何才会真正把存储包进去）
        self._dispatch_orphan_stores(boundary_inner, comp_by_id)
        for cid in boundary_ids:
            inner = boundary_inner[cid]
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
            xs = [positions[k]["x"] + self._w_of(k) / 2 for k in inner]
            ys = [positions[k]["y"] + self.NODE_HEIGHT / 2 for k in inner]
            cx, cy = sum(xs) / len(xs), sum(ys) / len(ys)
            minx = min(xs) - self.H_GAP * 1.4
            maxx = max(xs) + self.H_GAP * 1.4 + self._w_of(inner[-1]) / 2
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
                # 注意：泳道布局（_layout_lifecycle_lanes）里的同款避让有
                # 「children 不得推出所属 swimlane」的 clamp；但**本函数是普通
                # Kahn 分层布局，作用域内没有 lane_top/lane_h**，不能照抄那套
                # clamp（会 NameError）。非泳道布局本无泳道边界，全量下移即可。
                bounded_delta = delta
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

        # D1 兜底：正常路径由 _layout() 统一预计算宽度；但本方法可被单独调用
        # （测试/复用/未来重排接口），若此时 _node_w 为空，宽度会静默退化成
        # 固定 180，长名称节点又会重叠。这里做一次空值兜底，保证不依赖调用方。
        if not self._node_w:
            self._compute_node_widths(components)

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

        # --- B0. 泳道内顺序：参与流数降序 + 名字 + 稳定哈希（确定性） ---
        # 顺序必须在**任何宽度/几何计算之前**定下来：x 由行内顺序决定，
        # 进而决定 bbox、画布宽度与所有路由。
        #
        # 【实测记录 · 为什么不用"邻居重心法"重排】
        # 曾试过按"邻居在对面泳道的平均位置"重排（Sugiyama 重心法，上下交替
        # 扫掠 4 轮），它是分层图绘制的标准做法，但这张图不适用：
        #   · 直线交叉 44 → 33（代理指标变好）
        #   · 真实路由交叉 62 → 70（**反而更差**）
        # 原因是泳道在这里是"数据生命周期语义分组"，不是拓扑层：边会跨任意
        # 远近、双向连接，稀疏图上重心法的位置估计不可靠；而且正交路由的
        # 通道选择才是交叉的主导因素，直线代理量根本测不准。
        # 交叉的真正改善改在路由层做（plan_edge_routes 的单调局部重路由，
        # 实测 62 → 47），排布层保持原样。
        for k in visible:
            buckets[k].sort(
                key=lambda cid: (
                    -degree.get(cid, 0),
                    str(comp_by_id.get(cid, {}).get("name") or ""),
                    _stable_rank(cid),
                )
            )

        # D1：每行宽度按节点真实宽度累加（长名称节点更宽，不再用统一 col_width）
        per_lane_w = {
            k: self._row_width(buckets[k]) for k in visible
        }
        per_lane_max = max(per_lane_w.values(), default=self.NODE_WIDTH)
        # 画布宽度 = 最宽泳道的节点内容宽 + 两侧 margin + 少量余量。
        #
        # 历史实现是 `+ boundary_reserve`（boundary 数量 * 240 + 240），按边界
        # **数量**线性预留，与边界实际宽度无关。后果是泳道被撑到远超内容：
        # 实测 10 节点图泳道宽 1530px 而内容只占 810px（53%），4 节点最小
        # 反例内容仅占 15% —— 前端 fitView 按泳道（当时未正确排除）适配时
        # 整图被压成小点，观感与后端 PNG 差一大截。
        #
        # 边界容器自身宽度由 _recompute_boundary_bboxes() 按成员包围盒 + padding
        # 算出，不依赖这里的预留；若边界比泳道宽，下方 D7 溢出修正会把画布
        # 扩张到覆盖它，因此这里不必提前预留。
        #
        # SCROLL 余量 24px：单节点泳道会有锯齿偏移（_row_zig），节点 x 可能
        # 比 start_x 略偏右，留一点避免贴边。
        #
        # 注意：这里只是**下限**（不漏内容）。最终画布宽度在 canvas_h 算出后
        # 再按目标长宽比横向撑开，见下方「画布横向铺开」一段。
        content_w_min = max(
            per_lane_max + self.MARGIN * 2 + 24.0,
            self.NODE_WIDTH * 2 + self.MARGIN * 2,
        )

        # D3: 泳道间距按"跨相邻泳道的流条数"动态伸缩。
        # 原值 V_GAP*2.5=100px 要同时容纳：跨道流的水平过道段 + 边标签（10px
        # 字号，折行后最高约 26px）+ 同泳道拱顶，实测严重不足，导致标签互相
        # 叠压。这里以 100px 为下限，按道间流数每 3 条加 24px，上限 240px。
        cross_cnt: dict[tuple[int, int], int] = {}
        for f in flows:
            s_lane, t_lane = lane_of.get(f.get("sourceId") or ""), lane_of.get(f.get("targetId") or "")
            if s_lane is None or t_lane is None or s_lane == t_lane:
                continue
            lo, hi = min(s_lane, t_lane), max(s_lane, t_lane)
            if hi - lo == 1:  # 只统计相邻道间（跨多道的流走的是贯穿通道）
                cross_cnt[(lo, hi)] = cross_cnt.get((lo, hi), 0) + 1
        max_cross = max(cross_cnt.values(), default=0)
        lane_gap = min(
            self.V_GAP * 6, self.V_GAP * 2.5 + max(0, max_cross - 2) * 24
        )
        self._lane_gap = lane_gap  # D2 计算过道 x 时要用

        lane_h = self.NODE_HEIGHT + self.V_GAP * 2
        lane_top: dict[str, float] = {}
        y = self.MARGIN
        for k in visible:
            lane_top[k] = y
            y += lane_h + lane_gap
        canvas_h = y - lane_gap + self.MARGIN

        # --- 画布横向铺开：把"瘦高"的泳道带撑成横版，让组件分布到整块画布 ---
        # 泳道数量决定画布高度（lane_h + lane_gap 逐道累加），宽度若只按最宽
        # 一行内容取，画布长宽比会明显偏"瘦高"：前端适配时缩放比由高度决定，
        # 于是左右各空一大片（截图里的"泳道左右两片空白"）。
        # 做法：在**内容能承受**的范围内把画布拉宽到目标长宽比 ——
        #   · 下限 content_w_min：绝不能小于最宽一行 + margin（否则内容溢出）；
        #   · 上限 content_w_max：最宽一行按 H_GAP_SPREAD_MAX 摊开的宽度
        #     （再多就是无意义的空白，观感反而更散）。
        # 行内节点随后由 _spread_row_positions 等距铺开填满这段宽度。
        _widest_row = max((buckets[k] for k in visible), key=len, default=[])
        _widest_sum = sum(self._w_of(cid) for cid in _widest_row)
        content_w_max = (
            _widest_sum
            + max(0, len(_widest_row) - 1) * self.H_GAP * self.H_GAP_SPREAD_MAX
            + self.MARGIN * 2 + 24.0
        )
        canvas_width = max(
            content_w_min,
            min(canvas_h * self.CANVAS_ASPECT_TARGET,
                max(content_w_min, content_w_max)),
        )

        # y 错位最大幅度 = (lane_h - NODE_HEIGHT) / 2 * 0.65
        # 留 35% 缓冲，确保节点 y 始终落在所属 swimlane 矩形内，
        # 既让线明显分散、又不会被 _layout_sanity_check 报警。
        max_y_offset = (lane_h - self.NODE_HEIGHT) / 2 * 0.65

        positions: dict[str, Any] = {}
        for k in visible:
            # 行内顺序已在上方 B0 定好（初始排序 + 邻居重心重排）——
            # 这里**不能**再按流数重排，否则重心法的结果会被抹掉。
            ids = buckets[k]
            n = len(ids)
            # B. 行内等距铺开：把本行组件分布到整条泳道宽度上（不再是固定
            #    60px 间距 + 整体居中 —— 那会让组件全挤在画布中间一小段）。
            xs = self._spread_row_positions(ids, canvas_width)
            center_y = lane_top[k] + (lane_h - self.NODE_HEIGHT) / 2
            # D4: 同泳道内 Y 交错。原实现只用「入流/出流」方向决定单一偏移，
            # 相邻节点常拿到相同偏移值 → 同一水平线；且标签行高固定，视觉呆板。
            # 改为两级错落（奇偶交替上下）+ 方向修正：
            #   - 偶数索引偏上、奇数索引偏下（幅度 0.5 * max_y_offset），形成错落；
            #   - 再按入/出流方向微调（幅度 0.35 * max_y_offset），让跨道线更顺。
            # 总偏移仍受 max_y_offset 约束，节点始终留在泳道矩形内。
            for col, cid in enumerate(ids):
                x_pos = xs[col]
                if n >= 2:
                    # 两级错落：奇偶位置反向，避免并排节点共线
                    alt = -1.0 if col % 2 == 0 else 1.0
                    y_off = alt * max_y_offset * 0.5
                    in_n = in_from_above.get(cid, 0)
                    out_n = out_to_below.get(cid, 0)
                    total = in_n + out_n
                    if total > 0:
                        # -1（纯入流→偏上）~ +1（纯出流→偏下）
                        y_off += (out_n - in_n) / total * max_y_offset * 0.35
                    # clamp 到 ±max_y_offset，保证不越出泳道
                    y_off = max(-max_y_offset, min(max_y_offset, y_off))
                else:
                    y_off = 0.0
                positions[cid] = {
                    "x": x_pos,
                    "y": center_y + y_off,
                    "layer": lane_index[k],
                    "lifecycle": k,
                }

        # --- B++（D2）. 跨泳道流的「过道 x」错位预分配 ---
        # 跨泳道流（相邻两道之间）原先完全不做错位：多条流都从源节点中心
        # 竖直下行到目标节点中心，落在同一 x 区间 → 边与边标签互相叠压，
        # 是截图里"一片糊"的主因。
        # 这里按 (源泳道, 目标泳道) 分组，给每条流分配一个错开的「过道 x」
        # （即竖向下行段的水平位置），让并行跨道流在泳道缝隙里分层穿行。
        # 注意：这只是给前端的路由提示（diagram.edge_hints），不改变节点坐标，
        # 因此不会破坏任何已有语义，前端不消费时也完全无副作用。
        cross_hints: dict[str, dict[str, float]] = {}
        gap_step = 26.0  # 相邻过道间距
        self._layout_positions = positions  # 供 _group_cross_flows 读节点中心 x
        for grp_key, glist in self._group_cross_flows(flows, lane_of).items():
            # 按源节点 x 排序，保证同组内过道位置从左到右单调，避免交叉
            glist.sort(key=lambda t: (t[1], t[0]))
            mid = (len(glist) - 1) / 2.0
            for i, (fid, sx, tx) in enumerate(glist):
                # 两侧交错展开：0, +1, -1, +2, -2 …（围绕中点居中）
                offset = (i - mid) * gap_step
                cross_hints[fid] = {
                    "crossOffset": round(offset, 1),
                    "srcX": round(sx, 1),
                    "tgtX": round(tx, 1),
                }
        self._cross_hints = cross_hints

        # --- C. 信任边界容器化（泳道序号作为 layer 参与语义推断） ---
        boundary_inner: dict[str, list[str]] = {}
        for cid in boundary_ids:
            children_ids = self._infer_boundary_children(
                comp_by_id, comp_type, flows, cid, lane_of
            )
            boundary_inner[cid] = [
                k
                for k in children_ids
                if k in positions and comp_type.get(k) != "trustboundary"
            ]
        # 存储兜底：孤儿存储并入成员最多的边界（与 Kahn 布局口径一致）
        self._dispatch_orphan_stores(boundary_inner, comp_by_id)
        for cid in boundary_ids:
            inner = boundary_inner[cid]
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
            xs = [positions[k]["x"] + self._w_of(k) / 2 for k in inner]
            ys = [positions[k]["y"] + self.NODE_HEIGHT / 2 for k in inner]
            cx, cy = sum(xs) / len(xs), sum(ys) / len(ys)
            minx = min(xs) - self.H_GAP * 1.4
            maxx = max(xs) + self.H_GAP * 1.4 + self._w_of(inner[-1]) / 2
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

                # —— 容器下沿不得越过最后一条泳道 ——
                # children 被 clamp 在各自泳道内，但**容器的 y 没有被 clamp**：
                # 当 children 分属多个泳道（容器跨道）时，delta 可能把容器整体
                # 推到泳道带下方；而 canvas_h 只按泳道数量算，于是容器底部溢出
                # 泳道之外（实测 "云服务内网信任边界" bot=1108 而泳道只到 900，
                # 越界 208px —— 观感是"框掉出了灰色泳道带"）。
                # 把容器上移回泳道带内；children 不动（它们本来就合法），
                # 容器只是"略微收紧包裹"，不影响成员归属。
                c_h = cp.get("containerSize", {}).get("height", 0)
                lane_band_bottom = 0.0
                for lk in visible:
                    lane_band_bottom = max(lane_band_bottom, lane_top[lk] + lane_h)
                if lane_band_bottom and cp["y"] + c_h > lane_band_bottom:
                    shift_up = (cp["y"] + c_h) - lane_band_bottom
                    cp["y"] -= shift_up
                    cc2 = cp.get("containerCenter")
                    if cc2:
                        cp["containerCenter"] = (cc2[0], cc2[1] - shift_up)
                    logger.info(
                        "DFD 边界容器回收进泳道带：%s 上移 %.0fpx", cur, shift_up
                    )

        # --- C2（D7）. 同泳道节点重叠消解 ---
        # D1 已按真实宽度排布，但以下两种情况仍会残留重叠：
        #   1) NODE_WIDTH_MAX 截断：名称超长节点宽度被 clamp 到 280，
        #      按 clamp 后宽度排布仍可能不足；
        #   2) 信任边界容器避让（D 段）把 children 整体下移后，可能与
        #      同泳道其它节点在 y 上进入同一水平带。
        # 这里做一次「同泳道内两两 bbox 相交 → 沿 x 向右推开」的收敛
        # 迭代。仅处理同泳道节点（跨泳道节点分属不同水平带，本就互不遮挡），
        # 信任边界容器不参与（它设计上就该包住自己的 children）。
        # 推开后若有节点超出当前画布宽度，则扩张画布（由下方 canvas_width
        # 重算统一处理），保证不会被裁切。
        lane_members: dict[str, list[str]] = {}
        for k in visible:
            lane_members[k] = [
                cid for cid in buckets[k]
                if cid in positions and comp_type.get(cid) != "trustboundary"
            ]
        overlap_fixed = 0
        for _pass in range(6):  # 至多 6 轮，实际 1~2 轮即收敛
            moved = False
            for k, members in lane_members.items():
                if len(members) < 2:
                    continue
                # 按 x 排序后只比较相邻对：重叠修正在有序序列上等价，
                # O(n log n) 且避免 O(n²) 全比较（组件多时性能更稳）
                ordered = sorted(members, key=lambda cid: positions[cid]["x"])
                for i in range(len(ordered) - 1):
                    a, b = ordered[i], ordered[i + 1]
                    pa, pb = positions[a], positions[b]
                    wa = self._w_of(a)
                    # y 方向是否真正重叠（留有 V_GAP*0.4 的呼吸间距）
                    a_top, a_bot = pa["y"], pa["y"] + self.NODE_HEIGHT
                    b_top, b_bot = pb["y"], pb["y"] + self.NODE_HEIGHT
                    y_clash = min(a_bot, b_bot) - max(a_top, b_top) > -self.V_GAP * 0.4
                    if not y_clash:
                        continue
                    need_x = pa["x"] + wa + self.H_GAP  # b 的最小合法 x
                    if pb["x"] < need_x - 0.5:
                        shift = need_x - pb["x"]
                        # 把 b 及其右侧同泳道节点整体右推，保持相对顺序稳定
                        for cid in ordered[i + 1:]:
                            positions[cid] = dict(positions[cid], x=positions[cid]["x"] + shift)
                        overlap_fixed += 1
                        moved = True
            if not moved:
                break
        if overlap_fixed:
            logger.info("DFD 泳道内重叠消解：修正 %d 处节点水平挤压", overlap_fixed)
            # 画布宽度需覆盖修正后的最右节点（+ 右侧 margin 与容器余量）
            rightmost = max(
                (positions[cid]["x"] + self._w_of(cid) for cid in positions
                 if isinstance(positions[cid], dict) and "x" in positions[cid]
                 and comp_type.get(cid) != "trustboundary"),
                default=0.0,
            )
            # 右侧若被推到画布外，扩张画布；同时把泳道左边界收回 MARGIN
            needed = rightmost + self.MARGIN * 2
            if needed > canvas_width:
                canvas_width = needed
            # 若存在被推到 MARGIN 左侧的节点（不会发生，保险起见），左对齐修正
            leftmost = min(
                (positions[cid]["x"] for cid in positions
                 if isinstance(positions[cid], dict) and "x" in positions[cid]
                 and comp_type.get(cid) != "trustboundary"),
                default=self.MARGIN,
            )
            if leftmost < self.MARGIN:
                dx = self.MARGIN - leftmost
                for cid in positions:
                    if isinstance(positions[cid], dict) and "x" in positions[cid]:
                        positions[cid] = dict(positions[cid], x=positions[cid]["x"] + dx)

            # 同步重算信任边界容器 bbox：D7 可能把 children 横向推开，
            # 容器若沿用旧 bbox 就会出现「子节点跑出容器外」的视觉 bug。
            for cid in boundary_ids:
                inner = boundary_inner.get(cid)
                if not inner:
                    continue
                xs_in = [positions[k]["x"] + self._w_of(k) / 2 for k in inner if k in positions]
                ys_in = [positions[k]["y"] + self.NODE_HEIGHT / 2 for k in inner if k in positions]
                if not xs_in:
                    continue
                cx, cy = sum(xs_in) / len(xs_in), sum(ys_in) / len(ys_in)
                minx = min(xs_in) - self.H_GAP * 1.4
                maxx = max(xs_in) + self.H_GAP * 1.4 + self._w_of(inner[0]) / 2
                miny = min(ys_in) - self.V_GAP * 1.4
                maxy = max(ys_in) + self.V_GAP * 1.4 + self.NODE_HEIGHT / 2
                prev_size = positions[cid].get("containerSize", {})
                positions[cid] = dict(
                    positions[cid],
                    x=minx,
                    y=miny,
                    containerSize={
                        "width": max(260, maxx - minx),
                        "height": max(160, maxy - miny, prev_size.get("height", 0)),
                    },
                    containerCenter=(cx, cy),
                )

        # --- D7b. 泳道必须覆盖所有内容 ---
        # 画布宽度改为「按内容收紧」后，边界容器（bbox 包住成员，可跨多泳道）
        # 或锯齿偏移后的节点可能仍比泳道宽。历史上只在 overlap_fixed>0 时扩张
        # 画布，覆盖不到"节点没重叠但容器超宽"的情况 → 容器右沿露到泳道外，
        # 观感上"框跑出底色带"。
        # 这里独立做一道兜底：只要任一非泳道内容超出 swimlane 右边界，就扩宽画布。
        lane_right = self.MARGIN + max(0.0, canvas_width - self.MARGIN * 2)
        content_right = max(
            (
                (positions[cid]["x"] + (positions[cid].get("containerSize") or {}).get(
                    "width", self._w_of(cid)))
                if comp_type.get(cid) == "trustboundary"
                else (positions[cid]["x"] + self._w_of(cid))
                for cid in positions
                if isinstance(positions[cid], dict) and "x" in positions[cid]
            ),
            default=lane_right,
        )
        if content_right > lane_right:
            canvas_width += content_right - lane_right + self.MARGIN
            logger.info(
                "DFD 泳道宽度按内容扩张：+%.0fpx（容器/节点超出泳道右沿）",
                content_right - lane_right + self.MARGIN,
            )

        # --- C3（D5）. 边标签锚点预分配 ---
        # 前端原来把所有边标签钉在 distance=0.5, offset=0 → 同一区域多条边的
        # 标签必然叠在一起（截图里橙色文案糊成一片的直接原因）。
        # 这里为每条边给出 labelT（沿边归一化位置）与 labelOffset（法向偏移）：
        #   - 按 (源节点, 目标节点) 分组，同组内沿边分散到 0.25/0.5/0.75 附近；
        #   - 同组的法向 offset 交替 ±，进一步拉开；
        #   - 跨泳道流优先放在边的前段（0.3 附近），标签贴近源节点，避免
        #     落在泳道缝隙里与其它标签争位。
        # 前端未消费此字段时无副作用（纯附加提示）。
        label_hints: dict[str, dict[str, float]] = {}
        by_pair: dict[tuple[str, str], list[str]] = {}
        for f in flows:
            fid = f.get("id") or ""
            sid, tid = f.get("sourceId") or "", f.get("targetId") or ""
            if not fid or not sid or not tid or sid == tid:
                continue
            ps_l, pt_l = positions.get(sid), positions.get(tid)
            if not isinstance(ps_l, dict) or not isinstance(pt_l, dict):
                continue
            # 无向键：A→B 与 B→A 视为同组，避免反向流标签重叠
            key = (sid, tid) if sid < tid else (tid, sid)
            by_pair.setdefault(key, []).append(fid)
        for key, fids in by_pair.items():
            if len(fids) == 1:
                # 单条边保持中点，不引入额外偏移（观感更自然）
                label_hints[fids[0]] = {"labelT": 0.5, "labelOffset": 0.0}
                continue
            fids.sort()
            ts = (0.25, 0.5, 0.75)
            for i, fid in enumerate(fids):
                label_hints[fid] = {
                    "labelT": ts[i % len(ts)],
                    # 交替上下偏移，奇偶错开，避免同一 t 值仍重叠
                    "labelOffset": (-1 if (i // len(ts)) % 2 == 0 else 1)
                                    * (9 * (i // len(ts) + 1)),
                }
        self._label_hints = label_hints

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
        # D1: 普通组件用布局阶段算好的真实宽度（长名称更宽，避免渲染溢出重叠）
        width, height = self._w_of(comp["id"]), self.NODE_HEIGHT
        if is_boundary:
            # 自适应尺寸：根据内含组件 bbox
            csize = pos.get("containerSize") if pos else None
            if csize:
                width, height = csize["width"], csize["height"]
                # trustboundary 中心对齐"内含组件 bbox 中心"
                cx, cy = pos.get("containerCenter", (pos["x"] + width / 2,
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
            # D2/D5: 保留业务流 id，供前端查 diagram.layoutHints（过道/标签锚点）
            "flowId": flow.get("id") or "",
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
        # 边的折线几何**不再**在此处生成：由 dfd_layout_metrics.plan_edge_routes
        # 统一布线，经 recompute_layout_hints 写入 layoutHints[flowId].route，
        # 前端 X6 与后端 PNG 共用同一份（见 recompute_layout_hints 的说明）。
        #
        # 历史遗留：这里曾下发 cell["vertices"]（基于 sha1 哈希的斜向拱点），
        # 但前端从不读取 cell.vertices（只消费 layoutHints.route），属只写不读
        # 的死数据；且其"斜线拱起"语义与正交路由体系直接对立，会误导后来者
        # 以为存在第二套路由。已删除。
        return cell

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
        # threat.modelType 语义 = 本次建模所采用的方法论（任务级事实）。
        #   - 官方 TD 认识的通用方法论（STRIDE/CIA/CIADIE/LINDDUN/PLOT4ai/EOP）
        #     直接写入，官方 schema 与翻译映射都能正常匹配。
        #   - 平台扩展方法论（STRIDE-AI / MAESTRO）官方 TD 不识别，写入原值
        #     会令官方下拉退化为『全部方法论混合』。但此处不再降级改写为
        #     STRIDE —— 那会让前端把 MAESTRO 任务误显示成 STRIDE，且
        #     MAESTRO 的威胁类型（GoalHijacking/ToolMisuse 等）与 STRIDE
        #     完全不同体系，强行对齐没有意义。改为原值写入 + aiExtension
        #     标记，由平台前端负责显示正确的标签。
        model_type = normalize_methodology(methodology)
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
        # P1：现有安全措施（与 mitigation 区分：一个说现状，一个说待办）。
        # 「未知」视为无有效信息，不写入，避免报告里出现无意义的「未知」列。
        _existing = (t.get("existingControls") or "").strip()
        if _existing and _existing not in ("未知", "无", "-"):
            threat["existingControls"] = _existing
        # P1：合规映射（该威胁触达的法规条款）
        _comp_refs = t.get("complianceRefs") or []
        if isinstance(_comp_refs, list) and _comp_refs:
            threat["complianceRefs"] = [str(x) for x in _comp_refs if str(x).strip()]
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
