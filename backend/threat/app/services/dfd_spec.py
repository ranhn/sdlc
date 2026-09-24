"""DFD 视觉规格 —— 全链路**单一事实来源**（Single Source of Truth）。

为什么需要这个模块：
    DFD 有三条渲染链路会各自画同一张图——
      1. 前端 X6 交互画布（frontend/src/components/threat/DfdGraph.vue）
      2. 后端 Pillow 位图（dfd_renderer.py，供 Word 报告）
      3. 报告正文的图例表与元素编号（result_exporter.py）
    这三处曾经各自硬编码同一份视觉常量，导致反复出现不一致：
      - Store 圆柱顶盖占比 前端注释 14%/后端代码 20%
      - 图例表把 Store 写成"矩形"，实际两端都画圆柱
      - 跨边界线型注释写 7 5、前端实现 6 4
      - 图例里"跨边界"画灰虚线，实际渲染保留加密绿/公网橙
    本模块把这些常量收敛到一处，并在 `spec_for_frontend()` 中一次性
    序列化给前端（经 `/api/dfd/spec` 下发或构建期注入），使"改一处、
    两端同时生效"成为结构保证而非人工纪律。

设计约束：
    - 本模块**只放常量与纯函数**，不 import PIL、不 import 任何服务模块，
      因此可以被 result_exporter / dfd_renderer / API 层安全复用。
    - 常量命名为 SCREAMING_SNAKE，前端 JSON 键为 camelCase，
      由 `spec_for_frontend()` 统一转换，避免两边手写映射。
"""
from __future__ import annotations

import math
from typing import Any

# ======================================================================
# 一、节点造型与配色
# ======================================================================
# 每个条目的键与 Threat Dragon 的 cell.shape 严格一致（含 AI 扩展类型，
# 它们共用 tm.* 命名空间但语义独立）。
#
#   fill/stroke/text : 配色三元组
#   radius           : 圆角像素半径（仅对 rounded 造型有意义）
#   figure           : 造型族——决定两端如何画轮廓
#                      "capsule"  胶囊（外部实体）
#                      "rounded"  圆角矩形（处理过程 / 边界容器）
#                      "cylinder" 圆柱（数据存储，DFD 标准记法）
#   icon             : 图上叠加的字符图标（AI 元素用；空串表示无）
#   label_zh         : 报告图例中的中文名
#   abbrev_zh         : 报告图例中的缩写（EE/P/DS/TB）
NODE_STYLE: dict[str, dict[str, Any]] = {
    "tm.Actor": {
        "fill": "#e0f2fe", "stroke": "#0284c7", "text": "#075985",
        "radius": 26.0, "figure": "capsule", "icon": "",
        "label_zh": "外部实体", "abbrev_zh": "EE",
    },
    "tm.Process": {
        "fill": "#dcfce7", "stroke": "#16a34a", "text": "#14532d",
        "radius": 8.0, "figure": "rounded", "icon": "",
        "label_zh": "处理过程", "abbrev_zh": "P",
    },
    "tm.Store": {
        "fill": "#fef3c7", "stroke": "#d97706", "text": "#92400e",
        "radius": 0.0, "figure": "cylinder", "icon": "",
        "label_zh": "数据存储", "abbrev_zh": "DS",
    },
    "tm.BoundaryBox": {
        # stroke 由 #64748b 调浅到 #94a3b8：信任边界是"背景分区"层，边界一多
        # 深灰虚线和数据流互相抢权重，画布显乱（用户反馈）。
        "fill": "#f1f5f9", "stroke": "#94a3b8", "text": "#475569",
        "radius": 6.0, "figure": "rounded", "icon": "",
        "label_zh": "信任边界", "abbrev_zh": "TB",
    },
    # ---- AI 扩展元素（STRIDE-AI / MAESTRO）----
    "tm.Model": {
        "fill": "#ede9fe", "stroke": "#7c3aed", "text": "#4c1d95",
        "radius": 8.0, "figure": "rounded", "icon": "🧠",
        "label_zh": "大模型", "abbrev_zh": "M",
    },
    "tm.Prompt": {
        "fill": "#fae8ff", "stroke": "#c026d3", "text": "#86198f",
        "radius": 8.0, "figure": "rounded", "icon": "📝",
        "label_zh": "提示词", "abbrev_zh": "PR",
    },
    "tm.VectorStore": {
        "fill": "#f5d0fe", "stroke": "#a21caf", "text": "#701a75",
        "radius": 0.0, "figure": "cylinder", "icon": "📚",
        "label_zh": "向量库", "abbrev_zh": "VS",
    },
    "tm.Tool": {
        "fill": "#e0e7ff", "stroke": "#4f46e5", "text": "#3730a3",
        "radius": 8.0, "figure": "rounded", "icon": "🔧",
        "label_zh": "工具能力", "abbrev_zh": "TL",
    },
    "tm.TrainingData": {
        "fill": "#e0f2fe", "stroke": "#0891b2", "text": "#155e75",
        "radius": 8.0, "figure": "rounded", "icon": "🗂️",
        "label_zh": "训练数据", "abbrev_zh": "TD",
    },
    "tm.AgentConfig": {
        "fill": "#cffafe", "stroke": "#0e7490", "text": "#164e63",
        "radius": 8.0, "figure": "rounded", "icon": "⚙️",
        "label_zh": "Agent 配置", "abbrev_zh": "AC",
    },
    "tm.Agent": {
        "fill": "#dbeafe", "stroke": "#2563eb", "text": "#1e3a8a",
        "radius": 8.0, "figure": "rounded", "icon": "🤖",
        "label_zh": "智能体", "abbrev_zh": "AG",
    },
    "tm.Orchestrator": {
        "fill": "#e0e7ff", "stroke": "#4338ca", "text": "#312e81",
        "radius": 8.0, "figure": "rounded", "icon": "🎛️",
        "label_zh": "编排器", "abbrev_zh": "OR",
    },
    "tm.Memory": {
        "fill": "#f3e8ff", "stroke": "#9333ea", "text": "#581c87",
        "radius": 0.0, "figure": "cylinder", "icon": "💾",
        "label_zh": "智能体记忆", "abbrev_zh": "MM",
    },
}

# 兜底：未知 shape 按"处理过程"渲染（两端一致，不再各自兜底）
FALLBACK_SHAPE = "tm.Process"

# 泳道 / 文本 / 画布
LANE_STYLE = {"fill": "#f4f7fb", "stroke": "#cbd5e1", "text": "#64748b"}
TEXT_STYLE = {"text": "#334155"}
CANVAS_BG = "#ffffff"

# 数据流基线色（无语义标记时）
FLOW_DEFAULT_STROKE = "#475569"
# 语义色优先级：公网 > 加密 > 默认（两端必须一致）
FLOW_ENCRYPTED = "#16a34a"
FLOW_PUBLIC = "#ea580c"
BADGE_FILL = "#dc2626"


# ======================================================================
# 二、圆柱造型几何（前端 refD path 与后端 PIL 共用同一份比例）
# ======================================================================
# 前端在 0..100 归一化坐标里书写 path；后端按 (宽, 高, 顶盖比例) 反算。
# CAP_RATIO 是唯一权威值——历史上前端注释 14%、后端代码 20% 的分歧点。
CYLINDER_CAP_RATIO = 0.20      # 顶盖椭圆半高占节点总高的比例
CYLINDER_BOTTOM_BULGE = 0.20   # 底部下凸弧占节点总高的比例（与顶盖对称）

# 前端 path（0..100 归一化 → refD 按 bbox 缩放）。
# 顶盖：椭圆上弧从左上到右上；底部：下凸弧从右下到左下。
_CR = CYLINDER_CAP_RATIO * 100.0          # 20
_BR = CYLINDER_BOTTOM_BULGE * 100.0       # 20
CYLINDER_PATH_D = (
    f"M 0 {_CR:g} "
    f"L 0 {100 - _BR:g} "
    f"A 50 {_CR:g} 0 0 0 100 {100 - _BR:g} "
    f"L 100 {_CR:g} "
    f"A 50 {_CR:g} 0 0 1 0 {_CR:g} Z"
)
# 顶盖弦线（圆柱的"上沿翻边"，两端都要画这条横线）
CYLINDER_CAP_LINE_Y = _CR

# Store 文字中心相对节点顶部的比例：顶盖占 20% + 底部弧占 20%，
# 可视文本带为中间 60%，取其中最舒适的位置。
CYLINDER_LABEL_CENTER_RATIO = 0.56


# ======================================================================
# 三、线型规格
# ======================================================================
# 三种线型的 dash 模式：None = 实线
DASH_OUT_OF_SCOPE = (4.0, 3.0)      # 范围外（短虚线）
DASH_CROSS_BOUNDARY = (6.0, 4.0)    # 跨信任边界（中虚线）

# 线宽四档：加密+公网 2.0 > 单标记 1.8 > 跨边界 1.6 > 普通 1.4
FLOW_WIDTH_BOTH = 2.0
FLOW_WIDTH_SINGLE_MARK = 1.8
FLOW_WIDTH_CROSS = 1.6
FLOW_WIDTH_PLAIN = 1.4

# 箭头
ARROW_SIZE = 7.0                    # 前端 marker size
ARROW_SIZE_BACKEND = 9.0            # 后端三角形半宽（像素，放大后）


def flow_semantics(data: dict[str, Any] | None) -> tuple[bool, bool, bool, bool]:
    """从 flow 的 data 中提取四元语义标记（两端共用同一判定）。

    返回 (is_encrypted, is_public, crosses_boundary, out_of_scope)。

    注意：`crossesTrustBoundary` 必须是**已经判定好**的最终值。前端在
    读取老模型（无该字段）时会用位置推断补齐，判定规则见
    `infer_crosses_boundary()`，保证与后端 model_builder 语义一致。
    """
    d = data or {}
    return (
        bool(d.get("isEncrypted")),
        bool(d.get("isPublicNetwork")),
        bool(d.get("crossesTrustBoundary")),
        bool(d.get("outOfScope")),
    )


def flow_stroke_and_dash(enc: bool, pub: bool, cross: bool, oos: bool
                          ) -> tuple[str, tuple[float, float] | None, float]:
    """按语义标记算出 (描边色, dash 模式, 线宽)。

    优先级（两端必须一致）：
      - 颜色：公网 > 加密 > 默认；跨边界**不覆盖颜色**，只用虚线表达
      - dash：outOfScope > crossBoundary > 实线
      - 线宽：双标记 > 单标记 > 跨边界 > 普通
    """
    if pub:
        stroke = FLOW_PUBLIC
    elif enc:
        stroke = FLOW_ENCRYPTED
    else:
        stroke = FLOW_DEFAULT_STROKE

    if oos:
        dash: tuple[float, float] | None = DASH_OUT_OF_SCOPE
    elif cross:
        dash = DASH_CROSS_BOUNDARY
    else:
        dash = None

    if enc and pub:
        width = FLOW_WIDTH_BOTH
    elif enc or pub:
        width = FLOW_WIDTH_SINGLE_MARK
    elif cross:
        width = FLOW_WIDTH_CROSS
    else:
        width = FLOW_WIDTH_PLAIN

    return stroke, dash, width


# ======================================================================
# 四、元素编号（EID）—— 报告与图共用同一份
# ======================================================================
# 编号是 DFD 标准记法的核心：报告正文写"DF3 未加密"，图上就必须能
# 找到 DF3。历史上编号只在 result_exporter 生成、图上没有，导致读者
# 无法把正文引用定位到图上元素。现改为**布局阶段生成并写进 cell**，
# result_exporter 直接复用 cell 内的编号。
#
# 前缀规则：同类元素从 1 递增（EE1 / P2 / DS3 / DF5 / TB2）
EID_PREFIX: dict[str, str] = {
    shape: spec["abbrev_zh"] for shape, spec in NODE_STYLE.items()
}
EID_PREFIX_FLOW = "DF"

# 报告与图上都要用的"元素类别"三元组（kind, prefix, zh）
ELEMENT_KIND: dict[str, tuple[str, str, str]] = {
    "tm.Actor": ("externalentity", "EE", "外部实体"),
    "tm.Process": ("process", "P", "处理过程"),
    "tm.Store": ("datastore", "DS", "数据存储"),
    "tm.Flow": ("flow", "DF", "数据流"),
    "tm.BoundaryBox": ("trustboundary", "TB", "信任边界"),
    "tm.Model": ("model", "M", "大模型"),
    "tm.Prompt": ("prompt", "PR", "提示词"),
    "tm.VectorStore": ("vectorstore", "VS", "向量库"),
    "tm.Tool": ("tool", "TL", "工具能力"),
    "tm.TrainingData": ("trainingdata", "TD", "训练数据"),
    "tm.AgentConfig": ("agentconfig", "AC", "Agent 配置"),
    "tm.Agent": ("agent", "AG", "智能体"),
    "tm.Orchestrator": ("orchestrator", "OR", "编排器"),
    "tm.Memory": ("memory", "MM", "智能体记忆"),
}


def eid_of(shape: str) -> str:
    """取某 shape 的编号前缀（未知 shape 退回处理过程 P）。"""
    return EID_PREFIX.get(shape, EID_PREFIX[FALLBACK_SHAPE])


def node_spec(shape: str) -> dict[str, Any]:
    """取某 shape 的视觉规格（未知 shape 退回处理过程）。"""
    return NODE_STYLE.get(shape) or NODE_STYLE[FALLBACK_SHAPE]


def layer_zh(shape: str) -> str:
    """报告图例用的中文名（AI 元素也有自己的名字，不再统一叫"处理过程"）。"""
    spec = NODE_STYLE.get(shape)
    return spec["label_zh"] if spec else "处理过程"


# ======================================================================
# 五、图例定义（唯一事实来源 —— XML/PNG/前端都从这里取）
# ======================================================================
# 每一项：(类别, 键) —— "node" 表示节点造型，"flow" 表示线型，"badge" 徽标
# 报告图例表、PNG 左下角图例、前端 legend 三处都渲染这一份定义。
LEGEND_NODE_SHAPES: list[str] = [
    "tm.Actor", "tm.Process", "tm.Store", "tm.BoundaryBox",
]
LEGEND_FLOW_ITEMS: list[dict[str, Any]] = [
    {
        "key": "plain", "label_zh": "普通数据流",
        "enc": False, "pub": False, "cross": False, "oos": False,
        "desc_zh": "常规业务数据流转",
    },
    {
        "key": "encrypted", "label_zh": "加密数据流",
        "enc": True, "pub": False, "cross": False, "oos": False,
        "desc_zh": "链路上已启用加密",
    },
    {
        "key": "public", "label_zh": "公网数据流",
        "enc": False, "pub": True, "cross": False, "oos": False,
        "desc_zh": "经过公网传输的链路",
    },
    {
        "key": "cross", "label_zh": "跨信任边界流",
        "enc": False, "pub": False, "cross": True, "oos": False,
        "desc_zh": "穿越信任边界的数据流，属重点检查对象",
    },
    {
        "key": "cross_encrypted", "label_zh": "跨边界+加密",
        "enc": True, "pub": False, "cross": True, "oos": False,
        "desc_zh": "已加密且跨越信任边界",
    },
    {
        "key": "cross_public", "label_zh": "跨边界+公网",
        "enc": False, "pub": True, "cross": True, "oos": False,
        "desc_zh": "经公网且跨越信任边界（风险最高）",
    },
    {
        "key": "out_of_scope", "label_zh": "范围外数据流",
        "enc": False, "pub": False, "cross": False, "oos": True,
        "desc_zh": "不在本次评估范围内的链路",
    },
]

BADGE_LEGEND_ZH = "威胁数"
BADGE_LEGEND_DESC = "节点右下角数字表示该元素关联的威胁条数"

# 信任边界穿越点标记：跨界流在边界框上的落点画一个小方块（两端一致），
# 让"这里发生了信任级变化"在图上可定位——历史上只有边虚线一种手段。
CROSS_MARKER_SIZE = 7.0
CROSS_MARKER_FILL = "#dc2626"


# ======================================================================
# 五之二、边标签几何 —— 布局期唯一真源
# ======================================================================
# 【为什么放在这里】边标签的最终落点长期是三套算法各算各的：
#   后端 PNG   : dfd_renderer._place_label_avoiding（用 PIL 实测字宽 + 设备像素）
#   前端 X6    : DfdGraph.avoidEdgeLabels（自己一套 STEPS + 估算字宽）
#   后端度量   : 不管标签
# 三者对「标签该在哪」的判断不同，于是同一张图在页面上与导出图里标签
# 位置不一致，密集图尤其明显（前端截图里中部标签成灾）。
#
# 现在改为：**布局期（model_builder）用本模块的纯函数算一次最终落点**，
# 结果写进 diagram.layoutHints[flowId].labelX/labelY（模型坐标），
# 前端直接把标签钉在该坐标上，不再自行避让；后端 PNG 也优先消费同一
# 结果，只有拿不到时才回退到自己的运行时避让。
#
# 为什么字宽必须估算而不能实测：本模块**不允许** import PIL（见模块头
# 设计约束），且布局期在无字体的环境里也要能跑。估算口径与前端
# avoidEdgeLabels 原有的估算保持一致（CJK 全角 vs ASCII 半角），
# 因此前端换成"直供坐标"后标签视觉位置与之前不会突变。
LABEL_FONT_SIZE = 11.0          # 边标签字号（前端 labels.attrs.label.fontSize）

# 宽度估算：CJK 按 1.0em、ASCII 按 0.5em —— 与前端原实现同口径
LABEL_ASCII_W = 0.5             # × LABEL_FONT_SIZE
# 标签底板左右内边距（后端 _place_label_avoiding 的 pad）
LABEL_PAD_X = 3.0
LABEL_PAD_Y = 2.0
# 标签避让时沿法向的试位步长与最大步数（上/下交替）
LABEL_AVOID_STEP = 13.0
LABEL_AVOID_TRIES = 6
# 标签与节点矩形的重叠容差：贴边不算冲突（与后端 >2px 口径一致）
LABEL_NODE_TOL = 2.0


def point_on_polyline(
    pts: list[tuple[float, float]] | list[list[float]],
    t: float,
    normal_offset: float = 0.0,
) -> tuple[float, float]:
    """沿折线按**弧长比例** t∈[0,1] 取点，再沿该段左法向偏移 normal_offset。

    这是边标签锚点的唯一实现：后端 PNG 与布局期标签避让都调用它，
    语义与前端 X6 的 `labels.position {distance, offset}` 对齐
    （distance 沿边归一化弧长、offset 沿法向）。

    历史问题：本函数曾在 dfd_renderer 里有一份私有实现，布局期又需要
    同一口径，于是被提升到 dfd_spec 成为共享纯函数——避免再次出现
    「渲染一套、提示一套」的漂移。
    """
    if not pts:
        return 0.0, 0.0
    if len(pts) == 1:
        return float(pts[0][0]), float(pts[0][1])

    segs: list[tuple[float, float, float, float, float]] = []
    total = 0.0
    for i in range(len(pts) - 1):
        x0, y0 = float(pts[i][0]), float(pts[i][1])
        x1, y1 = float(pts[i + 1][0]), float(pts[i + 1][1])
        ln = math.hypot(x1 - x0, y1 - y0)
        segs.append((x0, y0, x1, y1, ln))
        total += ln
    if total <= 1e-6:
        return float(pts[0][0]), float(pts[0][1])

    tt = min(1.0, max(0.0, t))
    remain = total * tt
    for i, (x0, y0, x1, y1, ln) in enumerate(segs):
        if ln < 1e-6:
            continue
        if remain <= ln or i == len(segs) - 1:
            f = min(1.0, remain / ln) if ln > 1e-6 else 0.0
            px = x0 + (x1 - x0) * f
            py = y0 + (y1 - y0) * f
            ux, uy = (x1 - x0) / ln, (y1 - y0) / ln
            nx, ny = -uy, ux          # 左法向
            return px + nx * normal_offset, py + ny * normal_offset
        remain -= ln
    return float(pts[-1][0]), float(pts[-1][1])


def estimate_text_width(text: str, font_size: float = LABEL_FONT_SIZE) -> float:
    """估算一段文字在给定字号下的渲染宽度（px）。

    口径与前端 `avoidEdgeLabels` 原有的估算一致：CJK/全角按 1em，
    其余按 0.5em。这保证「换成后端直供坐标」不会让标签视觉跳变。
    """
    w = 0.0
    for ch in text or "":
        w += font_size if ord(ch) > 255 else font_size * LABEL_ASCII_W
    return w


def place_edge_labels(
    items: list[dict[str, Any]],
    node_boxes: list[tuple[float, float, float, float]],
) -> dict[str, tuple[float, float]]:
    """为一批边标签计算最终落点，返回 {key: (cx, cy)}（标签中心，模型坐标）。

    items 每项：{"key", "text", "x", "y"} —— x/y 是「未避让的初始落点」
    （由 route + labelT/labelOffset 算出的锚点，标签中心向上偏半个行高）。

    算法与后端 `_place_label_avoiding` **同构**（这是刻意的：后端 PNG 与
    前端必须得到同一答案）：
      1. 按调用方给定顺序逐个放置，先放的先占位；
      2. 每个标签先试原位，冲突则沿法向（垂直方向）上下交替加大偏移；
      3. 全部尝试都冲突时**保留原位**——宁可轻微叠压也不能丢标签。

    区别仅在度量单位：这里用估算字宽 + 模型坐标；后端渲染时再用实测
    字宽重算会得到近似结果。为消除这一层残余差异，后端 PNG 也改为
    **消费本函数的输出**（见 dfd_renderer 的标签绘制分支）。
    """
    placed: list[tuple[float, float, float, float]] = []
    out: dict[str, tuple[float, float]] = {}

    def _box(cx: float, cy: float, tw: float, th: float) -> tuple[float, float, float, float]:
        return (
            cx - tw / 2 - LABEL_PAD_X, cy - LABEL_PAD_Y,
            cx + tw / 2 + LABEL_PAD_X, cy + th + LABEL_PAD_Y,
        )

    def _hits(r: tuple[float, float, float, float]) -> bool:
        for o in placed:
            if (min(r[2], o[2]) - max(r[0], o[0]) > 0
                    and min(r[3], o[3]) - max(r[1], o[1]) > 0):
                return True
        for nb in node_boxes:
            if (min(r[2], nb[2]) - max(r[0], nb[0]) > LABEL_NODE_TOL
                    and min(r[3], nb[3]) - max(r[1], nb[1]) > LABEL_NODE_TOL):
                return True
        return False

    for it in items:
        text = it.get("text") or ""
        tw = estimate_text_width(text)
        th = LABEL_FONT_SIZE + 3.0            # 行高（与前端 h≈14 同量级）
        bx, by = float(it.get("x", 0.0)), float(it.get("y", 0.0))
        # cy 用「标签中心」，与原位（锚点 + 半行高）口径统一
        cands = [(bx, by)]
        for k in range(1, LABEL_AVOID_TRIES + 1):
            cands.append((bx, by - LABEL_AVOID_STEP * k))   # 优先向上（正交图常见空白）
            cands.append((bx, by + LABEL_AVOID_STEP * k))
        chosen = (bx, by)
        for cx, cy in cands:
            if not _hits(_box(cx, cy, tw, th)):
                chosen = (cx, cy)
                break
        placed.append(_box(chosen[0], chosen[1], tw, th))
        out[str(it.get("key"))] = chosen
    return out


# ======================================================================
# 六、序列化给前端
# ======================================================================
def spec_for_frontend() -> dict[str, Any]:
    """把规格转成前端可直接消费的 camelCase JSON。

    前端 `DfdGraph.vue` 在模块加载时先用自己的内置常量渲染（保证离线
    可用/首屏无闪烁），随后若拿到本接口返回的规格则覆盖——这样既不会
    因接口慢而白屏，也能保证长期一致性。
    """
    nodes = {}
    for shape, s in NODE_STYLE.items():
        nodes[shape] = {
            "fill": s["fill"],
            "stroke": s["stroke"],
            "text": s["text"],
            "radius": s["radius"],
            "figure": s["figure"],
            "icon": s["icon"],
            "labelZh": s["label_zh"],
            "abbrevZh": s["abbrev_zh"],
        }

    flow_legend = []
    for item in LEGEND_FLOW_ITEMS:
        stroke, dash, width = flow_stroke_and_dash(
            item["enc"], item["pub"], item["cross"], item["oos"])
        flow_legend.append({
            "key": item["key"],
            "labelZh": item["label_zh"],
            "descZh": item["desc_zh"],
            "stroke": stroke,
            "dash": list(dash) if dash else None,
            "width": width,
        })

    return {
        "nodes": nodes,
        "fallbackShape": FALLBACK_SHAPE,
        "lane": dict(LANE_STYLE),
        "text": dict(TEXT_STYLE),
        "canvasBg": CANVAS_BG,
        "flow": {
            "defaultStroke": FLOW_DEFAULT_STROKE,
            "encrypted": FLOW_ENCRYPTED,
            "public": FLOW_PUBLIC,
            "dashOutOfScope": list(DASH_OUT_OF_SCOPE),
            "dashCrossBoundary": list(DASH_CROSS_BOUNDARY),
            "widthBoth": FLOW_WIDTH_BOTH,
            "widthSingleMark": FLOW_WIDTH_SINGLE_MARK,
            "widthCross": FLOW_WIDTH_CROSS,
            "widthPlain": FLOW_WIDTH_PLAIN,
            "arrowSize": ARROW_SIZE,
        },
        "cylinder": {
            "pathD": CYLINDER_PATH_D,
            "capRatio": CYLINDER_CAP_RATIO,
            "bottomBulge": CYLINDER_BOTTOM_BULGE,
            "capLineY": CYLINDER_CAP_LINE_Y,
            "labelCenterRatio": CYLINDER_LABEL_CENTER_RATIO,
        },
        "badge": {
            "fill": BADGE_FILL,
            "legendZh": BADGE_LEGEND_ZH,
            "legendDesc": BADGE_LEGEND_DESC,
        },
        "crossMarker": {
            "size": CROSS_MARKER_SIZE,
            "fill": CROSS_MARKER_FILL,
        },
        "eid": {
            "prefix": dict(EID_PREFIX),
            "flowPrefix": EID_PREFIX_FLOW,
        },
        "legend": {
            "nodeShapes": list(LEGEND_NODE_SHAPES),
            "flows": flow_legend,
        },
    }
