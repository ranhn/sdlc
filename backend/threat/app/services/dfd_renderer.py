"""把 Threat Dragon 模型渲染成数据流图（DFD）位图，供 Word 报告嵌入。

为什么在**后端**画图，而不是前端截图：
    导出的入口不止一处（详情页、结果列表、未来的定时报告），而 DFD 画布
    只存在于建模页。若依赖前端截图，用户必须先把那次建模结果打开、等画布
    渲染完才能导出；后端直接根据模型里的坐标绘制，任何入口导出都一致。

坐标从哪来：
    model_builder 的布局算法（Kahn 分层 / 生命周期泳道）已把每个 cell 的
    position / size 写进模型 JSON，本模块只负责"按坐标把图形画出来"，
    不重新做布局。

绘制层级（自底向上，关键！边界容器的 zIndex 在数据里可能大于节点，
若按 zIndex 排序会把实心填充盖在内部节点上——前端 x6 有 embedding
机制所以没事，纯 2D 绘制必须显式分层）：
    1. 泳道背景
    2. 信任边界容器（最先画，作为"底"）
    3. 数据流连线
    4. 普通节点（Actor / Process / Store）

视觉规范与前端 DfdGraph.vue 严格对齐（见其 STYLE 常量与 addEdge 逻辑）：
    - 节点配色：Actor 蓝 / Process 绿 / Store 橙 / Boundary 灰
    - 圆角：Actor 26（胶囊）> 其余 8，信任边界 6
    - 信任边界：灰色虚线描边（10 5）
    - 边颜色优先级：公网(橙) > 加密(绿) > 默认(灰)
    - 边虚线：范围外(4 3) / 跨信任边界(6 4)
    - 边宽：加密+公网 2.0 > 单标记 1.8 > 跨边界 1.6 > 普通 1.4
    - 有未缓解威胁的节点右下角画红色条数徽标

依赖 Pillow（已随 pypdf[image] 安装）。
"""
from __future__ import annotations

import logging
import math
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# 视觉常量（与前端 DfdGraph.vue 的 STYLE 保持一致）
# ----------------------------------------------------------------------
NODE_STYLE = {
    "tm.Actor": {"fill": "#e0f2fe", "stroke": "#0284c7", "text": "#075985"},
    "tm.Process": {"fill": "#dcfce7", "stroke": "#16a34a", "text": "#14532d"},
    "tm.Store": {"fill": "#fef3c7", "stroke": "#d97706", "text": "#92400e"},
    "tm.BoundaryBox": {"fill": "#f1f5f9", "stroke": "#64748b", "text": "#475569"},
}
LANE_STYLE = {"fill": "#f4f7fb", "stroke": "#cbd5e1", "text": "#64748b"}
FLOW_DEFAULT_STROKE = "#475569"
FLOW_ENCRYPTED = "#16a34a"
FLOW_PUBLIC = "#ea580c"
BADGE_FILL = "#dc2626"
CANVAS_BG = "#ffffff"

TYPE_LABEL = {
    "tm.Actor": "外部实体",
    "tm.Process": "处理过程",
    "tm.Store": "数据存储",
    "tm.BoundaryBox": "信任边界",
}

# 放大 2 倍导出，Word 中按页宽缩放后文字仍清晰
_SCALE = 2.0
_MAX_PIXELS = 6400


class DfdRenderError(RuntimeError):
    """DFD 渲染失败（调用方应降级为"无图报告"而不是让导出失败）。"""


def render_dfd_png(record: dict[str, Any]) -> Optional[bytes]:
    """把一次建模结果的 DFD 渲染为 PNG 字节。

    返回 None 表示该结果没有可渲染的图（无图不是错误，导出应继续）。
    """
    model = record.get("model") or {}
    diagrams = ((model.get("detail") or {}).get("diagrams")) or []
    if not diagrams:
        return None

    try:
        from PIL import Image, ImageDraw  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise DfdRenderError(f"Pillow 不可用，无法渲染 DFD：{exc}") from exc

    diagram = diagrams[0]
    all_cells = [c for c in (diagram.get("cells") or []) if c.get("visible") is not False]
    if not all_cells:
        return None

    lanes = diagram.get("lanes") or []

    # ---------- 1. 画布范围 ----------
    xs: list[float] = []
    ys: list[float] = []
    xe: list[float] = []
    ye: list[float] = []
    for c in all_cells:
        pos = c.get("position")
        if not pos:
            continue
        size = c.get("size") or {}
        x, y = pos.get("x", 0), pos.get("y", 0)
        xs.append(x)
        ys.append(y)
        xe.append(x + size.get("width", 180))
        ye.append(y + size.get("height", 60))
    for lane in lanes:
        xs.append(lane.get("x", 0))
        ys.append(lane.get("y", 0))
        xe.append(lane.get("x", 0) + lane.get("width", 0))
        ye.append(lane.get("y", 0) + lane.get("height", 0))
    if not xs:
        return None

    pad = 50
    min_x, min_y = min(xs) - pad, min(ys) - pad
    width = max(1.0, max(xe) + pad - min_x)
    height = max(1.0, max(ye) + pad - min_y)

    scale = _SCALE
    if width * scale > _MAX_PIXELS:
        scale = _MAX_PIXELS / width
    if height * scale > _MAX_PIXELS:
        scale = min(scale, _MAX_PIXELS / height)
    img_w = max(1, int(width * scale))
    img_h = max(1, int(height * scale))

    # ---------- 2. 字体 ----------
    font_candidates = [
        r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\msyhbd.ttc",
        r"C:\Windows\Fonts\simhei.ttf",
        r"C:\Windows\Fonts\simsun.ttc",
    ]

    def _load_font(size: int):
        for path in font_candidates:
            try:
                return ImageFont_truetype(path, size)
            except Exception:
                continue
        return None

    def ImageFont_truetype(path: str, size: int):
        from PIL import ImageFont  # type: ignore

        return ImageFont.truetype(path, size)

    f_node = _load_font(int(15 * scale))
    f_lane = _load_font(int(13 * scale))
    f_edge = _load_font(int(12 * scale))
    f_badge = _load_font(int(11 * scale))
    f_title = _load_font(int(16 * scale))

    # ---------- 3. 超采样画布 ----------
    SS = 2
    img = Image.new("RGB", (img_w * SS, img_h * SS), CANVAS_BG)
    draw = ImageDraw.Draw(img)

    def P(x: float, y: float) -> tuple[float, float]:
        return ((x - min_x) * scale * SS, (y - min_y) * scale * SS)

    def S(v: float) -> float:
        return v * scale * SS

    # ---------- 4. 分类 cells ----------
    boundary_cells: list[dict] = []
    normal_nodes: list[dict] = []
    edge_cells: list[dict] = []
    for c in all_cells:
        if c.get("source") and c.get("target"):
            edge_cells.append(c)
        elif c.get("shape") == "tm.BoundaryBox":
            boundary_cells.append(c)
        else:
            normal_nodes.append(c)

    by_id = {c.get("id"): c for c in all_cells if c.get("id")}

    # ---------- 5. 第一层：泳道 ----------
    for lane in lanes:
        lx, ly = lane.get("x", 0), lane.get("y", 0)
        lw, lh = lane.get("width", 0), lane.get("height", 0)
        x0, y0 = P(lx, ly)
        x1, y1 = P(lx + lw, ly + lh)
        draw.rectangle([x0, y0, x1, y1], fill=LANE_STYLE["fill"],
                       outline=LANE_STYLE["stroke"], width=max(1, int(S(1))))
        label = lane.get("label") or lane.get("key") or ""
        if label and f_lane:
            _vertical_text(draw, label, x0 + S(8), (y0 + y1) / 2, f_lane, LANE_STYLE["text"], S)

    # ---------- 6. 第二层：信任边界容器 ----------
    for c in boundary_cells:
        if _boundary_child_count(c, all_cells) == 0:
            continue  # 空边界不画（与前端 visible:false 一致）
        style = NODE_STYLE["tm.BoundaryBox"]
        x0, y0, x1, y1 = _rect_of(c)
        px0, py0 = P(x0, y0)
        px1, py1 = P(x1, y1)
        # 容器底色
        draw.rounded_rectangle([px0, py0, px1, py1], radius=S(6), fill=style["fill"])
        # 名称标签（容器左上角）
        name = (c.get("data") or {}).get("name") or ""
        if name and f_lane:
            try:
                bbox = draw.textbbox((0, 0), name, font=f_lane)
                tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
                tx, ty = px0 + S(10), py0 + S(8)
                draw.rectangle([tx - S(3), ty - S(2), tx + tw + S(3), ty + th + S(3)],
                               fill=style["fill"])
                draw.text((tx, ty), name, font=f_lane, fill=style["text"])
            except Exception:
                pass
        # 虚线边框（后画，压在底色边缘上）
        _dashed_rect(draw, px0, py0, px1, py1, style["stroke"], max(1, int(S(2))), (10, 5), S)

    # ---------- 7. 第三层：数据流 ----------
    def _edge_semantics(e: dict) -> tuple[bool, bool, bool, bool]:
        d = e.get("data") or {}
        return (bool(d.get("isEncrypted")), bool(d.get("isPublicNetwork")),
                bool(d.get("crossesTrustBoundary")), bool(d.get("outOfScope")))

    # 排序：普通灰线先画，彩色/粗线后画（压在上面）
    def _edge_rank(e: dict) -> tuple:
        enc, pub, cross, _ = _edge_semantics(e)
        return (pub, enc, cross)

    # —— D6 对齐前端 padLevel：同一对节点间存在多条边时，按组内索引给
    # 中转段施加横向错位，避免后端 HV/VH 折线完全重叠成一束（前端 X6
    # 用 manhattan router + 按 id 哈希的 padding 天然错开，这里用组内
    # 索引效果等价且更可控）。键为无序 (src, tgt) 对。
    _PAD_STEP = 16.0  # 模型坐标 px
    pair_groups: dict[tuple, list[dict]] = {}
    for e in edge_cells:
        key = tuple(sorted([(e.get("source") or {}).get("cell") or "",
                            (e.get("target") or {}).get("cell") or ""]))
        pair_groups.setdefault(key, []).append(e)
    pad_of_edge: dict[str, float] = {}
    for _group in pair_groups.values():
        _group.sort(key=lambda e: e.get("id") or "")
        _n = len(_group)
        if _n < 2:
            continue
        for _i, _e in enumerate(_group):
            pad_of_edge[_e.get("id") or ""] = (_i - (_n - 1) / 2.0) * _PAD_STEP

    def _route_collisions(route: list[tuple[float, float]],
                          src_cell: dict, tgt_cell: dict) -> int:
        n = 0
        for c in all_cells:
            if c is src_cell or c is tgt_cell or (c.get("source") and c.get("target")):
                continue
            rx0, ry0, rx1, ry1 = _rect_of(c)
            for i in range(len(route) - 1):
                if _seg_intersects_rect(route[i], route[i + 1], (rx0, ry0, rx1, ry1), margin=6):
                    n += 1
                    break
        return n

    def _route_len(route: list[tuple[float, float]]) -> float:
        return sum(math.hypot(route[i + 1][0] - route[i][0], route[i + 1][1] - route[i][1])
                   for i in range(len(route) - 1))

    def _hv_route(p_src, p_tgt, x_mid):
        """H-V-H 三段严格正交：水平 → 垂直通道（x_mid）→ 水平。"""
        return [p_src, (x_mid, p_src[1]), (x_mid, p_tgt[1]), p_tgt]

    def _vh_route(p_src, p_tgt, y_mid):
        """V-H-V 三段严格正交：垂直 → 水平通道（y_mid）→ 垂直。"""
        return [p_src, (p_src[0], y_mid), (p_tgt[0], y_mid), p_tgt]

    for e in sorted(edge_cells, key=_edge_rank):
        enc, pub, crosses, oos = _edge_semantics(e)
        src_cell = by_id.get((e.get("source") or {}).get("cell"))
        tgt_cell = by_id.get((e.get("target") or {}).get("cell"))
        if not src_cell or not tgt_cell:
            continue

        if pub:
            stroke, label_color = FLOW_PUBLIC, "#c2410c"
        elif enc:
            stroke, label_color = FLOW_ENCRYPTED, "#15803d"
        else:
            stroke, label_color = FLOW_DEFAULT_STROKE, FLOW_DEFAULT_STROKE

        if oos:
            dash = (4, 3)
        elif crosses:
            dash = (6, 4)
        else:
            dash = None

        if enc and pub:
            w = 2.0
        elif enc or pub:
            w = 1.8
        elif crosses:
            w = 1.6
        else:
            w = 1.4

        sx0, sy0, sx1, sy1 = _rect_of(src_cell)
        tx0, ty0, tx1, ty1 = _rect_of(tgt_cell)
        src_c = ((sx0 + sx1) / 2, (sy0 + sy1) / 2)
        tgt_c = ((tx0 + tx1) / 2, (ty0 + ty1) / 2)

        p_src = _anchor(src_cell, tgt_c)
        p_tgt = _anchor(tgt_cell, src_c)

        # 正交折线路由（对齐前端 manhattan 观感）：
        # 1) 几乎同层/同列直连；2) HV/VH 两候选 + 并行边错位 + 中转段滑移避障；
        # 3) 按（碰撞数, 总长）择优。
        pts: list[tuple[float, float]]
        if abs(p_src[1] - p_tgt[1]) < 30 or abs(p_src[0] - p_tgt[0]) < 30:
            # 几乎同层/同列：正交小折角（避免两点直连产生斜线）
            if abs(p_src[0] - p_tgt[0]) >= abs(p_src[1] - p_tgt[1]):
                pts = [p_src, (p_tgt[0], p_src[1]), p_tgt]
            else:
                pts = [p_src, (p_src[0], p_tgt[1]), p_tgt]
        else:
            pad = pad_of_edge.get(e.get("id") or "", 0.0)
            # 并行边错位与避障滑移都作用在「自由中转通道」上（HV 的垂直列 /
            # VH 的水平行），路径始终严格正交——对齐前端 manhattan 观感。
            cands: list[tuple[int, float, list[tuple[float, float]]]] = []
            for make, mid0 in (
                (_hv_route, p_tgt[0] + pad),   # 垂直通道在目标列旁按组内序错开
                (_vh_route, p_src[1] + pad),   # 水平通道在源行旁按组内序错开
            ):
                route = make(p_src, p_tgt, mid0)
                n0 = _route_collisions(route, src_cell, tgt_cell)
                if n0:
                    # 滑移中转通道找无碰撞（其次最少碰撞）位置
                    for k in range(1, 9):
                        for sgn in (1, -1):
                            r2 = make(p_src, p_tgt, mid0 + sgn * k * 14)
                            n2 = _route_collisions(r2, src_cell, tgt_cell)
                            if n2 < n0:
                                route, n0 = r2, n2
                                if n2 == 0:
                                    break
                        if n0 == 0:
                            break
                cands.append((n0, _route_len(route), route))
            cands.sort(key=lambda t: (t[0], t[1]))
            pts = cands[0][2]

        dev_pts = [P(x, y) for x, y in pts]
        line_w = max(1, int(S(w)))
        draw.line(dev_pts, fill=stroke, width=line_w, joint="curve")
        if dash:
            _dashed_polyline(draw, dev_pts, stroke, line_w, dash, S)
        _arrow(draw, dev_pts[-2], dev_pts[-1], stroke, S(10), S(5))

        # 边标签：优先消费后端布局提示 labelT（沿边归一化位置）+ labelOffset
        # （法向偏移，模型坐标 px）——与前端 DfdGraph.vue 的消费方式一致，
        # 消除同一区域多条边标签叠压；无提示时退回第一段中点上方。
        name = ((e.get("data") or {}).get("name") or "").strip()
        if name and f_edge:
            hint_txt = "[加密] " if enc else ("[公网] " if pub else "")
            label = hint_txt + name
            flow_hint = (diagram.get("layoutHints") or {}).get(
                (e.get("data") or {}).get("flowId") or "")
            if flow_hint and isinstance(flow_hint.get("labelT"), (int, float)):
                tx, ty = _point_on_polyline(dev_pts, float(flow_hint["labelT"]),
                                            float(flow_hint.get("labelOffset") or 0.0) * scale * SS)
            else:
                mid = dev_pts[len(dev_pts) // 2]
                tx, ty = mid[0], mid[1]
                ty -= S(14)
            try:
                bbox = draw.textbbox((0, 0), label, font=f_edge)
                tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
                draw.rectangle([tx - tw / 2 - S(3), ty - S(2), tx + tw / 2 + S(3), ty + th + S(2)],
                               fill=CANVAS_BG)
                draw.text((tx - tw / 2, ty), label, font=f_edge, fill=label_color)
            except Exception:
                pass

    # ---------- 8. 第四层：普通节点 ----------
    for c in normal_nodes:
        shape = c.get("shape") or "tm.Process"
        style = NODE_STYLE.get(shape, NODE_STYLE["tm.Process"])
        data = c.get("data") or {}
        name = data.get("name") or ""

        x0, y0, x1, y1 = _rect_of(c)
        px0, py0 = P(x0, y0)
        px1, py1 = P(x1, y1)
        radius = 26 if shape == "tm.Actor" else 8

        draw.rounded_rectangle([px0, py0, px1, py1], radius=S(radius),
                               fill=style["fill"], outline=style["stroke"],
                               width=max(1, int(S(1.6))))

        if f_node and name:
            tag = TYPE_LABEL.get(shape, "")
            text_zone_w = px1 - px0 - S(10)
            lines = _wrap_text(draw, name, f_node, max(40, text_zone_w), max_lines=3)
            if tag:
                lines = lines + [tag]
            _centered_text(draw, lines, (px0 + px1) / 2, (py0 + py1) / 2, f_node, style["text"], S)

        threats = [t for t in (c.get("threats") or []) if not t.get("outOfScope")]
        if threats:
            cnt = len(threats)
            _badge(draw, px1, py1, "9+" if cnt > 9 else str(cnt), f_badge, S)

    # ---------- 9. 标题 & 图例 & 缩小 ----------
    title = None
    try:
        title = (diagram.get("title") or "").strip() or None
    except Exception:
        title = None
    if title and f_title:
        try:
            bbox = draw.textbbox((0, 0), title, font=f_title)
            tw = bbox[2] - bbox[0]
            draw.text((S(10), S(8)), title, font=f_title, fill="#334155")
        except Exception:
            pass

    _legend(draw, img, f_edge, S)

    out = img.resize((img_w, img_h), Image.LANCZOS)

    import io as _io
    buf = _io.BytesIO()
    out.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


# ----------------------------------------------------------------------
# 几何辅助
# ----------------------------------------------------------------------

def _rect_of(cell: dict) -> tuple[float, float, float, float]:
    """cell 的模型坐标矩形 (x0, y0, x1, y1)。模块级：主渲染流程与
    _boundary_child_count 共用。"""
    pos = cell.get("position") or {}
    size = cell.get("size") or {}
    x, y = pos.get("x", 0), pos.get("y", 0)
    return x, y, x + size.get("width", 180), y + size.get("height", 60)


def _anchor(cell: dict, toward: tuple[float, float]) -> tuple[float, float]:
    """连线从节点矩形边缘出发的锚点（中心连线与矩形边界交点）。"""
    x0, y0, x1, y1 = _rect_of(cell)
    cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
    tx, ty = toward
    dx, dy = tx - cx, ty - cy
    if dx == 0 and dy == 0:
        return cx, cy
    hw = max(1e-6, (x1 - x0) / 2)
    hh = max(1e-6, (y1 - y0) / 2)
    rx = hw / abs(dx) if dx else float("inf")
    ry = hh / abs(dy) if dy else float("inf")
    r = min(rx, ry)
    return cx + dx * r, cy + dy * r


def _point_on_polyline(pts: list[tuple[float, float]], t: float,
                       normal_offset: float = 0.0) -> tuple[float, float]:
    """沿折线按弧长比例 t∈[0,1] 取点，再沿该段的左法向偏移 normal_offset 像素。
    与前端边标签 position.distance/offset 语义对齐（offset 正值取法向一侧）。"""
    if not pts:
        return 0.0, 0.0
    if len(pts) == 1:
        return pts[0]
    segs: list[tuple[tuple[float, float], tuple[float, float], float]] = []
    total = 0.0
    for i in range(len(pts) - 1):
        x0, y0 = pts[i]
        x1, y1 = pts[i + 1]
        ln = math.hypot(x1 - x0, y1 - y0)
        segs.append(((x0, y0), (x1, y1), ln))
        total += ln
    if total <= 1e-6:
        return pts[0]
    tt = min(1.0, max(0.0, t))
    remain = total * tt
    for (x0, y0), (x1, y1), ln in segs:
        if ln < 1e-6:
            continue
        if remain <= ln or ((x0, y0), (x1, y1)) == segs[-1][:2]:
            f = min(1.0, remain / ln) if ln > 1e-6 else 0.0
            px = x0 + (x1 - x0) * f
            py = y0 + (y1 - y0) * f
            ux, uy = (x1 - x0) / ln, (y1 - y0) / ln
            # 左法向：法向偏移与前端 label offset 的视觉语义近似（垂直于边）
            nx, ny = -uy, ux
            return px + nx * normal_offset, py + ny * normal_offset
        remain -= ln
    return pts[-1]


def _seg_intersects_rect(p1, p2, rect: tuple[float, float, float, float], margin: float = 0) -> bool:
    """线段是否与矩形相交（含 margin 外扩）。简单实现：采样 + 端点判定。"""
    rx0, ry0, rx1, ry1 = rect[0] - margin, rect[1] - margin, rect[2] + margin, rect[3] + margin
    # 线段两端点同在矩形一侧则必不相交
    def side(x, y):
        return not (rx0 <= x <= rx1 and ry0 <= y <= ry1)
    if (p1[0] < rx0 and p2[0] < rx0) or (p1[0] > rx1 and p2[0] > rx1):
        return False
    if (p1[1] < ry0 and p2[1] < ry0) or (p1[1] > ry1 and p2[1] > ry1):
        return False
    # 采样判定（步长 8px，模型坐标尺度足够）
    steps = max(2, int(math.hypot(p2[0] - p1[0], p2[1] - p1[1]) / 8) + 1)
    for i in range(steps + 1):
        t = i / steps
        x = p1[0] + (p2[0] - p1[0]) * t
        y = p1[1] + (p2[1] - p1[1]) * t
        if rx0 <= x <= rx1 and ry0 <= y <= ry1:
            return True
    return False


# ----------------------------------------------------------------------
# 绘制辅助
# ----------------------------------------------------------------------

def _vertical_text(draw, text: str, x: float, cy: float, font, color, S) -> None:
    """竖排文字（泳道左侧标签）。"""
    try:
        chars = list(text)
        heights = []
        for ch in chars:
            bbox = draw.textbbox((0, 0), ch, font=font)
            heights.append(bbox[3] - bbox[1])
        line_h = max(heights) + S(4) if heights else S(14)
        total = line_h * len(chars)
        y = cy - total / 2
        for ch in chars:
            draw.text((x, y), ch, font=font, fill=color)
            y += line_h
    except Exception:
        pass


def _wrap_text(draw, text: str, font, max_width: float, max_lines: int = 3) -> list[str]:
    """按像素宽度折行。"""
    if not text:
        return []
    lines: list[str] = []
    cur = ""
    for ch in text:
        probe = cur + ch
        try:
            w = draw.textlength(probe, font=font)
        except Exception:
            w = len(probe) * 12
        if w > max_width and cur:
            lines.append(cur)
            cur = ch
            if len(lines) >= max_lines:
                break
        else:
            cur = probe
    if cur and len(lines) < max_lines:
        lines.append(cur)
    if len(lines) == max_lines and len("".join(lines)) < len(text):
        last = lines[-1]
        try:
            while last and draw.textlength(last + "…", font=font) > max_width:
                last = last[:-1]
        except Exception:
            pass
        lines[-1] = last + "…"
    return lines


def _centered_text(draw, lines: list[str], cx: float, cy: float, font, color, S) -> None:
    if not lines:
        return
    try:
        widths, heights = [], []
        for ln in lines:
            bbox = draw.textbbox((0, 0), ln, font=font)
            widths.append(bbox[2] - bbox[0])
            heights.append(bbox[3] - bbox[1])
    except Exception:
        return
    line_h = max(heights) + S(3)
    total = line_h * len(lines)
    y = cy - total / 2
    for i, ln in enumerate(lines):
        draw.text((cx - widths[i] / 2, y), ln, font=font, fill=color)
        y += line_h


def _arrow(draw, p_from, p_to, color, size: float, half: float) -> None:
    dx, dy = p_to[0] - p_from[0], p_to[1] - p_from[1]
    length = math.hypot(dx, dy)
    if length < 1e-6:
        return
    ux, uy = dx / length, dy / length
    bx, by = p_to[0] - ux * size, p_to[1] - uy * size
    nx, ny = -uy, ux
    draw.polygon([p_to, (bx + nx * half, by + ny * half), (bx - nx * half, by - ny * half)],
                 fill=color)


def _dashed_polyline(draw, pts, color, width, dash, S) -> None:
    on_len, off_len = dash[0] * S(1.2), dash[1] * S(1.2)
    for i in range(len(pts) - 1):
        x0, y0 = pts[i]
        x1, y1 = pts[i + 1]
        seg = math.hypot(x1 - x0, y1 - y0)
        if seg < 1e-6:
            continue
        ux, uy = (x1 - x0) / seg, (y1 - y0) / seg
        dist = 0.0
        while dist < seg:
            a, b = dist, min(dist + on_len, seg)
            draw.line([(x0 + ux * a, y0 + uy * a), (x0 + ux * b, y0 + uy * b)],
                      fill=color, width=width)
            dist += on_len + off_len


def _dashed_rect(draw, x0, y0, x1, y1, color, width, dash, S) -> None:
    corners = [(x0, y0), (x1, y0), (x1, y1), (x0, y1), (x0, y0)]
    _dashed_polyline(draw, corners, color, width, dash, S)


def _badge(draw, x1: float, y1: float, text: str, font, S) -> None:
    w = S(30) if len(text) > 1 else S(22)
    h = S(15)
    bx0, by0 = x1 - w, y1 - h
    try:
        draw.rounded_rectangle([bx0, by0, x1, y1], radius=S(7), fill=BADGE_FILL)
        bbox = draw.textbbox((0, 0), text, font=font)
        tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
        draw.text(((bx0 + x1) / 2 - tw / 2, (by0 + y1) / 2 - th / 2), text,
                  font=font, fill="#ffffff")
    except Exception:
        pass


def _boundary_child_count(boundary: dict, cells: list[dict]) -> int:
    bx0, by0, bx1, by1 = _rect_of(boundary)
    n = 0
    for c in cells:
        if c is boundary or c.get("shape") == "tm.BoundaryBox":
            continue
        if c.get("source") and c.get("target"):
            continue
        x0, y0, x1, y1 = _rect_of(c)
        cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
        if bx0 <= cx <= bx1 and by0 <= cy <= by1:
            n += 1
    return n


def _legend(draw, img, font, S) -> None:
    """左下角图例：线色/线型语义。"""
    try:
        W, H = img.size
        items = [
            (FLOW_ENCRYPTED, "加密流", None),
            (FLOW_PUBLIC, "公网流", None),
            (FLOW_DEFAULT_STROKE, "跨信任边界", (6, 4)),
            (FLOW_DEFAULT_STROKE, "普通流", None),
        ]
        pad = max(6, int(W * 0.005))
        lh = max(16, int(H * 0.024))
        label_w = 0
        if font:
            for _, label, _d in items:
                bbox = draw.textbbox((0, 0), label, font=font)
                label_w = max(label_w, bbox[2] - bbox[0])
        line_w = int(W * 0.045)
        box_w = pad * 3 + line_w + label_w
        box_h = lh * len(items) + pad * 2
        bx, by = pad * 2, H - box_h - pad * 2
        draw.rectangle([bx, by, bx + box_w, by + box_h], fill="#ffffff", outline="#e2e8f0")
        for i, (color, label, dash) in enumerate(items):
            cy = by + pad + lh * i + lh / 2
            xs_, xe_ = bx + pad, bx + pad + line_w
            if dash:
                seg = (xe_ - xs_) / 4
                for k in range(4):
                    draw.line([(xs_ + k * seg, cy), (xs_ + k * seg + seg * 0.55, cy)],
                              fill=color, width=2)
            else:
                draw.line([(xs_, cy), (xe_, cy)], fill=color, width=2)
            if font:
                draw.text((xe_ + pad, cy - lh * 0.32), label, font=font, fill="#475569")
    except Exception as exc:
        logger.debug("DFD 图例绘制失败（忽略）: %s", exc)
