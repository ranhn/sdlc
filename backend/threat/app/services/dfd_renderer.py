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

视觉规范与前端 DfdGraph.vue 严格对齐——**常量唯一来源是 dfd_spec**：
    - 节点配色与造型（figure）：Actor 胶囊蓝 / Process 圆角矩形绿 /
      Store 圆柱橙 / Boundary 灰虚线框 / AI 元素各自配色
    - 圆柱几何：顶盖 20% + 底部下凸 20%（与前端 refD path 同比例）
    - 跨信任边界落点画红色小方块标记（crossMarker）
    - 边颜色/虚线/线宽：flow_stroke_and_dash 统一判定
    - 图例：节点造型 + 线型语义 + 威胁徽标（LEGEND_* 定义）
    - 有未缓解威胁的节点右下角画红色条数徽标

依赖 Pillow（已随 pypdf[image] 安装）。
"""
from __future__ import annotations

import logging
import math
from typing import Any, Optional

from . import dfd_spec as _SPEC

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# 视觉常量 —— 全部从 dfd_spec 取（单一事实来源）。
# 以下名字同时被 result_exporter 导入用于报告图例文案，勿删：
#   NODE_STYLE / FLOW_ENCRYPTED / FLOW_PUBLIC / FLOW_DEFAULT_STROKE / BADGE_FILL
# ----------------------------------------------------------------------
NODE_STYLE = _SPEC.NODE_STYLE
LANE_STYLE = _SPEC.LANE_STYLE
FLOW_DEFAULT_STROKE = _SPEC.FLOW_DEFAULT_STROKE
FLOW_ENCRYPTED = _SPEC.FLOW_ENCRYPTED
FLOW_PUBLIC = _SPEC.FLOW_PUBLIC
BADGE_FILL = _SPEC.BADGE_FILL
CANVAS_BG = _SPEC.CANVAS_BG

TYPE_LABEL = {
    shape: s["label_zh"] for shape, s in _SPEC.NODE_STYLE.items()
}

# 放大 2 倍导出，Word 中按页宽缩放后文字仍清晰
_SCALE = 2.0
_MAX_PIXELS = 6400
# 超采样倍率：先画在 2 倍画布上再 LANCZOS 缩小，消除锯齿。
# 注意：字体尺寸必须乘 scale*SS（历史上只乘 scale，文字在成图里
# 只有预期一半大，节点内标签显得极小）。
_SS = 2


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

    # 字体尺寸 = 标称字号 × scale × SS（SS 超采样画布上绘制后再缩小，
    # 字体若只乘 scale，成图里文字会缩小一半）
    f_node = _load_font(int(15 * scale * _SS))
    f_lane = _load_font(int(13 * scale * _SS))
    f_edge = _load_font(int(12 * scale * _SS))
    f_badge = _load_font(int(11 * scale * _SS))
    f_title = _load_font(int(16 * scale * _SS))

    # ---------- 2b. 图例预留带 ----------
    # 图例不再叠画在内容左下角（历史版本会盖住节点/边），改为在内容
    # 下方预留一条独立带：先按与绘制完全相同的规则量出图例盒尺寸，
    # 把画布加高，绘制阶段（第 9 步）把图例盒放进带内。测量与绘制
    # 共用 _legend_box_size，保证「预留高度 = 实际高度」。
    _content_h_ss = img_h * _SS
    _legend_origin_y = None
    try:
        _meas = ImageDraw.Draw(Image.new("RGB", (4, 4)))
        _bw, _bh, *_ = _legend_box_size(
            _meas, f_edge, lambda v: v * scale * _SS, img_w * _SS)
        _gap = 10 * scale * _SS
        _band = _gap + _bh + 8 * scale * _SS
        img_h += max(1, int(_band / _SS))
        _legend_origin_y = _content_h_ss + _gap
    except Exception:
        pass  # 量不出尺寸就退回旧行为（叠画左下角，总比没图例好）

    # ---------- 3. 超采样画布 ----------
    SS = _SS
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
    _drawn_tb: list[tuple[float, float, float, float]] = []
    for c in boundary_cells:
        if _boundary_child_count(c, all_cells) == 0:
            continue  # 空边界不画（与前端 visible:false 一致）
        style = NODE_STYLE["tm.BoundaryBox"]
        x0, y0, x1, y1 = _rect_of(c)
        # 收缩/拉宽到子节点实际范围：建模产物里边界框可能远大于内容
        # （布局兜底尺寸 / 成员推断偏差），大片空白也被涂上底色会连成
        # 灰板。规则与前端 DfdGraph.boundaryLayout 完全同口径：
        #   垂直 = 只缩不涨（内容 ± 26，泳道上下堆叠，竖向膨胀会互压）；
        #   水平 = 主动拉宽到内容 ± 240（纵向长条 DFD 在宽画布上两侧
        #   全是空白，泳道作为背景应伸展填满），允许超出模型原始矩形，
        #   但不得侵入水平相邻泳道（垂直重叠、水平不相交）的领地。
        _inner = _boundary_children_bbox(c, all_cells)
        if _inner:
            _stretch_x, _pad_y = 240.0, 26.0
            _fx0 = min(x0, _inner[0] - _stretch_x)
            _fx1 = max(x1, _inner[2] + _stretch_x)
            for _ob in boundary_cells:
                if _ob is c:
                    continue
                _oi = _boundary_children_bbox(_ob, all_cells)
                if not _oi:
                    continue  # 空泳道不画也不挡
                if not (_oi[1] < _inner[3] and _oi[3] > _inner[1]):
                    continue  # 垂直不重叠：非邻居
                if _oi[2] <= _inner[0]:
                    _fx0 = max(_fx0, _oi[2] + 40.0)   # 左邻
                elif _oi[0] >= _inner[2]:
                    _fx1 = min(_fx1, _oi[0] - 40.0)   # 右邻
            _fy0 = max(y0, _inner[1] - _pad_y)
            _fy1 = min(y1, _inner[3] + _pad_y)
            # 防退化：收缩后过小则放弃收缩
            if _fx1 - _fx0 >= 60 and _fy1 - _fy0 >= 48:
                x0, y0, x1, y1 = _fx0, _fy0, _fx1, _fy1
        # 近重复边界跳过：异常模型里可能生成两个几乎重合的边界框，
        # 叠画只会产生双重虚线框与互相覆盖的名称标签。与已画边界重叠
        # 超过 0.9（按较小面积占比，双向收紧）视为重复；正常嵌套边界
        # （外层包内层）重叠比远低于此，不受影响。
        _rect_now = (x0, y0, x1, y1)
        _dup = False
        for _pr in _drawn_tb:
            _ix0, _iy0 = max(_pr[0], _rect_now[0]), max(_pr[1], _rect_now[1])
            _ix1, _iy1 = min(_pr[2], _rect_now[2]), min(_pr[3], _rect_now[3])
            _inter = max(0.0, _ix1 - _ix0) * max(0.0, _iy1 - _iy0)
            _a_now = (_rect_now[2] - _rect_now[0]) * (_rect_now[3] - _rect_now[1])
            _a_prev = (_pr[2] - _pr[0]) * (_pr[3] - _pr[1])
            if _a_now > 0 and _a_prev > 0 and _inter / min(_a_now, _a_prev) > 0.9:
                _dup = True
                break
        if _dup:
            continue
        _drawn_tb.append(_rect_now)
        px0, py0 = P(x0, y0)
        px1, py1 = P(x1, y1)
        # 容器底色：预混白减淡——多个边界矩形在异常模型里可能大面积
        # 重叠（历史记录里两个边界几何几乎重合），原色叠两层会形成
        # 明显灰色色块；45% 叠白后重叠也只剩极浅色差。
        draw.rounded_rectangle([px0, py0, px1, py1], radius=S(6),
                               fill=_blend_white(style["fill"], 0.45))
        # 名称标签（容器左上角）——标签底色仍用原色，保证在浅底上可读
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
        return _SPEC.flow_semantics(e.get("data"))

    # 排序：普通灰线先画，彩色/粗线后画（压在上面）
    def _edge_rank(e: dict) -> tuple:
        enc, pub, cross, _ = _edge_semantics(e)
        return (pub, enc, cross)

    # —— 正交路由：**唯一实现**在 dfd_layout_metrics.plan_edge_routes。
    # 渲染与「质量度量」必须走同一个函数，绝不能各留一份。
    # 历史教训：这里曾复制过一份布线循环，参数与共享实现慢慢漂移（渲染器
    # 用的是 slot 分散 + occupied 分离，plan_edge_routes 少了 pad_offset），
    # 结果「度量报的穿节点」和「图上真实画的线」根本不是同一条，
    # 排查方向被彻底带偏。现在只调用，不复制。
    from . import dfd_layout_metrics as _LM

    _routed: dict[str, list[tuple[float, float]]] = _LM.plan_edge_routes(diagram)

    # P1-1 标签避让：已放置标签的矩形（设备像素）+ 所有节点矩形。
    # 标签绘制按 _edge_rank 顺序进行，先画的先占位。
    _label_boxes: list[tuple[float, float, float, float]] = []
    _node_boxes_dev: list[tuple[float, float, float, float]] = []
    for _c in all_cells:
        if _c.get("source") and _c.get("target"):
            continue
        if _c.get("visible") is False:
            continue
        _nx0, _ny0, _nx1, _ny1 = _rect_of(_c)
        _node_boxes_dev.append((P(_nx0, _ny0)[0], P(_nx0, _ny0)[1],
                                P(_nx1, _ny1)[0], P(_nx1, _ny1)[1]))

    for e in sorted(edge_cells, key=_edge_rank):
        enc, pub, crosses, oos = _edge_semantics(e)
        src_cell = by_id.get((e.get("source") or {}).get("cell"))
        tgt_cell = by_id.get((e.get("target") or {}).get("cell"))
        if not src_cell or not tgt_cell:
            continue

        # 颜色 / 虚线 / 线宽：优先级判定收敛到 dfd_spec（两端同源）
        stroke, dash, w = _SPEC.flow_stroke_and_dash(enc, pub, crosses, oos)
        if pub:
            label_color = "#c2410c"
        elif enc:
            label_color = "#15803d"
        else:
            label_color = FLOW_DEFAULT_STROKE

        sx0, sy0, sx1, sy1 = _rect_of(src_cell)
        tx0, ty0, tx1, ty1 = _rect_of(tgt_cell)
        src_c = ((sx0 + sx1) / 2, (sy0 + sy1) / 2)
        tgt_c = ((tx0 + tx1) / 2, (ty0 + ty1) / 2)

        p_src = _anchor(src_cell, tgt_c)
        p_tgt = _anchor(tgt_cell, src_c)

        # 正交折线路由：使用上面**批量布好**的结果。
        # 为什么必须批量：A→B 与 B→A（DFD 里的「请求/响应」）用同一套规则
        # 独立计算会得到完全相同的路径，渲染成一条线；批量布线把已布路径
        # 作为占用通道传入，后续边自动让开 14px，形成两条可见平行线。
        pts: list[tuple[float, float]] = _routed.get(e.get("id") or "")
        if not pts:
            pts = [p_src, p_tgt]

        dev_pts = [P(x, y) for x, y in pts]
        line_w = max(1, int(S(w)))
        # P1-5 折线圆角：把直角拐点替换为贝塞尔采样弧，与前端 X6
        # connector 'rounded'(r=8) 观感一致。箭头方向仍用**原始末段**
        # 计算——圆角采样会在末尾插入弧点，用它算方向箭头会偏斜。
        smooth = _rounded_corners(dev_pts, S(8))
        draw.line(smooth, fill=stroke, width=line_w, joint="curve")
        if dash:
            _dashed_polyline(draw, smooth, stroke, line_w, dash, S)
        _arrow(draw, dev_pts[-2], dev_pts[-1], stroke,
               S(_SPEC.ARROW_SIZE_BACKEND), S(5))

        # 边标签：优先消费后端布局提示 labelT（沿边归一化位置）+ labelOffset
        # （法向偏移，模型坐标 px）——与前端 DfdGraph.vue 的消费方式一致，
        # 消除同一区域多条边标签叠压；无提示时退回第一段中点上方。
        #
        # P1-1 标签避让：后端 labelT/labelOffset 只保证**同一节点对**的多条流
        # 不重叠，不同节点对的标签仍可能在画布上撞在一起（尤其长标签）。
        # 这里额外做一层内容级碰撞检测：与已放置标签或节点矩形冲突时，
        # 沿法向依次试位（上/下/更远），全部失败则保留原位不丢标签。
        name = ((e.get("data") or {}).get("name") or "").strip()
        if name and f_edge:
            hint_txt = "[加密] " if enc else ("[公网] " if pub else "")
            label = hint_txt + name
            flow_hint = (diagram.get("layoutHints") or {}).get(
                (e.get("data") or {}).get("flowId") or "")
            try:
                bbox = draw.textbbox((0, 0), label, font=f_edge)
                tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
                pad = S(3)
                # —— 标签落点优先级（唯一真源在布局期）——
                # 1) layoutHints.labelX/labelY：布局期用 dfd_spec.place_edge_labels
                #    算定的**最终落点**（模型坐标，标签中心）。两端共用它，
                #    因此页面上与导出图里标签在同一位置。这是首选路径。
                # 2) labelT/labelOffset：仅给"沿边参数化位置"的旧模型/提示，
                #    运行时再本地避让一次（结果与布局期近似但不保证相同）。
                # 3) 都没有：第一段中点上方，纯兜底。
                _lx, _ly = flow_hint.get("labelX"), flow_hint.get("labelY")
                if isinstance(_lx, (int, float)) and isinstance(_ly, (int, float)):
                    # labelX/labelY 是标签**中心**（模型坐标）→ 转设备像素后
                    # 回退到"左上角"口径（绘制 API 用左上角）。
                    _cx, _cy = P(float(_lx), float(_ly))
                    tx, ty = _cx - tw / 2, _cy - th / 2
                    _label_boxes.append((
                        tx - pad, ty - S(2), tx + tw + pad, ty + th + S(2)))
                else:
                    if flow_hint and isinstance(flow_hint.get("labelT"), (int, float)):
                        tx, ty = _SPEC.point_on_polyline(
                            dev_pts, float(flow_hint["labelT"]),
                            float(flow_hint.get("labelOffset") or 0.0) * scale * SS)
                    else:
                        mid = dev_pts[len(dev_pts) // 2]
                        tx, ty = mid[0], mid[1]
                        ty -= S(14)
                    tx, ty = _place_label_avoiding(
                        tx, ty, tw, th, pad, _label_boxes, _node_boxes_dev, S
                    )
                draw.rectangle([tx - tw / 2 - pad, ty - S(2), tx + tw / 2 + pad, ty + th + S(2)],
                               fill=CANVAS_BG)
                draw.text((tx - tw / 2, ty), label, font=f_edge, fill=label_color)
            except Exception:
                pass

    # ---------- 7b. 跨界落点标记（dfd_spec.crossMarker，与前端同款） ----------
    # 跨信任边界的数据流在边界框上的穿越点画红色小方块，让「信任级变化」
    # 在图上可定位。历史上只有边虚线一种表达手段。
    # 用 6 步实际绘制的边界矩形（_drawn_tb，模型坐标），与视觉一致。
    if _drawn_tb:
        _msz = S(_SPEC.CROSS_MARKER_SIZE)
        for e in edge_cells:
            if not _edge_semantics(e)[2]:      # 只画 crosses=True
                continue
            _mpts = _routed.get(e.get("id") or "")
            if not _mpts or len(_mpts) < 2:
                continue
            for _br in _drawn_tb:
                for _seg_i in range(len(_mpts) - 1):
                    for _ix, _iy in _seg_rect_border(
                            _mpts[_seg_i], _mpts[_seg_i + 1], _br):
                        _dx, _dy = P(_ix, _iy)
                        draw.rectangle(
                            [_dx - _msz / 2, _dy - _msz / 2,
                             _dx + _msz / 2, _dy + _msz / 2],
                            fill=_SPEC.CROSS_MARKER_FILL,
                        )

    # ---------- 8. 第四层：普通节点 ----------
    # 造型由 dfd_spec 的 figure 决定（与前端 refD/rect 同源）：
    #   capsule  —— 外部实体（全圆角胶囊）
    #   cylinder —— 数据存储 / AI 存储类（圆柱，DFD 标准记法）
    #   rounded  —— 处理过程 / 信任边界 / 其余 AI 元素（圆角矩形）
    # AI 元素的 emoji 图标（spec.icon）在 PNG 里刻意不画：Docker 容器
    # 字体无彩色 emoji 字形，会渲染成「豆腐块」，反而毁掉商业观感；
    # 类型语义由名称下方的类型小字（label_zh）表达。
    for c in normal_nodes:
        shape = c.get("shape") or "tm.Process"
        sp = _SPEC.node_spec(shape)
        figure = sp["figure"]
        data = c.get("data") or {}
        name = data.get("name") or ""

        x0, y0, x1, y1 = _rect_of(c)
        px0, py0 = P(x0, y0)
        px1, py1 = P(x1, y1)
        h = py1 - py0
        lw = max(1, int(S(1.6)))

        if figure == "cylinder":
            _cylinder(draw, px0, py0, px1, py1, sp["fill"], sp["stroke"], lw)
            cx, cy = (px0 + px1) / 2, py0 + h * _SPEC.CYLINDER_LABEL_CENTER_RATIO
            text_zone_w = (px1 - px0) - S(24)
            max_lines = 2     # 可视文字带只有中间 60%，防止压到顶盖/底弧
        else:
            # 胶囊半径不得超过高度一半（防 PIL 圆角溢出变形）
            r = min(sp["radius"], h / 2.0) if figure == "capsule" else sp["radius"]
            draw.rounded_rectangle([px0, py0, px1, py1], radius=S(r),
                                   fill=sp["fill"], outline=sp["stroke"], width=lw)
            cx, cy = (px0 + px1) / 2, (py0 + py1) / 2
            text_zone_w = (px1 - px0) - (S(36) if figure == "capsule" else S(10))
            max_lines = 3

        if f_node and name:
            tag = sp["label_zh"]
            lines = _wrap_text(draw, name, f_node, max(40, text_zone_w), max_lines=max_lines)
            if tag:
                lines = lines + [tag]
            _centered_text(draw, lines, cx, cy, f_node, sp["text"], S)

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

    _legend(draw, img, f_edge, f_lane, S, _legend_origin_y)

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
    """沿折线按弧长比例 t∈[0,1] 取点 + 法向偏移（**委托** dfd_spec 唯一实现）。

    本函数历史上在此处有一份私有实现，布局期又需要同一口径，遂提升到
    dfd_spec.point_on_polyline。这里只保留同名薄包装，避免调用方大改，
    也杜绝「两处各有一份弧长采样」的再次漂移。
    """
    return _SPEC.point_on_polyline(pts, t, normal_offset)


def _cylinder(draw, px0: float, py0: float, px1: float, py1: float,
              fill: str, stroke: str, lw: int) -> None:
    """圆柱造型（数据存储的 DFD 标准记法）。

    几何与前端 refD path 严格同源：顶盖椭圆半高与底部下凸弧均取
    dfd_spec.CYLINDER_CAP_RATIO / CYLINDER_BOTTOM_BULGE（各占节点高 20%），
    顶盖弦线 = 前端的 capLineY。
    """
    h = max(4.0, py1 - py0)
    cap = h * _SPEC.CYLINDER_CAP_RATIO
    # 填充：主体矩形 + 底部下凸半弧 + 顶盖椭圆（三者并成完整柱体）
    draw.rectangle([px0, py0 + cap, px1, py1 - cap], fill=fill)
    draw.ellipse([px0, py1 - 2 * cap, px1, py1], fill=fill)
    draw.ellipse([px0, py0, px1, py0 + 2 * cap], fill=fill)
    # 轮廓：左右边线 + 底部下半弧 + 顶盖完整椭圆 + 顶盖弦线
    draw.line([(px0, py0 + cap), (px0, py1 - cap)], fill=stroke, width=lw)
    draw.line([(px1, py0 + cap), (px1, py1 - cap)], fill=stroke, width=lw)
    draw.arc([px0, py1 - 2 * cap, px1, py1], start=0, end=180,
             fill=stroke, width=lw)
    draw.ellipse([px0, py0, px1, py0 + 2 * cap], outline=stroke, width=lw)
    draw.line([(px0, py0 + cap), (px1, py0 + cap)], fill=stroke, width=lw)


def _seg_rect_border(p1: tuple[float, float], p2: tuple[float, float],
                     rect: tuple[float, float, float, float]
                     ) -> list[tuple[float, float]]:
    """线段与矩形**边框**的全部交点（角点去重）。

    用于跨信任边界标记：跨界流的折线穿过边界框边框的位置就是
    「信任级变化」的发生点。线段整体在框外/框内时返回空列表。
    """
    x0, y0, x1, y1 = rect
    ax, ay = p1
    bx, by = p2
    dx, dy = bx - ax, by - ay
    pts: list[tuple[float, float]] = []
    if dx:
        for bx_ in (x0, x1):
            t = (bx_ - ax) / dx
            if 0.0 <= t <= 1.0:
                y = ay + dy * t
                if y0 - 1e-6 <= y <= y1 + 1e-6:
                    pts.append((bx_, y))
    if dy:
        for by_ in (y0, y1):
            t = (by_ - ay) / dy
            if 0.0 <= t <= 1.0:
                x = ax + dx * t
                if x0 - 1e-6 <= x <= x1 + 1e-6:
                    pts.append((x, by_))
    out: list[tuple[float, float]] = []
    for p in pts:
        if all(abs(p[0] - q[0]) > 0.5 or abs(p[1] - q[1]) > 0.5 for q in out):
            out.append(p)
    return out


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


def _place_label_avoiding(
    tx: float, ty: float, tw: float, th: float, pad: float,
    placed: list, node_boxes: list, S,
) -> tuple[float, float]:
    """把边标签放到不与「已放置标签 / 节点矩形」冲突的位置。

    策略：先试原位；冲突则沿法向（垂直方向）上下交替加大偏移试位。
    全部尝试失败时返回原位——**宁可轻微叠压也不能丢标签**，标签丢失
    比叠压严重得多（用户看不到数据流语义）。

    副作用：选中位置会写入 placed，供后续标签避让。
    """
    def _rect(x: float, y: float) -> tuple[float, float, float, float]:
        return (x - tw / 2 - pad, y - S(2), x + tw / 2 + pad, y + th + S(2))

    def _hit(r) -> bool:
        for o in placed:
            if (min(r[2], o[2]) - max(r[0], o[0]) > 0
                    and min(r[3], o[3]) - max(r[1], o[1]) > 0):
                return True
        for nb in node_boxes:
            # 标签压在节点上是明显缺陷，但允许少量贴边（>2px 重叠才算）
            if (min(r[2], nb[2]) - max(r[0], nb[0]) > 2
                    and min(r[3], nb[3]) - max(r[1], nb[1]) > 2):
                return True
        return False

    step = max(S(13), th + S(6))
    best = (tx, ty)
    cands = [(tx, ty)]
    for k in range(1, 7):
        cands.append((tx, ty - step * k))   # 优先向上（正交图的常见空白区）
        cands.append((tx, ty + step * k))
    for cx, cy in cands:
        r = _rect(cx, cy)
        if not _hit(r):
            placed.append(r)
            return cx, cy
    placed.append(_rect(*best))
    return best


def _rounded_corners(pts, radius: float, steps: int = 6):
    """把正交折线的直角拐点替换成 1/4 圆弧的密集采样点。

    PIL 的 draw.line 没有 join='round'，直接画折线在拐角处会出现
    「缺角」（外角露白、内角重叠发黑）。这里在每个拐点上插入一段
    steps 段的圆弧采样，观感与前端 X6 connector rounded 一致。
    """
    if len(pts) < 3 or radius <= 0.5:
        return pts
    out = [pts[0]]
    for i in range(1, len(pts) - 1):
        p0, p1, p2 = pts[i - 1], pts[i], pts[i + 1]
        v0 = (p0[0] - p1[0], p0[1] - p1[1])
        v2 = (p2[0] - p1[0], p2[1] - p1[1])
        l0 = math.hypot(*v0)
        l2 = math.hypot(*v2)
        if l0 < 1e-6 or l2 < 1e-6:
            out.append(p1)
            continue
        u0 = (v0[0] / l0, v0[1] / l0)
        u2 = (v2[0] / l2, v2[1] / l2)
        # 近似共线（无实际拐角）时不切角，直接保留
        if abs(u0[0] * u2[0] + u0[1] * u2[1]) > 0.9995:
            out.append(p1)
            continue
        r = min(radius, l0 / 2.0, l2 / 2.0)
        if r < 0.5:
            out.append(p1)
            continue
        a = (p1[0] + u0[0] * r, p1[1] + u0[1] * r)
        b = (p1[0] + u2[0] * r, p1[1] + u2[1] * r)
        out.append(a)
        # 二次贝塞尔（以 p1 为控制点）采样，等价于圆角弧
        for s in range(1, steps):
            t = s / float(steps)
            mt = 1.0 - t
            out.append((
                mt * mt * a[0] + 2 * mt * t * p1[0] + t * t * b[0],
                mt * mt * a[1] + 2 * mt * t * p1[1] + t * t * b[1],
            ))
        out.append(b)
    out.append(pts[-1])
    return out


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


def _blend_white(hex_color: str, alpha: float) -> str:
    """把颜色按透明度 alpha 叠到白底上（PIL 无真 alpha 合成，预先混色）。

    信任边界底色用它减淡：异常模型里多个边界矩形可能大面积重叠（历史
    记录里两个边界几何几乎重合），原色叠两层会形成明显的灰色色块；
    预混白后即使重叠也只剩极浅的冷暖差。
    """
    h = (hex_color or "#ffffff").lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    mix = lambda c: int(round(c * alpha + 255 * (1 - alpha)))  # noqa: E731
    return f"#{mix(r):02x}{mix(g):02x}{mix(b):02x}"


def _boundary_children_bbox(boundary: dict, cells: list[dict]):
    """边界内子节点的包围盒（中心点落在边界内即算包含），无子节点返回 None。

    建模产物里边界框可能比实际内容大很多（布局兜底尺寸/推断偏差），
    渲染时把边框收缩到真实内容范围，避免大片空白也被涂上底色。
    """
    bx0, by0, bx1, by1 = _rect_of(boundary)
    x0 = y0 = x1 = y1 = None
    for c in cells:
        if c is boundary or c.get("shape") == "tm.BoundaryBox":
            continue
        if c.get("source") and c.get("target"):
            continue
        cx0, cy0, cx1, cy1 = _rect_of(c)
        ccx, ccy = (cx0 + cx1) / 2, (cy0 + cy1) / 2
        if bx0 <= ccx <= bx1 and by0 <= ccy <= by1:
            x0 = cx0 if x0 is None else min(x0, cx0)
            y0 = cy0 if y0 is None else min(y0, cy0)
            x1 = cx1 if x1 is None else max(x1, cx1)
            y1 = cy1 if y1 is None else max(y1, cy1)
    return (x0, y0, x1, y1) if x0 is not None else None


def _mini_shape(draw, shape: str, x0: float, y0: float, x1: float, y1: float, S) -> None:
    """图例用的节点迷你造型（与正式节点同几何规则，缩到 12px 高）。"""
    sp = _SPEC.node_spec(shape)
    figure = sp["figure"]
    lw = 1
    if figure == "cylinder":
        _cylinder(draw, x0, y0, x1, y1, sp["fill"], sp["stroke"], lw)
    elif shape == "tm.BoundaryBox":
        draw.rectangle([x0, y0, x1, y1], fill=_blend_white(sp["fill"], 0.45))
        _dashed_rect(draw, x0, y0, x1, y1, sp["stroke"], lw, (3, 2), S)
    else:
        h = y1 - y0
        r = min(sp["radius"], h / 2.0) if figure == "capsule" else min(sp["radius"], h / 2.0, 4.0)
        draw.rounded_rectangle([x0, y0, x1, y1], radius=max(1.0, r * 0.5),
                               fill=sp["fill"], outline=sp["stroke"], width=lw)


def _legend_items(draw, font, S) -> tuple[list, list]:
    """图例条目（节点造型 + 线型语义）。

    条目唯一来源是 dfd_spec 的 LEGEND_NODE_SHAPES / LEGEND_FLOW_ITEMS——
    测量（_legend_box_size）与绘制（_legend）共用，两边看到的条目
    永远一致。
    """
    node_items = [(sh, _SPEC.node_spec(sh)["label_zh"])
                  for sh in _SPEC.LEGEND_NODE_SHAPES]
    flow_items = []
    for it in _SPEC.LEGEND_FLOW_ITEMS:
        stroke, dash, _w = _SPEC.flow_stroke_and_dash(
            it["enc"], it["pub"], it["cross"], it["oos"])
        flow_items.append((stroke, dash, it["label_zh"]))
    return node_items, flow_items


def _legend_box_size(draw, font, S, canvas_w: float) -> tuple[float, float, float, float, float]:
    """图例盒尺寸与列布局（超采样画布像素）。

    返回 (box_w, box_h, col1_w, col2_w, title_h)。渲染入口预留图例带
    与 _legend 实际绘制共用本函数，两边必然一致——预留带高度正好
    装下图例盒，不多不少。
    """
    pad = S(10)
    row_h = S(17)
    col_gap = S(24)
    sample_w = S(34)

    node_items, flow_items = _legend_items(draw, font, S)

    def _tlen(t: str) -> float:
        if not font:
            return S(len(t) * 11.0)
        bbox = draw.textbbox((0, 0), t, font=font)
        return bbox[2] - bbox[0]

    shape_label_w = max((_tlen(t) for _, t in node_items), default=S(40))
    flow_label_w = max((_tlen(t) for _, _, t in flow_items), default=S(40))
    col1_w = sample_w + S(6) + shape_label_w
    col2_w = sample_w + S(6) + flow_label_w
    rows = max(len(node_items) + 1, len(flow_items))
    title_h = row_h + S(4)
    box_w = pad * 2 + col1_w + col_gap + col2_w
    box_h = title_h + rows * row_h + pad * 2
    # 画布过窄时收缩盒宽，保证图例不越界
    if box_w > canvas_w - pad * 4:
        box_w = canvas_w - pad * 4
    return box_w, box_h, col1_w, col2_w, title_h


def _legend(draw, img, font, title_font, S, origin_y=None) -> None:
    """图例：节点造型 + 线型语义 + 威胁徽标。

    origin_y 给定时画在内容下方**预留带**内（推荐路径，绝不遮挡
    内容）；为 None 时退回左下角叠画（仅直接调用本函数时的兜底）。
    条目唯一来源是 dfd_spec 的 LEGEND_NODE_SHAPES / LEGEND_FLOW_ITEMS /
    BADGE_LEGEND_ZH——与 Word 报告的图例表、前端图例消费同一份定义，
    规格改动三处自动同步。
    """
    try:
        W, H = img.size
        pad = S(10)
        row_h = S(17)
        col_gap = S(24)
        sample_w = S(34)
        box_w, box_h, col1_w, col2_w, title_h = _legend_box_size(draw, font, S, W)
        node_items, flow_items = _legend_items(draw, font, S)
        bx = pad * 2
        if origin_y is not None:
            by = origin_y
            if by + box_h > H:
                by = H - box_h - pad  # 预留带被取整裁短时的兜底
        else:
            by = H - box_h - pad * 2
        if by < 0:
            return  # 画布过小：宁可无图例也不遮挡内容
        draw.rectangle([bx, by, bx + box_w, by + box_h],
                       fill="#ffffff", outline="#e2e8f0")
        if title_font:
            draw.text((bx + pad, by + S(3)), "图例", font=title_font, fill="#334155")

        # 第一列：节点造型（含徽标行）
        cy = by + title_h + pad - row_h / 2
        for sh, label in node_items:
            cy += row_h
            scy = cy + row_h / 2
            sx0, sx1 = bx + pad, bx + pad + sample_w
            sy0, sy1 = scy - S(6), scy + S(6)
            _mini_shape(draw, sh, sx0, sy0, sx1, sy1, S)
            if font:
                draw.text((sx1 + S(6), scy - S(6)), label, font=font, fill="#475569")
        # 徽标行
        cy += row_h
        scy = cy + row_h / 2
        _badge(draw, bx + pad + sample_w, scy + S(7), "N", font, S)
        if font:
            draw.text((bx + pad + sample_w + S(6), scy - S(6)),
                      _SPEC.BADGE_LEGEND_ZH, font=font, fill="#475569")

        # 第二列：线型语义
        cx0 = bx + pad + col1_w + col_gap
        cy = by + title_h + pad - row_h / 2
        for stroke, dash, label in flow_items:
            cy += row_h
            lcy = cy + row_h / 2
            lx0, lx1 = cx0, cx0 + sample_w
            if dash:
                _dashed_polyline(draw, [(lx0, lcy), (lx1, lcy)], stroke, 2, dash, S)
            else:
                draw.line([(lx0, lcy), (lx1, lcy)], fill=stroke, width=2)
            if font:
                draw.text((lx1 + S(6), lcy - S(6)), label, font=font, fill="#475569")
    except Exception as exc:
        logger.debug("DFD 图例绘制失败（忽略）: %s", exc)
