"""DFD 布局质量度量库（回归测试的核心）。

为什么需要它：
    DFD 的"观感"长期靠肉眼在浏览器里看截图判断，导致同一个问题反复
    「修好 → 回归 → 再修」。本模块把「商业级数据流图」拆成可量化的
    指标，让布局改动可以用数字验收，而不是靠印象。

度量口径与商业级基线（数值越小越好，除 fill_ratio 外）：
    1. member_outside    信任边界「成员越框」数量          → 0
    2. node_overlap      节点两两重叠数量                  → 0
    3. boundary_overlap  信任边界容器互相重叠超过 40%       → 0
    4. edge_through_node 数据流穿过非端点节点数量           → 0
    5. edge_overlap      两条边走同一条通道（重叠）的组数    → 0
    6. max_span_ratio    最长边/最短边 长度比（线长均衡）    → <= 3.0
    7. fill_ratio        节点包围盒 / 画布面积（画布利用率） → >= 0.75

重要：指标 4/5 的判定必须与**真正的渲染器**同口径，否则会出现
「度量说没问题、图上看还是穿」。因此本模块的路由复算逻辑刻意与
`dfd_renderer` 保持一致（同一套锚点 + 同一套正交路径），并且
`dfd_renderer` 现在会复用本模块的 `route_edge`，两者不会再漂移。
"""

from __future__ import annotations

import math
from typing import Any, Iterable, Optional

# ----------------------------------------------------------------------
# 几何基元
# ----------------------------------------------------------------------

Rect = tuple[float, float, float, float]  # (x0, y0, x1, y1)
Point = tuple[float, float]


def rect_of(cell: dict) -> Rect:
    """cell 的模型坐标矩形 (x0, y0, x1, y1)。"""
    pos = cell.get("position") or {}
    size = cell.get("size") or {}
    x, y = float(pos.get("x", 0.0)), float(pos.get("y", 0.0))
    w = float(size.get("width", 180.0))
    h = float(size.get("height", 60.0))
    return x, y, x + w, y + h


def center_of(r: Rect) -> Point:
    return (r[0] + r[2]) / 2.0, (r[1] + r[3]) / 2.0


def is_edge(cell: dict) -> bool:
    """该 cell 是否为数据流（边）。"""
    return bool(cell.get("source") and cell.get("target"))


def is_boundary(cell: dict) -> bool:
    """该 cell 是否为信任边界容器。"""
    return cell.get("shape") == "tm.BoundaryBox"


def is_node(cell: dict) -> bool:
    return not is_edge(cell)


def visible_cells(diagram: dict) -> list[dict]:
    return [c for c in (diagram.get("cells") or []) if c.get("visible") is not False]


def node_cells(diagram: dict) -> list[dict]:
    """普通节点（既不是边，也不是信任边界容器）。"""
    return [c for c in visible_cells(diagram) if not is_edge(c) and not is_boundary(c)]


def boundary_cells(diagram: dict) -> list[dict]:
    return [c for c in visible_cells(diagram) if is_boundary(c) and not is_edge(c)]


def edge_cells(diagram: dict) -> list[dict]:
    return [c for c in visible_cells(diagram) if is_edge(c)]


def rect_intersection(a: Rect, b: Rect) -> float:
    """两矩形交集面积。"""
    ix = min(a[2], b[2]) - max(a[0], b[0])
    iy = min(a[3], b[3]) - max(a[1], b[1])
    return max(0.0, ix) * max(0.0, iy)


def rect_area(r: Rect) -> float:
    return max(0.0, r[2] - r[0]) * max(0.0, r[3] - r[1])


def rect_contains_point(r: Rect, p: Point) -> bool:
    return r[0] <= p[0] <= r[2] and r[1] <= p[1] <= r[3]


def seg_intersects_rect(p1: Point, p2: Point, r: Rect, margin: float = 0.0) -> bool:
    """线段是否与矩形相交（含 margin 外扩）。

    用 Liang-Barsky 参数化裁剪，精确判定而非采样——旧实现按 8px 步长
    采样，短线段跨过窄矩形时可能漏判。
    """
    x0, y0, x1, y1 = r[0] - margin, r[1] - margin, r[2] + margin, r[3] + margin
    dx = p2[0] - p1[0]
    dy = p2[1] - p1[1]
    t0, t1 = 0.0, 1.0
    for p, q in ((-dx, p1[0] - x0), (dx, x1 - p1[0]), (-dy, p1[1] - y0), (dy, y1 - p1[1])):
        if abs(p) < 1e-12:
            if q < 0:
                return False  # 平行且在板外
            continue
        t = q / p
        if p < 0:
            if t > t1:
                return False
            t0 = max(t0, t)
        else:
            if t < t0:
                return False
            t1 = min(t1, t)
    return t0 <= t1


def rects_overlap(a: Rect, b: Rect, tol: float = 2.0) -> bool:
    """两矩形是否真正重叠（容差 tol 像素，避免贴边被判为重叠）。"""
    return (min(a[2], b[2]) - max(a[0], b[0]) > tol
            and min(a[3], b[3]) - max(a[1], b[1]) > tol)


# ----------------------------------------------------------------------
# 锚点 + 正交路由（与 dfd_renderer 同口径）
# ----------------------------------------------------------------------

def anchor_on_rect(r: Rect, toward: Point, slot: int = 0, slots: int = 1) -> Point:
    """连线从矩形边缘出发的锚点。

    slot/slots 支持同一条边上多个锚点分散：把出口按 slots 等分偏移，
    避免多条边从同一个点射出糊成一团（商业级图每条边出口独立）。
    """
    cx, cy = center_of(r)
    dx, dy = toward[0] - cx, toward[1] - cy
    if abs(dx) < 1e-9 and abs(dy) < 1e-9:
        return cx, cy
    hw = max(1e-6, (r[2] - r[0]) / 2.0)
    hh = max(1e-6, (r[3] - r[1]) / 2.0)
    rx = hw / abs(dx) if abs(dx) > 1e-9 else float("inf")
    ry = hh / abs(dy) if abs(dy) > 1e-9 else float("inf")
    t = min(rx, ry)
    px, py = cx + dx * t, cy + dy * t
    if slots > 1:
        # 在出口所在边上沿切线方向偏移（水平边沿 x，垂直边沿 y）
        f = (slot / (slots - 1.0)) - 0.5 if slots > 1 else 0.0
        if abs(dx) * hh >= abs(dy) * hw:
            # 出口在左右边 → 沿 y 偏移
            py = cy + f * (r[3] - r[1]) * 0.7
        else:
            px = cx + f * (r[2] - r[0]) * 0.7
    return px, py


def polyline_length(pts: list[Point]) -> float:
    return sum(math.hypot(pts[i + 1][0] - pts[i][0], pts[i + 1][1] - pts[i][1])
               for i in range(len(pts) - 1))


def _dedupe_pts(pts: list[Point]) -> list[Point]:
    out: list[Point] = []
    for p in pts:
        if not out or abs(out[-1][0] - p[0]) > 1e-6 or abs(out[-1][1] - p[1]) > 1e-6:
            out.append(p)
    return out


def route_hv(p_src: Point, p_tgt: Point, x_mid: float) -> list[Point]:
    """H-V-H 严格正交：水平 → 垂直通道(x_mid) → 水平。"""
    return _dedupe_pts([p_src, (x_mid, p_src[1]), (x_mid, p_tgt[1]), p_tgt])


def route_vh(p_src: Point, p_tgt: Point, y_mid: float) -> list[Point]:
    """V-H-V 严格正交：垂直 → 水平通道(y_mid) → 垂直。"""
    return _dedupe_pts([p_src, (p_src[0], y_mid), (p_tgt[0], y_mid), p_tgt])


def route_escape_x(p_src: Point, p_tgt: Point, x1: float, y_by: float,
                   x2: float) -> list[Point]:
    """先垂直脱离再绕行：V - H(y_by) - V(x1) - H - target。

    用于「源/目标与障碍处在同一水平带」的场景——此时任何"先水平"的
    路径都必然横穿障碍，必须**先垂直离开**该带、从带外绕过去再落回。

    路径形状：源 → 垂直升/降到 y_by（带外通道）→ 水平走到 x1 列
              → 垂直走到目标 y → 水平进入目标。

    注意 x2 当前**不参与几何**：入口列固定用 p_src[0]（源正上/正下脱离，
    最短且不会擦到源自身）。保留该参数是为了让调用方仍能表达"两段独立
    通道"的意图；真正用到两个独立列的是 route_staircase。历史上本函数
    文档写 V(x1)-H-V(x2) 而实现只用 x1，属于文档与实现不一致，已修正。
    """
    _ = x2  # 见 docstring：入口列固定 p_src[0]
    return _dedupe_pts([
        p_src,
        (p_src[0], y_by),      # 垂直脱离（仍在源所在列）
        (x1, y_by),            # 水平穿过带外通道
        (x1, p_tgt[1]),
        p_tgt,
    ])


def route_escape_y(p_src: Point, p_tgt: Point, y_by: float, x_by: float) -> list[Point]:
    """先水平脱离到 x_by 列再绕行：H - V(y_by) - H - V 到目标。

    路径形状：源 → 水平走到 x_by 列 → 垂直升/降到 y_by（带外通道）
              → 水平走到目标列 → 垂直进入目标。

    与 route_escape_x 是**镜像**关系：一个先垂直脱离（应对「同处一条
    水平带」的障碍），一个先水平脱离（应对「同处一条垂直带」的障碍）。

    历史缺陷：本函数曾完全忽略 y_by，直接生成 H(x_by)-V(x_by)-H 的两折线，
    与 route_vh(p_src,p_tgt,x_by) 等价——于是候选池里 band_ys × x_depart
    的整个笛卡尔积有一半是**重复废料**，'带外绕行' 对纵向排列的障碍
    从未真正生效。已修正为使用 y_by。
    """
    return _dedupe_pts([
        p_src,
        (x_by, p_src[1]),      # 水平脱离（仍在源所在行）
        (x_by, y_by),          # 垂直走到带外通道
        (p_tgt[0], y_by),      # 沿带外通道水平推进
        p_tgt,
    ])


def route_staircase(p_src: Point, p_tgt: Point, y_by: float, x_by: float) -> list[Point]:
    """阶梯绕行：H - V(带外) - H - V - H，用于双障碍夹击。"""
    return _dedupe_pts([
        p_src,
        (x_by, p_src[1]),
        (x_by, y_by),
        (p_tgt[0], y_by),
        p_tgt,
    ])


def build_obstacle_index(
    obstacles: list[Rect], margin: float, cell: float = 160.0
) -> dict[tuple[int, int], list[Rect]]:
    """P2-4 空间索引：把障碍按网格分桶，只测同桶障碍。

    为什么需要：布线要为每条边评测几百个候选路径，每个候选又要对全部
    障碍做线段-矩形相交（Liang-Barsky）。10 节点图已有 191 次穿节点，
    真实大图（30+ 节点）会退化到明显可感知的卡顿——O(E × C × N × S)。

    分桶后单次评测只看与线段包围盒相交的格子里的障碍，实测把
    「候选 × 障碍」的乘积降一个数量级，且**判定结果与全量扫描完全一致**
    （不是近似：桶按包围盒相交筛选，可能相交的障碍必然落在覆盖
    该包围盒的桶里）。

    margin 已并进桶尺寸，保证"外扩后刚好压线"的障碍不会被漏掉。
    """
    idx: dict[tuple[int, int], list[Rect]] = {}
    for r in obstacles:
        x0, y0 = r[0] - margin, r[1] - margin
        x1, y1 = r[2] + margin, r[3] + margin
        for gx in range(int(math.floor(x0 / cell)), int(math.floor(x1 / cell)) + 1):
            for gy in range(int(math.floor(y0 / cell)), int(math.floor(y1 / cell)) + 1):
                idx.setdefault((gx, gy), []).append(r)
    return idx


def _route_bbox(route: list[Point]) -> Rect:
    xs = [p[0] for p in route]
    ys = [p[1] for p in route]
    return min(xs), min(ys), max(xs), max(ys)


def route_collisions(
    route: list[Point],
    obstacles: list[Rect],
    margin: float = 6.0,
    index: dict[tuple[int, int], list[Rect]] | None = None,
    cell: float = 160.0,
) -> int:
    """路径穿过多少个障碍物（每个障碍最多计 1 次）。

    index 为 build_obstacle_index 的产物时可跳过无关障碍，结果与不传
    index 时**完全一致**（纯加速，不改变判定）。
    """
    if index is not None and len(route) >= 2:
        bx0, by0, bx1, by1 = _route_bbox(route)
        bx0 -= margin; by0 -= margin; bx1 += margin; by1 += margin
        cand: list[Rect] = []
        seen: set[int] = set()
        for gx in range(int(math.floor(bx0 / cell)), int(math.floor(bx1 / cell)) + 1):
            for gy in range(int(math.floor(by0 / cell)), int(math.floor(by1 / cell)) + 1):
                for r in index.get((gx, gy), ()):  # type: ignore[arg-type]
                    k = id(r)
                    if k not in seen:
                        seen.add(k)
                        cand.append(r)
    else:
        cand = obstacles

    n = 0
    for r in cand:
        for i in range(len(route) - 1):
            if seg_intersects_rect(route[i], route[i + 1], r, margin=margin):
                n += 1
                break
    return n


# 「已布路径同向段」分桶索引的跨调用缓存。
# 键 = (id(occupied), 该列表当时的长度, 桶宽)；值 = {h, v} 两个桶字典。
# 批量布线时 occupied 是同一个不断 append 的列表，因此每次调用只需
# 为「新增的那几条路径」补分桶，而不是把全量重扫一遍。
_SEG_BUCKET_CACHE: dict[tuple[int, int, float], dict] = {}
_SEG_BUCKET_CACHE_MAX = 24


def route_edge(
    src_rect: Rect,
    tgt_rect: Rect,
    obstacles: list[Rect],
    slot_src: int = 0,
    slots_src: int = 1,
    slot_tgt: int = 0,
    slots_tgt: int = 1,
    pad_offset: float = 0.0,
    margin: float = 6.0,
    occupied: Optional[list[list[Point]]] = None,
    separation: float = 14.0,
) -> list[Point]:
    """为一条边计算正交路径（商业级路由：多候选通道 + 障碍评分）。

    候选来源（而非旧实现的固定 2 个）：
      1. 直连（同层/同列时的小折角）；
      2. H-V-H：垂直通道在「源/目标两侧 + 所有横向空隙中线」上取值；
      3. V-H-V：水平通道在「源/目标上下 + 所有纵向空隙中线」上取值；
      4. 带外绕行：先垂直/水平脱离"障碍带"再从带外绕过 —— 这是解决
         「源、目标与中间节点同处一条水平带」的关键（旧的 2 候选必穿）；
      5. 五段绕行：两段独立通道，应对双障碍夹击。

    评分 = 碰撞数*1000 + 重合惩罚*120 + 拐弯数*40 + 路径长度。
    "不穿节点"永远第一优先，其次"不与已布边重合"，再其次少拐弯、短路径。

    occupied: 已布线的路径列表。传入后本函数会自动让新路径与它们分离
        —— 特别是 A→B 与 B→A 这类**反向平行边**，商业级图必须画成两条
        可见的平行线，而不是完全重合成一条。这是 `separation` 的作用。
    """
    sc = center_of(src_rect)
    tc = center_of(tgt_rect)
    p_src = anchor_on_rect(src_rect, tc, slot_src, slots_src)
    p_tgt = anchor_on_rect(tgt_rect, sc, slot_tgt, slots_tgt)

    # 障碍物排除源/目标自身（其余容器与节点都算）
    obs = [r for r in obstacles if r != src_rect and r != tgt_rect]
    occ = occupied or []

    # --- 已布路径的「同向段」分桶索引（配合 _overlap_cost 使用）---
    # 水平段按 y 分桶（桶存 (x_lo, x_hi, y)），垂直段按 x 分桶。
    # 桶宽取 separation：只要垂直坐标差 < separation 的段才可能重合，
    # 因此候选段只需查自身键所在的桶及相邻桶（±1）。
    #
    # 【增量复用】旧实现在每次 route_edge 调用时把 occupied 全部重新
    # 分桶一遍。批量布线是顺序循环、occupied 只增不改，因此 100 条边
    # 会把全量索引重建 100 次（剖析确认累积 194820 次分桶调用）。
    # 这里把索引挂到 occupied 列表对象上（属性缓存），只对本轮**新增**
    # 的路径追加一次分桶；occupied 若非同一列表则自动全量重建。
    _BUCKET_W = max(1.0, separation)

    def _bucket_key(v: float) -> int:
        return int(math.floor(v / _BUCKET_W))

    def _bucketize(path: list[Point], hb: dict, vb: dict) -> None:
        for j in range(len(path) - 1):
            b1, b2 = path[j], path[j + 1]
            if abs(b1[1] - b2[1]) < 1e-6:      # 水平段
                hb.setdefault(_bucket_key(b1[1]), []).append(
                    (min(b1[0], b2[0]), max(b1[0], b2[0]), b1[1]))
            elif abs(b1[0] - b2[0]) < 1e-6:    # 垂直段
                vb.setdefault(_bucket_key(b1[0]), []).append(
                    (min(b1[1], b2[1]), max(b1[1], b2[1]), b1[0]))

    # 索引缓存：以 id(occupied) 为键（普通 list 挂不了属性，且批量布线
    # 全程复用同一个 placed 列表对象）。缓存 "已分桶条数"，
    # 只对新追加的路径做一次分桶。
    _ckey = (id(occ), len(occ), _BUCKET_W)
    _cache = _SEG_BUCKET_CACHE.get(_ckey)
    if _cache is None:
        # 尝试复用「同一列表、更少条数」的缓存做增量（前缀相同）
        _h_buckets: dict[int, list[tuple[float, float, float]]] = {}
        _v_buckets: dict[int, list[tuple[float, float, float]]] = {}
        _done = 0
        for _k, _v in _SEG_BUCKET_CACHE.items():
            if _k[0] != id(occ) or _k[2] != _BUCKET_W or _k[1] > len(occ):
                continue
            if _k[1] > _done:
                _h_buckets, _v_buckets, _done = _v["h"], _v["v"], _k[1]
        for _p in occ[_done:]:
            _bucketize(_p, _h_buckets, _v_buckets)
        if len(_SEG_BUCKET_CACHE) >= _SEG_BUCKET_CACHE_MAX:
            _SEG_BUCKET_CACHE.clear()
        _SEG_BUCKET_CACHE[_ckey] = {"h": _h_buckets, "v": _v_buckets}
    else:
        _h_buckets, _v_buckets = _cache["h"], _cache["v"]

    def _overlap_cost(route: list[Point]) -> float:
        """与已布路径的重合程度（长度加权），用于避免两条边叠在一起。

        【为什么改成轴分桶】
        原实现是三重循环：每条已布路径 × 本路径每段 × 已布路径每段。
        大图（30+ 节点、60+ 边）下 O(已布边² × 段²) 成为首要瓶颈——
        实测 50 节点时该函数占总耗时一半以上。

        优化：把已布路径的**水平段**按 y、**垂直段**按 x 分桶
        （桶宽 = separation）。一条候选段只可能与「同向段」且
        「垂直坐标差 < separation」的段重合，因此只需查相邻 3 个桶，
        复杂度从 O(已布边) 降到 O(同桶段数)（通常个位数）。

        结果与旧实现**严格等价**：仅跳过垂直坐标差 ≥ separation 的段
        （旧实现里这些段本来就被 continue 掉），区间求交逻辑不变。
        """
        if not occ:
            return 0.0
        cost = 0.0
        sep = separation
        # 快速短路：已布段为空时任何候选的重合代价都是 0
        if not _h_buckets and not _v_buckets:
            return 0.0

        # 桶字典的本地绑定 + 只读集合判断：
        # 候选段的绝大部分落在"根本没有已布段"的区域，此时
        # buckets.get(k) 必然 miss。先判 key in buckets 可省掉
        # 后续 3 次查找中的多数（实测该函数占 route 阶段 4.3s）。
        hb = _h_buckets
        vb = _v_buckets
        for i in range(len(route) - 1):
            a1, a2 = route[i], route[i + 1]
            x1, y1 = a1
            x2, y2 = a2
            if y1 == y2:                          # 水平段：按 y 查
                kb = int(math.floor(y1 / _BUCKET_W))
                if (kb - 1) not in hb and kb not in hb and (kb + 1) not in hb:
                    continue
                lo = x1 if x1 < x2 else x2
                hi = x2 if x1 < x2 else x1
                for k in (kb - 1, kb, kb + 1):
                    bucket = hb.get(k)
                    if not bucket:
                        continue
                    for bl, bh, bp in bucket:
                        d = y1 - bp
                        if (d if d >= 0 else -d) >= sep:
                            continue
                        l2 = lo if lo > bl else bl
                        h2 = hi if hi < bh else bh
                        if h2 > l2:
                            cost += h2 - l2
            elif x1 == x2:                        # 垂直段：按 x 查
                kb = int(math.floor(x1 / _BUCKET_W))
                if (kb - 1) not in vb and kb not in vb and (kb + 1) not in vb:
                    continue
                lo = y1 if y1 < y2 else y2
                hi = y2 if y1 < y2 else y1
                for k in (kb - 1, kb, kb + 1):
                    bucket = vb.get(k)
                    if not bucket:
                        continue
                    for bl, bh, bp in bucket:
                        d = x1 - bp
                        if (d if d >= 0 else -d) >= sep:
                            continue
                        l2 = lo if lo > bl else bl
                        h2 = hi if hi < bh else bh
                        if h2 > l2:
                            cost += h2 - l2
        return cost

    def score(route: list[Point]) -> tuple:
        """评分：**字典序**优先级，不用加权求和。

        为什么必须是字典序而不是加权：加权时"少 1 次穿节点(1000)可以换
        8 像素重合(120*8=960)"这类交易会被判为划算，实测这样会把穿节点
        从 4 处推到 116 处。"不穿节点"是硬约束，任何情况下都不能为了
        让开其它线而穿节点，所以碰撞数必须放在元组首位做绝对优先。
        """
        coll = route_collisions(route, obs, margin=margin, index=obs_index)
        ov = _overlap_cost(route)
        bends = max(0, len(route) - 2)
        return (coll, ov, bends, polyline_length(route))

    # P2-4：障碍空间索引。候选数可达数百，逐个全量扫描障碍在大图上
    # 是主要耗时；分桶后判定结果不变、速度显著提升。
    obs_index = build_obstacle_index(obs, margin) if len(obs) >= 8 else None

    def _cap(vals, n: int) -> list:
        """通道候选封顶：排序去重后均匀抽样保留 n 个。

        候选 4/4b/5 的数量是通道列表的平方/立方——_sample_gaps 把通道
        扩到 ~80 个后，单边候选曾暴涨到 ~59 万（评分含 O(已布边²) 的
        重合代价），实测 15 张图的度量要跑数小时。均匀抽样保序保留
        两端与均匀分布的代表值，配合两阶段评分把单边控制在毫秒级。
        """
        vs = sorted(set(vals))
        if len(vs) <= n:
            return vs
        step = len(vs) / float(n)
        return [vs[min(len(vs) - 1, int(i * step))] for i in range(n)]

    cands: list[list[Point]] = []

    # --- 候选 1：几乎同层/同列 → 单折角直连 ---
    if abs(p_src[1] - p_tgt[1]) < 30 or abs(p_src[0] - p_tgt[0]) < 30:
        if abs(p_src[0] - p_tgt[0]) >= abs(p_src[1] - p_tgt[1]):
            cands.append(_dedupe_pts([p_src, (p_tgt[0], p_src[1]), p_tgt]))
        else:
            cands.append(_dedupe_pts([p_src, (p_src[0], p_tgt[1]), p_tgt]))

    # --- 通道取值集合：所有节点边界的空隙（**在整个空隙内采样，不只取中线**） ---
    #
    # 为什么不能只取中线：空隙宽 270px 时只生成一个候选（正中间），
    # 而「恰好能绕开某个中间带节点」的窄通道往往贴着空隙一侧，中线候选
    # 会直接压在该节点上。实测 4 处穿节点全是这个原因——最优通道存在
    # （x∈[1186,1398] 或 x∈[0,394]），但候选池里根本没有它。
    #
    # 采样策略：中线 + 空隙两侧各内缩 CAND_INSET（保证不与矩形边界相切），
    # 空隙足够宽时再补 1/4、3/4 位置。候选数量是 O(节点数)，
    # 后面还有排序兜底，宽一点不会爆炸。
    CAND_INSET = 12.0   # 距矩形边界的安全内缩
    CAND_MIN_GAP = 4.0  # 小于此宽度的空隙视为无缝，不生成通道

    def _sample_gaps(sorted_edges: list[float]) -> list[float]:
        out: set[float] = set()
        for i in range(len(sorted_edges) - 1):
            lo, hi = sorted_edges[i], sorted_edges[i + 1]
            w = hi - lo
            if w <= CAND_MIN_GAP:
                continue
            mid = (lo + hi) / 2.0
            out.add(mid)
            # 两侧内缩（空隙太窄时内缩会交叉，退化为中线）
            a, b = lo + CAND_INSET, hi - CAND_INSET
            if b > a:
                out.add(a)
                out.add(b)
                if w > 200.0:
                    out.add(lo + w * 0.25)
                    out.add(lo + w * 0.75)
        return sorted(out)

    xs_gap: set[float] = set()
    ys_gap: set[float] = set()
    for r in [src_rect, tgt_rect] + obs:
        xs_gap.add(r[0]); xs_gap.add(r[2])
        ys_gap.add(r[1]); ys_gap.add(r[3])
    x_mids = _sample_gaps(sorted(xs_gap))
    y_mids = _sample_gaps(sorted(ys_gap))

    # 宽度兜底：极端情况下（只有源/目标两个矩形）也要有可用通道
    if not x_mids:
        x_mids = [min(src_rect[0], tgt_rect[0]) - 40, max(src_rect[2], tgt_rect[2]) + 40]
    if not y_mids:
        y_mids = [min(src_rect[1], tgt_rect[1]) - 40, max(src_rect[3], tgt_rect[3]) + 40]

    # --- 候选 2：H-V-H（垂直通道按空隙遍历，pad_offset 用于并行边错位） ---
    x_cands = _cap(list(x_mids) + [p_tgt[0] + pad_offset, p_src[0] + pad_offset], 18)
    for xm in x_cands:
        cands.append(route_hv(p_src, p_tgt, xm))

    # --- 候选 3：V-H-V（水平通道同理） ---
    y_cands = _cap(list(y_mids) + [p_src[1] + pad_offset, p_tgt[1] + pad_offset], 18)
    for ym in y_cands:
        cands.append(route_vh(p_src, p_tgt, ym))

    # ================= 候选 4 / 4b / 5：带外绕行与多段绕行 =================
    #
    # 【为什么不再是笛卡尔积】
    # 旧实现直接枚举「带外通道 × 脱离列 × 阶梯列」的完整组合：
    #   候选 4  = 14 × 14 × 7 ≈ 1372
    #   候选 4b = 24 × 14     ≈ 336
    #   候选 5  = 18² × 2     = 648
    # 单边候选达 2600+，且未排序前每个都要对全部障碍做 Liang-Barsky
    # 相交判定。实测 50 节点/100 边耗时 50s，属于超线性爆炸，30+ 节点的
    # 真实系统完全不可用。
    #
    # 【关键洞察：通道线碰撞可分解】
    # 这些绕行路径都是「脱离线 + 通道线 + 回落线」的三段结构，
    # 且**大部分候选共享同一条通道线**（只有脱离列不同）。通道线自身
    # 是否穿障碍与脱离列无关，可以**对每个通道只算一次并缓存**；
    # 通道穿障碍时，给整族候选记一个下界，低于下界的候选直接丢弃
    # ——不必对它做完整碰撞判定。
    #
    # 【分层构造】
    #   ① 先按通道线的碰撞数给通道排序（零碰撞通道优先）；
    #   ② 每个通道只配少量"代表性脱离列"（按几何合理性挑选，
    #      而非全枚举笛卡尔积）；
    #   ③ 只有当零/低碰撞通道的候选数不足时才补充高碰撞通道。
    # 这样单边候选从 O(C²·D) 降到 O(C·D′)（C=通道数, D′=代表列数），
    # 且碰撞判定次数进一步被通道级缓存压缩。

    def _seg_collisions(p1: Point, p2: Point) -> int:
        """单条线段的穿障碍数（复用空间索引）。"""
        return route_collisions([p1, p2], obs, margin=margin, index=obs_index)

    # --- 通道候选集合 ---
    # 水平带外通道：所有障碍带的上下外侧留 24px，并入横向空隙中线
    band_ys: set[float] = set()
    for r in [src_rect, tgt_rect] + obs:
        band_ys.add(r[1] - 24.0)
        band_ys.add(r[3] + 24.0)
    band_ys |= set(y_mids)
    band_ys_sorted = _cap(sorted(band_ys), 14)

    # 垂直带外通道（候选 4b）：障碍带左右外侧 + 纵向空隙中线
    band_xs: set[float] = set()
    for r in [src_rect, tgt_rect] + obs:
        band_xs.add(r[0] - 24.0)
        band_xs.add(r[2] + 24.0)
    band_xs |= set(x_mids)
    band_xs_sorted = _cap(sorted(band_xs), 14)

    # --- 候选 4：水平带外绕行 ---
    # 脱离列的分层构造（**不是全枚举**）：
    #   源侧两列 + 目标侧两列 = 4 个"必然语义合理"的列（不擦源/目标本身），
    #   再从 x_cands 里补少量零碰撞的"干净列"（绕开障碍更彻底）。
    _x_clean = sorted(x_cands, key=lambda x: _seg_collisions((x, p_src[1]), (x, p_tgt[1])))[:5]
    x_depart = list(dict.fromkeys(
        [p_src[0] - 26.0, p_src[0] + 26.0, p_tgt[0] - 26.0, p_tgt[0] + 26.0] + _x_clean
    ))

    # 【通道级剪枝】候选按 (碰撞数, 重合, 拐弯, 长度) 字典序评分，而**碰撞数
    # 由通道线主导**：通道线自身穿 N 个障碍时，由它派生的任何候选至少穿 N 个
    # （脱离/回落段只会增加、不会减少碰撞）。因此：
    #   ① 通道线按碰撞数升序排序；
    #   ② 只对碰撞数最小的前 _CH_LIMIT 条通道展开脱离列——更差的通道
    #      即使展开，其候选在"碰撞数"这一首要指标上必然劣于前面通道的
    #      产物，永远排不进 shortlist；
    #   ③ 若全图通道都零碰撞（常见情形），_CH_LIMIT 之外的同分通道被截断
    #      ——它们碰撞数相同、几何相邻，截断不改变最终选择质量。
    #
    # 这一步把候选 4/4b 的规模从 O(全部通道 × 脱离列) 降到
    # O(8 × 脱离列)，实测单边候选 945 → ~330，是**减少候选数量本身**
    # 而非优化单次判定——后者（段级缓存/包围盒预筛）实测反而更慢。
    _CH_LIMIT = 8

    _by_scored = sorted(
        ((_seg_collisions((p_src[0], y), (p_tgt[0], y)), y) for y in band_ys_sorted),
        key=lambda t: t[0],
    )
    for _c, y_by in _by_scored[:_CH_LIMIT]:
        for xd in x_depart:
            cands.append(route_escape_x(p_src, p_tgt, xd, y_by, xd))
            # route_escape_y 与 route_staircase 在三段式下几何等价
            # （见其 docstring），只保留语义更明确的 route_escape_y，
            # 避免候选池里出现逐点完全相同的重复项。
            cands.append(route_escape_y(p_src, p_tgt, y_by, xd))

    # --- 候选 4b：垂直带外绕行（候选 4 的镜像）---
    # 脱离行同样分层构造：源/目标上下 4 行 + 5 条干净行。
    _y_clean = sorted(y_cands, key=lambda y: _seg_collisions((p_src[0], y), (p_tgt[0], y)))[:5]
    y_depart = list(dict.fromkeys(
        [p_src[1] - 26.0, p_src[1] + 26.0, p_tgt[1] - 26.0, p_tgt[1] + 26.0] + _y_clean
    ))

    _bx_scored = sorted(
        ((_seg_collisions((x, p_src[1]), (x, p_tgt[1])), x) for x in band_xs_sorted),
        key=lambda t: t[0],
    )
    for _c, x_by in _bx_scored[:_CH_LIMIT]:
        for yd in y_depart:
            # 先水平脱离到 x_by，再垂直推进，最后水平进入目标
            cands.append(_dedupe_pts([
                p_src, (x_by, p_src[1]), (x_by, yd), (p_tgt[0], yd), p_tgt,
            ]))
            # 先垂直脱离到 yd，再水平穿过带外通道，再垂直进入目标
            cands.append(_dedupe_pts([
                p_src, (p_src[0], yd), (x_by, yd), (x_by, p_tgt[1]), p_tgt,
            ]))

    # --- 候选 5：五段绕行（两段独立通道，应对双障碍夹击）---
    # "两段独立通道"的真正语义是「第一段通道 + 第二段通道各自独立选」，
    # 而两段都被障碍挡住是罕见场景。主通道取前 8 条（与 4/4b 同策略），
    # 副通道只取零碰撞的干净通道（各 4 条），避免 O(n²) 枚举。
    for x1 in [x for _, x in sorted(
            ((_seg_collisions((x, p_src[1]), (x, p_tgt[1])), x) for x in x_cands),
            key=lambda t: t[0])[:_CH_LIMIT]]:
        for x2 in _x_clean[:4]:
            if abs(x1 - x2) > 4:
                cands.append(_dedupe_pts([p_src, (x1, p_src[1]), (x1, p_tgt[1]),
                                          (x2, p_tgt[1]), p_tgt]))
    for y1 in [y for _, y in sorted(
            ((_seg_collisions((p_src[0], y), (p_tgt[0], y)), y) for y in y_cands),
            key=lambda t: t[0])[:_CH_LIMIT]]:
        for y2 in _y_clean[:4]:
            if abs(y1 - y2) > 4:
                cands.append(_dedupe_pts([p_src, (p_src[0], y1), (p_tgt[0], y1),
                                          (p_tgt[0], y2), p_tgt]))

    if not cands:
        return _dedupe_pts([p_src, p_tgt])

    # --- 候选级去重（整条路径，而非相邻重复点）---
    # _dedupe_pts 只消掉相邻重合点，不同几何族仍可能产出**逐点相同**的
    # 路径（escape_x / escape_y / 阶梯在三段式下常退化成同一条）。
    # 按路径点序列去重，保留首次出现者，判定结果完全不变。
    _uniq: dict[tuple, list[Point]] = {}
    for r in cands:
        _uniq.setdefault(tuple(r), r)
    cands = list(_uniq.values())

    # --- 两阶段评分（性能硬约束下的精确性取舍）---
    # 候选总数仍可达数百，碰撞判定是绝对重头（实测占布线耗时 60%+）。
    # 先用「碰撞数 + 长度」做廉价预筛，只对前 96 名做含重合惩罚的完整
    # 评分（重合代价含轴向分桶查询）。
    # 字典序语义保留：预筛按 (coll, length) 排序，凡零碰撞候选总数
    # ≤ 96 时全部进入终评——实际图中正是如此，选择结果与全量评分一致。
    #
    # 注：曾尝试「段级碰撞缓存」（按段端点+障碍 id 缓存相交布尔）与
    # 「候选障碍包围盒预筛」，实测均**反而变慢**（50 节点 5.0s→12.5s）：
    # 海量小字典查找的开销远超它节省的相交判定，且缓存跨边持续膨胀。
    # 已回滚。真正的解法只能是减少候选数本身，而非优化单次判定。
    prelim = sorted(
        (
            (route_collisions(r, obs, margin=margin, index=obs_index),
             polyline_length(r), i)
            for i, r in enumerate(cands)
        ),
        key=lambda t: (t[0], t[1]),
    )
    shortlist = [cands[i] for _, _, i in prelim[:96]]
    shortlist.sort(key=score)
    return shortlist[0]


# ----------------------------------------------------------------------
# plan_edge_routes 结果缓存
# ----------------------------------------------------------------------
# 【为什么需要】metric_edge_through_node 与 metric_edge_overlap 各自
# 独立调用 plan_edge_routes，evaluate 自身再加一次 —— 同一张图被完整
# 布线 2~3 遍。实测 50 节点单次布线 ~6.5s，evaluate 因此白付整轮耗时
# （剖析确认：plan_edge_routes 被调用 2 次）。
#
# 布线是**纯函数**：只依赖 diagram 的 cells 内容。缓存以
# (id(diagram), 结构指纹) 为键：id() 让同一对象必然命中，指纹保证
# 原对象被就地修改后不会命中脏数据。
#
# 只在顶层调用时缓存（_PLAN_DEPTH == 0）；嵌套调用不走缓存，
# 避免把半成品状态缓存下来。
_ROUTE_CACHE: dict[tuple, dict[str, list[Point]]] = {}
_ROUTE_CACHE_MAX = 8
_PLAN_DEPTH = 0


def _diagram_fingerprint(diagram: dict) -> tuple:
    """diagram 的廉价结构指纹：各 cell 的 id 与几何。

    比序列化/深拷贝便宜得多，但足以识别"原地改了坐标"的情况。
    """
    cells = diagram.get("cells") or []
    parts = []
    for c in cells:
        pos = c.get("position") or {}
        size = c.get("size") or {}
        parts.append((
            c.get("id"), pos.get("x"), pos.get("y"),
            size.get("width"), size.get("height"),
        ))
    return (len(cells), tuple(parts), len(diagram.get("lanes") or []))


def plan_edge_routes(diagram: dict) -> dict[str, list[Point]]:
    """为图中**所有**边统一布线，返回 {edge_id: path}。

    为什么必须批量而不是逐条独立算：
        反向平行边（A→B 与 B→A，DFD 里就是「请求/响应」）用同一套规则
        独立计算会得到**完全相同**的路径，渲染出来两条流重叠成一条，
        真实数据里曾出现 19 处这种情况。批量布线时把已布路径作为
        "占用通道"传入，后续边会自动让开 separation 像素。

    布序：先长边后短边（长边通道选择余地小，优先占位），
          同长时按 id 排序保证结果可复现。

    结果带缓存：同一张图被多个指标重复布线时直接命中，不再重算。
    """
    global _PLAN_DEPTH
    if _PLAN_DEPTH > 0:
        return _plan_edge_routes_uncached(diagram)

    key = (id(diagram), _diagram_fingerprint(diagram))
    hit = _ROUTE_CACHE.get(key)
    if hit is not None:
        return hit

    _PLAN_DEPTH += 1
    try:
        result = _plan_edge_routes_uncached(diagram)
    finally:
        _PLAN_DEPTH -= 1

    if len(_ROUTE_CACHE) >= _ROUTE_CACHE_MAX:
        _ROUTE_CACHE.clear()
    _ROUTE_CACHE[key] = result
    return result


def _plan_edge_routes_uncached(diagram: dict) -> dict[str, list[Point]]:
    """plan_edge_routes 的实际实现（无缓存）。"""
    cells = visible_cells(diagram)
    by_id = {c.get("id"): c for c in cells if c.get("id")}
    nodes = node_cells(diagram)
    obstacles = [rect_of(n) for n in nodes]

    edges = [e for e in edge_cells(diagram) if _edge_endpoints(e, by_id)]

    def _len(e: dict) -> float:
        s, t = _edge_endpoints(e, by_id)  # type: ignore[misc]
        cs, ct = center_of(rect_of(s)), center_of(rect_of(t))
        return -math.hypot(ct[0] - cs[0], ct[1] - cs[1])  # 负号=长的排前面

    edges.sort(key=lambda e: (_len(e), e.get("id") or ""))

    # 同端点的边分成一组做锚点分散（避免出口挤在一点）
    groups: dict[tuple[str, str], list[dict]] = {}
    for e in edges:
        s, t = _edge_endpoints(e, by_id)  # type: ignore[misc]
        groups.setdefault(tuple(sorted([s.get("id") or "", t.get("id") or ""])), []).append(e)
    slot_of: dict[str, tuple[int, int, int, int]] = {}
    for group in groups.values():
        n = len(group)
        for i, e in enumerate(group):
            slot_of[e.get("id") or ""] = (i, n, i, n)

    routes: dict[str, list[Point]] = {}
    placed: list[list[Point]] = []
    for e in edges:
        s, t = _edge_endpoints(e, by_id)  # type: ignore[misc]
        eid = e.get("id") or ""
        s_i, s_n, t_i, t_n = slot_of.get(eid, (0, 1, 0, 1))
        # 反向边让锚点镜像，出口自然分开
        num = 1 if abs(s_i - t_i) % 2 == 0 else -1
        route = route_edge(
            rect_of(s), rect_of(t), obstacles,
            slot_src=s_i * num, slots_src=max(1, s_n),
            slot_tgt=t_i * num, slots_tgt=max(1, t_n),
            occupied=placed, separation=14.0,
        )
        routes[eid] = route
        placed.append(route)
    return routes


# ----------------------------------------------------------------------
# 指标计算
# ----------------------------------------------------------------------

def _edge_endpoints(cell: dict, by_id: dict[str, dict]) -> Optional[tuple[dict, dict]]:
    s = by_id.get((cell.get("source") or {}).get("cell") or "")
    t = by_id.get((cell.get("target") or {}).get("cell") or "")
    if not s or not t:
        return None
    return s, t


def metric_member_outside(diagram: dict) -> list[str]:
    """信任边界成员越框：成员中心在容器内、但成员 bbox 超出容器边界。

    与渲染器同口径：渲染器用 `boundaryMembers` 判定成员（建模期事实），
    缺失时退回几何包含。返回问题描述列表。
    """
    problems: list[str] = []
    nodes = node_cells(diagram)
    for b in boundary_cells(diagram):
        br = rect_of(b)
        members = (b.get("data") or {}).get("boundaryMembers")
        for n in nodes:
            nr = rect_of(n)
            cn = center_of(nr)
            in_container = rect_contains_point(br, cn)
            named_member = bool(members) and n.get("id") in members
            if not (in_container or named_member):
                continue
            if nr[0] < br[0] - 1 or nr[2] > br[2] + 1 or nr[1] < br[1] - 1 or nr[3] > br[3] + 1:
                name = (n.get("data") or {}).get("name") or n.get("id")
                problems.append(
                    f"节点「{name}」越出容器「{(b.get('data') or {}).get('name') or b.get('id')}」"
                )
    return problems


def metric_node_overlap(diagram: dict) -> list[str]:
    """节点两两重叠（含节点压信任边界外的其它节点）。"""
    problems: list[str] = []
    nodes = node_cells(diagram)
    rects = [(n, rect_of(n)) for n in nodes]
    for i in range(len(rects)):
        for j in range(i + 1, len(rects)):
            a, ra = rects[i]
            b, rb = rects[j]
            if rects_overlap(ra, rb):
                na = (a.get("data") or {}).get("name") or a.get("id")
                nb = (b.get("data") or {}).get("name") or b.get("id")
                problems.append(f"「{na}」与「{nb}」重叠")
    return problems


def metric_boundary_overlap(diagram: dict) -> list[str]:
    """信任边界容器互相大面积重叠（>40% 较小者面积）。

    正常嵌套（外层包内层）交集/较小者会很接近 1，因此这里额外排除
    「一个完全包含另一个」的合法嵌套，只报真正的并排重叠。
    """
    problems: list[str] = []
    bs = [(b, rect_of(b)) for b in boundary_cells(diagram)]
    for i in range(len(bs)):
        for j in range(i + 1, len(bs)):
            a, ra = bs[i]
            b, rb = bs[j]
            inter = rect_intersection(ra, rb)
            if inter <= 0:
                continue
            small = min(rect_area(ra), rect_area(rb))
            if small <= 0:
                continue
            if inter / small < 0.4:
                continue
            na = (a.get("data") or {}).get("name") or a.get("id")
            nb = (b.get("data") or {}).get("name") or b.get("id")
            problems.append(f"边界「{na}」与「{nb}」重叠 {inter / small:.0%}")
    return problems


def metric_edge_through_node(diagram: dict) -> list[str]:
    """数据流穿过非端点节点（用与渲染器一致的路由复算）。"""
    problems: list[str] = []
    cells = visible_cells(diagram)
    by_id = {c.get("id"): c for c in cells if c.get("id")}
    nodes = node_cells(diagram)
    routes = plan_edge_routes(diagram)

    for e in edge_cells(diagram):
        ep = _edge_endpoints(e, by_id)
        if not ep:
            continue
        s, t = ep
        eid = e.get("id") or ""
        route = routes.get(eid)
        if not route:
            continue
        nm = (e.get("data") or {}).get("name") or eid
        for n in nodes:
            if n is s or n is t:
                continue
            if route_collisions(route, [rect_of(n)], margin=4.0) > 0:
                nn = (n.get("data") or {}).get("name") or n.get("id")
                problems.append(f"流「{nm}」穿过节点「{nn}」")
    return problems


def _route_key(route: list[Point]) -> tuple:
    """路径指纹（用于识别"两条边走同一条通道"）。

    量化到 6px 网格：同一通道上相距 <6px 的两条线视为重合
    （视觉上已经糊在一起，等同于重合）。
    """
    pts = [(round(p[0] / 6.0) * 6, round(p[1] / 6.0) * 6) for p in route]
    fwd = tuple(pts)
    rev = tuple(reversed(pts))
    return min(fwd, rev)


def metric_edge_overlap(diagram: dict) -> list[str]:
    """两条边路径高度重合（走同一通道）——商业级图不应出现。

    DFD 里 A→B 与 B→A 就是「请求/响应」，必须画成两条可见的平行线。
    """
    problems: list[str] = []
    cells = visible_cells(diagram)
    by_id = {c.get("id"): c for c in cells if c.get("id")}
    routes = plan_edge_routes(diagram)

    seen: dict[tuple, str] = {}
    for e in edge_cells(diagram):
        if not _edge_endpoints(e, by_id):
            continue
        eid = e.get("id") or ""
        route = routes.get(eid)
        if not route:
            continue
        key = _route_key(route)
        nm = (e.get("data") or {}).get("name") or eid
        if key in seen and seen[key] != nm:
            problems.append(f"流「{seen[key]}」与「{nm}」路径重合")
        else:
            seen[key] = nm
    return problems


def metric_span_ratio(diagram: dict) -> float:
    """最长边 / 最短边 的中心距比值。比值大 = 线长极不均衡，观感散乱。"""
    cells = visible_cells(diagram)
    by_id = {c.get("id"): c for c in cells if c.get("id")}
    lens: list[float] = []
    for e in edge_cells(diagram):
        ep = _edge_endpoints(e, by_id)
        if not ep:
            continue
        sc = center_of(rect_of(ep[0]))
        tc = center_of(rect_of(ep[1]))
        d = math.hypot(tc[0] - sc[0], tc[1] - sc[1])
        if d > 1.0:
            lens.append(d)
    if len(lens) < 2 or min(lens) <= 1.0:
        return 0.0
    return max(lens) / min(lens)


def metric_fill_ratio(diagram: dict) -> float:
    """节点包围盒面积 / 画布（含泳道与容器）面积。衡量画布利用率。"""
    nodes = node_cells(diagram)
    if not nodes:
        return 0.0
    nrs = [rect_of(n) for n in nodes]
    nx0, ny0 = min(r[0] for r in nrs), min(r[1] for r in nrs)
    nx1, ny1 = max(r[2] for r in nrs), max(r[3] for r in nrs)
    n_area = max(0.0, nx1 - nx0) * max(0.0, ny1 - ny0)

    allr = [rect_of(c) for c in visible_cells(diagram)]
    for lane in diagram.get("lanes") or []:
        lx, ly = float(lane.get("x", 0)), float(lane.get("y", 0))
        allr.append((lx, ly, lx + float(lane.get("width", 0)), ly + float(lane.get("height", 0))))
    if not allr:
        return 0.0
    cw = max(r[2] for r in allr) - min(r[0] for r in allr)
    ch = max(r[3] for r in allr) - min(r[1] for r in allr)
    if cw <= 0 or ch <= 0:
        return 0.0
    return n_area / (cw * ch)


def metric_canvas_aspect(diagram: dict) -> float:
    """画布长宽比（长边/短边）。商业级图应接近 4:3 ~ 16:9。"""
    allr = [rect_of(c) for c in visible_cells(diagram)]
    for lane in diagram.get("lanes") or []:
        lx, ly = float(lane.get("x", 0)), float(lane.get("y", 0))
        allr.append((lx, ly, lx + float(lane.get("width", 0)), ly + float(lane.get("height", 0))))
    if not allr:
        return 0.0
    cw = max(r[2] for r in allr) - min(r[0] for r in allr)
    ch = max(r[3] for r in allr) - min(r[1] for r in allr)
    if cw <= 0 or ch <= 0:
        return 0.0
    return max(cw, ch) / min(cw, ch)


def first_diagram(record: dict) -> Optional[dict]:
    diagrams = ((record.get("model") or {}).get("detail") or {}).get("diagrams") or []
    return diagrams[0] if diagrams else None


def evaluate(record: dict) -> Optional[dict[str, Any]]:
    """对一次建模结果算出全部指标。无 DFD 时返回 None。"""
    d = first_diagram(record)
    if not d:
        return None
    return {
        "member_outside": metric_member_outside(d),
        "node_overlap": metric_node_overlap(d),
        "boundary_overlap": metric_boundary_overlap(d),
        "edge_through_node": metric_edge_through_node(d),
        "edge_overlap": metric_edge_overlap(d),
        "span_ratio": metric_span_ratio(d),
        "fill_ratio": metric_fill_ratio(d),
        "canvas_aspect": metric_canvas_aspect(d),
        "n_nodes": len(node_cells(d)),
        "n_edges": len(edge_cells(d)),
        "n_boundaries": len(boundary_cells(d)),
    }


def format_report(name: str, m: dict[str, Any]) -> str:
    """单图指标的可读报告。"""
    lines = [f"[{name}] 节点 {m['n_nodes']} / 流 {m['n_edges']} / 边界 {m['n_boundaries']}"]
    for key, label in (
        ("member_outside", "成员越框"),
        ("node_overlap", "节点重叠"),
        ("boundary_overlap", "边界重叠"),
        ("edge_through_node", "边穿节点"),
        ("edge_overlap", "路径重合"),
    ):
        items = m[key]
        mark = "OK " if not items else "FAIL"
        lines.append(f"  {mark} {label}: {len(items)}")
        for it in items[:5]:
            lines.append(f"       - {it}")
        if len(items) > 5:
            lines.append(f"       ... ���有 {len(items) - 5} 项")
    lines.append(f"  span_ratio={m['span_ratio']:.2f} (目标<=3.0)  "
                 f"fill_ratio={m['fill_ratio']:.1%} (目标>=75%)  "
                 f"aspect={m['canvas_aspect']:.2f}")
    return "\n".join(lines)


def iter_results(results_dir: str) -> Iterable[tuple[str, dict]]:
    """遍历结果目录下的所有 json（按文件名排序，保证可复现）。"""
    import glob
    import json
    import os

    for fp in sorted(glob.glob(os.path.join(results_dir, "*.json"))):
        try:
            with open(fp, encoding="utf-8") as fh:
                yield os.path.basename(fp), json.load(fh)
        except Exception:
            continue
