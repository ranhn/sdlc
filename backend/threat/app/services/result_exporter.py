"""威胁建模结果的文档导出（商业级报告版）。

把一次已保存的建模结果（含完整 Threat Dragon 模型）渲染为：

- Markdown 报告  —— 元信息表 + 执行摘要 + 等级分布 + 威胁明细（按等级）+ 附录
- Threat Dragon 标准 JSON —— 官方 v2 模型结构（格式约定，保持兼容不动）
- CSV 威胁清单 —— 中文列头 + DREAD 五维 + 状态中文化（UTF-8 BOM，Excel 直开）
- Word (.docx) 报告 —— 封面 / 目录域 / 页眉页脚页码 / 着色风险表 / 分级明细 / 附录

所有 render_* 函数签名保持与路由层（router.export_result）的既有约定一致：
    render_result_markdown(record) -> str
    render_result_json(record)     -> str
    render_result_csv(record)      -> str
    render_result_docx(record)     -> bytes
"""
from __future__ import annotations

import csv
import io
import json
import logging
import os
import threading
from datetime import datetime
from functools import lru_cache
from typing import Any

# 统一网络时钟（与项目其它 service 一致的引入方式）
from app.utils import network_clock as nc

logger = logging.getLogger(__name__)

# Word COM 自动化串行锁：COM 非线程安全，且并发导出时多个隐藏 Word 实例
# 会放大启动开销与资源占用，这里统一串行（导出频率低，无吞吐压力）。
_WORD_COM_LOCK = threading.Lock()

# ----------------------------------------------------------------------
# 中文字体解析（DFD 图 / 等级分布图共用）
# ----------------------------------------------------------------------
# 覆盖 Windows / Linux / macOS 三类常见部署环境：缺字体会导致 Pillow 退化为
# 内置位图字体，中文渲染成方块——这比「无图」更糟（用户以为导出成功）。
# 因此这里显式探测，找不到时由调用方决定降级策略。
_CJK_FONT_FILES = (
    "msyh.ttc",        # 微软雅黑（Windows 首选）
    "msyhbd.ttc",
    "simhei.ttf",      # 黑体
    "simsun.ttc",      # 宋体
    "wqy-zenhei.ttc",  # 文泉驿正黑（常见 Linux 发行版）
    "wqy-microhei.ttc",
    "NotoSansCJK-Regular.ttc",   # Noto CJK（容器镜像常用）
    "SourceHanSansSC-Regular.otf",
    "PingFang.ttc",    # 苹方（macOS）
    "STHeiti Light.ttc",
)
_CJK_FONT_DIRS = (
    r"C:\Windows\Fonts",
    "/usr/share/fonts/truetype",
    "/usr/share/fonts/truetype/wqy",
    "/usr/share/fonts/opentype",
    "/usr/share/fonts",
    "/usr/local/share/fonts",
    "/System/Library/Fonts",
    "/Library/Fonts",
)


@lru_cache(maxsize=64)
def _font_path_cached(size: int, bold: bool = False) -> str | None:
    """查找可用的中文字体文件路径。

    结果按 (size, bold) 缓存——Pillow 的 truetype 加载本身也有缓存，但
    「遍历 9 个目录 × 10 个字体名」的探测开销不该每次导出都付一遍。
    """
    prefer = (
        ("msyhbd.ttc", "simhei.ttf", "NotoSansCJK-Bold.ttc") + _CJK_FONT_FILES
        if bold else _CJK_FONT_FILES
    )
    for name in prefer:
        for base in _CJK_FONT_DIRS:
            p = os.path.join(base, name)
            if os.path.exists(p):
                return p
    return None

# severity 排序权重（用于报告内排序）
SEV_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Unknown": 9,
}

# severity -> 中文标签
SEV_ZH = {
    "Critical": "严重",
    "High": "高危",
    "Medium": "中危",
    "Low": "低危",
    "Unknown": "未知",
}

# severity -> Word 报告中的强调色（字体色 / 表格底纹）
SEV_COLOR = {
    "Critical": ("C0392B", "FDECEA"),  # 深红 / 浅红底
    "High": ("D97706", "FEF5E7"),      # 橙 / 浅橙底
    "Medium": ("B45309", "FEF9E7"),    # 黄褐 / 浅黄底
    "Low": ("1E8449", "EAF7EE"),       # 绿 / 浅绿底
    "Unknown": ("6B7280", "F3F4F6"),
}

# 处置状态 -> 中文
STATUS_ZH = {
    "Open": "待处理",
    "In Progress": "进行中",
    "Mitigated": "已缓解",
    "Accepted": "已接受",
    "NotApplicable": "不适用",
}

# 商业报告统一配色（主色 / 辅助色 / 中性色）。
# 全报告只从这里取色，避免各处硬编码十六进制导致版式不一致。
BRAND = {
    "primary": "1F3A5F",     # 主色：封面标题、一级标题
    "secondary": "2B579A",   # 辅助色：二级标题、表头
    "accent": "C8A75B",      # 点缀色：封面分隔线、装饰条
    "rule": "D6DCE5",        # 分隔线灰
    "muted": "64748B",       # 说明文字灰
    "muted_light": "8A94A6", # 页眉页脚灰
    "zebra": "F7F9FC",       # 表格隔行底纹
    "border": "B8C2D1",      # 表格边框
    "danger": "C0392B",      # 密级提示红
}

# ----------------------------------------------------------------------
# 版心宽度（页面可用宽度）——所有表格与图片的宽度上限
# ----------------------------------------------------------------------
# A4 宽 21.0cm，左右页边距 2.4 / 2.2cm，故版心 = 21.0 - 2.4 - 2.2 = 16.4cm。
# 历史遗留：早期页边距为 2.5/2.5（版心 16.0），后续调整页边距时未同步表格
# 宽度，导致全部表格比正文窄 0.4cm、右边缘与正文不齐。此处集中定义，
# 表格宽度一律取 16.4，不再各处硬编码。
CONTENT_WIDTH_CM = 16.4
PAGE_WIDTH_CM = 21.0
MARGIN_LEFT_CM = 2.4
MARGIN_RIGHT_CM = 2.2

# ----------------------------------------------------------------------
# 章节编号与标题之间的分隔符（全角空格）
# ----------------------------------------------------------------------
# 目录条目、正文标题、书签名三者必须使用**完全相同**的标题文本，否则由
# md5(文本) 派生的书签名对不上，目录里的 PAGEREF 域会全部失效（页码恒显示
# 占位符「-」）。此前正文 _h1 用半角空格、书签用全角空格，靠「恰好两侧都
# 用全角」才没出错——一旦有人改动空格类型即静默失效。此处收敛为单一常量，
# 所有拼标题的地方一律引用它。
TITLE_SEP = "　"

# 严重度分级定义（商业报告附录用：定义 + 建议响应时限）
SEV_DEFINITIONS = [
    ("严重 Critical", "可被远程利用、影响核心数据资产或业务主流程，可能造成大规模数据泄露 / 系统失控", "24 小时内启动处置"),
    ("高危 High", "利用条件明确、影响重要功能或敏感数据，攻击成本较低", "7 天内完成整改"),
    ("中危 Medium", "需要特定条件利用，影响范围有限", "30 天内纳入迭代修复"),
    ("低危 Low", "利用成本高、影响轻微，属加固项", "排期处理"),
]


def _fmt_time(epoch: float) -> str:
    try:
        return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OSError, TypeError):
        return "-"


def _now_str() -> str:
    """报告生成时间（网络时钟，秒级）。"""
    try:
        return nc.now().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _sev(key: str) -> str:
    return SEV_ORDER.get(key, SEV_ORDER["Unknown"])


def _sev_label(key: str) -> str:
    """等级显示标签：中文 + 英文原值（如「严重 Critical」）。

    全报告统一使用本函数输出等级，避免同一文档里一处写「严重」、一处写
    「严重 Critical」——口径不一致会让读者怀疑两处指的是不同等级。
    首次出现处（执行摘要）额外给出中英对照，此处已隐含英文，无需重复。
    """
    zh = SEV_ZH.get(key, key)
    return f"{zh} {key}" if key else key


def _sev_zh(key: str) -> str:
    """等级纯中文标签（用于句子中间，避免中英夹杂影响阅读）。"""
    return SEV_ZH.get(key, key) if key else key


def _status_label(status: str | None) -> str:
    if not status:
        return STATUS_ZH["Open"]
    return STATUS_ZH.get(status, status)


def _one_line(text: Any) -> str:
    """把任意字段压成单行（表格单元格内不允许换行，否则 Markdown 表
    会被换行符截断成多个残表）。"""
    if text is None:
        return ""
    return " ".join(str(text).split())


def _pct(rate) -> str:
    """把 0~1 比率格式化为百分比字符串。"""
    try:
        return f"{round(float(rate) * 100, 1)}%"
    except (TypeError, ValueError):
        return "-"


def _dread_total(dread) -> int:
    if isinstance(dread, dict):
        try:
            return int(dread.get("total", sum(v for k, v in dread.items() if isinstance(v, (int, float)))))
        except (TypeError, ValueError):
            return 0
    return 0


def _iter_diagram_cells(model: dict[str, Any], first_only: bool = False):
    """遍历模型图表的「单元格」，跳过结构非法的部分。

    历史记录或人工改过的 JSON 里 detail.diagrams 可能是字符串 / None，
    cells 里也可能混入非字典项。导出是报告的最后一环，为脏数据抛异常
    会让用户拿到 500 而不是「一份内容略少的报告」——这里统一做类型
    过滤，_collect_elements / _collect_threats 共用同一份清洗逻辑，
    避免每处各写一遍 isinstance 检查（漏一处就是一个崩溃点）。

    first_only=True 时只遍历第一张图：系统分解章的**元素清单**（EE/P/
    DS/DF/TB 编号）必须与「图 1」的图元一一对应，混入其它图的元素会让
    编号跨图连续、清单里出现图上没有的条目，读者无法对照图与表。
    威胁收集则要用全部图（用户可能只对第二张图做了分析），故默认 False。
    """
    detail = model.get("detail")
    diagrams = detail.get("diagrams") if isinstance(detail, dict) else None
    if not isinstance(diagrams, list):
        return
    for diagram in diagrams:
        if not isinstance(diagram, dict):
            continue
        cells = diagram.get("cells")
        if not isinstance(cells, list):
            continue
        for cell in cells:
            if isinstance(cell, dict):
                yield cell
        if first_only:
            return


def _first_diagram(model: dict[str, Any]) -> dict[str, Any]:
    """取第一张图表的元信息（标题/描述），脏数据时返回空字典。"""
    detail = model.get("detail")
    diagrams = detail.get("diagrams") if isinstance(detail, dict) else None
    if isinstance(diagrams, list):
        for diagram in diagrams:
            if isinstance(diagram, dict):
                return diagram
    return {}


def _collect_threats(model: dict[str, Any]) -> list[dict[str, Any]]:
    """从 Threat Dragon 模型中收集所有威胁，并补充所属组件名。

    对脏数据宽容：历史记录或人工改过的 JSON 里 diagrams / cells /
    threats 可能是字符串、None 或混入非字典项。导出是报告的最后一环，
    这里抛异常会让用户看到 500 而不是「一份少了点内容的报告」——因此
    逐层做类型检查，跳过结构不合法者而不是整体失败。清洗逻辑与
    _collect_elements 共用 _iter_diagram_cells，避免两处各自维护。
    """
    out: list[dict[str, Any]] = []
    cells = list(_iter_diagram_cells(model))
    name_by_cell = {
        c.get("id"): ((c.get("data") or {}).get("name") or "")
        if isinstance(c.get("data"), dict) else ""
        for c in cells
    }
    for cell in cells:
        threats = cell.get("threats")
        if not isinstance(threats, list):
            continue
        for threat in threats:
            if not isinstance(threat, dict):
                continue
            t = dict(threat)
            t["component"] = name_by_cell.get(cell.get("id"), "")
            out.append(t)
    return out


def _sorted_threats(threats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """统一排序：严重度升序 -> DREAD 降序 -> 标题。全报告共用一份顺序。"""
    return sorted(
        threats,
        key=lambda t: (_sev(t.get("severity", "")), -_dread_total(t.get("dread")), t.get("title", "")),
    )


def _sev_counts(stats: dict[str, Any]) -> list[tuple[str, int]]:
    """按固定顺序返回 (severity, count) 列表。

    数值容错：threatCountBySeverity 可能缺失、是列表，或值是非数字字符串
    （人工改过的 JSON），此处统一转成 int，转换失败按 0 计——分布表是
    执行摘要的核心内容，不能因为一个脏计数就让整份报告导出失败。
    """
    by_sev = stats.get("threatCountBySeverity")
    if not isinstance(by_sev, dict):
        by_sev = {}
    order = ["Critical", "High", "Medium", "Low"]

    def _num(val: Any) -> int:
        try:
            return int(val or 0)
        except (TypeError, ValueError):
            return 0

    counts = [(s, _num(by_sev.get(s))) for s in order]
    extra = [(str(k), _num(v)) for k, v in by_sev.items() if k not in order]
    return counts + extra


def _status_counts(threats: list[dict[str, Any]]) -> dict[str, int]:
    """处置状态 + 范围外计数。"""
    counts: dict[str, int] = {}
    oos = 0
    for t in threats:
        key = _status_label(t.get("status"))
        counts[key] = counts.get(key, 0) + 1
        if t.get("outOfScope"):
            oos += 1
    counts["范围外"] = oos
    return counts


# 元素 cellType（Threat Dragon）-> 报告中的元素类别
ELEMENT_KIND = {
    "tm.Actor": ("externalentity", "EE", "外部实体"),
    "tm.Process": ("process", "P", "处理过程"),
    "tm.Store": ("datastore", "DS", "数据存储"),
    "tm.Flow": ("flow", "DF", "数据流"),
    "tm.BoundaryBox": ("trustboundary", "TB", "信任边界"),
    # AI 扩展元素（STRIDE-AI / MAESTRO）在报告中归入处理过程类，
    # 但保留独立前缀，便于读者区分 AI 专属元素
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

# STRIDE 六类的中文释义与缩写（方法论说明章用）
STRIDE_LETTER_ZH = [
    ("S", "Spoofing", "仿冒", "冒充他人身份访问系统或数据"),
    ("T", "Tampering", "篡改", "未授权修改数据或代码，破坏完整性"),
    ("R", "Repudiation", "抵赖", "否认已执行的操作，缺乏审计证据"),
    ("I", "Information Disclosure", "信息泄露", "敏感信息暴露给未授权方"),
    ("D", "Denial of Service", "拒绝服务", "耗尽资源或中断服务，破坏可用性"),
    ("E", "Elevation of Privilege", "权限提升", "获取超出授权的权限，越权操作"),
]

# 术语表（附录 B）
GLOSSARY = [
    ("DFD", "Data Flow Diagram，数据流图。用图形描述系统内元素与数据流向，是威胁建模的输入。"),
    ("外部实体 EE", "系统边界之外与系统交互的人、组织或外部系统，通常不受我方控制。"),
    ("处理过程 P", "对数据执行计算、转换、校验或编排的组件（服务、接口、函数）。"),
    ("数据存储 DS", "数据的持久化载体，包括数据库、缓存、对象存储、消息队列、日志。"),
    ("数据流 DF", "数据在元素之间传输的通道，如 HTTP 请求、消息投递、数据库连接。"),
    ("信任边界 TB", "信任级别发生变化的边界，跨越边界的每次交互都需要独立校验。"),
    ("威胁", "可能对系统造成损害的潜在事件，由威胁源利用脆弱性触发。"),
    ("脆弱性", "系统中可被威胁利用的缺陷或弱点。"),
    ("残余风险", "在已实施现有安全措施之后，仍然存在的风险水平。"),
    ("固有风险", "未考虑任何现有措施时的原始风险水平。"),
    ("消减措施", "为降低风险而计划实施的改进动作，对应残余风险的进一步收敛。"),
    ("严重度", "威胁对业务的影响程度分级，本报告采用严重 / 高危 / 中危 / 低危四档。"),
    ("CWE", "Common Weakness Enumeration，通用缺陷枚举，脆弱性的标准编号体系。"),
    ("DREAD", "危害 / 可重复性 / 可利用性 / 受影响面 / 可发现性 五维风险评分法，满分 50。"),
]


def _toc_bookmark(level: int, text: str) -> str:
    """由目录条目文本生成稳定、合法的 Word 书签名。

    Word 书签名须以字母开头、只含字母/数字/下划线、长度 <= 40，故不能用
    中文标题本身。这里用「层级 + 编号 + 哈希摘要」派生 ASCII 名。

    哈希必须用 md5 而非内置 hash()：后者对字符串加了随机盐（PYTHONHASHSEED），
    同一标题在不同进程/不同次导出会得到不同名字，目录页与正文页的书签就会
    对不上（页码域全部失效）。
    """
    import hashlib

    head = text.split("　")[0].strip()          # 取「3.1」这类编号
    safe = "".join(ch if ch.isalnum() else "_" for ch in head if ord(ch) < 128)
    safe = f"{safe}_" if safe else ""
    digest = hashlib.md5(text.encode("utf-8")).hexdigest()[:6]
    return f"_Toc{level}_{safe}{digest}"


def _kind_of(cell: dict[str, Any]) -> tuple[str, str, str]:
    """返回元素的 (kind_key, id_prefix, 中文名)。"""
    shape = cell.get("shape") or ""
    return ELEMENT_KIND.get(shape, ("process", "P", "处理过程"))


def _collect_elements(model: dict[str, Any]) -> dict[str, Any]:
    """从模型中提取元素清单（P0「系统分解」章的数据源）。

    返回：
        {
          "diagram": {...},                    # 图元信息（标题/描述）
          "groups": [ (中文名, [元素行...]) ],  # 按 EE/P/DS/DF/TB 分组的清单
          "boundaries": [ {..} ],              # 信任边界及其内部元素
          "flow_rows": [ {..} ],               # 数据流（带穿越的信任边界）
        }
    """
    out: dict[str, Any] = {"diagram": {}, "groups": [], "boundaries": [], "flow_rows": []}
    diagram = _first_diagram(model)
    # 只取第一张图的元素：清单编号必须与「图 1」一一对应（见函数注释）
    all_cells = [c for c in _iter_diagram_cells(model, first_only=True)
                 if c.get("visible") is not False]
    if not diagram and not all_cells:
        return out
    out["diagram"] = {
        "title": diagram.get("title") or "",
        "description": diagram.get("description") or "",
    }

    # ---- 分桶：节点 / 边 / 边界 ----
    node_cells, edge_cells, boundary_cells = [], [], []
    for c in all_cells:
        if c.get("source") and c.get("target"):
            edge_cells.append(c)
        elif c.get("shape") == "tm.BoundaryBox":
            boundary_cells.append(c)
        else:
            node_cells.append(c)

    # ---- 元素编号：按类别分别从 1 开始（EE1 / P2 / DS3 / DF5 / TB2）----
    id_by_cell: dict[str, str] = {}
    counters: dict[str, int] = {}

    def _assign(cell: dict) -> tuple[str, str, str]:
        kind, prefix, zh = _kind_of(cell)
        counters[prefix] = counters.get(prefix, 0) + 1
        eid = f"{prefix}{counters[prefix]}"
        id_by_cell[cell.get("id")] = eid
        return eid, zh, kind

    # 节点先编号（保证 EE/P/DS 序号稳定），再编号数据流
    for c in node_cells:
        _assign(c)
    for c in edge_cells:
        _assign(c)
    for c in boundary_cells:
        _assign(c)

    name_by_cell = {
        c.get("id"): ((c.get("data") or {}).get("name") or "")
        for c in all_cells
    }

    # ---- 元素所属信任边界（按几何包含关系判断）----
    def _in_boundary(cell: dict, boundary: dict) -> bool:
        pos, size = cell.get("position") or {}, cell.get("size") or {}
        bpos, bsize = boundary.get("position") or {}, boundary.get("size") or {}
        if not pos or not bpos:
            return False
        cx = pos.get("x", 0) + size.get("width", 0) / 2
        cy = pos.get("y", 0) + size.get("height", 0) / 2
        return (
            bpos.get("x", 0) <= cx <= bpos.get("x", 0) + bsize.get("width", 0)
            and bpos.get("y", 0) <= cy <= bpos.get("y", 0) + bsize.get("height", 0)
        )

    boundary_of: dict[str, str] = {}
    for c in node_cells:
        for b in boundary_cells:
            if _in_boundary(c, b):
                boundary_of[c.get("id")] = id_by_cell.get(b.get("id"), "")
                break

    # ---- 威胁数（每个元素关联多少条威胁）----
    threat_count: dict[str, int] = {}
    for c in all_cells:
        n = len(c.get("threats") or [])
        if n:
            threat_count[c.get("id")] = n

    def _props(cell: dict) -> dict:
        return (cell.get("data") or {}).get("properties") or {}

    # ---- 分组清单 ----
    def _row(cell: dict, extra: str = "") -> list[str]:
        cid = cell.get("id")
        eid = id_by_cell.get(cid, "-")
        props = _props(cell)
        marks = []
        if props.get("isEncrypted"):
            marks.append("已加密")
        if props.get("isPublicNetwork"):
            marks.append("公网")
        if props.get("storesCredentials"):
            marks.append("存凭据")
        if props.get("handlesCardPayment"):
            marks.append("支付数据")
        if props.get("isALog"):
            marks.append("日志")
        if props.get("privilegeLevel"):
            marks.append(f"权限:{props['privilegeLevel']}")
        if props.get("protocol"):
            marks.append(f"协议:{props['protocol']}")
        return [
            eid,
            name_by_cell.get(cid, "-") or "-",
            ((cell.get("data") or {}).get("description") or "") or "-",
            boundary_of.get(cid) or "边界外",
            "、".join(marks) or "—",
            str(threat_count.get(cid, 0)) if threat_count.get(cid) else "—",
            extra or "—",
        ]

    groups: list[tuple[str, list[list[str]]]] = []
    order = ["tm.Actor", "tm.Process", "tm.Store"]
    # 节点类：按固定类别顺序输出
    for shape in order:
        rows = [_row(c) for c in node_cells if c.get("shape") == shape]
        if rows:
            groups.append((ELEMENT_KIND[shape][2], rows))
    # 其余节点类（AI 扩展元素等）合并输出
    other = [c for c in node_cells if c.get("shape") not in order]
    if other:
        groups.append(("AI / 智能体元素", [_row(c) for c in other]))

    # 数据流清单：带「穿越的信任边界」
    flow_rows = []
    for c in edge_cells:
        src = (c.get("source") or {}).get("cell")
        tgt = (c.get("target") or {}).get("cell")
        b_from = boundary_of.get(src, "")
        b_to = boundary_of.get(tgt, "")
        crosses = [b for b in {b_from, b_to} if b]
        out_of_scope = bool((c.get("data") or {}).get("outOfScope"))
        flow_rows.append([
            id_by_cell.get(c.get("id"), "-"),
            name_by_cell.get(c.get("id"), "-") or "-",
            f"{id_by_cell.get(src, '?')} {name_by_cell.get(src, '')}".strip(),
            f"{id_by_cell.get(tgt, '?')} {name_by_cell.get(tgt, '')}".strip(),
            "、".join(crosses) if crosses else "—",
            "跨边界" if len(crosses) >= 1 and b_from != b_to else "边界内",
            _row(c)[4],  # 属性标记（加密/公网等）
            _row(c)[5],  # 威胁数
        ])
    out["flow_rows"] = flow_rows
    if flow_rows:
        # 数据流组直接携带 8 列 flow_rows（编号/名称/源/目标/穿越边界/边界关系/
        # 属性/威胁数），与报告端「数据流清单」表头一一对应。此前塞的是按节点表
        # 7 列重排的占位行（源/目标/穿越边界皆为空串），报告端按 8 列表头取值
        # 时列位整体错位：源/目标/穿越边界恒为空、威胁数恒为「—」。
        groups.append(("数据流", flow_rows))

    # 信任边界清单
    for b in boundary_cells:
        bid = id_by_cell.get(b.get("id"), "-")
        inner = [id_by_cell.get(c.get("id"), "?") for c in node_cells
                 if boundary_of.get(c.get("id")) == bid]
        out["boundaries"].append({
            "id": bid,
            "name": name_by_cell.get(b.get("id"), "-") or "-",
            "description": ((b.get("data") or {}).get("description") or "") or "-",
            "members": inner,
            "member_names": [name_by_cell.get(c.get("id"), "") for c in node_cells
                             if boundary_of.get(c.get("id")) == bid],
        })

    out["groups"] = groups
    out["id_by_cell"] = id_by_cell
    out["name_by_cell"] = name_by_cell
    out["boundary_of"] = boundary_of
    return out


# 威胁类型 -> 短代号（用于威胁 ID，如 P2-E / EE1-S）
# 覆盖平台支持的全部 8 种方法论：STRIDE / STRIDE-AI / CIA / CIADIE /
# LINDDUN / PLOT4ai / EOP / MAESTRO。
# 注意：同一方法论内代号必须互不相同，否则「元素ID-类型」无法唯一标识类型
# （如 EOP 的 Authentication 与 Authorization 都取首字母会撞成 Aut）。
THREAT_TYPE_ABBR = {
    # --- STRIDE / STRIDE-AI ---
    "Spoofing": "S",
    "Tampering": "T",
    "Repudiation": "R",
    "Information Disclosure": "I",
    "Denial of Service": "D",
    "Elevation of Privilege": "E",
    # --- CIA ---
    "Confidentiality": "C",
    "Integrity": "It",
    "Availability": "A",
    # --- CIADIE（CIA + 三个分布式特性）---
    "Distributed": "Dis",
    "Immutable": "Imm",
    "Ephemeral": "Eph",
    # --- LINDDUN（隐私七维）---
    "Linkability": "L",
    "Identifiability": "Id",
    "Non-Repudiation": "Nr",
    "Detectability": "Dt",
    "Disclosure of Information": "Di",
    "Unawareness": "U",
    "Non-Compliance": "Nc",
    # --- PLOT4ai ---
    "Technique & Processes": "TP",
    "Accessibility": "Acc",
    "Identifiability & Linkability": "IL",
    "Security": "Sec",
    "Safety": "Saf",
    "Ethics & Human Rights": "EHR",
    # --- EOP (Cornucopia) ---
    # Authentication / Authorization 天然撞首字母，用 Au / Az 区分
    "Authentication": "Au",
    "Authorization": "Az",
    "Cryptography": "Cry",
    "Data Validation & Encoding": "DVE",
    "Session Management": "SM",
    # --- MAESTRO（多智能体）---
    "GoalHijacking": "GH",
    "InterAgentDeception": "IAD",
    "InsecureOrchestration": "IO",
    "ToolMisuse": "TM",
    "PrivilegeAmplification": "PA",
    "MemoryPoisoning": "MP",
    "DataLeakage": "DL",
    "SupplyChainCompromise": "SCC",
    "AutonomyRunaway": "AR",
    "ObservabilityGap": "OG",
}


def _threat_short_type(ttype: str) -> str:
    """威胁类型 -> 短代号（用于威胁 ID，如 P2-E / EE1-S）。

    未在映射表中登记的类型（自定义/新增方法论）退化为取首字母，
    保证不会抛错——但同时会给报告里留下难以理解的 ID，因此新增方法论
    时应在此登记。
    """
    t = (ttype or "").strip()
    if not t:
        return "X"
    if t in THREAT_TYPE_ABBR:
        return THREAT_TYPE_ABBR[t]
    # 未登记：驼峰命名取大写字母（如 SomeThreatName -> STN）
    caps = "".join(ch for ch in t if ch.isupper())
    if len(caps) >= 2:
        return caps[:3]
    return t[:3]


def _assign_threat_ids(threats: list[dict[str, Any]], elements: dict[str, Any]) -> None:
    """为每条威胁就地写入稳定 ID（元素ID-类型代号，如 P2-E）。

    同一元素同一类型出现多条时追加序号（P2-E-2），保证全文唯一可引用。
    """
    id_by_name = {}
    for cell_id, eid in (elements.get("id_by_cell") or {}).items():
        nm = (elements.get("name_by_cell") or {}).get(cell_id)
        if nm:
            id_by_name.setdefault(nm, eid)

    used: dict[str, int] = {}
    for t in threats:
        eid = ""
        # 优先用元素名反查（模型里 threat 只带 component 名，不带 cell id）
        comp = t.get("component") or ""
        if comp:
            eid = id_by_name.get(comp, "")
        base = f"{eid}-{_threat_short_type(t.get('type'))}" if eid else f"T-{_threat_short_type(t.get('type'))}"
        used[base] = used.get(base, 0) + 1
        t["threatId"] = base if used[base] == 1 else f"{base}-{used[base]}"


# 按元素类型分析时的顺序。说明文字不写死威胁类型名——不同方法论下
# 「哪些威胁类型适用于这类元素」完全不同（STRIDE 关注篡改/泄露，
# LINDDUN 关注可链接性/可识别性，PLOT4ai 关注安全/可及性），
# 因此口径说明由 _element_analysis_note 按实际方法论动态生成。
ELEMENT_ANALYSIS_ORDER = [
    ("外部实体", "externalentity"),
    ("处理过程", "process"),
    ("数据存储", "datastore"),
    ("数据流", "flow"),
    ("AI / 智能体元素", "process"),   # AI 元素在方法论上归入 process
]


def _element_analysis_note(methodology: str, group_name: str, cell_key: str) -> str:
    """按方法论 + 元素类别生成分析口径说明（不写死威胁类型名）。

    说明里列出该方法论下该类元素实际需要分析的威胁类型，读者一眼就能
    看出「为什么这类元素只分析了这几类威胁」。
    """
    base = {
        "外部实体": "外部实体不受我方控制，只能从交互侧分析其可能造成的威胁。",
        "处理过程": "处理过程承载业务逻辑，是威胁类型覆盖最完整的元素类别。",
        "数据存储": "数据存储主要关注数据在静态存放期间面临的威胁。",
        "数据流": "数据流关注数据在传输链路上的威胁，跨信任边界与公网链路是检查重点。",
        "AI / 智能体元素": (
            "AI 与智能体元素除通用威胁外，还需关注提示注入、工具越权、"
            "记忆污染与自主失控等专属风险。"
        ),
    }.get(group_name, "")

    try:
        from .methodology import get_threat_types_by_element

        types = get_threat_types_by_element(methodology, cell_key)
    except Exception:  # noqa: BLE001 - 方法论映射缺失时只输出通用说明
        types = []

    if not types:
        return base
    listed = "、".join(types)
    return f"{base}本次方法论下该类元素需分析：{listed}。"


def _group_by_element_kind(
    threats: list[dict[str, Any]],
    elements: dict[str, Any],
    methodology: str = "STRIDE",
) -> list[tuple[str, str, list[dict]]]:
    """按「元素类别」分组威胁（P0 分析章）。

    返回 [(类别名, 口径说明, [威胁...])]，顺序按 ELEMENT_ANALYSIS_ORDER。
    元素类别由元素 ID 前缀反查（EE/P/DS/DF 等）。口径说明按方法论动态
    生成，因此对 CIA / LINDDUN / PLOT4ai / MAESTRO 等同样成立。
    """
    prefix_to_group = {
        "EE": "外部实体",
        "P": "处理过程",
        "DS": "数据存储",
        "DF": "数据流",
        "TB": "信任边界",
    }
    ai_prefixes = {"M", "PR", "VS", "TL", "TD", "AC", "AG", "OR", "MM"}

    # 元素名 -> 类别名
    name_to_group: dict[str, str] = {}
    id_by_cell = elements.get("id_by_cell") or {}
    name_by_cell = elements.get("name_by_cell") or {}
    for cell_id, eid in id_by_cell.items():
        nm = name_by_cell.get(cell_id)
        if not nm:
            continue
        prefix = "".join(ch for ch in eid if ch.isalpha())
        if prefix in ai_prefixes:
            name_to_group[nm] = "AI / 智能体元素"
        else:
            name_to_group[nm] = prefix_to_group.get(prefix, "处理过程")

    buckets: dict[str, list[dict]] = {}
    for t in threats:
        grp = name_to_group.get(t.get("component") or "", "处理过程")
        buckets.setdefault(grp, []).append(t)

    out: list[tuple[str, str, list[dict]]] = []
    for name, cell_key in ELEMENT_ANALYSIS_ORDER:
        if buckets.get(name):
            note = _element_analysis_note(methodology, name, cell_key)
            out.append((name, note, buckets[name]))
    # 兜底：不在预设顺序里的类别（数据异常时也要输出，不能静默丢失）
    for name, items in buckets.items():
        if not any(name == n for n, _, _ in out):
            out.append((name, _element_analysis_note(methodology, name, "process"), items))
    return out


def _build_risk_matrix(threats: list[dict[str, Any]]) -> dict[str, Any]:
    """构造 3×3 风险矩阵：行=影响，列=可能性，格内为威胁条目。

    格内每行是「威胁编号　威胁简称」——只放编号读者无法知道每条威胁
    是什么（编号 = 元素ID-类型代号，须翻明细章或附录 B 对照），附上
    截断后的标题后矩阵本身即可独立读懂。

    没有 DREAD 数据时，退化为按 severity 直接映射（保证矩阵不为空）。
    """
    sev_to_cell = {
        "Critical": (2, 2),
        "High": (1, 2),
        "Medium": (1, 1),
        "Low": (0, 0),
        "Unknown": (1, 1),
    }
    grid: dict[tuple[int, int], list[str]] = {}
    for t in threats:
        dread = t.get("dread")
        if isinstance(dread, dict) and dread:
            try:
                like = (
                    float(dread.get("reproducibility", 0))
                    + float(dread.get("exploitability", 0))
                    + float(dread.get("discoverability", 0))
                ) / 3
                impact = (
                    float(dread.get("damage", 0)) + float(dread.get("affectedUsers", 0))
                ) / 2
                li = 0 if like < 4 else (1 if like < 7 else 2)
                ii = 0 if impact < 4 else (1 if impact < 7 else 2)
            except (TypeError, ValueError):
                ii, li = sev_to_cell.get(t.get("severity", "Unknown"), (1, 1))
        else:
            ii, li = sev_to_cell.get(t.get("severity", "Unknown"), (1, 1))
        _tid = t.get("threatId") or "?"
        # 标题压平空白并截断——矩阵格子宽度有限，完整标题会把格子撑得过高
        _title = " ".join((t.get("title") or "").split())
        if len(_title) > 12:
            _title = _title[:11] + "…"
        grid.setdefault((ii, li), []).append(f"{_tid}　{_title}" if _title else _tid)
    return grid


# 3×3 矩阵的格子配色（影响×可能性的风险等级）。
#
# 与 SEV_COLOR 的关系（两套色板并存，勿混淆）：
# - SEV_COLOR 是「等级标签」色，用于严重/高危/中危/低危的**文字与底纹**，
#   取值固定四档，读者看到红色即知是「严重」；
# - MATRIX_CELL_COLOR 是「矩阵格子」色，表达的是**风险等级连续渐变**
#   （格子只取 绿/黄/橙/红 四种底色，但一格里可能落多条不同等级的威胁，
#   因此不能直接用 SEV_COLOR 的等级-底纹一一对应）。
# 两者的绿/黄/红取向必须一致（都是「绿=低风险」），否则读者会困惑，
# 因此这里复用 SEV_COLOR 的浅色档位作为取值来源，保证色相一致。
MATRIX_CELL_COLOR = [
    ["EAF7EE", "FEF9E7", "FEF5E7"],   # 低影响：低 / 中 / 高
    ["FEF9E7", "FEF5E7", "FDECEA"],   # 中影响
    ["FEF5E7", "FDECEA", "FDECEA"],   # 高影响
]


def _industry_label(stats: dict[str, Any]) -> str:
    industry = stats.get("industry")
    if not industry:
        return ""
    try:
        from .ai_knowledge import get_industry_template

        tmpl = get_industry_template(industry)
        return tmpl["label"] if tmpl else industry
    except Exception:
        return industry


def _exec_summary_text(title: str, methodology: str, threats: list[dict], stats: dict) -> str:
    """执行摘要一句话结论（商业报告标准动作：先给结论再给明细）。"""
    total = len(threats)
    counts = dict(_sev_counts(stats))
    c, h = counts.get("Critical", 0), counts.get("High", 0)
    if total == 0:
        return f"本次基于 {methodology} 方法论对「{title}」的威胁建模未识别到威胁。"
    # 等级口径：摘要句内用纯中文（避免中英夹杂），并在此处首次给出中英对照，
    # 后文表格统一用「严重 Critical」形式，两侧口径一致。
    risk_line = (
        f"其中严重（Critical）{c} 条、高危（High）{h} 条" if (c or h) else "无严重 / 高危项"
    )
    pct_line = f"，合计占 {round((c + h) / total * 100, 1)}%" if (c or h) else ""
    if c:
        advice = "建议立即处置全部严重项，并在 7 天内完成高危项整改。"
    elif h:
        advice = "建议 7 天内完成高危项整改，中低危纳入常规迭代。"
    else:
        advice = "整体风险可控，建议按计划跟进中低危项。"
    return (
        f"本次基于 {methodology} 方法论对「{title}」开展威胁建模，共识别 {total} 条威胁，{risk_line}{pct_line}。{advice}"
    )


# ======================================================================
# Markdown 报告
# ======================================================================

def render_result_markdown(record: dict[str, Any]) -> str:
    """把一条结果记录渲染为 Markdown 报告。

    结构（商业级约定）：元信息表 -> 执行摘要（结论先行）-> 模型概览 ->
    度量指标 -> 威胁明细（按等级分组，唯一全量清单）-> 附录（分级定义）-> 生成声明。
    """
    model = record.get("model") or {}
    summary = model.get("summary") or {}
    stats = record.get("stats") or {}
    methodology = record.get("methodology") or "STRIDE"
    created = _fmt_time(record.get("created_at", 0))
    generated = _now_str()
    title = record.get("title", "未命名")

    threats = _sorted_threats(_collect_threats(model))
    sev_counts = _sev_counts(stats)
    status_counts = _status_counts(threats)
    total = len(threats)
    high_critical = sum(c for s, c in sev_counts if s in ("Critical", "High"))

    lines: list[str] = []

    # —— 报告头 + 元信息表 ——
    lines.append(f"# 威胁建模报告：{title}")
    lines.append("")
    lines.append("| 项目 | 内容 |")
    lines.append("|---|---|")
    lines.append(f"| 报告标题 | {title} |")
    lines.append(f"| 建模方法论 | {methodology} |")
    industry = _industry_label(stats)
    if industry:
        lines.append(f"| 行业场景 | {industry} |")
    lines.append(f"| 建模时间 | {created} |")
    lines.append(f"| 报告生成时间 | {generated} |")
    lines.append(f"| 威胁总数 | {total} |")
    lines.append(f"| 高危及以上 | {high_critical} |")
    lines.append("")

    # —— 1 执行摘要 ——
    lines.append("## 1 执行摘要")
    lines.append("")
    lines.append(_exec_summary_text(title, methodology, threats, stats))
    lines.append("")
    lines.append("**风险等级分布**")
    lines.append("")
    lines.append("| 等级 | 数量 | 占比 |")
    lines.append("|---|---:|---:|")
    for sev, cnt in sev_counts:
        share = f"{round(cnt / total * 100, 1)}%" if total else "-"
        lines.append(f"| {_sev_label(sev)} | {cnt} | {share} |")
    lines.append("")
    bits = " / ".join(f"{k} {v}" for k, v in status_counts.items() if v)
    lines.append(f"**处置状态**：{bits or '无'}")
    lines.append("")

    # —— 2 模型概览 ——
    lines.append(f"## 2 模型概览")
    lines.append("")
    lines.append(f"- **模型标题**：{summary.get('title', '-')}")
    lines.append(f"- **模型描述**：{summary.get('description', '-') or '-'}")
    lines.append(f"- **组件数**：{stats.get('componentCount', '-')}")
    lines.append(f"- **数据流数**：{stats.get('flowCount', '-')}")
    lines.append("")

    # —— 3 度量指标（仅当存在）——
    metrics = stats.get("metrics") or {}
    if metrics:
        lines.append("## 3 度量指标")
        lines.append("")
        lines.append(f"- 元素覆盖度：{_pct(metrics.get('coverageRate'))}（{metrics.get('modeledElements', 0)}/{metrics.get('totalElements', 0)}）")
        lines.append(f"- 高风险威胁收敛率：{_pct(metrics.get('riskConvergence'))}")
        dread_avg = metrics.get("dreadAverage")
        if dread_avg:
            dread_label = {
                "damage": "危害", "reproducibility": "可重复性",
                "exploitability": "可利用性", "affectedUsers": "受影响面",
                "discoverability": "可发现性",
            }
            bits = [f"{dread_label.get(k, k)}:{v}" for k, v in dread_avg.items() if k != "total"]
            lines.append(f"- DREAD 均值：{' / '.join(bits)}（综合 {dread_avg.get('total', 0)}）")
        llm_cov = metrics.get("owaspLlmCoverRate")
        if llm_cov is not None:
            covered = metrics.get("owaspLlmCovered") or []
            lines.append(f"- OWASP Top10 for LLM 覆盖：{_pct(llm_cov)}（{', '.join(covered) if covered else '无'}）")
        compliance = metrics.get("compliance")
        if compliance:
            lines.append("- 合规影响面（仅表示威胁触达的法规域，不代表合规结论）：")
            for item in compliance:
                mark = "●" if item.get("hit") else "○"
                cnt = item.get("relatedThreatCount") or 0
                tail = f"（关联威胁 {cnt} 条）" if cnt else ""
                lines.append(f"  - {mark} {item['code']} {item['label']}{tail}")
                basis = item.get("basis") or ""
                version = item.get("version") or ""
                if basis:
                    lines.append(f"      依据：{basis}{f'（{version}）' if version else ''}")
        lines.append("")

    # 「4 威胁总览」表已裁剪：与下方全量威胁明细逐条重复（同样的 ID/等级/标题/状态），
    # 「按等级浏览」由明细的分组顺序（严重 → 低）直接承接。

    # —— 4 威胁明细 ——
    lines.append(f"## 4 威胁明细")
    lines.append("")
    if not threats:
        lines.append("_未识别到威胁。_")
        lines.append("")
    else:
        # 分组（保持总览的排序顺序，同组内重新聚组）
        by_sev_threats: dict[str, list[dict]] = {}
        for t in threats:
            by_sev_threats.setdefault(t.get("severity", "Unknown"), []).append(t)
        for gi, sev in enumerate(sorted(by_sev_threats, key=_sev), 1):
            items = by_sev_threats[sev]
            lines.append(f"### 4.{gi} {_sev_label(sev)}（{len(items)} 条）")
            lines.append("")
            for i, t in enumerate(items, 1):
                lines.append(f"#### 4.{gi}.{i} {t.get('title', '')}")
                lines.append("")
                dread = _dread_total(t.get("dread"))
                oos_mark = "、**范围外**" if t.get("outOfScope") else ""
                lines.append(f"- **类型**：{t.get('type', '') or '-'}　**组件**：{t.get('component', '') or '-'}")
                lines.append(f"- **状态**：{_status_label(t.get('status'))}{oos_mark}")
                if t.get("cwe"):
                    lines.append(f"- **CWE**：{t['cwe']}")
                if isinstance(t.get("dread"), dict):
                    d = t["dread"]
                    lines.append(
                        f"- **DREAD**：{dread}/50（危害:{d.get('damage',0)} 可重复:{d.get('reproducibility',0)}"
                        f" 可利用:{d.get('exploitability',0)} 影响:{d.get('affectedUsers',0)} 可发现:{d.get('discoverability',0)}）"
                    )
                lines.append(f"- **威胁描述**：{t.get('description', '') or '-'}")
                lines.append(f"- **缓解措施**：{t.get('mitigation', '') or '-'}")
                refs = t.get("references") or []
                if refs:
                    lines.append(f"- **参考资料**：{'；'.join(refs)}")
                lines.append("")

    # —— 附录 ——
    lines.append("## 附录 A　严重度分级定义")
    lines.append("")
    lines.append("| 等级 | 定义 | 建议响应时限 |")
    lines.append("|---|---|---|")
    for name, definition, sla in SEV_DEFINITIONS:
        lines.append(f"| {name} | {definition} | {sla} |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(
        f"*本报告由 VeSync SDLC 平台自动生成于 {generated}，方法论 {methodology}；"
        f"合规影响面等内容仅表示威胁触达的法规域，不代表合规结论。*"
    )
    lines.append("")
    return "\n".join(lines)


# ======================================================================
# Threat Dragon JSON（官方兼容格式，保持不变）
# ======================================================================

def _to_td_json(record: dict[str, Any]) -> dict[str, Any]:
    """返回 Threat Dragon v2 标准模型 JSON（可直接导入官方 TD）。"""
    model = record.get("model") or {}
    td = dict(model)
    detail = td.get("detail") or {}
    if not detail.get("version"):
        detail = dict(detail)
        detail["version"] = "0.1.0"
    td["detail"] = detail
    td.setdefault("summary", {})
    td["summary"]["title"] = record.get("title", td["summary"].get("title", "Threat Model"))
    return td


def render_result_json(record: dict[str, Any]) -> str:
    """把结果渲染为 Threat Dragon 标准 JSON 字符串。"""
    return json.dumps(_to_td_json(record), ensure_ascii=False, indent=2)


# ======================================================================
# CSV 威胁清单
# ======================================================================

def render_result_csv(record: dict[str, Any]) -> str:
    """把威胁清单渲染为 CSV 文本。

    商业级约定：中文列头（便于业务方阅读）、编号列、DREAD 五维展开、
    状态中文化、范围外标记；UTF-8 BOM 保证 Excel 直接打开不乱码。
    """
    model = record.get("model") or {}
    threats = _sorted_threats(_collect_threats(model))
    fieldnames = [
        "编号", "等级", "类型", "威胁标题", "所属组件", "处置状态", "范围外",
        "CWE", "DREAD总分", "危害", "可重复性", "可利用性", "受影响面", "可发现性",
        "威胁描述", "缓解措施", "参考资料",
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for i, t in enumerate(threats, 1):
        d = t.get("dread") if isinstance(t.get("dread"), dict) else {}
        refs = t.get("references") or []
        writer.writerow({
            "编号": i,
            "等级": _sev_label(t.get("severity", "")),
            "类型": t.get("type", ""),
            "威胁标题": t.get("title", ""),
            "所属组件": t.get("component", ""),
            "处置状态": _status_label(t.get("status")),
            "范围外": "是" if t.get("outOfScope") else "否",
            "CWE": t.get("cwe", ""),
            "DREAD总分": _dread_total(t.get("dread")) or "",
            "危害": d.get("damage", "") if d else "",
            "可重复性": d.get("reproducibility", "") if d else "",
            "可利用性": d.get("exploitability", "") if d else "",
            "受影响面": d.get("affectedUsers", "") if d else "",
            "可发现性": d.get("discoverability", "") if d else "",
            "威胁描述": t.get("description", ""),
            "缓解措施": t.get("mitigation", ""),
            "参考资料": "；".join(refs),
        })
    return "\ufeff" + buf.getvalue()


# ======================================================================
# Word (.docx) 报告
# ======================================================================

def _chart_severity_donut(sev_counts: list[tuple[str, int]], total: int) -> bytes | None:
    """生成风险等级分布环形图 PNG（无第三方绘图依赖，纯 Pillow 绘制）。

    商业报告里「等级分布」用图表表达比表格更直观。为避免引入
    matplotlib（体积大、字体配置在容器里易出错），这里用 Pillow 直接
    绘制：环形 + 图例 + 中心总数，导出后即静态图片，打开即见。
    """
    try:
        from PIL import Image, ImageDraw, ImageFont  # type: ignore
    except Exception:  # noqa: BLE001
        return None
    if not total:
        return None

    W, H = 1000, 420
    img = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(img)

    def _font(size: int, bold: bool = False):
        """加载中文字体；系统无中文字体时**放弃出图**（返回图会显示方块乱码）。

        乱码图表比无图更糟：读者会以为数据有问题。因此这里显式返回 None，
        由调用方降级为纯表格呈现。
        """
        path = _font_path_cached(size, bold)
        if not path:
            logger.warning("未找到可用中文字体，等级分布图跳过渲染（降级为表格）")
            return None
        try:
            return ImageFont.truetype(path, size)
        except Exception as exc:  # noqa: BLE001
            logger.warning("中文字体加载失败 %s: %s", path, exc)
            return None

    f_legend = _font(19)
    f_num = _font(30, bold=True)
    f_small = _font(17)
    if f_legend is None or f_num is None or f_small is None:
        return None

    # ---- 左侧环形图 ----
    cx, cy, r_out, r_in = 235, 210, 148, 92
    order = ["Critical", "High", "Medium", "Low", "Unknown"]
    items = [(s, c) for s in order for ss, c in sev_counts if ss == s and c > 0]

    start = -90.0
    for sev, cnt in items:
        sweep = 360.0 * cnt / total
        fg, _bg = SEV_COLOR.get(sev, SEV_COLOR["Unknown"])
        color = tuple(int(fg[i:i + 2], 16) for i in (0, 2, 4))
        d.pieslice(
            [cx - r_out, cy - r_out, cx + r_out, cy + r_out],
            start=start, end=start + sweep, fill=color, outline="white", width=2,
        )
        start += sweep
    # 挖出中心 -> 环形
    d.ellipse([cx - r_in, cy - r_in, cx + r_in, cy + r_in], fill="white")
    # 中心总数
    txt_total = str(total)
    try:
        tw = d.textlength(txt_total, font=f_num)
    except Exception:  # noqa: BLE001
        tw = len(txt_total) * 18
    d.text((cx - tw / 2, cy - 26), txt_total, fill=(31, 58, 95), font=f_num)
    label = "威胁总数"
    try:
        lw = d.textlength(label, font=f_small)
    except Exception:  # noqa: BLE001
        lw = 68
    d.text((cx - lw / 2, cy + 12), label, fill=(100, 116, 139), font=f_small)

    # ---- 右侧图例（含数量与占比）----
    lx, ly = 480, 78
    for sev, cnt in items:
        fg, bg = SEV_COLOR.get(sev, SEV_COLOR["Unknown"])
        color = tuple(int(fg[i:i + 2], 16) for i in (0, 2, 4))
        d.rounded_rectangle([lx, ly + 3, lx + 26, ly + 23], radius=5, fill=color)
        d.text((lx + 40, ly), _sev_label(sev), fill=(55, 65, 81), font=f_legend)
        pct = f"{round(cnt / total * 100, 1)}%"
        d.text((lx + 250, ly + 1), f"{cnt} 条", fill=(100, 116, 139), font=f_small)
        d.text((lx + 340, ly + 1), pct, fill=(100, 116, 139), font=f_small)
        ly += 42

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ======================================================================

def render_result_docx(record: dict[str, Any]) -> bytes:
    """把一条结果记录渲染为 Word (.docx) 商业级报告（二进制字节）。

    结构：封面（标题/信息表/密级）-> 目录域 -> 页眉页脚页码 ->
    执行摘要 -> 模型概览 -> 按元素类型的威胁分析（唯一全量明细章）->
    风险评定 -> 度量指标 -> 附录 A～D（附录 B 为唯一处置跟踪清单）。
    """
    from docx import Document  # type: ignore
    from docx.shared import Pt, RGBColor, Cm  # type: ignore
    from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK  # type: ignore
    from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL  # type: ignore
    from docx.enum.section import WD_SECTION  # type: ignore
    from docx.oxml.ns import qn  # type: ignore
    from docx.oxml import OxmlElement  # type: ignore

    # ---------- 入口类型净化 ----------
    # 记录来自数据库/历史 JSON，字段类型不保证：model / stats 可能是
    # 字符串或列表，title 可能是数字，systemProfile / metrics 可能是列表。
    # 全文有数百处 .get()/.items() 调用，逐处加 isinstance 既啰嗦又必然
    # 漏改；在唯一入口把类型收敛掉，下游即可按契约正常使用。
    def _as_dict(val: Any) -> dict[str, Any]:
        return val if isinstance(val, dict) else {}

    def _as_text(val: Any, default: str = "") -> str:
        if isinstance(val, str):
            return val
        if val is None:
            return default
        return str(val)

    model = _as_dict(record.get("model"))
    summary = _as_dict(model.get("summary"))
    stats = _as_dict(record.get("stats"))
    methodology = _as_text(record.get("methodology")) or "STRIDE"
    created = _fmt_time(record.get("created_at", 0))
    generated = _now_str()
    title = _as_text(record.get("title")) or "威胁建模报告"
    # stats 下的两个高频字典字段同样可能在脏数据里变成列表
    stats = dict(stats)
    stats["systemProfile"] = _as_dict(stats.get("systemProfile"))
    stats["metrics"] = _as_dict(stats.get("metrics"))
    stats["threatCountBySeverity"] = _as_dict(stats.get("threatCountBySeverity"))
    # 模型摘要同样可能被写成非字典：回填净化后的 summary，并保证其文本
    # 字段是字符串（标题/描述为数字或列表时 str() 化，避免下游拼接报错）
    model = dict(model)
    model["summary"] = summary
    for _k in ("description", "title"):
        if _k in summary:
            summary[_k] = _as_text(summary[_k])

    threats = _sorted_threats(_collect_threats(model))
    sev_counts = _sev_counts(stats)
    status_counts = _status_counts(threats)
    total = len(threats)
    high_critical = sum(c for s, c in sev_counts if s in ("Critical", "High"))

    # P0：元素清单（系统分解章） + 威胁 ID 规范化 + 风险矩阵
    elements = _collect_elements(model)
    _assign_threat_ids(threats, elements)
    risk_grid = _build_risk_matrix(threats)

    # P0：章节按内容条件渲染（威胁很少的模型不铺满全部章节，避免空洞）。
    # 按元素类型分组的明细章节紧随其后，动态编号。
    elem_type_groups = _group_by_element_kind(threats, elements, methodology)

    doc = Document()

    # ---------- 基础样式 ----------
    def _set_font(style, name="宋体", size=None, bold=None, color=None):
        try:
            style.font.name = name
            rpr = style.element.get_or_add_rPr()
            rfonts = rpr.get_or_add_rFonts()
            rfonts.set(qn("w:eastAsia"), name)
            rfonts.set(qn("w:ascii"), "Times New Roman")
            rfonts.set(qn("w:hAnsi"), "Times New Roman")
        except Exception:
            pass
        if size is not None:
            style.font.size = Pt(size)
        if bold is not None:
            style.font.bold = bold
        if color is not None:
            style.font.color.rgb = color

    _set_font(doc.styles["Normal"], size=11)
    _set_font(doc.styles["Heading 1"], size=16, bold=True, color=RGBColor(0x1F, 0x3A, 0x5F))
    _set_font(doc.styles["Heading 2"], size=14, bold=True, color=RGBColor(0x2B, 0x57, 0x9A))
    _set_font(doc.styles["Heading 3"], size=12, bold=True, color=RGBColor(0x2B, 0x57, 0x9A))
    _set_font(doc.styles["Heading 4"], size=11, bold=True, color=RGBColor(0x37, 0x41, 0x51))

    # ---------- 商业报告排版基线 ----------
    # 正文行距与段间距：1.5 倍行距是正式报告的可读性基线，
    # 段后 6pt 让段落之间有呼吸感（默认 0 会挤成一坨）。
    try:
        from docx.enum.text import WD_LINE_SPACING  # type: ignore
        from docx.shared import Cm as _Cm  # type: ignore

        nf = doc.styles["Normal"].paragraph_format
        nf.line_spacing_rule = WD_LINE_SPACING.MULTIPLE
        nf.line_spacing = 1.5
        nf.space_after = Pt(6)
        nf.space_before = Pt(0)
    except Exception:  # noqa: BLE001
        pass

    # 章节标题的段间距：标题前留白大、标题后留白小（符合「标题贴正文」惯例）
    for _lvl, (_sb, _sa) in {1: (18, 8), 2: (14, 6), 3: (10, 4), 4: (8, 4)}.items():
        try:
            _pf = doc.styles[f"Heading {_lvl}"].paragraph_format
            _pf.space_before = Pt(_sb)
            _pf.space_after = Pt(_sa)
            _pf.keep_with_next = True   # 标题不与正文被分页割裂
        except Exception:  # noqa: BLE001
            pass

    # 页面设置：A4 + 对称页边距（商业报告常用 2.2~2.5cm）
    for _sec in doc.sections:
        try:
            _sec.page_width = _Cm(21.0)
            _sec.page_height = _Cm(29.7)
            _sec.top_margin = _Cm(2.4)
            _sec.bottom_margin = _Cm(2.2)
            _sec.left_margin = _Cm(2.4)
            _sec.right_margin = _Cm(2.2)
            _sec.header_distance = _Cm(1.4)
            _sec.footer_distance = _Cm(1.2)
        except Exception:  # noqa: BLE001
            pass

    # 文档属性（商业报告元数据）
    props = doc.core_properties
    props.title = f"威胁建模报告：{title}"
    props.author = "VeSync SDLC 平台"
    props.subject = f"威胁建模（{methodology}）"
    props.comments = f"报告生成时间 {generated}"
    props.category = "安全评估报告"

    # ---------- 章节编排（条件渲染，目录与实际章节共用同一份清单） ----------
    # P1：系统说明（建模对象）——由分析阶段产出的 systemProfile 驱动，
    # 缺失时��章省略（不占位、不写“无数据”）。
    system_profile = stats.get("systemProfile") or {}
    has_profile = bool(system_profile)

    # 逻辑章节键 -> 标题（编号在渲染时按顺序分配）
    plan: list[str] = []
    if has_profile:
        plan.append("system")
    plan.append("summary")          # 执行摘要
    plan.append("method")           # 方法说明
    plan.append("decomposition")    # 系统分解
    plan.append("analysis")         # 按元素类型的威胁分析
    plan.append("assessment")       # 风险评定
    # 「tracking（风险汇总与跟踪）」「overview（威胁总览）」两章已裁剪：
    # 与第 5 章全量明细、附录 B 处置跟踪清单高度重复（同一批威胁渲染三遍）。
    plan.append("metrics")          # 度量指标（仅有数据时）
    # 「limitation（建模局限与后续建议）」章已裁剪：按需移除。

    CHAPTER_TITLES = {
        "system": "系统说明：建模对象",
        "summary": "执行摘要",
        "method": "方法说明",
        "decomposition": "系统分解：数据流图",
        "analysis": "威胁分析（按元素类型）",
        "assessment": "风险评定",
        "metrics": "度量指标",
    }
    # 度量指标章仅在存在 metrics 时才渲染
    metrics_data = stats.get("metrics") or {}
    if not metrics_data:
        plan.remove("metrics")

    chapter_no: dict[str, int] = {}
    plan_render: list[tuple[str, int, str]] = []  # (key, 编号, 标题)
    _n = 0
    for _k in plan:
        _n += 1
        chapter_no[_k] = _n
        plan_render.append((_k, _n, CHAPTER_TITLES[_k]))

    # 目录条目（一级章 + 二级节）——(层级, 标题文本)
    # 二级条目的编号与标题必须与正文实际渲染的 add_heading 文本完全一致，
    # 否则目录与正文会对不上。这里集中生成一份 sub_sections 清单，正文渲染
    # 与目录渲染共用（此前两处各自拼接标题，改章节结构时必然漏改一处）。
    _toc_entries: list[tuple[int, str]] = []
    sub_sections: dict[str, list[str]] = {}   # 章节 key -> 二级节标题清单
    for _k, _no, _t in plan_render:
        subs: list[str] = []
        if _k == "system":
            subs.append(f"{_no}.1{TITLE_SEP}产品概述")
            if system_profile.get("architecture"):
                subs.append(f"{_no}.2{TITLE_SEP}架构分层")
            if system_profile.get("journeys"):
                subs.append(f"{_no}.3{TITLE_SEP}关键用户旅程")
            if (system_profile.get("inScope") or system_profile.get("outOfScope")
                    or system_profile.get("assumptions")):
                subs.append(f"{_no}.4{TITLE_SEP}建模范围与前提假设")
            if system_profile.get("attackSurface"):
                subs.append(f"{_no}.5{TITLE_SEP}攻击面清单")
        elif _k == "summary":
            subs.append(f"{_no}.1{TITLE_SEP}风险等级分布")
            subs.append(f"{_no}.2{TITLE_SEP}处置状态分布")
        elif _k == "method":
            subs.append(f"{_no}.1{TITLE_SEP}元素类型与威胁类型映射")
            if "STRIDE" in methodology.upper():
                subs.append(f"{_no}.2{TITLE_SEP}STRIDE 六类威胁释义")
        elif _k == "decomposition":
            subs.append(f"{_no}.1{TITLE_SEP}图例说明")
            for _gi, (_gname, _,) in enumerate(elements.get("groups") or [], 1):
                subs.append(f"{_no}.{_gi + 1}{TITLE_SEP}{_gname}清单")
            if elements.get("boundaries"):
                subs.append(f"{_no}.{len(elements.get('groups') or []) + 2}"
                            f"{TITLE_SEP}信任边界安全分析")
        elif _k == "analysis":
            for _ai, (_aname, _anote_x, _aitems) in enumerate(elem_type_groups, 1):
                subs.append(f"{_no}.{_ai}{TITLE_SEP}{_aname}（{len(_aitems)} 条）")
        elif _k == "assessment":
            subs.append(f"{_no}.1{TITLE_SEP}残余风险矩阵")
            subs.append(f"{_no}.2{TITLE_SEP}" + ("DREAD 评分汇总" if any(
                isinstance(t.get("dread"), dict) for t in threats) else "风险评分方式说明"))
        elif _k == "metrics":
            if metrics_data.get("compliance"):
                subs.append(f"{_no}.1{TITLE_SEP}合规影响面")
        sub_sections[_k] = subs
        _toc_entries.append((1, f"{_no}{TITLE_SEP}{_t}"))
        for _s in subs:
            _toc_entries.append((2, _s))

    # ---------- 小工具 ----------
    def _shade(cell, color_hex: str) -> None:
        """单元格底纹。"""
        tc_pr = cell._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:fill"), color_hex)
        tc_pr.append(shd)

    def _cell_text(cell, text: str, bold=None, size=None, color=None, align=None,
                   keep_newlines: bool = False) -> None:
        """写入单元格文本。

        默认把换行压平（威胁字段里的 \\n 会把单行内容拆成多段、破坏读感）；
        keep_newlines=True 时保留换行（用于确需多行显示的格子）。
        """
        cell.text = ""
        p = cell.paragraphs[0]
        if align is not None:
            p.alignment = align
        if keep_newlines:
            parts = [ln for ln in str(text).split("\n")]
        else:
            parts = [" ".join(str(text).split())]
        for _i, _part in enumerate(parts):
            if _i > 0:
                p = cell.add_paragraph()
                if align is not None:
                    p.alignment = align
                p.paragraph_format.space_after = Pt(0)
            run = p.add_run(_part)
            if bold is not None:
                run.bold = bold
            if size is not None:
                run.font.size = Pt(size)
            if color is not None:
                run.font.color.rgb = color
            try:
                run.font.name = "宋体"
                run._element.rPr.rFonts.set(qn("w:eastAsia"), "宋体")
            except Exception:
                pass

    def _cell_borders(cell, color: str = BRAND["border"], size: int = 4) -> None:
        """为单元格设置四边细边框（统一色调，替代 Word 默认黑框）。"""
        tc_pr = cell._tc.get_or_add_tcPr()
        borders = OxmlElement("w:tcBorders")
        for edge in ("top", "left", "bottom", "right"):
            el = OxmlElement(f"w:{edge}")
            el.set(qn("w:val"), "single")
            el.set(qn("w:sz"), str(size))
            el.set(qn("w:color"), color)
            borders.append(el)
        tc_pr.append(borders)

    def _cell_valign(cell) -> None:
        """单元格内容垂直居中（多行长文本表格更整齐）。"""
        tc_pr = cell._tc.get_or_add_tcPr()
        va = OxmlElement("w:vAlign")
        va.set(qn("w:val"), "center")
        tc_pr.append(va)

    def _repeat_header(row) -> None:
        """跨页时自动重复表头行（长表格必备）。"""
        tr_pr = row._tr.get_or_add_trPr()
        el = OxmlElement("w:tblHeader")
        el.set(qn("w:val"), "true")
        tr_pr.append(el)

    def _est_row_cm(row) -> float:
        """按单元格文本量粗估行的渲染高度（cm）。

        10pt 中文字符宽约 0.36cm，行高（含行距）约 0.48cm；列宽取自
        cell.width（_make_table 已按 widths 设置）。误差对「矮/高行」
        的粗分足够用——只服务于长表的 cantSplit 阈值判断。
        """
        lines = 1
        for cell in row.cells:
            w = cell.width
            w_cm = w.cm if (w is not None and w.cm) else 3.6
            cpl = max(4, int(w_cm / 0.36))  # 每行可容纳字符数
            n = 0
            for seg in (cell.text or "").split("\n"):
                n += max(1, (len(seg) + cpl - 1) // cpl)
            lines = max(lines, n)
        return lines * 0.48 + 0.25

    def _wrap_no_split(table, widths: list[float] | None) -> None:
        """把整张小表包进一个 1x1 无边框容器表的单元格内，容器行设
        cantSplit——整张表随之不可分割（要么完整留在本页，要么整体去下页）。

        这是「与下段同页」（keep_with_next）胶合方案的替代：Word/WPS 对
        该分页属性的段落**常显小黑点**，且任何显示设置都无法隐藏（编辑
        标记开关只控制空格/段落符等，不控制分页属性点）；而嵌套 + 行
        cantSplit 属于行属性，**不产生任何编辑标记**。cantSplit 是软约束，
        内容超过一页时 Word 仍会强制分页，不会死锁。
        """
        outer = doc.add_table(rows=1, cols=1)
        outer.style = "Normal Table"  # 无边框、无底纹
        outer.alignment = WD_TABLE_ALIGNMENT.CENTER
        oc = outer.rows[0].cells[0]
        # 单元格边距清零（两级都要清）：
        # - tcPr/tcMar：单元格自身的左右内边距
        # - tblPr/tblCellMar：**表格级的默认单元格内边距**，来自 TableNormal
        #   样式的 w:tblCellMar（左右各 108 twips = 5.4pt）。只清 tcMar 不够：
        #   表格级边距会把容器表整体撑宽 10.8pt，居中对齐后左右各溢出
        #   5.4pt，内表右缘越过版心右边界（实测「右缘 538.4pt vs 版心限
        #   532.9pt」即此因，21 张表全部越界）。表格级必须显式清零。
        tc_pr = oc._tc.get_or_add_tcPr()
        mar = OxmlElement("w:tcMar")
        for side in ("top", "left", "bottom", "right"):
            el = OxmlElement(f"w:{side}")
            el.set(qn("w:w"), "0")
            el.set(qn("w:type"), "dxa")
            mar.append(el)
        tc_pr.append(mar)
        # 表格级几何修正（总宽 / 零缩进 / 零表格级单元格边距）——与内表同一
        # 套修正：容器表不修正同样会因继承的 108 twips 边距而整体右移越界。
        if widths:
            outer.autofit = False
            oc.width = Cm(sum(widths))
        _fix_table_box(outer, widths)
        # 把内表 XML 搬进外层单元格（lxml 移动 = 同一节点，后续对 table
        # 的引用——如威胁分析表的等级着色——依然有效）
        oc.paragraphs[0]._p.addprevious(table._tbl)
        # 单元格必须以段落结尾；把搬运后残余的空段压到最小（1pt），
        # 避免表下多出一条空白
        tail_p = oc.paragraphs[-1]
        tail_p.paragraph_format.space_before = Pt(0)
        tail_p.paragraph_format.space_after = Pt(0)
        _p_pr = tail_p._p.get_or_add_pPr()
        _r_pr = OxmlElement("w:rPr")
        _sz = OxmlElement("w:sz")
        _sz.set(qn("w:val"), "2")  # 半磅 = 1pt
        _r_pr.append(_sz)
        _p_pr.append(_r_pr)
        # 容器行整行不可拆 → 内表整体不可拆
        _tr_pr = outer.rows[0]._tr.get_or_add_trPr()
        _tr_pr.append(OxmlElement("w:cantSplit"))

    def _set_row_height(row, cm: float) -> None:
        """设置行最小高度，避免单行表格过于压缩。"""
        tr_pr = row._tr.get_or_add_trPr()
        h = OxmlElement("w:trHeight")
        h.set(qn("w:val"), str(int(cm * 567)))  # cm -> twips
        h.set(qn("w:hRule"), "atLeast")
        tr_pr.append(h)

    def _fix_table_box(table, widths: list[float] | None) -> None:
        """固定表格的几何盒子：显式总宽 + 零缩进 + 零表格级单元格边距。

        为什么必须做（实测过的坑）：Word 计算表格宽度时把**表格级单元格
        边距**（TableNormal / Table Grid 样式的 w:tblCellMar，左右各 108
        twips = 5.4pt）算在表格占位里。widths 合计已经等于版心宽（464.9pt）
        时，Word 仍按 464.9+10.8 布局，配合居中对齐就把整表右移/越界
        （实测：表格左缘 73.5pt 而非版心左缘 68.1pt，右缘 538.4pt 超过版心
        右限 532.9pt —— 26 张表里 21 张如此）。

        修法三件套缺一不可：
        1. w:tblW 显式给出总宽（dxa），让表格宽度不再由内容/边距推导；
        2. w:tblInd = 0，清除从样式继承的缩进；
        3. w:tblCellMar 四边归零，表格布局不再附带隐形边距。
        """
        tbl_pr = table._tbl.tblPr
        if widths:
            total_tw = int(sum(widths) * 567)   # cm -> twips
            tbl_w = tbl_pr.find(qn("w:tblW"))
            if tbl_w is None:
                tbl_w = OxmlElement("w:tblW")
                tbl_pr.insert(0, tbl_w)
            tbl_w.set(qn("w:type"), "dxa")
            tbl_w.set(qn("w:w"), str(total_tw))
        # 缩进清零
        tbl_ind = OxmlElement("w:tblInd")
        tbl_ind.set(qn("w:w"), "0")
        tbl_ind.set(qn("w:type"), "dxa")
        # 表格级单元格边距清零
        tbl_cell_mar = OxmlElement("w:tblCellMar")
        for side in ("top", "left", "bottom", "right"):
            el = OxmlElement(f"w:{side}")
            el.set(qn("w:w"), "0")
            el.set(qn("w:type"), "dxa")
            tbl_cell_mar.append(el)
        # tblInd / tblCellMar 在 tblPr 中的顺序受 schema 约束：须排在 tblLook
        # 之前；tblInd 又要排在 tblCellMar 之前。统一插到 tblLook 前并保持
        # 相对顺序，避免严格校验器（Word 会对乱序的 tblPr 报「无法打开」）。
        lookup = tbl_pr.find(qn("w:tblLook"))
        for el in (tbl_ind, tbl_cell_mar):
            if lookup is not None:
                lookup.addprevious(el)
            else:
                tbl_pr.append(el)

    def _make_table(headers: list[str], rows: list[list[str]], widths: list[float] | None = None,
                    header_fill: str = BRAND["secondary"], zebra: bool = True) -> Any:
        """带表头底纹 + 隔行底纹 + 统一边框的数据表。

        相比 Word 默认表格：表头用品牌色白字、奇偶行交替浅底（便于横向读行）、
        边框统一为浅灰而非纯黑、内容垂直居中、跨页自动重复表头。
        """
        table = doc.add_table(rows=1, cols=len(headers))
        table.style = "Table Grid"
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        # 表头：底纹 + 白字加粗 + 垂直居中 + 跨页重复
        for i, h in enumerate(headers):
            hc = table.rows[0].cells[i]
            _cell_text(hc, h, bold=True, color=RGBColor(0xFF, 0xFF, 0xFF), size=10,
                       align=WD_ALIGN_PARAGRAPH.CENTER)
            # 表头段落 keepNext：把表头行与首个数据行绑定。否则表格起始位置
            # 靠近页尾时会出现「表头孤行」——首个数据行（不可拆）跳到下页，
            # 表头单独留在上页并在下页重复一次，中间留大片空白（附录 C
            # 术语表曾出现）。这是 Word 防表格孤行的标准手段；行属性没有
            # 等价物，只能设在表头段落的分页属性上。
            for _hp in hc.paragraphs:
                _hp.paragraph_format.keep_with_next = True
            _shade(hc, header_fill)
            _cell_valign(hc)
            _cell_borders(hc, BRAND["border"])
        _repeat_header(table.rows[0])
        _set_row_height(table.rows[0], 0.72)

        for r_i, row in enumerate(rows):
            cells = table.add_row().cells
            for i, val in enumerate(row):
                _cell_text(cells[i], val, size=10)
                _cell_valign(cells[i])
                _cell_borders(cells[i], BRAND["border"])
                if zebra and r_i % 2 == 1:
                    _shade(cells[i], BRAND["zebra"])
        if widths:
            # 自动布局关闭后列宽才生效
            table.autofit = False
            for row in table.rows:
                for i, w in enumerate(widths):
                    row.cells[i].width = Cm(w)
            # 固定表格盒子（总宽/零缩进/零单元格边距），否则 Word 会把
            # 表格级默认边距算进宽度导致整表右移越界（见 _fix_table_box）
            _fix_table_box(table, widths)

        # ---------- 分页控制（全部使用无编辑标记的行属性，构建时就地设置） ----------
        # 行属性（trPr）不会被后续 _cell_text 重写洗掉（那只会重建段落），
        # 因此无需再留保存前的后处理步骤。
        # - 小表（<=12 行）：全行不拆 + 整表嵌入防拆容器（嵌套方案见
        #   _wrap_no_split）——整表要么完整在本页要么整体去下页；
        # - 长表（>12 行）：矮行（估算 <=3cm）不拆保证可读；高行（威胁描述/
        #   消减措施动辄七八行文字）允许跨页拆开避免页尾大块空白，下页开头
        #   由 tblHeader 自动重复表头。
        _is_small = len(table.rows) <= 12
        for row in table.rows:
            if not _is_small and _est_row_cm(row) > 3.0:
                continue  # 长表的高行允许拆分
            row._tr.get_or_add_trPr().append(OxmlElement("w:cantSplit"))
        if _is_small:
            _wrap_no_split(table, widths)
        return table

    def _field(paragraph, instr: str, placeholder: str = "") -> None:
        """插入 Word 域（目录 TOC / 页码 PAGE）。"""
        run = paragraph.add_run()
        fld_begin = OxmlElement("w:fldChar")
        fld_begin.set(qn("w:fldCharType"), "begin")
        instr_el = OxmlElement("w:instrText")
        instr_el.set(qn("xml:space"), "preserve")
        instr_el.text = instr
        fld_sep = OxmlElement("w:fldChar")
        fld_sep.set(qn("w:fldCharType"), "separate")
        t_el = OxmlElement("w:t")
        t_el.text = placeholder
        fld_end = OxmlElement("w:fldChar")
        fld_end.set(qn("w:fldCharType"), "end")
        for el in (fld_begin, instr_el, fld_sep, t_el, fld_end):
            run._element.append(el)

    def _kv_table(pairs: list[tuple[str, str]], zebra: bool = True) -> None:
        """两列「项目 | 内容」信息表（键列窄底纹、值列正常）。

        宽度合计 = 版心宽 16.4cm（键列 3.8 + 值列 12.6），与正文右边缘对齐。
        """
        _make_table(["项目", "内容"], [(k, v) for k, v in pairs],
                    widths=[3.8, 12.6], zebra=zebra)

    def _bookmark(paragraph, name: str) -> None:
        """在段落起始处插入书签（供目录的 PAGEREF 域引用页码）。

        bookmarkStart 必须作为段落的第一个子元素插入，且 bookmarkEnd 的
        w:id 与 start 一致，否则 Word 会报「书签已损坏」。
        """
        try:
            import hashlib

            bid = str(int(hashlib.md5(name.encode("utf-8")).hexdigest()[:6], 16))
            start = OxmlElement("w:bookmarkStart")
            start.set(qn("w:id"), bid)
            start.set(qn("w:name"), name)
            end = OxmlElement("w:bookmarkEnd")
            end.set(qn("w:id"), bid)
            paragraph._p.insert(0, start)
            paragraph._p.append(end)
        except Exception as _exc:  # noqa: BLE001
            logger.warning("书签插入失败 %s: %s", name, _exc)

    def _page_ref_field(paragraph, bookmark: str) -> None:
        """插入 PAGEREF 域（引用书签所在页码）。

        未更新域时显示占位符「-」：宁可显示占位符，也不能显示一个错误的
        页码——后者会让读者按错误页码翻找。
        """
        _field(paragraph, f"PAGEREF {bookmark} \\h", "-")

    def _h2(no: int | str, text: str, bookmark: str | None = None):
        """二级标题：文本与书签名都由「编号 + 标题」内部拼出。

        目录条目与正文标题必须产生**完全相同**的标题文本，否则书签对不上、
        页码域全部失效。这里把拼接收口到本函数，调用方只传编号与纯标题，
        两侧分别经 _h2 / _toc_bookmark 生成同一结果。
        """
        full = f"{no}{TITLE_SEP}{text}"
        p = doc.add_heading(full, level=2)
        _bookmark(p, bookmark or _toc_bookmark(2, full))
        return p

    def _h1(no: int | str, text: str) -> None:
        """一级章节标题：带主色下划线装饰条 + 书签（供目录页码域引用）。

        商业报告的一级标题通常在下方压一条实线（区分「章」与普通段落），
        这里用段落底边框实现——打印与转 PDF 都不会丢。

        注意：标题文本与书签文本必须是**同一个字符串**（同一 TITLE_SEP），
        书签名由 md5(文本) 派生，文本差一个字符书签就对不上。
        """
        full = f"{no}{TITLE_SEP}{text}"
        p = doc.add_heading(full, level=1)
        _bookmark(p, _toc_bookmark(1, full))
        p_pr = p._p.get_or_add_pPr()
        pbdr = OxmlElement("w:pBdr")
        bottom = OxmlElement("w:bottom")
        bottom.set(qn("w:val"), "single")
        bottom.set(qn("w:sz"), "12")
        bottom.set(qn("w:space"), "4")
        bottom.set(qn("w:color"), BRAND["secondary"])
        pbdr.append(bottom)
        p_pr.append(pbdr)
        return p

    def _appendix_title(text: str) -> None:
        """附录标题（不参与正文编号，同样带装饰条）。"""
        p = doc.add_heading(text, level=1)
        p_pr = p._p.get_or_add_pPr()
        pbdr = OxmlElement("w:pBdr")
        bottom = OxmlElement("w:bottom")
        bottom.set(qn("w:val"), "single")
        bottom.set(qn("w:sz"), "12")
        bottom.set(qn("w:space"), "4")
        bottom.set(qn("w:color"), BRAND["accent"])
        pbdr.append(bottom)
        p_pr.append(pbdr)
        return p

    def _make_analysis_table(container, items: list[dict]) -> None:
        """按元素类型的威胁分析表（一行一条威胁）。

        列：威胁 ID / 等级 / 威胁描述 / 现有安全措施 / 消减措施。
        「现有安全措施」区分「当前已有什么」与「接下来做什么」——这是
        残余风险判定的前提，两者混淆会让读者无法判断风险是否已被覆盖。
        """
        rows = []
        for t in items:
            sev = t.get("severity", "")
            # 原「威胁明细（按等级）」章已裁剪（与本章内容重复），其独有字段
            # （CWE / 合规映射 / 参考资料）并入对应列尾，保证信息不丢失。
            _desc = t.get("description", "") or t.get("title", "") or "-"
            if t.get("cwe"):
                _desc += f"（CWE {t['cwe']}）"
            _mit = t.get("mitigation", "") or "—"
            _comp = t.get("complianceRefs") or []
            _refs = t.get("references") or []
            if _comp:
                _mit += f"　合规映射：{'、'.join(str(x) for x in _comp)}"
            if _refs:
                _mit += f"　参考：{'；'.join(str(x) for x in _refs)}"
            rows.append([
                t.get("threatId", "-"),
                _sev_label(sev),
                _desc,
                t.get("existingControls") or "—",
                _mit,
            ])
        tbl = _make_table(
            ["威胁 ID", "等级", "威胁描述", "现有安全措施", "消减措施"],
            rows, widths=[1.8, 1.6, 5.6, 3.6, 3.8],   # 合计 16.4
        )
        for r_idx, t in enumerate(items, start=1):
            sev = t.get("severity", "")
            fg, bg = SEV_COLOR.get(sev, SEV_COLOR["Unknown"])
            cell = tbl.rows[r_idx].cells[1]
            _shade(cell, bg)
            _cell_text(cell, _sev_label(sev), bold=True, color=RGBColor(
                int(fg[0:2], 16), int(fg[2:4], 16), int(fg[4:6], 16)), size=9)

    # ---------- 页眉 / 页脚分节 ----------
    # 商业报告惯例：封面不显示页眉页脚；目录用罗马数字；正文用阿拉伯数字
    # 且从 1 重新起算。这需要 3 个「节」，并断开与前一节的页眉页脚链接。
    def _hr(paragraph, color: str = BRAND["rule"]) -> None:
        """段落底部边框（用作页眉下的分隔横线）。"""
        p_pr = paragraph._p.get_or_add_pPr()
        pbdr = OxmlElement("w:pBdr")
        bottom = OxmlElement("w:bottom")
        bottom.set(qn("w:val"), "single")
        bottom.set(qn("w:sz"), "6")
        bottom.set(qn("w:space"), "2")
        bottom.set(qn("w:color"), color)
        pbdr.append(bottom)
        p_pr.append(pbdr)

    def _set_page_numbering(section, fmt: str, start: int | None = None) -> None:
        """设置本节页码格式与起始页号。"""
        sect_pr = section._sectPr
        pg = sect_pr.find(qn("w:pgNumType"))
        if pg is None:
            pg = OxmlElement("w:pgNumType")
            sect_pr.append(pg)
        pg.set(qn("w:fmt"), fmt)
        if start is not None:
            pg.set(qn("w:start"), str(start))

    def _unlink(part) -> None:
        """断开与前一节的链接，使本节可独立设置页眉/页脚内容。"""
        try:
            part.is_linked_to_previous = False
        except Exception:  # noqa: BLE001
            pass

    def _style_runs(paragraph, size: float = 8.5, color: str = BRAND["muted_light"]) -> None:
        for r in paragraph.runs:
            r.font.size = Pt(size)
            r.font.color.rgb = RGBColor(
                int(color[0:2], 16), int(color[2:4], 16), int(color[4:6], 16)
            )

    # ---------- 封面（第 1 节，无页眉页脚） ----------
    # 顶部品牌条
    _brand_p = doc.add_paragraph()
    _brand_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _br = _brand_p.add_run("VeSync　安全开发生命周期（SDLC）平台")
    _br.font.size = Pt(10)
    _br.font.color.rgb = RGBColor(0x64, 0x74, 0x8B)
    try:
        _br.font.name = "微软雅黑"
        _br._element.rPr.rFonts.set(qn("w:eastAsia"), "微软雅黑")
    except Exception:
        pass

    # 封面垂直定位：用一个固定高度的空白段落把标题压到视觉中线附近，
    # 而不是靠 4 个空段落堆叠——空段落的高度受 Normal 样式（1.5 倍行距）
    # 影响，一旦正文行距调整，封面版式就会整体漂移。这里显式指定行高，
    # 版式与样式解耦。
    _spacer = doc.add_paragraph()
    _spacer.paragraph_format.space_after = Pt(0)
    _spacer.paragraph_format.line_spacing = Pt(72)   # 固定 72pt 行高
    _spacer.add_run("")

    # 封面主标题
    cover_title = doc.add_paragraph()
    cover_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cover_title.paragraph_format.space_after = Pt(0)
    ct = cover_title.add_run("威胁建模报告")
    ct.bold = True
    ct.font.size = Pt(32)
    ct.font.color.rgb = RGBColor(0x1F, 0x3A, 0x5F)
    try:
        ct.font.name = "微软雅黑"
        ct._element.rPr.rFonts.set(qn("w:eastAsia"), "微软雅黑")
    except Exception:
        pass

    # 英文副题（商业报告常见的中英对照标题）
    cover_en = doc.add_paragraph()
    cover_en.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cover_en.paragraph_format.space_after = Pt(10)
    ce = cover_en.add_run("THREAT MODELING REPORT")
    ce.font.size = Pt(11)
    ce.font.color.rgb = RGBColor(0xC8, 0xA7, 0x5B)
    ce.font.name = "Times New Roman"

    # 标题下的装饰分隔线（点缀色，短横线）
    _deco = doc.add_paragraph()
    _deco.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _deco.paragraph_format.space_after = Pt(14)
    _dr = _deco.add_run("────────────　◆　────────────")
    _dr.font.size = Pt(10)
    _dr.font.color.rgb = RGBColor(0xC8, 0xA7, 0x5B)

    # 报告对象标题
    cover_sub = doc.add_paragraph()
    cover_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cover_sub.paragraph_format.space_after = Pt(24)
    cs = cover_sub.add_run(title)
    cs.bold = True
    cs.font.size = Pt(17)
    cs.font.color.rgb = RGBColor(0x2B, 0x57, 0x9A)
    try:
        cs.font.name = "微软雅黑"
        cs._element.rPr.rFonts.set(qn("w:eastAsia"), "微软雅黑")
    except Exception:
        pass

    # 行业场景仅在建模时选择了行业模板才有值，为空时整行不渲染（避免无意义的「—」行）
    _industry = _industry_label(stats)
    _meta_rows = [
        ("报告标题", title),
        ("建模方法论", methodology),
    ]
    if _industry:
        _meta_rows.append(("行业场景", _industry))
    _meta_rows += [
        ("威胁总数", f"{total} 条（严重 {dict(sev_counts).get('Critical', 0)}、"
                     f"高危 {dict(sev_counts).get('High', 0)}）"),
        ("建模时间", created),
        ("报告生成时间", generated),
        ("报告版本", "V1.0"),
        ("报告密级", "内部"),
        ("编制单位", "VeSync SDLC 安全平台"),
    ]
    _kv_table(_meta_rows, zebra=False)

    doc.add_paragraph()
    cover_note = doc.add_paragraph()
    cover_note.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cn = cover_note.add_run("本文档包含公司安全评估信息，请勿外传")
    cn.font.size = Pt(9)
    cn.font.color.rgb = RGBColor(0xC0, 0x39, 0x2B)

    # 封面结束 → 新节（目录节）
    doc.add_section(WD_SECTION.NEW_PAGE)

    # ---------- 目录节：页眉页脚 + 罗马数字页码 ----------
    _toc_sec = doc.sections[-1]
    _unlink(_toc_sec.header)
    _unlink(_toc_sec.footer)
    _set_page_numbering(_toc_sec, "upperRoman", start=1)

    _th_p = _toc_sec.header.paragraphs[0]
    _th_p.text = ""
    _th_p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    _thr = _th_p.add_run(f"{title}　威胁建模报告")
    _style_runs(_th_p)
    _hr(_th_p)

    _tf_p = _toc_sec.footer.paragraphs[0]
    _tf_p.text = ""
    _tf_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _tfr = _tf_p.add_run("VeSync SDLC 安全平台　·　")
    _field(_tf_p, "PAGE", "I")
    _style_runs(_tf_p)

    # ---------- 目录 ----------
    doc.add_heading("目　录", level=1)
    toc_intro = doc.add_paragraph()
    tir = toc_intro.add_run(
        "本报告按「建模对象 → 分析方法 → 系统分解 → 逐元素威胁分析 → 风险评定 → 处置跟踪」"
        "的顺序编排，读者可顺序阅读，也可按目录直达关注章节。"
    )
    tir.font.size = Pt(9.5)
    tir.font.color.rgb = RGBColor(0x64, 0x74, 0x8B)

    doc.add_paragraph()

    # ---- 目录条目：段落右对齐制表位 + 前导点，页码用 PAGEREF 域 ----
    # 规范目录的形制是「标题 …… 页码」。这里为每个条目设置右对齐制表位
    # （位置 = 版心宽度）并启用 dot leader，标题与页码之间自动铺满前导点；
    # 页码用 PAGEREF 域指向对应书签，Word 更新域后即为准确页码，未更新时
    # 显示占位符「-」而不是错误的页码——宁可不显示，也不能显示错页码。
    #
    # 说明：不再插入整篇 TOC 域。此前 TOC 域与静态条目并存，用户按 F9 更新
    # 后 Word 会在静态目录之前再插入一份完整目录，页面上出现两份目录。
    # 现在静态条目本身带书签与 PAGEREF 域，按 F9 更新本地目录即可得到
    # 带页码的可跳转目录，行为唯一且不会重复。
    for _lvl, _txt in _toc_entries:
        _tp = doc.add_paragraph()
        _pf = _tp.paragraph_format
        _pf.space_after = Pt(2)
        _pf.line_spacing = 1.15
        # 二级条目左缩进（用段落缩进而非全角空格硬撑，保证对齐精确）
        if _lvl == 2:
            _pf.left_indent = Cm(0.74)
        # 右对齐制表位 + 前导点，位置到版心右缘
        _tabs = OxmlElement("w:tabs")
        _tab = OxmlElement("w:tab")
        _tab.set(qn("w:val"), "right")
        _tab.set(qn("w:leader"), "dot")
        _tab.set(qn("w:pos"), str(int(CONTENT_WIDTH_CM * 567)))  # cm -> twips
        _tabs.append(_tab)
        _tp._p.get_or_add_pPr().append(_tabs)

        _tr = _tp.add_run(_txt)
        _tr.font.size = Pt(10.5 if _lvl == 1 else 10)
        _tr.bold = _lvl == 1
        if _lvl == 1:
            _tr.font.color.rgb = RGBColor(0x1F, 0x3A, 0x5F)
        else:
            _tr.font.color.rgb = RGBColor(0x47, 0x55, 0x69)
        # 制表符 -> 页码域
        _tp.add_run("\t")
        _page_ref_field(_tp, _toc_bookmark(_lvl, _txt))

    doc.add_paragraph()
    _toc_hint = doc.add_paragraph()
    _thr2 = _toc_hint.add_run(
        "提示：目录页码为导出时按实际分页写入。若后续编辑了文档内容导致"
        "页码变化，可在本目录处右键选择「更新域」→「更新整个目录」刷新。"
    )
    _thr2.font.size = Pt(8.5)
    _thr2.font.color.rgb = RGBColor(0x8A, 0x94, 0xA6)
    _thr2.italic = True

    # 目录结束 → 新节（正文节，页码从 1 重新起算）
    doc.add_section(WD_SECTION.NEW_PAGE)

    # ---------- 正文节：页眉页脚 + 阿拉伯数字页码（从 1 起） ----------
    _body_sec = doc.sections[-1]
    _unlink(_body_sec.header)
    _unlink(_body_sec.footer)
    _set_page_numbering(_body_sec, "decimal", start=1)

    _bh_p = _body_sec.header.paragraphs[0]
    _bh_p.text = ""
    _bh_p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    _bhr = _bh_p.add_run(f"威胁建模报告　|　{title}")
    _style_runs(_bh_p)
    _hr(_bh_p)

    _bf_p = _body_sec.footer.paragraphs[0]
    _bf_p.text = ""
    _bf_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _bfr = _bf_p.add_run("VeSync SDLC 安全平台　·　第 ")
    _field(_bf_p, "PAGE", "1")
    _bfr2 = _bf_p.add_run(" 页")
    _style_runs(_bf_p)

    # ---------- 密级水印（斜向浅色，铺满每页） ----------
    def _add_watermark(section) -> None:
        """用页眉里的 WordArt 形状实现「内部」斜向水印。

        说明：python-docx 无水印 API，这里手写 VML 形状放入页眉——
        Word 中即为标准的「自定义水印」，不影响正文内容与可编辑性。
        """
        try:
            header = section.header
            p = header.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run = p.add_run()
            vml = (
                '<w:r xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                '<w:rPr><w:noProof/></w:rPr>'
                '<w:pict xmlns:v="urn:schemas-microsoft-com:vml" '
                'xmlns:o="urn:schemas-microsoft-com:office:office">'
                '<v:shape id="WaterMark" o:spid="_x0000_s2049" type="#_x0000_t136" '
                'style="position:absolute;margin-left:0;margin-top:0;width:420pt;height:210pt;'
                'rotation:315;z-index:-251658752;mso-position-horizontal:center;'
                'mso-position-horizontal-relative:margin;mso-position-vertical:center;'
                'mso-position-vertical-relative:margin" o:allowincell="f" fillcolor="#d9d9d9" '
                'stroked="f">'
                '<v:fill opacity=".5"/>'
                '<v:textpath style="font-family:&quot;宋体&quot;;font-size:1pt" '
                'string="内 部 资 料"/>'
                '</v:shape></w:pict></w:r>'
            )
            from lxml import etree  # type: ignore

            run._element.append(etree.fromstring(vml))
        except Exception as _exc:  # noqa: BLE001
            logger.warning("水印添加失败（不阻断导出）: %s", _exc)

    # 密级水印必须覆盖**全部页面**：封面节、目录节、正文节各自独立页眉，
    # 只给正文节加水印会让封面与目录成为无密级标识的「裸页」——密级文件
    # 的合规要求是每页可识别密级，不能有例外页。
    for _wm_sec in doc.sections:
        _add_watermark(_wm_sec)

    # ==================================================================
    # 正文：严格按 plan_render 的顺序渲染
    # ==================================================================

    # ---------- 系统说明：建模对象（P1，仅在 LLM 产出 profile 时渲染） ----------
    if has_profile:
        _no = chapter_no["system"]
        _h1(_no, CHAPTER_TITLES['system'])
        _p_intro = doc.add_paragraph()
        _pr = _p_intro.add_run(
            "本章说明本次威胁建模的对象范围与前提假设。威胁建模的结论只在"
            "本章界定的范围内成立；若系统架构或边界发生变化，需重新建模。"
        )
        _pr.font.size = Pt(10)
        _pr.font.color.rgb = RGBColor(0x64, 0x74, 0x8B)

        # 产品概述
        overview_txt = system_profile.get("overview") or summary.get("description") or ""
        _h2(f"{_no}.1", "产品概述")
        _ov_rows = [
            ("模型标题", summary.get("title", "-") or "-"),
            ("产品概述", overview_txt or "-"),
            ("建模方法论", methodology),
        ]
        _industry2 = _industry_label(stats)
        if _industry2:
            _ov_rows.append(("行业场景", _industry2))
        _kv_table(_ov_rows)

        # 架构分层
        arch = system_profile.get("architecture") or []
        if arch:
            _h2(f"{_no}.2", "架构分层")
            _make_table(
                ["层级", "说明", "关键组件"],
                [[a.get("layer", ""), a.get("description", ""), a.get("components", "")]
                 for a in arch],
                widths=[3.0, 7.8, 5.6],   # 合计 16.4
            )

        # 用户旅程 / 关键场景
        journeys = system_profile.get("journeys") or []
        if journeys:
            _h2(f"{_no}.3", "关键用户旅程")
            _p = doc.add_paragraph()
            _r = _p.add_run(
                "以下场景是后续威胁分析的锚点，威胁描述中的攻击路径均可对回这些场景。"
            )
            _r.font.size = Pt(9.5)
            _r.font.color.rgb = RGBColor(0x64, 0x74, 0x8B)
            _make_table(
                ["#", "场景", "说明"],
                [[str(i), j.get("name", ""), j.get("description", "")]
                 for i, j in enumerate(journeys, 1)],
                widths=[1.2, 4.2, 11.0],   # 合计 16.4
            )

        # 范围界定（In / Out of Scope）
        in_scope = system_profile.get("inScope") or []
        out_scope = system_profile.get("outOfScope") or []
        assumptions = system_profile.get("assumptions") or []
        if in_scope or out_scope or assumptions:
            _h2(f"{_no}.4", "建模范围与前提假设")
            _rows = []
            if in_scope:
                _rows.append(["范围内", "；".join(str(x) for x in in_scope), "本次建模覆盖"])
            if out_scope:
                _rows.append(["范围外", "；".join(str(x) for x in out_scope), "明确排除，不在结论范围内"])
            if assumptions:
                _rows.append(["前提假设", "；".join(str(x) for x in assumptions), "若假设不成立需重新评估"])
            _make_table(["类别", "内容", "说明"], _rows, widths=[2.6, 9.6, 4.2])  # 合计 16.4

        # 攻击面清单
        surfaces = system_profile.get("attackSurface") or []
        if surfaces:
            _h2(f"{_no}.5", "攻击面清单")
            _p = doc.add_paragraph()
            _r = _p.add_run(
                "下表由架构推断得出，建议结合实际端口扫描与配置核查验证，并在每次发版前复核。"
            )
            _r.font.size = Pt(9.5)
            _r.font.color.rgb = RGBColor(0x64, 0x74, 0x8B)
            _make_table(
                ["暴露面", "可达范围", "端口/协议", "当前认证", "风险提示"],
                [[s.get("surface", ""), s.get("reachability", ""), s.get("protocol", ""),
                  s.get("authentication", ""), s.get("risk", "")] for s in surfaces],
                widths=[3.0, 3.0, 2.8, 3.2, 4.4],   # 合计 16.4
            )

    # ---------- 执行摘要 ----------
    _no = chapter_no["summary"]
    _h1(_no, CHAPTER_TITLES['summary'])
    p = doc.add_paragraph()
    p.add_run(_exec_summary_text(title, methodology, threats, stats))

    _h2(f"{_no}.1", "风险等级分布")
    # 图表优先：商业报告用图表传达分布比纯表格更直观。
    # 图表生成失败（缺 Pillow / 字体）时静默降级为仅表格，不阻断导出。
    _chart_png = _chart_severity_donut(sev_counts, total)
    if _chart_png:
        try:
            _cp = doc.add_paragraph()
            _cp.alignment = WD_ALIGN_PARAGRAPH.CENTER
            _cp.add_run().add_picture(io.BytesIO(_chart_png), width=Cm(15.0))
            _cap = doc.add_paragraph()
            _cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
            _cr = _cap.add_run("图 1　威胁风险等级分布")
            _cr.font.size = Pt(9)
            _cr.bold = True
            _cr.font.color.rgb = RGBColor(0x8A, 0x94, 0xA6)
        except Exception as _exc:  # noqa: BLE001
            logger.warning("等级分布图嵌入失败（降级为表格）: %s", _exc)

    rows = []
    for sev, cnt in sev_counts:
        share = f"{round(cnt / total * 100, 1)}%" if total else "-"
        rows.append([_sev_label(sev), str(cnt), share])
    t = _make_table(["等级", "数量", "占比"], rows, widths=[5.5, 5.45, 5.45])  # 合计 16.4
    # 等级单元格按语义色着色
    for r_idx, (sev, _cnt) in enumerate(sev_counts, start=1):
        fg, bg = SEV_COLOR.get(sev, SEV_COLOR["Unknown"])
        cell = t.rows[r_idx].cells[0]
        _shade(cell, bg)
        _cell_text(cell, _sev_label(sev), bold=True, color=RGBColor(
            int(fg[0:2], 16), int(fg[2:4], 16), int(fg[4:6], 16)), size=10)

    _h2(f"{_no}.2", "处置状态分布")
    bits = [f"{k} {v} 条" for k, v in status_counts.items() if v]
    doc.add_paragraph("、".join(bits) if bits else "无")

    # ---------- 方法说明 ----------
    _no_m = chapter_no["method"]
    _h1(_no_m, CHAPTER_TITLES['method'])
    _p = doc.add_paragraph()
    _r = _p.add_run(
        f"本次建模采用 {methodology} 方法论。该方法的分析逻辑是：先识别系统中"
        "不同类型的元素，再针对每类元素检查其适用的威胁类别——不同元素暴露的"
        "风险面不同，因此并非所有威胁类型都需要在每个元素上分析。"
    )
    _h2(f"{_no_m}.1", "元素类型与威胁类型映射")
    _p = doc.add_paragraph()
    _r = _p.add_run(
        "下表给出本次建模中「元素类型 → 需要分析的威胁类型」的对应关系，"
        "分析章即按此口径组织。"
    )
    _r.font.size = Pt(9.5)
    _r.font.color.rgb = RGBColor(0x64, 0x74, 0x8B)
    try:
        from .methodology import get_threat_types_by_element, normalize_methodology

        _method_key = normalize_methodology(methodology)
    except Exception:  # noqa: BLE001
        _method_key = methodology

    # 说明文字按方法论动态生成（不同方法论的适用威胁类型完全不同，
    # 不能写死 STRIDE 的「仿冒/抵赖」等字样）
    _ELEM_ORDER_M = [
        ("externalentity", "外部实体"),
        ("process", "处理过程"),
        ("datastore", "数据存储"),
        ("flow", "数据流"),
    ]
    try:
        _map_rows = []
        for _k, _zh in _ELEM_ORDER_M:
            _types = get_threat_types_by_element(methodology, _k)
            if _types:
                _map_rows.append([
                    _zh,
                    "、".join(_types),
                    f"需分析 {len(_types)} 类威胁",
                ])
        if _map_rows:
            _make_table(["元素类型", "需分析的威胁类型", "说明"], _map_rows,
                        widths=[2.6, 9.0, 4.8])   # 合计 16.4
    except Exception as exc:  # noqa: BLE001
        logger.warning("方法论映射表渲染失败: %s", exc)

    # STRIDE 六类释义（仅 STRIDE 系方法论渲染）
    if "STRIDE" in methodology.upper():
        _h2(f"{_no_m}.2", "STRIDE 六类威胁释义")
        _make_table(
            ["字母", "威胁类型", "中文", "含义"],
            [[l, en, zh, desc] for l, en, zh, desc in STRIDE_LETTER_ZH],
            widths=[1.6, 4.0, 2.0, 8.8],   # 合计 16.4
        )
        _pn = doc.add_paragraph()
        _rn = _pn.add_run(
            "说明：外部实体不被系统信任，因此在其上只分析仿冒（S）与抵赖（R）；"
            "数据流的仿冒与抵赖通常在两端实体上分析，避免重复计数。"
        )
        _rn.font.size = Pt(9.5)
        _rn.font.color.rgb = RGBColor(0x64, 0x74, 0x8B)

    # ---------- 系统分解（DFD 图 + 图例 + 元素清单 + 信任边界） ----------
    # 按模型里已持久化的坐标在后端复现前端画布（泳道/信任边界/节点/数据流
    # 全要素），渲染失败时降级为无图报告（不阻断导出）。
    try:
        from .dfd_renderer import render_dfd_png, DfdRenderError

        png = render_dfd_png(record)
    except DfdRenderError as exc:
        png = None
        logger.warning("DFD 渲染降级（无图导出）: %s", exc)
    except Exception as exc:  # noqa: BLE001
        png = None
        logger.warning("DFD 渲染异常（无图导出）: %s", exc)

    _no_d = chapter_no["decomposition"]
    _h1(_no_d, CHAPTER_TITLES['decomposition'])
    _p = doc.add_paragraph()
    _r = _p.add_run(
        "本章把系统拆解为可独立分析的单元，并统一编号：外部实体 EE、处理过程 P、"
        "数据存储 DS、数据流 DF、信任边界 TB。后续章节的威胁均以元素编号引用，"
        "便于对照与追溯。"
    )
    _r.font.size = Pt(10)

    if png:
        p_img = doc.add_paragraph()
        p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run_img = p_img.add_run()
        try:
            import io as _io

            # 宽度严格取版心宽（16.4cm）：此前写死 16.5 会超出右边界 0.1cm，
            # Word 会自行压缩导致图片与正文右缘不齐。
            run_img.add_picture(_io.BytesIO(png), width=Cm(CONTENT_WIDTH_CM))
        except Exception as exc:  # noqa: BLE001
            p_img.text = f"（图片嵌入失败：{exc}）"
        cap = doc.add_paragraph()
        cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        cap_run = cap.add_run("图 2　数据流图（DFD）")
        cap_run.font.size = Pt(9)
        cap_run.font.color.rgb = RGBColor(0x8A, 0x94, 0xA6)
        cap_run.bold = True
    else:
        doc.add_paragraph(
            "（本次结果未包含可渲染的数据流图，或图片渲染失败。）"
        ).runs[0].font.color.rgb = RGBColor(0x8A, 0x94, 0xA6)

    # ---- 图例说明 ----
    _h2(f"{_no_d}.1", "图例说明")
    # 图例的「颜色描述」由 DFD 渲染器的实际配色常量推导，而不是手写
    # 「蓝色/绿色/橙色」这类文字——此前图例与渲染器两处各自维护配色，
    # 渲染器一改配色图例立刻失真。现在颜色词由十六进制色值反查得到，
    # 配色变更时图例自动跟随（找不到对应色名时兜底显示色值）。
    def _color_word(hex_color: str) -> str:
        """由十六进制色值反查中文颜色名（用于图例文案）。

        判定用「饱和度 + 色相」而非「RGB 最大值减最小值」的粗糙阈值——
        后者在 #64748b（灰蓝，差值恰好 28）这类临界色上会把灰色判成蓝色、
        把 #ea580c（橙，g=88）这类偏暗的橙色判成红色。改用 HSV：饱和度过低
        即为灰；否则按色相角划分（0~20 与 330~360 红、20~45 橙、45~70 黄、
        70~165 绿、165~260 蓝、260~330 紫）。
        """
        try:
            raw = hex_color.lstrip("#")
            r, g, b = (int(raw[i:i + 2], 16) / 255.0 for i in (0, 2, 4))
        except (ValueError, IndexError):
            return "彩色"
        mx, mn = max(r, g, b), min(r, g, b)
        if mx - mn < 0.06:                      # 近无彩色（灰阶）
            return "灰色" if mx > 0.55 else "深灰"
        # 色相角
        d = mx - mn
        if mx == r:
            hue = (60 * ((g - b) / d)) % 360
        elif mx == g:
            hue = 60 * ((b - r) / d) + 120
        else:
            hue = 60 * ((r - g) / d) + 240
        sat = d / mx if mx else 0.0
        # 低饱和度一律视为灰调。阈值取 0.38：slate 系（#64748b → 0.24、
        # #475569 → 0.325）色相虽落在蓝色区间，但人眼看到的是深灰——
        # 图例写「蓝色」会让读者去图上找并不存在的蓝色元素。而真正的主题蓝
        # 饱和度都很高（#0284c7 → 0.98、#2B579A → 0.72），0.38 不会误伤。
        if sat < 0.38:
            return "灰色"
        if hue < 20 or hue >= 330:
            return "红色"
        if hue < 45:
            return "橙色"
        if hue < 70:
            return "黄色"
        if hue < 165:
            return "绿色"
        if hue < 260:
            return "蓝色"
        return "紫色"

    try:
        from .dfd_renderer import (
            NODE_STYLE as _NODE_STYLE,
            FLOW_ENCRYPTED as _FLOW_ENC,
            FLOW_PUBLIC as _FLOW_PUB,
            FLOW_DEFAULT_STROKE as _FLOW_DEF,
            BADGE_FILL as _BADGE,
        )
        _actor_c = _color_word(_NODE_STYLE["tm.Actor"]["stroke"])
        _proc_c = _color_word(_NODE_STYLE["tm.Process"]["stroke"])
        _store_c = _color_word(_NODE_STYLE["tm.Store"]["stroke"])
        _tb_c = _color_word(_NODE_STYLE["tm.BoundaryBox"]["stroke"])
        _enc_c = _color_word(_FLOW_ENC)
        _pub_c = _color_word(_FLOW_PUB)
        _def_c = _color_word(_FLOW_DEF)
        _badge_c = _color_word(_BADGE)
    except Exception:  # noqa: BLE001 - 渲染器不可用时退回通用描述
        _actor_c = _proc_c = _store_c = _tb_c = _enc_c = _pub_c = _def_c = _badge_c = "彩色"
    _make_table(
        ["图形元素", "含义", "说明"],
        [
            [f"{_actor_c}胶囊", "外部实体（EE）", "系统边界之外、与系统交互的人或外部系统"],
            [f"{_proc_c}矩形", "处理过程（P）", "执行业务逻辑的服务、接口或组件"],
            [f"{_store_c}矩形", "数据存储（DS）", "数据库、缓存、对象存储等持久化载体"],
            [f"{_tb_c}虚线框", "信任边界（TB）", "信任级别变化的边界，跨界交互需独立校验"],
            [f"{_enc_c}实线", "加密数据流", "链路上已启用加密"],
            [f"{_pub_c}实线", "公网数据流", "经过公网传输的链路"],
            [f"{_def_c}虚线", "跨信任边界流", "穿越信任边界的数据流，属重点检查对象"],
            [f"{_badge_c}徽标", "威胁数", "节点右下角数字表示该元素关联的威胁条数"],
        ],
        widths=[2.6, 3.8, 10.0],   # 合计 16.4
    )

    # ---- 元素清单（按类别分节）----
    # 空列裁剪：模型数据缺失的维度（如 LLM 未产出任何组件属性、元素未划入
    # 任何边界）整列只会渲染「—」，在商业报告里像渲染错误（用户反馈过的
    # 「所属边界/关键属性怎么都是空的」）。整列为占位符的列直接裁掉、宽度
    # 并入主内容列——这是对数据缺失的诚实降级而非掩盖：信息一旦存在，列
    # 一定会渲染出来。
    def _prune_cols(headers: list[str], rows: list[list[str]], widths: list[float],
                    blanks: dict[int, set[str]], merge_into: int = 2,
                    ):
        """裁掉整列均为占位符的列，返回 (headers, rows, widths)。"""
        drop = set()
        for idx, blank_vals in blanks.items():
            if rows and all((r[idx] if len(r) > idx else "—") in blank_vals
                            for r in rows):
                drop.add(idx)
        if not drop:
            return headers, rows, widths
        keep = [i for i in range(len(headers)) if i not in drop]
        new_rows = [[(r[i] if len(r) > i else "—") for i in keep] for r in rows]
        new_widths = [widths[i] for i in keep]
        # 裁掉的宽度并入主内容列（节点表=说明、数据流表=数据流名），保持版心 16.4cm
        new_widths[merge_into] += CONTENT_WIDTH_CM - sum(new_widths)
        return [headers[i] for i in keep], new_rows, new_widths

    _groups = elements.get("groups") or []
    for _gi, (_gname, _grows) in enumerate(_groups, 1):
        _h2(f"{_no_d}.{_gi + 1}", f"{_gname}清单")
        if _gname == "数据流":
            # 数据流清单额外展示「穿越的信任边界」与流向端点
            _h8 = ["编号", "数据流", "源", "目标", "穿越边界", "边界关系", "属性", "威胁数"]
            _w8 = [1.2, 2.6, 2.6, 2.6, 2.0, 2.0, 2.0, 1.4]   # 合计 16.4
            _h8, _rows8, _w8 = _prune_cols(_h8, _grows, _w8, {6: {"—"}}, merge_into=1)
            _make_table(_h8, _rows8, widths=_w8)
        else:
            _h7 = ["编号", "名称", "说明", "所属边界", "关键属性", "威胁数", "备注"]
            _w7 = [1.2, 2.6, 4.4, 1.8, 3.2, 1.4, 1.8]   # 合计 16.4
            _h7, _rows7, _w7 = _prune_cols(
                _h7, _grows, _w7,
                {3: {"—", "边界外"}, 4: {"—"}, 6: {"—"}}, merge_into=2)
            _make_table(_h7, _rows7, widths=_w7)

    # ---- 信任边界安全分析 ----
    _bounds = elements.get("boundaries") or []
    if _bounds:
        _bi = len(_groups) + 2
        _h2(f"{_no_d}.{_bi}", "信任边界安全分析")
        _p = doc.add_paragraph()
        _r = _p.add_run(
            "信任边界的两侧信任级别不同，攻击者通常沿边界逐级渗透。下表列出每个边界"
            "包含的元素与关联威胁数，建议按「边界防护强度与两侧信任级差成正比」的原则加固。"
        )
        _r.font.size = Pt(10)
        _bound_rows = []
        for b in _bounds:
            _members = b.get("member_names") or []
            _bound_rows.append([
                b["id"],
                b["name"],
                "、".join(_members) if _members else "—",
                str(len(_members)),
                b.get("description", "-"),
            ])
        _make_table(
            ["编号", "边界名称", "包含元素", "元素数", "说明"],
            _bound_rows, widths=[1.4, 3.0, 5.6, 1.4, 5.0],   # 合计 16.4
        )

    # ---------- 威胁分析（按元素类型） ----------
    _no_a = chapter_no["analysis"]
    _h1(_no_a, CHAPTER_TITLES['analysis'])
    if not threats:
        doc.add_paragraph("未识别到威胁。")
    else:
        # 示例 ID 按当前方法论的实际类型动态生成，避免出现该方法论下并不存在的类型
        _sample_types = []
        try:
            from .methodology import get_threat_types_by_element

            _sample_types = get_threat_types_by_element(methodology, "process")
        except Exception:  # noqa: BLE001
            _sample_types = []
        if _sample_types:
            _sample_id = f"P1-{_threat_short_type(_sample_types[0])}"
        else:
            _sample_id = "P1-X"
        _p = doc.add_paragraph()
        _r = _p.add_run(
            "本章按元素类型组织威胁分析：同一类元素暴露的风险面相同，放在一起便于"
            "横向比较同类元素之间的防护差异。每条威胁以「元素编号-类型」唯一标识"
            f"（如 {_sample_id}），可在总览与台账中交叉检索。"
        )
        _r.font.size = Pt(10)

        for _ai, (_aname, _anote, _aitems) in enumerate(elem_type_groups, 1):
            _h2(f"{_no_a}.{_ai}", f"{_aname}（{len(_aitems)} 条）")
            if _anote:
                _pn = doc.add_paragraph()
                _rn = _pn.add_run(f"分析口径：{_anote}")
                _rn.font.size = Pt(9.5)
                _rn.font.color.rgb = RGBColor(0x64, 0x74, 0x8B)
            _make_analysis_table(doc, _aitems)

    # ---------- 风险评定 ----------
    _no_r = chapter_no["assessment"]
    _h1(_no_r, CHAPTER_TITLES['assessment'])
    _p = doc.add_paragraph()
    _r = _p.add_run(
        "风险评定采用「可能性 × 影响」二维矩阵：可能性反映漏洞被利用的难易程度，"
        "影响反映一旦发生对业务与数据的损害程度。矩阵中的编号为威胁 ID。"
    )
    _p2 = doc.add_paragraph()
    _r2 = _p2.add_run(
        "评定口径说明：矩阵反映的是「残余风险」——即在现有安全措施已生效的前提下"
        "仍需承担的风险，而非完全无防护时的固有风险。因此同一威胁若已有较强防护，"
        "其落点可能低于直觉判断。"
    )
    _r2.font.size = Pt(9.5)
    _r2.font.color.rgb = RGBColor(0x64, 0x74, 0x8B)

    _h2(f"{_no_r}.1", "残余风险矩阵")
    _axis_impact = ["高（严重损害）", "中（局部影响）", "低（轻微影响）"]
    _m_rows = []
    for _ii, _impact_label in enumerate(_axis_impact):
        _row_cells = [_impact_label]
        for _li in range(3):
            _items = (risk_grid or {}).get((2 - _ii, _li), [])
            _row_cells.append("\n".join(_items) if _items else "—")
        _m_rows.append(_row_cells)

    _mt = _make_table(
        ["影响 ＼ 可能性", "低（难以利用）", "中（需特定条件）", "高（易被利用）"],
        _m_rows, widths=[3.2, 4.4, 4.4, 4.4], zebra=False,   # 合计 16.4
    )
    # 矩阵格子按风险等级着色（红=高风险，黄=中，绿=低）
    for _ri in range(1, 4):
        _impact_idx = 2 - (_ri - 1)  # 第一行 = 高影响
        for _ci in range(1, 4):
            _shade(_mt.rows[_ri].cells[_ci], MATRIX_CELL_COLOR[_impact_idx][_ci - 1])
    # 格子内容逐行显示：每行「加粗编号 + 简称」。编号加粗便于在明细章
    # 与附录 B 清单间对照扫读；简称常规字重弱化为次要信息。注意
    # _make_table 写入时会把 \n 压平成空格，因此这里不读回单元格文本，
    # 直接从 risk_grid 取数据重建段落。
    for _ri in range(1, 4):
        for _ci in range(1, 4):
            _cell = _mt.rows[_ri].cells[_ci]
            _items = (risk_grid or {}).get((3 - _ri, _ci - 1), [])
            _cell.text = ""
            _mp = _cell.paragraphs[0]
            for _mi, _line in enumerate(_items if _items else ["—"]):
                if _mi > 0:
                    _mp = _cell.add_paragraph()
                    _mp.paragraph_format.space_after = Pt(0)
                if _line == "—":
                    _mp.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    _mp.add_run(_line)
                else:
                    # 行首到全角空格为编号（加粗），其余为简称
                    _mid, _, _rest = _line.partition("　")
                    _mp.alignment = WD_ALIGN_PARAGRAPH.LEFT
                    _mrun = _mp.add_run(_mid)
                    _mrun.bold = True
                    if _rest:
                        _mp.add_run(f"　{_rest}")
                for _mr in _mp.runs:
                    _mr.font.size = Pt(9)
                    try:
                        _mr.font.name = "宋体"
                        _mr._element.rPr.rFonts.set(qn("w:eastAsia"), "宋体")
                    except Exception:
                        pass
            _cell_valign(_cell)
    # 行头（影响轴）加浅底纹，与数据格子区分
    for _ri in range(1, 4):
        _shade(_mt.rows[_ri].cells[0], "EEF2F7")
        _cell_text(_mt.rows[_ri].cells[0], _axis_impact[_ri - 1], bold=True, size=10)

    # 编号解读：矩阵是全文唯一不展开威胁标题全文的地方，必须告诉读者
    # 编号怎么读、去哪里对照，否则格子内容无法独立理解。章节号是动态
    # 的（条件渲染会平移），因此说明里不写死「第 X 章」，用章名指代。
    _pn = doc.add_paragraph()
    _rn = _pn.add_run(
        "注：格内编号 =「元素编号-威胁类型代号」，如 DF3-T 即数据流 DF3 上的"
        "篡改类威胁（P=处理过程、DS=数据存储、DF=数据流、EE=外部实体；"
        "代号随方法论不同而变化，STRIDE 为 S 欺骗/T 篡改/R 抵赖/"
        "I 信息泄露/D 拒绝服务/E 权限提升；后缀 -2 表示同元素同类型的"
        "第二条）。威胁全称与完整描述见威胁分析章的分类明细及附录 B。"
    )
    _rn.font.size = Pt(9)
    _rn.font.color.rgb = RGBColor(0x64, 0x74, 0x8B)

    # 标题随内容走：有 DREAD 数据时叫「DREAD 评分汇总」，否则用中性的
    # 「风险评分方式说明」——避免标题写着「DREAD 评分汇总」、内容却说
    # 「不输出 DREAD 评分」的自相矛盾（普通 STRIDE 用户会误以为建模有缺失）。
    _has_dread = any(isinstance(t.get("dread"), dict) for t in threats)
    _h2(f"{_no_r}.2", "DREAD 评分汇总" if _has_dread else "风险评分方式说明")
    if _has_dread:
        _dread_rows = []
        for t in threats:
            if not isinstance(t.get("dread"), dict):
                continue
            d = t["dread"]
            _dread_rows.append([
                t.get("threatId", "-"),
                _sev_label(t.get("severity", "")),
                str(_dread_total(d)),
                str(d.get("damage", 0)),
                str(d.get("reproducibility", 0)),
                str(d.get("exploitability", 0)),
                str(d.get("affectedUsers", 0)),
                str(d.get("discoverability", 0)),
            ])
        _make_table(
            ["威胁 ID", "等级", "总分", "危害", "可重复", "可利用", "影响面", "可发现"],
            _dread_rows, widths=[2.0, 2.0, 1.6, 1.6, 1.9, 1.9, 1.9, 1.5],  # 合计 16.4
        )
    else:
        _pd = doc.add_paragraph()
        _rd = _pd.add_run(
            "本次建模采用定性的严重度分级（严重 / 高危 / 中危 / 低危）判定风险等级，"
            "不输出 DREAD 五维评分。"
        )
        _rd.font.size = Pt(10)

    # 「风险汇总与跟踪」章已裁剪：其跟踪台账（ID/等级/标题各渲染一遍）与
    # 第 5 章明细、附录 B 清单高度重复；当前状态与责任/时限的跟踪口径
    # 并入附录 B「威胁处置跟踪清单」。

    # ---------- 度量指标 ----------
    metrics = stats.get("metrics") or {}
    if metrics:
        _no_mt = chapter_no["metrics"]
        _h1(_no_mt, CHAPTER_TITLES['metrics'])
        metric_rows: list[list[str]] = [
            ["元素覆盖度", f"{_pct(metrics.get('coverageRate'))}（{metrics.get('modeledElements', 0)}/{metrics.get('totalElements', 0)}）"],
            ["高风险威胁收敛率", _pct(metrics.get("riskConvergence"))],
        ]
        dread_avg = metrics.get("dreadAverage")
        if dread_avg:
            _dread_label = {
                "damage": "危害", "reproducibility": "可重复性",
                "exploitability": "可利用性", "affectedUsers": "受影响面",
                "discoverability": "可发现性",
            }
            _bits = [f"{_dread_label.get(k, k)}:{v}" for k, v in dread_avg.items() if k != "total"]
            metric_rows.append(["DREAD 均值", " / ".join(_bits) + f"（综合 {dread_avg.get('total', 0)}）"])
        llm_cov = metrics.get("owaspLlmCoverRate")
        if llm_cov is not None:
            _covered = metrics.get("owaspLlmCovered") or []
            metric_rows.append(["OWASP Top10 for LLM 覆盖",
                                f"{_pct(llm_cov)}（{', '.join(_covered) if _covered else '无'}）"])
        _make_table(["指标", "数值"], metric_rows, widths=[6.0, 10.4])   # 合计 16.4

        compliance = metrics.get("compliance")
        if compliance:
            _h2(f"{_no_mt}.1", "合规影响面")
            note_p = doc.add_paragraph()
            nr = note_p.add_run("仅表示威胁触达的法规域，不代表合规结论。")
            nr.font.size = Pt(9)
            nr.font.color.rgb = RGBColor(0x8A, 0x94, 0xA6)
            comp_rows = []
            for item in compliance:
                mark = "●" if item.get("hit") else "○"
                cnt = item.get("relatedThreatCount") or 0
                comp_rows.append([
                    f"{mark} {item.get('code', '')}",
                    item.get("label", ""),
                    str(cnt) if cnt else "-",
                    (item.get("basis") or "") + (f"（{item.get('version')}）" if item.get("version") else ""),
                ])
            _make_table(["法规域", "名称", "关联威胁", "依据"], comp_rows,
                        widths=[3.2, 5.4, 2.2, 5.6])   # 合计 16.4

    # 「威胁总览」章已裁剪：全部威胁的索引表与第 5 章全量明细、附录 B 清单
    # 重复渲染同一批威胁；「按等级浏览」由附录 B 的降序排列承接，
    # 逐条 DREAD 评分见风险评定章的 DREAD 汇总节。

    # ---------- 附录 A　严重度分级定义 ----------
    _appendix_title("附录 A　严重度分级定义")
    _pa = doc.add_paragraph()
    _ar = _pa.add_run(
        "分级用于统一评审口径：等级由「可利用性 × 影响面」综合判定，"
        "并与本报告的风险矩阵、整改时限一一对应。"
    )
    _ar.font.size = Pt(9.5)
    _ar.font.color.rgb = RGBColor(0x64, 0x74, 0x8B)
    _at = _make_table(
        ["等级", "定义", "建议响应时限"],
        [list(x) for x in SEV_DEFINITIONS],
        widths=[3.4, 8.4, 4.6],   # 合计 16.4
    )
    # 等级列着色，与全文配色一致
    for _ai, (_name, _desc, _sla) in enumerate(SEV_DEFINITIONS, start=1):
        _sev_key = _name.split()[-1]
        _fg, _bg = SEV_COLOR.get(_sev_key, SEV_COLOR["Unknown"])
        _c = _at.rows[_ai].cells[0]
        _shade(_c, _bg)
        _cell_text(_c, _name, bold=True, size=10,
                   color=RGBColor(int(_fg[0:2], 16), int(_fg[2:4], 16), int(_fg[4:6], 16)))

    # ---------- 附录 B　威胁处置跟踪清单 ----------
    # 原第 7 章「风险汇总与跟踪」与第 9 章「威胁总览」已裁剪（与第 5 章及本章重复），
    # 其跟踪信息并入本章：当前状态列 + 责任/时限填写口径 + 按等级降序排列。
    _appendix_title("附录 B　威胁处置跟踪清单")
    _pb = doc.add_paragraph()
    _br2 = _pb.add_run(
        "本清单由报告自动生成，按严重度从高到低排列，汇总全部严重 / 高危 / 中危威胁"
        "（若仅有低危则列全部），供研发/运维整改时逐项核对与跟踪。"
        "低危项按常规迭代处理，不进入清单。「责任团队」与「目标完成时间」由责任人"
        "评审时在「验证方式」栏补记；复测结论由安全团队填写，作为关闭依据。"
    )
    _br2.font.size = Pt(9.5)
    _br2.font.color.rgb = RGBColor(0x64, 0x74, 0x8B)
    # 高/中危以上为跟踪对象；一条都没有时回退为全量清单（保持原行为）
    _high_med = [t for t in threats if t.get("severity") in ("Critical", "High", "Medium")]
    _ck_source = sorted(_high_med if _high_med else threats,
                        key=lambda t: _sev(t.get("severity", "")))
    if _ck_source:
        _ck_rows = []
        for _ci2, _t in enumerate(_ck_source, 1):
            _oos2 = "（范围外）" if _t.get("outOfScope") else ""
            _ck_rows.append([
                str(_ci2),
                _t.get("threatId", "-"),
                _sev_label(_t.get("severity", "")),
                (_t.get("title", "") or "-"),
                _t.get("mitigation", "") or "—",
                _status_label(_t.get("status")) + _oos2,
                "☐ 未验证",
            ])
        _ckt = _make_table(
            ["#", "威胁 ID", "等级", "威胁标题", "处置建议", "当前状态", "验证方式"],
            _ck_rows, widths=[0.8, 1.7, 1.5, 3.5, 4.5, 2.1, 2.3],   # 合计 16.4
        )
        # 等级列着色（局部变量带后缀，避免遮蔽模块级 _sev 排序函数）
        for _ri2, _t in enumerate(_ck_source, start=1):
            _sev2 = _t.get("severity", "")
            _fg2, _bg2 = SEV_COLOR.get(_sev2, SEV_COLOR["Unknown"])
            _c2 = _ckt.rows[_ri2].cells[2]
            _shade(_c2, _bg2)
            _cell_text(_c2, _sev_label(_sev2), bold=True, size=9,
                       color=RGBColor(int(_fg2[0:2], 16), int(_fg2[2:4], 16), int(_fg2[4:6], 16)))
    else:
        doc.add_paragraph("本次建模未识别到威胁，无需处置清单。")

    # ---------- 附录 C　术语表 ----------
    _appendix_title("附录 C　术语表")
    _make_table(
        ["术语", "说明"],
        [[k, v] for k, v in GLOSSARY],
        widths=[3.4, 13.0],   # 合计 16.4
    )

    # ---------- 附录 D　文档修订记录 ----------
    _appendix_title("附录 D　文档修订记录")
    _pd_rev = doc.add_paragraph()
    _rd_rev = _pd_rev.add_run(
        "本报告为平台自动生成。如需基于评审意见修订，请在下方追加记录，"
        "并在修订说明中标注与上一版的差异（如新增威胁、等级调整）。"
    )
    _rd_rev.font.size = Pt(9.5)
    _rd_rev.font.color.rgb = RGBColor(0x64, 0x74, 0x8B)
    _make_table(
        ["版本", "修订日期", "修订说明", "修订人"],
        [
            ["V1.0", generated.split(" ")[0] if generated else "-",
             "报告首次生成（由平台依据建模结果自动输出）", "SDLC 安全平台"],
            # 空行留作人工续写位，显式标注「—」而非留白：整行空白会让读者
            # 误以为表格渲染出错，占位符则明确传达「此处待填写」。
            ["", "", "—（待填写）", "—（待填写）"],
            ["", "", "—（待填写）", "—（待填写）"],
        ],
        widths=[2.0, 3.0, 8.4, 3.0],   # 合计 16.4
    )

    doc.add_paragraph()
    _end_p = doc.add_paragraph()
    _end_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _er = _end_p.add_run("— 报告结束 —")
    _er.font.size = Pt(10)
    _er.bold = True
    _er.font.color.rgb = RGBColor(0xC8, 0xA7, 0x5B)

    doc.add_paragraph()
    tail_p = doc.add_paragraph()
    tail_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    tr = tail_p.add_run(
        f"本报告由 VeSync SDLC 平台自动生成于 {generated}　·　方法论 {methodology}　·　内部资料请勿外传"
    )
    tr.font.size = Pt(8.5)
    tr.font.color.rgb = RGBColor(0x8A, 0x94, 0xA6)

    # ---------- 目录页码烘焙（用本机 Office 实际分页回填域缓存值） ----------
    # PAGEREF 域的显示分两层：域缓存值（文件内保存的结果）与打开后的实时
    # 计算。此前缓存值是占位符「-」，并往 settings 写 updateFields=true 期望
    # Word 打开时自动刷新——实测（Word COM 验证）打开时的自动更新发生在
    # 分页完成之前，所有 PAGEREF 被算成「1」，比占位符更糟：是**错误的页码**
    # （用户看到目录页码全是 1 即此因）。现改为：导出时把文档落到临时文件，
    # 用 Office COM 打开并重新分页，读取每个书签的实际页码回填进域缓存值；
    # 同时不再写 updateFields（避免打开时又被预分页状态覆盖成 1）。
    # Office COM 不可用（Linux 部署、未装 Office、执行超时）时静默降级：
    # 缓存值保持「-」，由目录下的提示语引导手动「更新域」。
    _PS_BAKE = """param([string]$D,[string]$O,[string]$N)
$ErrorActionPreference='Stop'
$app=New-Object -ComObject Word.Application
$app.Visible=$false
try{
  $doc=$app.Documents.Open($D,$false,$true)
  $doc.Repaginate()
  $r=@{}
  foreach($n in $N.Split('|')){
    if($n -and $doc.Bookmarks.Exists($n)){
      $r[$n]=[int]$doc.Bookmarks.Item($n).Range.Information(1)
    }
  }
  $doc.Close($false)
  $r|ConvertTo-Json|Set-Content -Path $O -Encoding UTF8
}finally{$app.Quit()}
"""

    def _bake_toc_pages() -> None:
        import subprocess
        import tempfile

        # 先收集需要回填的书签名（全部目录 PAGEREF 的引用目标）。注意不能
        # 用 Bookmarks 集合枚举：书签名以 _Toc 开头属 Word 的「隐藏书签」，
        # 集合默认不枚举（Count 恒为 0），但按名 Exists/Item 可以正常取到。
        names: list[str] = []
        for it in doc.element.body.iter(qn("w:instrText")):
            txt = (it.text or "").strip()
            if txt.startswith("PAGEREF "):
                names.append(txt.split()[1])
        if not names:
            return

        with _WORD_COM_LOCK:
            doc_path = json_path = ps_path = None
            try:
                fd, doc_path = tempfile.mkstemp(suffix=".docx")
                os.close(fd)
                doc.save(doc_path)
                fd, json_path = tempfile.mkstemp(suffix=".json")
                os.close(fd)
                fd, ps_path = tempfile.mkstemp(suffix=".ps1")
                # utf-8-sig：PowerShell 5.1 对无 BOM 的 UTF-8 脚本按 ANSI 解析
                with os.fdopen(fd, "w", encoding="utf-8-sig") as f:
                    f.write(_PS_BAKE)
                subprocess.run(
                    ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                     "-File", ps_path, doc_path, json_path,
                     "|".join(dict.fromkeys(names))],
                    timeout=120, capture_output=True,
                )
                pages: dict[str, int] = {}
                if os.path.exists(json_path):
                    raw = open(json_path, encoding="utf-8-sig").read()
                    parsed = json.loads(raw) if raw.strip() else {}
                    pages = {str(k): int(v) for k, v in parsed.items()}
                if not pages:
                    logger.warning("Office COM 分页未返回数据，目录页码保持占位符")
                    return
                # 回填：定位每个 PAGEREF 域的 instrText → 书签名 → 缓存 w:t。
                # 域的 begin/instr/separate/缓存t/end 都在同一个 w:r 里（见
                # _field），所以缓存 t 就在该 run 内 separate 之后的第一个 w:t。
                patched = 0
                for it in doc.element.body.iter(qn("w:instrText")):
                    txt = (it.text or "").strip()
                    if not txt.startswith("PAGEREF "):
                        continue
                    page = pages.get(txt.split()[1])
                    if page is None:
                        continue
                    seen_sep = False
                    for el in it.getparent():
                        if el.tag == qn("w:fldChar") and \
                                el.get(qn("w:fldCharType")) == "separate":
                            seen_sep = True
                        elif seen_sep and el.tag == qn("w:t"):
                            el.text = str(page)
                            patched += 1
                            break
                logger.info("目录页码烘焙完成：%d/%d 个 PAGEREF 已回填",
                            patched, len(names))
            except FileNotFoundError:
                logger.warning("未找到 PowerShell，目录页码保持占位符「-」")
            except subprocess.TimeoutExpired:
                logger.warning("Office COM 分页超时，目录页码保持占位符「-」")
            except Exception as exc:  # noqa: BLE001
                logger.warning("目录页码烘焙失败（保持占位符）: %s", exc)
            finally:
                # COM 打开过的临时文件可能被企业文档加密系统原地转密，删除
                # 失败仅造成临时目录残留，不影响导出结果（最终字节来自内存）
                for p in (doc_path, json_path, ps_path):
                    if p:
                        try:
                            os.remove(p)
                        except OSError:
                            pass

    _bake_toc_pages()

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()
