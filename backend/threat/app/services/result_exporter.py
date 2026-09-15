"""威胁建模结果的文档导出（商业级报告版）。

把一次已保存的建模结果（含完整 Threat Dragon 模型）渲染为：

- Markdown 报告  —— 元信息表 + 执行摘要 + 等级分布 + 威胁总览表 + 分级明细 + 附录
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
from datetime import datetime
from typing import Any

# 统一网络时钟（与项目其它 service 一致的引入方式）
from app.utils import network_clock as nc

logger = logging.getLogger(__name__)

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
    zh = SEV_ZH.get(key, key)
    return f"{zh} {key}" if key else key


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


def _collect_threats(model: dict[str, Any]) -> list[dict[str, Any]]:
    """从 Threat Dragon 模型中收集所有威胁，并补充所属组件名。"""
    out: list[dict[str, Any]] = []
    diagrams = ((model.get("detail") or {}).get("diagrams")) or []
    for diagram in diagrams:
        cells = diagram.get("cells") or []
        name_by_cell = {
            c["id"]: ((c.get("data") or {}).get("name") or "")
            for c in cells
        }
        for cell in cells:
            for threat in cell.get("threats") or []:
                t = dict(threat)
                t["component"] = name_by_cell.get(cell["id"], "")
                out.append(t)
    return out


def _sorted_threats(threats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """统一排序：严重度升序 -> DREAD 降序 -> 标题。全报告共用一份顺序。"""
    return sorted(
        threats,
        key=lambda t: (_sev(t.get("severity", "")), -_dread_total(t.get("dread")), t.get("title", "")),
    )


def _sev_counts(stats: dict[str, Any]) -> list[tuple[str, int]]:
    """按固定顺序返回 (severity, count) 列表。"""
    by_sev = stats.get("threatCountBySeverity") or {}
    order = ["Critical", "High", "Medium", "Low"]
    counts = [(s, int(by_sev.get(s) or 0)) for s in order]
    extra = [(k, int(v or 0)) for k, v in by_sev.items() if k not in order]
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
    risk_line = f"其中严重 {c} 条、高危 {h} 条" if (c or h) else "无严重 / 高危项"
    pct_line = f"（占 {round((c + h) / total * 100, 1)}%）" if (c or h) else ""
    if c:
        advice = "建议立即处置全部 Critical 项，并在 7 天内完成 High 项整改。"
    elif h:
        advice = "建议 7 天内完成 High 项整改，中低危纳入常规迭代。"
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
    度量指标 -> 威胁总览表 -> 分级明细 -> 附录（分级定义）-> 生成声明。
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

    # —— 4 威胁总览表 ——
    lines.append(f"## 4 威胁总览（{total} 条）")
    lines.append("")
    if not threats:
        lines.append("_未识别到威胁。_")
    else:
        lines.append("| # | 等级 | 威胁标题 | 类型 | 组件 | 状态 | DREAD |")
        lines.append("|---:|---|---|---|---|---|---:|")
        for i, t in enumerate(threats, 1):
            dread = _dread_total(t.get("dread"))
            dread_cell = str(dread) if dread else "-"
            oos_mark = "（范围外）" if t.get("outOfScope") else ""
            lines.append(
                f"| {i} | {_one_line(_sev_label(t.get('severity', '')))} | {_one_line(t.get('title'))} | "
                f"{_one_line(t.get('type')) or '-'} | {_one_line(t.get('component')) or '-'} | "
                f"{_one_line(_status_label(t.get('status')))}{oos_mark} | {dread_cell} |"
            )
        lines.append("")

    # —— 5 威胁明细 ——
    lines.append(f"## 5 威胁明细")
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
            lines.append(f"### 5.{gi} {_sev_label(sev)}（{len(items)} 条）")
            lines.append("")
            for i, t in enumerate(items, 1):
                lines.append(f"#### 5.{gi}.{i} {t.get('title', '')}")
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

def render_result_docx(record: dict[str, Any]) -> bytes:
    """把一条结果记录渲染为 Word (.docx) 商业级报告（二进制字节）。

    结构：封面（标题/信息表/密级）-> 目录域 -> 页眉页脚页码 ->
    1 执行摘要（等级分布着色表）-> 2 模型概览 -> 3 度量指标 ->
    4 威胁总览表 -> 5 分级明细（每条结构化）-> 附录 A 分级定义。
    """
    from docx import Document  # type: ignore
    from docx.shared import Pt, RGBColor, Cm  # type: ignore
    from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK  # type: ignore
    from docx.enum.table import WD_TABLE_ALIGNMENT  # type: ignore
    from docx.oxml.ns import qn  # type: ignore
    from docx.oxml import OxmlElement  # type: ignore

    model = record.get("model") or {}
    summary = model.get("summary") or {}
    stats = record.get("stats") or {}
    methodology = record.get("methodology") or "STRIDE"
    created = _fmt_time(record.get("created_at", 0))
    generated = _now_str()
    title = record.get("title", "威胁建模报告")

    threats = _sorted_threats(_collect_threats(model))
    sev_counts = _sev_counts(stats)
    status_counts = _status_counts(threats)
    total = len(threats)
    high_critical = sum(c for s, c in sev_counts if s in ("Critical", "High"))

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

    # 文档属性（商业报告元数据）
    props = doc.core_properties
    props.title = f"威胁建模报告：{title}"
    props.author = "VeSync SDLC 平台"
    props.subject = f"威胁建模（{methodology}）"
    props.comments = f"报告生成时间 {generated}"

    # ---------- 小工具 ----------
    def _shade(cell, color_hex: str) -> None:
        """单元格底纹。"""
        tc_pr = cell._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:fill"), color_hex)
        tc_pr.append(shd)

    def _cell_text(cell, text: str, bold=None, size=None, color=None, align=None) -> None:
        cell.text = ""
        p = cell.paragraphs[0]
        if align is not None:
            p.alignment = align
        # 单元格内压平换行，避免威胁字段里的 \n 把一行内容拆成多段
        run = p.add_run(" ".join(str(text).split()))
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

    def _make_table(headers: list[str], rows: list[list[str]], widths: list[float] | None = None,
                    header_fill: str = "2B579A") -> Any:
        """带表头底纹的数据表。"""
        table = doc.add_table(rows=1, cols=len(headers))
        table.style = "Table Grid"
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        for i, h in enumerate(headers):
            _cell_text(table.rows[0].cells[i], h, bold=True, color=RGBColor(0xFF, 0xFF, 0xFF),
                       size=10)
            _shade(table.rows[0].cells[i], header_fill)
        for row in rows:
            cells = table.add_row().cells
            for i, val in enumerate(row):
                _cell_text(cells[i], val, size=10)
        if widths:
            # 自动布局关闭后列宽才生效
            table.autofit = False
            for row in table.rows:
                for i, w in enumerate(widths):
                    row.cells[i].width = Cm(w)
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

    def _kv_table(pairs: list[tuple[str, str]]) -> None:
        """两列「项目 | 内容」信息表。"""
        _make_table(["项目", "内容"], [(k, v) for k, v in pairs], widths=[3.6, 12.4])

    # ---------- 页眉 / 页脚（正文各节统一） ----------
    for section in doc.sections:
        header_p = section.header.paragraphs[0]
        header_p.text = ""
        h_run = header_p.add_run(f"威胁建模报告　|　{title}")
        h_run.font.size = Pt(8.5)
        h_run.font.color.rgb = RGBColor(0x8A, 0x94, 0xA6)
        header_p.alignment = WD_ALIGN_PARAGRAPH.RIGHT

        footer_p = section.footer.paragraphs[0]
        footer_p.text = ""
        footer_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        f_run1 = footer_p.add_run("VeSync SDLC 安全平台　·　第 ")
        f_run1.font.size = Pt(8.5)
        f_run1.font.color.rgb = RGBColor(0x8A, 0x94, 0xA6)
        _field(footer_p, "PAGE", "1")
        f_run2 = footer_p.add_run(" 页")
        f_run2.font.size = Pt(8.5)
        f_run2.font.color.rgb = RGBColor(0x8A, 0x94, 0xA6)
        for r in footer_p.runs:
            r.font.size = Pt(8.5)
            r.font.color.rgb = RGBColor(0x8A, 0x94, 0xA6)

    # ---------- 封面 ----------
    for _ in range(5):
        doc.add_paragraph()
    cover_title = doc.add_paragraph()
    cover_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    ct = cover_title.add_run("威胁建模报告")
    ct.bold = True
    ct.font.size = Pt(30)
    ct.font.color.rgb = RGBColor(0x1F, 0x3A, 0x5F)
    try:
        ct.font.name = "微软雅黑"
        ct._element.rPr.rFonts.set(qn("w:eastAsia"), "微软雅黑")
    except Exception:
        pass

    cover_sub = doc.add_paragraph()
    cover_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cs = cover_sub.add_run(title)
    cs.font.size = Pt(15)
    cs.font.color.rgb = RGBColor(0x2B, 0x57, 0x9A)

    doc.add_paragraph()

    _kv_table([
        ("报告标题", title),
        ("建模方法论", methodology),
        ("行业场景", _industry_label(stats) or "-"),
        ("建模时间", created),
        ("报告生成时间", generated),
        ("报告版本", "V1.0"),
        ("密级", "内部"),
        ("编制", "VeSync SDLC 安全平台"),
    ])

    doc.add_paragraph()
    cover_note = doc.add_paragraph()
    cover_note.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cn = cover_note.add_run("本文档包含公司安全评估信息，请勿外传")
    cn.font.size = Pt(9)
    cn.font.color.rgb = RGBColor(0xC0, 0x39, 0x2B)
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)

    # ---------- 目录（Word 打开后 Ctrl+A -> F9 或右键“更新域”生成） ----------
    doc.add_heading("目录", level=1)
    toc_p = doc.add_paragraph()
    _field(toc_p, r'TOC \o "1-3" \h \z \u', "（在 Word 中右键此处 → 更新域，即可生成目录）")
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)

    # ---------- 1 执行摘要 ----------
    doc.add_heading("1 执行摘要", level=1)
    p = doc.add_paragraph()
    p.add_run(_exec_summary_text(title, methodology, threats, stats))

    doc.add_heading("1.1 风险等级分布", level=2)
    rows = []
    for sev, cnt in sev_counts:
        share = f"{round(cnt / total * 100, 1)}%" if total else "-"
        rows.append([_sev_label(sev), str(cnt), share])
    t = _make_table(["等级", "数量", "占比"], rows, widths=[5.3, 5.3, 5.3])
    # 等级单元格按语义色着色
    for r_idx, (sev, _cnt) in enumerate(sev_counts, start=1):
        fg, bg = SEV_COLOR.get(sev, SEV_COLOR["Unknown"])
        cell = t.rows[r_idx].cells[0]
        _shade(cell, bg)
        _cell_text(cell, _sev_label(sev), bold=True, color=RGBColor(
            int(fg[0:2], 16), int(fg[2:4], 16), int(fg[4:6], 16)), size=10)

    doc.add_heading("1.2 处置状态分布", level=2)
    bits = [f"{k} {v} 条" for k, v in status_counts.items() if v]
    doc.add_paragraph("、".join(bits) if bits else "无")

    # ---------- 2 模型概览 ----------
    doc.add_heading("2 模型概览", level=1)
    _kv_table([
        ("模型标题", summary.get("title", "-")),
        ("模型描述", summary.get("description", "-") or "-"),
        ("组件数", str(stats.get("componentCount", "-"))),
        ("数据流数", str(stats.get("flowCount", "-"))),
        ("威胁总数", str(total)),
    ])

    # ---------- 3 数据流图（DFD） ----------
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

    doc.add_heading("3 数据流图", level=1)
    if png:
        doc.add_paragraph(
            "下图展示本次建模识别的组件、信任边界与数据流：蓝色胶囊为外部实体、"
            "绿色矩形为处理过程、橙色为数据存储、虚线框为信任边界；绿色连线表示"
            "加密流、橙色为公网流、灰色虚线为跨信任边界流，节点右下角红色徽标"
            "为该组件关联的威胁数。"
        ).runs[0].font.size = Pt(10)
        p_img = doc.add_paragraph()
        p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run_img = p_img.add_run()
        try:
            import io as _io

            run_img.add_picture(_io.BytesIO(png), width=Cm(16.5))
        except Exception as exc:  # noqa: BLE001
            p_img.text = f"（图片嵌入失败：{exc}）"
        cap = doc.add_paragraph()
        cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        cap_run = cap.add_run("图 1　数据流图（DFD）")
        cap_run.font.size = Pt(9)
        cap_run.font.color.rgb = RGBColor(0x8A, 0x94, 0xA6)
        cap_run.bold = True
    else:
        doc.add_paragraph(
            "（本次结果未包含可渲染的数据流图，或图片渲染失败。）"
        ).runs[0].font.color.rgb = RGBColor(0x8A, 0x94, 0xA6)

    # ---------- 4 度量指标 ----------
    metrics = stats.get("metrics") or {}
    if metrics:
        doc.add_heading("4 度量指标", level=1)
        metric_rows: list[list[str]] = [
            ["元素覆盖度", f"{_pct(metrics.get('coverageRate'))}（{metrics.get('modeledElements', 0)}/{metrics.get('totalElements', 0)}）"],
            ["高风险威胁收敛率", _pct(metrics.get("riskConvergence"))],
        ]
        dread_avg = metrics.get("dreadAverage")
        if dread_avg:
            dread_label = {
                "damage": "危害", "reproducibility": "可重复性",
                "exploitability": "可利用性", "affectedUsers": "受影响面",
                "discoverability": "可发现性",
            }
            bits = [f"{dread_label.get(k, k)}:{v}" for k, v in dread_avg.items() if k != "total"]
            metric_rows.append(["DREAD 均值", " / ".join(bits) + f"（综合 {dread_avg.get('total', 0)}）"])
        llm_cov = metrics.get("owaspLlmCoverRate")
        if llm_cov is not None:
            covered = metrics.get("owaspLlmCovered") or []
            metric_rows.append(["OWASP Top10 for LLM 覆盖", f"{_pct(llm_cov)}（{', '.join(covered) if covered else '无'}）"])
        _make_table(["指标", "数值"], metric_rows, widths=[6.0, 10.0])
        compliance = metrics.get("compliance")
        if compliance:
            doc.add_heading("4.1 合规影响面", level=2)
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
            _make_table(["法规域", "名称", "关联威胁", "依据"], comp_rows, widths=[3.2, 5.2, 2.2, 5.4])

    # ---------- 5 威胁总览表 ----------
    doc.add_heading(f"5 威胁总览（{total} 条）", level=1)
    if not threats:
        doc.add_paragraph("未识别到威胁。")
    else:
        ov_rows = []
        for i, t in enumerate(threats, 1):
            dread = _dread_total(t.get("dread"))
            oos_mark = "（范围外）" if t.get("outOfScope") else ""
            ov_rows.append([
                str(i),
                _sev_label(t.get("severity", "")),
                t.get("title", ""),
                t.get("type", "") or "-",
                t.get("component", "") or "-",
                _status_label(t.get("status")) + oos_mark,
                str(dread) if dread else "-",
            ])
        ov_table = _make_table(
            ["#", "等级", "威胁标题", "类型", "组件", "状态", "DREAD"],
            ov_rows, widths=[1.0, 2.2, 5.2, 2.0, 2.6, 2.4, 1.6],
        )
        for r_idx, t in enumerate(threats, start=1):
            sev = t.get("severity", "")
            fg, bg = SEV_COLOR.get(sev, SEV_COLOR["Unknown"])
            cell = ov_table.rows[r_idx].cells[1]
            _shade(cell, bg)
            _cell_text(cell, _sev_label(sev), bold=True, color=RGBColor(
                int(fg[0:2], 16), int(fg[2:4], 16), int(fg[4:6], 16)), size=9)

    # ---------- 6 威胁明细 ----------
    doc.add_heading("6 威胁明细", level=1)
    if not threats:
        doc.add_paragraph("未识别到威胁。")
    else:
        by_sev_threats: dict[str, list[dict]] = {}
        for t in threats:
            by_sev_threats.setdefault(t.get("severity", "Unknown"), []).append(t)
        for gi, sev in enumerate(sorted(by_sev_threats, key=_sev), 1):
            items = by_sev_threats[sev]
            doc.add_heading(f"6.{gi} {_sev_label(sev)}（{len(items)} 条）", level=2)
            for i, t in enumerate(items, 1):
                doc.add_heading(f"6.{gi}.{i}　{t.get('title', '')}", level=3)
                oos_mark = "、范围外" if t.get("outOfScope") else ""
                rows = [
                    ("类型", t.get("type", "") or "-"),
                    ("所属组件", t.get("component", "") or "-"),
                    ("处置状态", _status_label(t.get("status")) + oos_mark),
                ]
                if t.get("cwe"):
                    rows.append(("CWE", t["cwe"]))
                if isinstance(t.get("dread"), dict):
                    d = t["dread"]
                    rows.append((
                        "DREAD",
                        f"{_dread_total(d)}/50（危害:{d.get('damage',0)} 可重复:{d.get('reproducibility',0)}"
                        f" 可利用:{d.get('exploitability',0)} 影响:{d.get('affectedUsers',0)} 可发现:{d.get('discoverability',0)}）",
                    ))
                rows.append(("威胁描述", t.get("description", "") or "-"))
                rows.append(("缓解措施", t.get("mitigation", "") or "-"))
                refs = t.get("references") or []
                if refs:
                    rows.append(("参考资料", "；".join(refs)))
                _make_table(["字段", "内容"], [(k, v) for k, v in rows], widths=[2.8, 13.2])

    # ---------- 附录 ----------
    doc.add_heading("附录 A　严重度分级定义", level=1)
    _make_table(
        ["等级", "定义", "建议响应时限"],
        [list(x) for x in SEV_DEFINITIONS],
        widths=[3.4, 8.2, 4.4],
    )

    doc.add_paragraph()
    tail_p = doc.add_paragraph()
    tail_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    tr = tail_p.add_run(
        f"本报告由 VeSync SDLC 平台自动生成于 {generated}　·　方法论 {methodology}　·　内部资料请勿外传"
    )
    tr.font.size = Pt(8.5)
    tr.font.color.rgb = RGBColor(0x8A, 0x94, 0xA6)

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()
