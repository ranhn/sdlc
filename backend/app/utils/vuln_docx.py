"""漏洞清单 Word (.docx) 报告渲染（商业级排版）。

为什么重写这一版
----------------
旧版导出把 10 列塞进 A4 **纵向**版心（16.4cm）且**没有指定任何列宽**：
python-docx 与 Word 只能等分，每列不到 1.8cm，长文本被按"一行塞得下几个字就几个字"
排 —— 标题一字一行、ID 竖排、接口地址成了一列竖字（用户截图反馈"格式有点问题"）。

Word 的表格默认是**固定布局**：列宽必须显式写在 tblGrid / tcW 上，且合计恰好等于
版心宽；否则 Word 会按内容/等分自行分配。这是本模块的核心修复点，其余是补齐
商业报告该有的要素（封面、结论先行、分布统计、跨页重复表头、页眉页脚页码、详情卡片）。

排版口径（与威胁建模报告 ``result_exporter.render_result_docx`` 同一套视觉语言，
两份报告摆在一起应像同一家的产品）
------------------------------------------------------------------
· 页面 A4，页边距 上 2.4 / 下 2.2 / 左 2.4 / 右 2.2 cm
  → 纵向版心 16.4cm、横向版心 25.1cm（所有表格宽度都取自这里，不各处硬编码）；
· 正文微软雅黑 10pt、表格 9pt；主色 #1F3864，等级配色沿用同一套 SEV_COLOR；
· 章节：封面（纵向）→ 统计概览（纵向）→ 漏洞清单（**横向**，10 列需要宽度）
  → 漏洞详情（纵向）→ 附录（纵向）；
· 清单表：固定布局 + 显式列宽 + 表头跨页重复 + 行不跨页拆分 + 斑马纹 + 等级色标。

用法::

    from ..utils.vuln_docx import render_vulns_docx

    data = render_vulns_docx(rows, exported_by="张三", scope_desc="全部漏洞")

``rows`` 只要能按属性访问即可（VulnOut / ORM 对象 / SimpleNamespace 都支持），
不依赖 FastAPI 与数据库，便于离线生成与回归测试。
"""

from __future__ import annotations

import base64
import io
import logging
from typing import Any, Iterable, Sequence

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 版式常量
# ---------------------------------------------------------------------------
FONT_ZH = "Microsoft YaHei"
FONT_MONO = "Consolas"

# 版心宽度（cm）= 页宽 - 左右页边距。A4 纵向 21-2.4-2.2=16.4；横向 29.7-2.4-2.2=25.1
PORTRAIT_CONTENT_CM = 16.4
LANDSCAPE_CONTENT_CM = 25.1
TWIPS_PER_CM = 567.0

# 主色（与前端主题、威胁建模报告一致）
BRAND = "1F3864"        # 深蓝：封面块 / 表头底纹
BRAND_LIGHT = "2E5395"  # 次级蓝：标签文字
INK = "1F2937"          # 正文近黑
MUTED = "64748B"        # 次要灰：页眉页脚 / 说明
LINE = "D6DEE8"         # 表格线
ZEBRA = "F4F7FB"        # 斑马纹浅底
SOFT = "F2F5FA"         # 信息表键列底

# ---------------------------------------------------------------------------
# 等级 / 状态口径
# ---------------------------------------------------------------------------
SEV_ORDER = ("critical", "high", "medium", "low")
SEV_ZH = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}

# 等级配色：(文字色, 底纹色)。与威胁建模报告 SEV_COLOR 同色板 ——
# 跨报告看到同一颜色即代表同一等级，不要各自另配色。
SEV_COLOR = {
    "critical": ("C0392B", "FDECEA"),
    "high": ("D97706", "FEF5E7"),
    "medium": ("B45309", "FEF9E7"),
    "low": ("1E8449", "EAF7EE"),
}
SEV_COLOR_UNKNOWN = ("6B7280", "F3F4F6")

# 建议响应时限（与威胁建模报告附录 A 的措辞保持一致）
SEV_SLA = {
    "critical": "24 小时内启动处置",
    "high": "7 天内完成整改",
    "medium": "30 天内纳入迭代修复",
    "low": "排期处理",
}

# 闭环口径：**与数据大盘「已修复」卡片完全一致**（已修复 + 已关闭 + 已驳回 + 已忽略）。
# 报告里统一叫「已闭环」；不在这里另立一套口径，否则同一个数字在列表/大盘/报告
# 三处对不上（历史踩过：大盘算闭环、报告只算 fixed）。
CLOSED_STATUSES = ("fixed", "closed", "rejected", "ignored")

# 状态 -> 分组（统计概览用）：把 9 个状态收成读者能直接用的 3 组
STATUS_GROUPS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("待处置", ("draft", "pending", "confirmed"), "等待确认或研发排期"),
    ("处置中", ("fixing", "retest"), "研发修复中 / 待复测"),
    ("已闭环", CLOSED_STATUSES, "已修复、已关闭、已驳回、已忽略（终态）"),
)

# ---------------------------------------------------------------------------
# 清单表列定义：(表头, 权重, 单列最少字符提示)
# ---------------------------------------------------------------------------
# 权重是"相对宽度"，由 _fit_widths 按比例缩放到版心总宽（本例合计恰好 25.1cm）。
# 依据（微软雅黑 9pt 实测度量，**不是** 0.5em 的经验值）：汉字 0.317cm/字、
# 数字与英文约 0.55em ≈ 0.176cm/字，单元格左右内边距合计 0.28cm。
#   · 创建时间 3.20 → 空 2.92cm，"2026-09-18 18:21"（16 字符）约 2.82cm → 单行 ✓
#     （这里踩过坑：按 0.5em 估成 2.6cm，实际雅黑数字更宽 → 日期被折成两行）；
#   · 大类/类型 2.40/2.35 → 空 2.1cm 左右，容得下 6 个汉字（"跨站与客户端"）✓；
#   · 标题 5.40 → 空 5.12cm ≈ 16 汉字/行，60 字内的标题 2~4 行读完；
#   · 接口地址 3.90 → 空 3.62cm，URL 在 / . - 处可断行，窄一点也不影响可读性。
LIST_COLUMNS: tuple[tuple[str, float], ...] = (
    ("ID", 1.25),
    ("漏洞标题", 5.40),
    ("所属系统", 2.20),
    ("接口地址", 3.90),
    ("等级", 1.25),
    ("大类", 2.40),
    ("类型", 2.35),
    ("状态", 1.50),
    ("负责人", 1.65),
    ("创建时间", 3.20),
)

# 清单单元格截断长度：**按列给**，让"最长内容 × 列宽 ≤ 可接受行数"。
# 截掉的部分在「三、漏洞详情」里是完整的，CSV 导出也是完整值。
# 依据（列宽见 LIST_COLUMNS，汉字 0.317cm/字）：
#   标题 5.40cm → 60 字 ≈ 4 行（再长就该去详情章读）
#   接口 3.90cm → 56 字 ≈ 3 行（URL 在 / . - 处断行）
#   系统 2.20cm → 12 字 ≈ 2 行；大类/类型 2.4cm → 10 字 ≈ 2 行；负责人 1.65cm → 8 字
CLIP_TITLE = 60
CLIP_API = 56
CLIP_SYSTEM = 12
CLIP_CATEGORY = 10
CLIP_ASSIGNEE = 8


def _fit_widths(weights: Sequence[float], total: float) -> list[float]:
    """把权重按比例缩放到版心总宽，并把舍入误差补进最后一列。

    列宽合计必须**恰好**等于版心宽：多一分会溢出页边距（打印被裁），
    少一分则右边缘与正文不齐（一眼就能看出业余）。
    """
    s = float(sum(weights)) or 1.0
    out = [round(w / s * total, 2) for w in weights]
    out[-1] = round(total - sum(out[:-1]), 2)
    return out


def _clip(text: Any, limit: int) -> str:
    """压平空白并截断（超过 limit 用省略号），供清单表用。"""
    s = " ".join(str(text or "").split())
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _twips(cm: float) -> str:
    """厘米 -> twips（1cm = 567 twips，Word 的 OOXML 长度单位）。"""
    return str(int(round(cm * TWIPS_PER_CM)))


def _val(row: Any, name: str, default: Any = "") -> Any:
    v = getattr(row, name, None)
    return default if v is None else v


# ===========================================================================
# python-docx 底层工具
# ===========================================================================
def _set_run(run, *, size=None, bold=None, italic=None, color=None, font=FONT_ZH):
    """设置 run 字体。中文字体必须同时写 eastAsia，否则 Word 用默认宋体/方块。"""
    from docx.oxml.ns import qn
    from docx.shared import Pt, RGBColor

    run.font.name = font
    rpr = run._element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = rpr.makeelement(qn("w:rFonts"), {})
        rpr.insert(0, rfonts)
    for attr in ("w:ascii", "w:hAnsi", "w:eastAsia", "w:cs"):
        rfonts.set(qn(attr), font)
    if size is not None:
        run.font.size = Pt(size)
    if bold is not None:
        run.bold = bold
    if italic is not None:
        run.italic = italic
    if color:
        run.font.color.rgb = RGBColor.from_string(color)


def _fmt_para(p, *, align=None, space_before=None, space_after=None,
              line=None, keep_with_next=None):
    from docx.shared import Pt

    pf = p.paragraph_format
    if align is not None:
        p.alignment = align
    if space_before is not None:
        pf.space_before = Pt(space_before)
    if space_after is not None:
        pf.space_after = Pt(space_after)
    if line is not None:
        pf.line_spacing = line
    if keep_with_next is not None:
        pf.keep_with_next = keep_with_next
    return p


def _write_text(paragraph, text: str, **run_kw):
    """把含换行的文本写进段落（换行转成软回车，不用多段落，避免行距翻倍）。"""
    lines = str(text if text is not None else "").split("\n")
    for i, seg in enumerate(lines):
        if i:
            br = paragraph.add_run()
            _set_run(br, **{k: v for k, v in run_kw.items() if k in ("size", "font")})
            br.add_break()
        run = paragraph.add_run(seg)
        _set_run(run, **run_kw)
    return paragraph


def _para(doc, text: str = "", *, size=10, bold=False, italic=False, color=INK,
          align=None, space_before=0, space_after=4, line=1.4, font=FONT_ZH):
    p = doc.add_paragraph()
    if text:
        _write_text(p, text, size=size, bold=bold, italic=italic, color=color, font=font)
    return _fmt_para(p, align=align, space_before=space_before,
                     space_after=space_after, line=line)


def _heading(doc, text: str, *, level: int = 1):
    """章节标题：用真 heading 样式（保留 Word 导航窗格/大纲），并覆盖中文字体与配色。"""
    from docx.shared import Pt

    h = doc.add_heading("", level=level)
    sizes = {1: 16, 2: 13, 3: 11}
    run = h.add_run(text)
    _set_run(run, size=sizes.get(level, 11), bold=True, color=BRAND)
    _fmt_para(h, space_before=14 if level == 1 else 10, space_after=6,
              line=1.25, keep_with_next=True)
    if level >= 2:
        for r in h.runs:
            r.font.size = Pt(sizes.get(level, 11))
    return h


def _bottom_rule(paragraph, color=BRAND, size=8):
    """给段落加下边框（标题下的横线，商业报告的分栏观感）。"""
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    ppr = paragraph._p.get_or_add_pPr()
    borders = OxmlElement("w:pBdr")
    bottom = OxmlElement("w:bottom")
    bottom.set(qn("w:val"), "single")
    bottom.set(qn("w:sz"), str(size))
    bottom.set(qn("w:space"), "4")
    bottom.set(qn("w:color"), color)
    borders.append(bottom)
    ppr.append(borders)


def _shade(cell, fill: str) -> None:
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    tc_pr = cell._tc.get_or_add_tcPr()
    for old in tc_pr.findall(qn("w:shd")):
        tc_pr.remove(old)
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    tc_pr.append(shd)


def _cell_text(cell, text: Any, *, size=9, bold=False, color=INK, align=None,
               font=FONT_ZH):
    """写单元格：清空首段后写 run（保留段落，避免多出空行）。"""
    cell.text = ""
    p = cell.paragraphs[0]
    _write_text(p, "" if text is None else str(text), size=size, bold=bold,
                color=color, font=font)
    _fmt_para(p, align=align, space_before=0, space_after=0, line=1.25)
    return cell


def _vcenter(cell) -> None:
    from docx.enum.table import WD_ALIGN_VERTICAL

    cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER


def _cell_margins(table, *, top=0.05, left=0.14, bottom=0.05, right=0.14) -> None:
    """统一单元格内边距（默认内边距偏大，长表格会白占很多高度）。"""
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    tbl_pr = table._tbl.tblPr
    for old in tbl_pr.findall(qn("w:tblCellMar")):
        tbl_pr.remove(old)
    mar = OxmlElement("w:tblCellMar")
    for tag, cm in (("w:top", top), ("w:left", left),
                    ("w:bottom", bottom), ("w:right", right)):
        el = OxmlElement(tag)
        el.set(qn("w:w"), _twips(cm))
        el.set(qn("w:type"), "dxa")
        mar.append(el)
    tbl_pr.append(mar)


def _borders(table, *, color=LINE, size=6) -> None:
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    tbl_pr = table._tbl.tblPr
    for old in tbl_pr.findall(qn("w:tblBorders")):
        tbl_pr.remove(old)
    borders = OxmlElement("w:tblBorders")
    for tag in ("top", "left", "bottom", "right", "insideH", "insideV"):
        el = OxmlElement(f"w:{tag}")
        el.set(qn("w:val"), "single")
        el.set(qn("w:sz"), str(size))
        el.set(qn("w:space"), "0")
        el.set(qn("w:color"), color)
        borders.append(el)
    tbl_pr.append(borders)


def _set_col_widths(table, widths_cm: Sequence[float]) -> None:
    """**核心**：固定表格布局 + 显式列宽（tblW / tblGrid / 每个 tcW）。

    只设某一行或只设 gridCol 都不够：Word 渲染时以单元格自己的 tcW 为准，
    漏设的单元格会回退成"内容自适应"，于是同一列在不同行宽度不一致（表格看起来
    歪歪扭扭）。所以这里对每一行的每个单元格都写一遍。
    """
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Cm

    table.autofit = False
    tbl_pr = table._tbl.tblPr

    for old in tbl_pr.findall(qn("w:tblLayout")):
        tbl_pr.remove(old)
    layout = OxmlElement("w:tblLayout")
    layout.set(qn("w:type"), "fixed")
    tbl_pr.append(layout)

    for old in tbl_pr.findall(qn("w:tblW")):
        tbl_pr.remove(old)
    tbl_w = OxmlElement("w:tblW")
    tbl_w.set(qn("w:w"), _twips(sum(widths_cm)))
    tbl_w.set(qn("w:type"), "dxa")
    tbl_pr.append(tbl_w)

    grid = table._tbl.find(qn("w:tblGrid"))
    if grid is not None:
        cols = grid.findall(qn("w:gridCol"))
        for gc, w in zip(cols, widths_cm):
            gc.set(qn("w:w"), _twips(w))

    for row in table.rows:
        for cell, w in zip(row.cells, widths_cm):
            cell.width = Cm(w)


def _repeat_header(row) -> None:
    """跨页时自动重复表头行（长表格必备，否则翻页后不知道列是什么）。"""
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    tr_pr = row._tr.get_or_add_trPr()
    el = OxmlElement("w:tblHeader")
    el.set(qn("w:val"), "true")
    tr_pr.append(el)


def _no_split(row) -> None:
    """该行不可跨页拆分（避免一行被劈成两半，读起来断句）。"""
    from docx.oxml import OxmlElement

    row._tr.get_or_add_trPr().append(OxmlElement("w:cantSplit"))


def _row_height(row, cm: float) -> None:
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    tr_pr = row._tr.get_or_add_trPr()
    h = OxmlElement("w:trHeight")
    h.set(qn("w:val"), _twips(cm))
    h.set(qn("w:hRule"), "atLeast")
    tr_pr.append(h)


def _field(paragraph, instr: str, placeholder: str = "1"):
    """插入 Word 域（页码 / 总页数）：打开文档时 Word 会自行求值。"""
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    run = paragraph.add_run()
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    instr_el = OxmlElement("w:instrText")
    instr_el.set(qn("xml:space"), "preserve")
    instr_el.text = instr
    sep = OxmlElement("w:fldChar")
    sep.set(qn("w:fldCharType"), "separate")
    text_el = OxmlElement("w:t")
    text_el.text = placeholder
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    for el in (begin, instr_el, sep, text_el, end):
        run._r.append(el)
    return run


def _page(section, *, landscape: bool = False) -> None:
    """统一页面设置。**改朝向时必须同时换 page_width/page_height**，
    只设 orientation 会让 Word 报"纸张尺寸异常"（Word 不自动交换长宽）。"""
    from docx.enum.section import WD_ORIENT
    from docx.shared import Cm

    if landscape:
        section.orientation = WD_ORIENT.LANDSCAPE
        section.page_width, section.page_height = Cm(29.7), Cm(21.0)
    else:
        section.orientation = WD_ORIENT.PORTRAIT
        section.page_width, section.page_height = Cm(21.0), Cm(29.7)
    section.top_margin = Cm(2.4)
    section.bottom_margin = Cm(2.2)
    section.left_margin = Cm(2.4)
    section.right_margin = Cm(2.2)
    section.header_distance = Cm(1.4)
    section.footer_distance = Cm(1.2)


def _header_footer(section, *, exported_at: str) -> None:
    """页眉（报告名 + 密级）/ 页脚（页码 + 生成信息）。居中排版：
    章节有纵向也有横向，居中在两种版心下都不会错位（左右分栏会）。"""
    from docx.enum.text import WD_ALIGN_PARAGRAPH

    hdr = section.header
    hp = hdr.paragraphs[0]
    hp.text = ""
    _write_text(hp, "漏洞清单报告　·　内部资料，请勿外传", size=8.5, color=MUTED)
    _fmt_para(hp, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=0)
    _bottom_rule(hp, color=LINE, size=4)

    ftr = section.footer
    fp = ftr.paragraphs[0]
    fp.text = ""
    _write_text(fp, "第 ", size=8.5, color=MUTED)
    _field(fp, "PAGE", "1")
    _write_text(fp, " 页 / 共 ", size=8.5, color=MUTED)
    _field(fp, "NUMPAGES", "1")
    _write_text(fp, f" 页　·　导出时间：{exported_at}　·　由 VeSync SDLC 平台生成",
                size=8.5, color=MUTED)
    for run in fp.runs:
        if run.text:
            _set_run(run, size=8.5, color=MUTED)
    _fmt_para(fp, align=WD_ALIGN_PARAGRAPH.CENTER, space_before=0)


def _make_table(doc, headers: Sequence[str], rows: Sequence[Sequence[Any]],
                widths: Sequence[float], *, size=9, header_size=9,
                aligns: Sequence[Any] | None = None, zebra=True):
    """建表：表头深蓝底白字 + 跨页重复，数据行斑马纹 + 行不拆分。"""
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH

    table = doc.add_table(rows=1, cols=len(headers))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    _borders(table)
    _cell_margins(table)

    aligns = list(aligns or [WD_ALIGN_PARAGRAPH.LEFT] * len(headers))
    hdr = table.rows[0]
    for i, h in enumerate(headers):
        cell = hdr.cells[i]
        _cell_text(cell, h, size=header_size, bold=True, color="FFFFFF",
                   align=WD_ALIGN_PARAGRAPH.CENTER)
        _shade(cell, BRAND)
        _vcenter(cell)
    _repeat_header(hdr)
    _no_split(hdr)
    _row_height(hdr, 0.62)

    for ri, values in enumerate(rows):
        row = table.add_row()
        for ci, v in enumerate(values):
            cell = row.cells[ci]
            _cell_text(cell, v, size=size, align=aligns[ci])
            _vcenter(cell)
            if zebra and ri % 2 == 1:
                _shade(cell, ZEBRA)
        _no_split(row)
    _set_col_widths(table, widths)
    return table


# ===========================================================================
# 章节渲染
# ===========================================================================
def _cover(doc, rows: list[Any], *, scope_desc: str, exported_by: str,
           exported_at: str) -> None:
    """封面：色块标题 + 元信息表 + 保密声明。"""
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.shared import Cm

    _para(doc, "", size=10, space_after=0)
    _para(doc, "", size=10, space_after=0)

    band = doc.add_table(rows=1, cols=1)
    band.alignment = 1
    _cell_margins(band, top=0.5, bottom=0.5, left=0.3, right=0.3)
    cell = band.rows[0].cells[0]
    _shade(cell, BRAND)
    cell.text = ""
    t1 = cell.paragraphs[0]
    _write_text(t1, "漏洞清单报告", size=26, bold=True, color="FFFFFF")
    _fmt_para(t1, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2)
    t2 = cell.add_paragraph()
    _write_text(t2, "Vulnerability Report", size=11, color="D6E1F5")
    _fmt_para(t2, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=0)
    _set_col_widths(band, [PORTRAIT_CONTENT_CM])
    _row_height(band.rows[0], 3.2)

    _para(doc, "", size=10, space_after=6)
    _para(doc, scope_desc or "全部漏洞", size=12, bold=True, color=INK,
          align=WD_ALIGN_PARAGRAPH.CENTER, space_after=10)

    sev_counts = _severity_counts(rows)
    closed = sum(1 for r in rows if str(_val(r, "status")) in CLOSED_STATUSES)
    meta = [
        ("导出范围", scope_desc or "全部漏洞"),
        ("导出人", exported_by or "—"),
        ("导出时间", exported_at),
        ("漏洞总数", f"{len(rows)} 条"),
        ("风险分布", "　".join(f"{SEV_ZH[k]} {sev_counts.get(k, 0)}" for k in SEV_ORDER)),
        ("处置进度", f"已闭环 {closed} 条 / 待处置中 {len(rows) - closed} 条"),
        ("数据来源", "VeSync SDLC 平台 · 漏洞管理"),
    ]
    table = _make_table(doc, ["项目", "内容"], meta,
                        [3.8, PORTRAIT_CONTENT_CM - 3.8], size=10, header_size=10,
                        zebra=True)
    for row in table.rows[1:]:
        _shade(row.cells[0], SOFT)
        for p in row.cells[0].paragraphs:
            for run in p.runs:
                _set_run(run, size=10, bold=True, color=BRAND)

    _para(doc, "", size=10, space_after=10)
    _para(doc,
          "本报告含未修复漏洞的技术细节与复现证据，属公司内部敏感资料；"
          "请按信息安全管理制度限定传阅范围，对外提供前须完成脱敏与审批。",
          size=8.5, italic=True, color=MUTED, align=WD_ALIGN_PARAGRAPH.CENTER,
          space_after=0)


def _severity_counts(rows: Iterable[Any]) -> dict[str, int]:
    counts = {k: 0 for k in SEV_ORDER}
    for r in rows:
        key = str(_val(r, "severity")).lower()
        counts[key] = counts.get(key, 0) + 1
    return counts


def _summary(doc, rows: list[Any]) -> None:
    """统计概览：结论一句 + 等级/状态/系统/类型四张分布表。"""
    from docx.enum.text import WD_ALIGN_PARAGRAPH

    total = len(rows)
    counts = _severity_counts(rows)
    crit, high = counts.get("critical", 0), counts.get("high", 0)
    closed = sum(1 for r in rows if str(_val(r, "status")) in CLOSED_STATUSES)
    pending = total - closed

    h = _heading(doc, "一、统计概览", level=1)
    _bottom_rule(h)

    if total == 0:
        _para(doc, "本次导出范围内没有漏洞记录。", size=10, color=MUTED)
        return

    # 结论先行（商业报告标准动作）
    risk = "整体风险偏高，建议优先处置严重/高危项。" if (crit + high) else "未发现严重/高危项。"
    if crit and (crit + high) / total >= 0.3:
        risk = "严重/高危占比突出，建议本周内成立专项处置。"
    _para(doc,
          f"本次共导出 {total} 条漏洞：严重 {crit} 条、高危 {high} 条、"
          f"中危 {counts.get('medium', 0)} 条、低危 {counts.get('low', 0)} 条；"
          f"其中已闭环 {closed} 条（闭环率 {round(closed / total * 100, 1)}%），"
          f"待处置 {pending} 条。{risk}",
          size=10, color=INK, line=1.5, space_after=8)

    # 1.1 等级分布（含建议响应时限：读者一眼知道该多快动手）
    _para(doc, "1.1　风险等级分布", size=10.5, bold=True, color=BRAND_LIGHT,
          space_before=6, space_after=4)
    sev_rows = []
    for key in SEV_ORDER:
        c = counts.get(key, 0)
        sev_rows.append([SEV_ZH[key], c, f"{round(c / total * 100, 1)}%",
                         SEV_SLA[key], f"{c} / {total}"])
    sev_table = _make_table(
        doc, ["等级", "数量", "占比", "建议响应时限", "累计对比"],
        sev_rows, [2.2, 1.6, 1.7, 8.0, 2.9], size=9,
        aligns=[WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.CENTER,
                WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT,
                WD_ALIGN_PARAGRAPH.CENTER],
    )
    for i, key in enumerate(SEV_ORDER, start=1):
        fg, bg = SEV_COLOR.get(key, SEV_COLOR_UNKNOWN)
        cell = sev_table.rows[i].cells[0]
        _shade(cell, bg)
        for p in cell.paragraphs:
            for run in p.runs:
                _set_run(run, size=9, bold=True, color=fg)
    _para(doc, "", size=6, space_after=4)

    # 1.2 处置状态分布（按"待处置 / 处置中 / 已闭环"三组，读者才知道进度含义）
    _para(doc, "1.2　处置进度", size=10.5, bold=True, color=BRAND_LIGHT,
          space_before=6, space_after=4)
    status_rows = []
    for label, codes, note in STATUS_GROUPS:
        c = sum(1 for r in rows if str(_val(r, "status")) in codes)
        status_rows.append([label, c, f"{round(c / total * 100, 1)}%", note])
    st_table = _make_table(
        doc, ["处置阶段", "数量", "占比", "说明"], status_rows,
        [2.6, 1.6, 1.7, PORTRAIT_CONTENT_CM - 5.9], size=9,
        aligns=[WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.CENTER,
                WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT],
    )
    for i, (label, _codes, _note) in enumerate(STATUS_GROUPS, start=1):
        fill = "EAF7EE" if label == "已闭环" else None
        if fill:
            for cell in st_table.rows[i].cells:
                _shade(cell, fill)
    _para(doc, "", size=6, space_after=4)

    # 1.3 系统分布（Top 8 + 合计行）
    by_system: dict[str, dict[str, int]] = {}
    for r in rows:
        name = str(_val(r, "system_name") or "未指定系统")
        bucket = by_system.setdefault(name, {"total": 0, "high": 0, "closed": 0})
        bucket["total"] += 1
        if str(_val(r, "severity")).lower() in ("critical", "high"):
            bucket["high"] += 1
        if str(_val(r, "status")) in CLOSED_STATUSES:
            bucket["closed"] += 1
    top = sorted(by_system.items(), key=lambda kv: (-kv[1]["total"], kv[0]))[:8]
    if top:
        _para(doc, "1.3　系统分布（按漏洞数，Top 8）", size=10.5, bold=True,
              color=BRAND_LIGHT, space_before=6, space_after=4)
        sys_rows = [
            [name, b["total"], f"{round(b['total'] / total * 100, 1)}%",
             b["high"], b["closed"], b["total"] - b["closed"]]
            for name, b in top
        ]
        sys_rows.append(["合计", total, "100.0%",
                         sum(b["high"] for _, b in top),
                         sum(b["closed"] for _, b in top),
                         sum(b["total"] - b["closed"] for _, b in top)])
        sys_table = _make_table(
            doc, ["所属系统", "漏洞数", "占比", "严重/高危", "已闭环", "待处置"],
            sys_rows,
            [4.6, 1.7, 1.7, 2.4, 2.0, PORTRAIT_CONTENT_CM - 12.4], size=9,
            aligns=[WD_ALIGN_PARAGRAPH.LEFT] + [WD_ALIGN_PARAGRAPH.CENTER] * 5,
        )
        last = sys_table.rows[-1]
        for cell in last.cells:
            _shade(cell, SOFT)
            for p in cell.paragraphs:
                for run in p.runs:
                    _set_run(run, size=9, bold=True, color=BRAND)
        _para(doc, "", size=6, space_after=4)

    # 1.4 漏洞类型分布（一二级合并展示，Top 8）
    by_type: dict[tuple[str, str], int] = {}
    for r in rows:
        key = (str(_val(r, "vuln_category") or "未分类"),
               str(_val(r, "vuln_type") or "未分类"))
        by_type[key] = by_type.get(key, 0) + 1
    top_types = sorted(by_type.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
    if top_types:
        _para(doc, "1.4　漏洞类型分布（Top 8）", size=10.5, bold=True,
              color=BRAND_LIGHT, space_before=6, space_after=4)
        type_rows = [[cat, typ, c, f"{round(c / total * 100, 1)}%"]
                     for (cat, typ), c in top_types]
        _make_table(doc, ["一级大类", "二级类型", "数量", "占比"], type_rows,
                    [3.6, 7.5, 1.7, PORTRAIT_CONTENT_CM - 12.8], size=9,
                    aligns=[WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT,
                            WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.CENTER])


def _list_section(doc, rows: list[Any]) -> None:
    """漏洞清单（横向章节）：10 列宽表，固定列宽 + 跨页重复表头。"""
    from docx.enum.text import WD_ALIGN_PARAGRAPH

    h = _heading(doc, f"二、漏洞清单（共 {len(rows)} 条）", level=1)
    _bottom_rule(h)
    if not rows:
        _para(doc, "本次导出范围内没有漏洞记录。", size=10, color=MUTED)
        return
    _para(doc,
          "按创建时间倒序。表格中长文本已截断，完整内容见「三、漏洞详情」；"
          "如需全字段数据请导出 CSV。",
          size=9, color=MUTED, space_after=6)

    sev_map = dict(SEV_ZH)
    status_names = _status_names()
    table_rows = []
    for r in rows:
        sev_key = str(_val(r, "severity")).lower()
        table_rows.append([
            str(_val(r, "id")),
            _clip(_val(r, "title"), CLIP_TITLE),
            _clip(_val(r, "system_name") or "—", CLIP_SYSTEM),
            _clip(_val(r, "api_endpoint") or "—", CLIP_API),
            sev_map.get(sev_key, sev_key or "—"),
            _clip(_val(r, "vuln_category") or "—", CLIP_CATEGORY),
            _clip(_val(r, "vuln_type") or "—", CLIP_CATEGORY),
            status_names.get(str(_val(r, "status")), str(_val(r, "status"))),
            _clip(_val(r, "assignee_name") or "未指派", CLIP_ASSIGNEE),
            _fmt_time(_val(r, "created_at")),
        ])

    center = WD_ALIGN_PARAGRAPH.CENTER
    widths = _fit_widths([w for _h, w in LIST_COLUMNS], LANDSCAPE_CONTENT_CM)
    table = _make_table(
        doc, [h for h, _w in LIST_COLUMNS], table_rows, widths, size=9,
        aligns=[center, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT,
                WD_ALIGN_PARAGRAPH.LEFT, center, WD_ALIGN_PARAGRAPH.LEFT,
                WD_ALIGN_PARAGRAPH.LEFT, center, center, center],
    )

    # 等级列着色：红/橙/黄褐/绿，扫一眼即可定位高危项
    for i, r in enumerate(rows, start=1):
        key = str(_val(r, "severity")).lower()
        fg, bg = SEV_COLOR.get(key, SEV_COLOR_UNKNOWN)
        cell = table.rows[i].cells[4]
        _shade(cell, bg)
        for p in cell.paragraphs:
            for run in p.runs:
                _set_run(run, size=9, bold=True, color=fg)
        # 已闭环的行整体压灰，便于与待处置项区分
        if str(_val(r, "status")) in CLOSED_STATUSES:
            for j, cell in enumerate(table.rows[i].cells):
                if j == 4:
                    continue
                for p in cell.paragraphs:
                    for run in p.runs:
                        _set_run(run, size=9, color=MUTED)


def _detail_section(doc, rows: list[Any]) -> None:
    """漏洞详情（纵向章节）：每条一页，信息表 + 正文分块 + 复现截图。"""
    from docx.enum.text import WD_ALIGN_PARAGRAPH

    h = _heading(doc, f"三、漏洞详情（共 {len(rows)} 条）", level=1)
    _bottom_rule(h)
    if not rows:
        _para(doc, "无。", size=10, color=MUTED)
        return

    sev_map = dict(SEV_ZH)
    status_names = _status_names()
    for idx, r in enumerate(rows):
        if idx:
            # 每条漏洞独立起页：报告常被拆分发给对应负责人，跨页割裂会很难读
            doc.add_page_break()
        sev_key = str(_val(r, "severity")).lower()
        sev_zh = sev_map.get(sev_key, sev_key or "—")

        # 标题行：[等级] #ID 标题
        head = doc.add_paragraph()
        run = head.add_run(f"#{_val(r, 'id')}　{_val(r, 'title') or ''}")
        _set_run(run, size=13, bold=True, color=BRAND)
        _fmt_para(head, space_before=6, space_after=4, line=1.3,
                  keep_with_next=True)
        _bottom_rule(head, color=LINE, size=4)

        # 等级色标 + 状态
        tag = doc.add_paragraph()
        fg, bg = SEV_COLOR.get(sev_key, SEV_COLOR_UNKNOWN)
        tag_run = tag.add_run(f" {sev_zh} ")
        _set_run(tag_run, size=9, bold=True, color=fg)
        _shade_run(tag_run, bg)
        st_run = tag.add_run(
            f"　处置状态：{status_names.get(str(_val(r, 'status')), str(_val(r, 'status')))}"
            f"　·　所属系统：{_val(r, 'system_name') or '—'}"
        )
        _set_run(st_run, size=9, color=MUTED)
        _fmt_para(tag, space_after=6, keep_with_next=True)

        # 信息表（两列：键列窄底纹、值列正文）
        pairs: list[tuple[str, str]] = [
            ("接口地址", str(_val(r, "api_endpoint") or "—")),
            ("漏洞类型", f"{_val(r, 'vuln_category') or '—'} / {_val(r, 'vuln_type') or '—'}"),
        ]
        if _val(r, "cvss"):
            pairs.append(("CVSS", str(_val(r, "cvss"))))
        pairs.append(("来源", ("外部 · " + str(_val(r, "external_source") or "外部提交"))
                      if _val(r, "is_external") else "内部自评/扫描"))
        pairs.append(("提交人", str(_val(r, "reporter_name") or "—")))
        pairs.append(("负责人", str(_val(r, "assignee_name") or "未指派")))
        if _val(r, "reviewer_name"):
            pairs.append(("复测人", str(_val(r, "reviewer_name"))))
        pairs.append(("创建时间", _fmt_time(_val(r, "created_at"))))
        if _val(r, "updated_at"):
            pairs.append(("最后更新", _fmt_time(_val(r, "updated_at"))))
        if _val(r, "sla_deadline"):
            pairs.append(("SLA 截止", _fmt_time(_val(r, "sla_deadline"))))
        if _val(r, "rejection_reason"):
            pairs.append(("驳回原因", str(_val(r, "rejection_reason"))))
        info = _make_table(doc, ["项目", "内容"], pairs,
                           [3.4, PORTRAIT_CONTENT_CM - 3.4], size=9,
                           header_size=9)
        for row in info.rows[1:]:
            _shade(row.cells[0], SOFT)
            for p in row.cells[0].paragraphs:
                for run in p.runs:
                    _set_run(run, size=9, bold=True, color=BRAND)
        _para(doc, "", size=6, space_after=2)

        for label, value in (("漏洞描述", _val(r, "description")),
                             ("复现步骤", _val(r, "reproduce_steps")),
                             ("影响范围", _val(r, "impact")),
                             ("修复建议", _val(r, "fix_suggestion"))):
            if value:
                p = doc.add_paragraph()
                _write_text(p, f"【{label}】", size=10, bold=True, color=BRAND_LIGHT)
                _write_text(p, f"　{str(value).strip()}", size=10, color=INK)
                _fmt_para(p, space_before=4, space_after=2, line=1.5)

        _render_evidence(doc, r)

    doc.add_paragraph()


def _render_evidence(doc, r: Any) -> None:
    """复现步骤截图 / 截图证据：按步骤分组，配图注，宽度限制在版心内。"""
    from docx.enum.text import WD_ALIGN_PARAGRAPH

    shots: list[tuple[str, str]] = []   # (图注, data_url)
    step_shots = _val(r, "step_screenshots", None) or []
    if isinstance(step_shots, list):
        for i, shot in enumerate(step_shots, 1):
            if isinstance(shot, dict):
                url = shot.get("data_url") or shot.get("url") or ""
                no = shot.get("step_no")
                cap = f"步骤 {no}" if no is not None else f"复现截图 {i}"
            else:
                url, cap = shot, f"复现截图 {i}"
            if url:
                shots.append((str(cap), str(url)))
    raw_shots = _val(r, "screenshots", None) or []
    if isinstance(raw_shots, list):
        for i, url in enumerate(raw_shots, 1):
            if isinstance(url, dict):
                url = url.get("data_url") or url.get("url") or ""
            if url:
                shots.append((f"截图证据 {i}", str(url)))

    if not shots:
        return
    p = doc.add_paragraph()
    _write_text(p, f"【复现证据】共 {len(shots)} 张", size=10, bold=True,
                color=BRAND_LIGHT)
    _fmt_para(p, space_before=6, space_after=4, keep_with_next=True)

    idx = 0
    for cap, url in shots:
        data = _data_url_bytes(url)
        idx += 1
        if not data or not _is_valid_image(data):
            # 库里存在只有 PNG 魔数（8 字节）的脏数据：提前判定为"无法解析"，
            # 不要走到 add_picture 再去 catch —— 那样日志里会刷一堆
            # UnexpectedEndOfFileError 警告，运维看了会以为是导出功能坏了。
            _para(doc, f"（{cap}：图片数据无法解析，请在系统内查看）", size=9,
                  color=MUTED, space_after=4)
            continue
        try:
            doc.add_picture(io.BytesIO(data), width=_picture_width(data))
        except Exception as exc:  # noqa: BLE001
            logger.warning("漏洞截图插入失败：%s", exc)
            _para(doc, f"（{cap}：图片格式不受支持，请在系统内查看）", size=9,
                  color=MUTED, space_after=4)
            continue
        cap_p = doc.add_paragraph()
        _write_text(cap_p, f"图 {idx}　{cap}", size=8.5, italic=True, color=MUTED)
        _fmt_para(cap_p, align=WD_ALIGN_PARAGRAPH.CENTER, space_before=2,
                  space_after=8)


def _shade_run(run, fill: str) -> None:
    """给文字加底纹（等级标签用；单元格底纹不适用行内标记）。"""
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    run._element.get_or_add_rPr().append(shd)


def _data_url_bytes(data_url: str) -> bytes | None:
    """把 data:image/png;base64,xxx 还原成图片字节。"""
    if not data_url or not isinstance(data_url, str):
        return None
    if not data_url.startswith("data:"):
        return None
    comma = data_url.find(",")
    if comma < 0:
        return None
    head, payload = data_url[:comma], data_url[comma + 1:]
    if "base64" not in head:
        return None
    try:
        return base64.b64decode(payload)
    except Exception:  # noqa: BLE001
        return None


def _is_valid_image(data: bytes) -> bool:
    """能否被识别为图片（PIL 不可用时退化为"非空即认为可试"）。

    为什么需要：库里有历史脏数据（只有一个 PNG 魔数的 8 字节），
    交给 python-docx 会抛 UnexpectedEndOfFileError —— 导出仍能成功，但日志里
    会刷警告，看起来像导出坏了。这里提前判定，走"请在系统内查看"的友好提示。
    """
    if not data:
        return False
    try:
        from PIL import Image

        with Image.open(io.BytesIO(data)) as im:
            im.verify()
        return True
    except ImportError:
        return True
    except Exception:  # noqa: BLE001
        return False


def _picture_width(data: bytes):
    """按原图长宽比算插入宽度（返回 docx 的 Length，不能返回裸浮点）：
    不超版心、不超高，避免狭长截图把一页撑爆。

    注意：``add_picture(width=...)`` 的单位是 EMU，传 Python 浮点会被当成 EMU
    （图片缩成几微米，肉眼就是"图不见了"），必须传 Cm()/Inches() 这类 Length。
    """
    from docx.shared import Cm

    max_w, max_h = 15.0, 17.5
    try:
        from PIL import Image

        with Image.open(io.BytesIO(data)) as im:
            w, h = im.size
        if w and h:
            width = max_w
            if width * h / w > max_h:
                width = max_h * w / h
            return Cm(max(4.0, width))
    except Exception:  # noqa: BLE001
        return Cm(max_w)


def _appendix(doc, rows: list[Any], *, scope_desc: str, exported_by: str,
              exported_at: str) -> None:
    """附录：严重度分级定义 + 导出范围与口径说明。"""
    from docx.enum.text import WD_ALIGN_PARAGRAPH

    doc.add_page_break()   # 附录独立起页（详情章最后一条可能占满整页）
    h = _heading(doc, "附录", level=1)
    _bottom_rule(h)

    _para(doc, "附录 A　严重度分级定义", size=10.5, bold=True, color=BRAND_LIGHT,
          space_before=4, space_after=4)
    sev_table = _make_table(
        doc, ["等级", "判定标准", "建议响应时限"],
        [
            ["严重", "可被远程利用、影响核心数据资产或业务主流程，可能造成大规模数据泄露 / 系统失控", SEV_SLA["critical"]],
            ["高危", "利用条件明确、影响重要功能或敏感数据，攻击成本较低", SEV_SLA["high"]],
            ["中危", "需要特定条件利用，影响范围有限", SEV_SLA["medium"]],
            ["低危", "利用成本高、影响轻微，属加固项", SEV_SLA["low"]],
        ],
        [2.2, 9.0, PORTRAIT_CONTENT_CM - 11.2], size=9,
        aligns=[WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT,
                WD_ALIGN_PARAGRAPH.LEFT],
    )
    for i, key in enumerate(SEV_ORDER, start=1):
        fg, bg = SEV_COLOR[key]
        cell = sev_table.rows[i].cells[0]
        _shade(cell, bg)
        for p in cell.paragraphs:
            for run in p.runs:
                _set_run(run, size=9, bold=True, color=fg)
    _para(doc, "", size=6, space_after=6)

    _para(doc, "附录 B　导出范围与口径说明", size=10.5, bold=True, color=BRAND_LIGHT,
          space_before=4, space_after=4)
    _make_table(
        doc, ["项目", "说明"],
        [
            ["导出范围", scope_desc or "全部漏洞"],
            ["导出人", exported_by or "—"],
            ["导出时间", exported_at],
            ["排序规则", "清单与详情均按创建时间倒序（最新在前）"],
            ["已闭环口径", "已修复 + 已关闭 + 已驳回 + 已忽略；与数据大盘「已修复」一致"],
            ["长文本处理", "清单表内标题/接口地址超长会截断（详情章为完整内容）"],
            ["数据导出", "需要全字段数据（含提交/复测人、CVSS 等）请使用 CSV 导出"],
            ["密级", "内部资料，请勿外传"],
        ],
        [3.4, PORTRAIT_CONTENT_CM - 3.4], size=9,
    )


# ===========================================================================
# 对外入口
# ===========================================================================
def _status_names() -> dict[str, str]:
    """状态中文名。单一来源在 state_machine，避免与路由层各存一份而漂移。"""
    try:
        from ..state_machine import STATUS_NAMES as _sn

        return dict(_sn)
    except Exception:  # noqa: BLE001
        return {}


def _fmt_time(value: Any) -> str:
    """时间统一按东八区展示（数据库存 naive UTC，与页面一致）。"""
    if value is None or value == "":
        return "—"
    try:
        from zoneinfo import ZoneInfo

        import datetime as _dt

        tz = ZoneInfo("Asia/Shanghai")
        if isinstance(value, _dt.datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=_dt.timezone.utc)
            return value.astimezone(tz).strftime("%Y-%m-%d %H:%M")
        text = str(value)
        parsed = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_dt.timezone.utc)
        return parsed.astimezone(tz).strftime("%Y-%m-%d %H:%M")
    except Exception:  # noqa: BLE001
        return str(value)


def render_vulns_docx(
    rows: Iterable[Any],
    *,
    exported_by: str | None = None,
    scope_desc: str | None = None,
    exported_at: str | None = None,
) -> bytes:
    """把漏洞列表渲染成商业级 Word 报告，返回 docx 二进制。

    Args:
        rows: 漏洞记录（按属性访问即可，VulnOut / ORM 对象均可）
        exported_by: 导出人姓名（封面与附录署名）
        scope_desc: 导出范围的人类可读描述（如「全部漏洞」「系统：商城 · 高危」）
        exported_at: 导出时间文本（缺省用平台网络时间）
    """
    from docx import Document
    from docx.enum.section import WD_SECTION

    rows = list(rows)
    if not exported_at:
        try:
            from . import network_clock as nc

            exported_at = nc.now().strftime("%Y-%m-%d %H:%M")
        except Exception:  # noqa: BLE001
            from datetime import datetime as _dt

            exported_at = _dt.now().strftime("%Y-%m-%d %H:%M")
    scope_desc = scope_desc or "全部漏洞"

    doc = Document()
    _init_styles(doc)

    sec0 = doc.sections[0]
    _page(sec0, landscape=False)
    # 封面不显示页眉页脚：密级抬头 + 页码压在色块封面上很难看
    sec0.different_first_page_header_footer = True
    _header_footer(sec0, exported_at=exported_at)

    _cover(doc, rows, scope_desc=scope_desc, exported_by=exported_by or "—",
           exported_at=exported_at)
    doc.add_page_break()
    _summary(doc, rows)

    # 横向章节：清单 10 列需要 25.1cm 版心（纵向只有 16.4cm，必然挤成一字一行）
    sec1 = doc.add_section(WD_SECTION.NEW_PAGE)
    _page(sec1, landscape=True)
    # 必须显式关掉「首页不同」：w:titlePg 会被**后续章节继承**（python-docx 的
    # titlePg_val 亦按继承读取），只设封面那一节的话，清单页与第一个详情页会一起
    # 变成"首页"、套用空白页眉页脚 —— 表现为这两页突然没有页码。
    sec1.different_first_page_header_footer = False
    _list_section(doc, rows)

    sec2 = doc.add_section(WD_SECTION.NEW_PAGE)
    _page(sec2, landscape=False)
    sec2.different_first_page_header_footer = False
    _detail_section(doc, rows)

    _appendix(doc, rows, scope_desc=scope_desc, exported_by=exported_by or "—",
              exported_at=exported_at)

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def _init_styles(doc) -> None:
    """全局 Normal 样式：微软雅黑（ascii/hAnsi/eastAsia 全设），10pt，行距 1.35。"""
    from docx.oxml.ns import qn
    from docx.shared import Pt

    style = doc.styles["Normal"]
    style.font.name = FONT_ZH
    style.font.size = Pt(10)
    rpr = style.element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = rpr.makeelement(qn("w:rFonts"), {})
        rpr.insert(0, rfonts)
    for attr in ("w:eastAsia", "w:ascii", "w:hAnsi", "w:cs"):
        rfonts.set(qn(attr), FONT_ZH)
    pf = style.paragraph_format
    pf.line_spacing = 1.35
    pf.space_after = Pt(4)
    for name in ("Heading 1", "Heading 2", "Heading 3", "Title"):
        try:
            s = doc.styles[name]
            s.font.name = FONT_ZH
            srpr = s.element.get_or_add_rPr()
            srf = srpr.find(qn("w:rFonts"))
            if srf is None:
                srf = srpr.makeelement(qn("w:rFonts"), {})
                srpr.insert(0, srf)
            for attr in ("w:eastAsia", "w:ascii", "w:hAnsi", "w:cs"):
                srf.set(qn(attr), FONT_ZH)
        except KeyError:
            continue
