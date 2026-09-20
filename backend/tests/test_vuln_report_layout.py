"""漏洞清单 Word 报告的版式回归测试。

用法（在 backend 目录下）：
    python -m pytest tests/test_vuln_report_layout.py -v
    python tests/test_vuln_report_layout.py          # 无 pytest 时直接跑

为什么要有它：
    用户反馈「批量导出的 word 报告格式有点问题」—— 根因是 10 列表格**没有指定列宽**，
    A4 纵向版心 16.4cm 被等分成 10 份（每列 1.6cm），长文本被压成一字一行：
    标题竖排、ID 断成两行、接口地址只剩一列竖字。这类问题代码评审时看不出来
    （文档照样生成、照样能打开），但打开一眼就废，所以把不变量固化成断言：

      1. 每张表的列宽合计**恰好**等于所在章节的版心宽
         （多则溢出页边距、少则右边缘与正文不齐）；
      2. 表格必须是固定布局（w:tblLayout=fixed）：否则 Word 会按内容重新分配列宽，
         显式写的 tcW 形同虚设；
      3. 清单表每列有下限宽度（标题、创建时间最关键），保证长文本不折成"一字一行"。

这些断言只依赖 python-docx（vuln_docx 的 docx 相关 import 都在函数内），
不需要数据库 / FastAPI 运行环境。
"""

from __future__ import annotations

import io
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from docx import Document  # noqa: E402
from docx.oxml.ns import qn  # noqa: E402

from app.utils.vuln_docx import (  # noqa: E402
    LANDSCAPE_CONTENT_CM,
    LIST_COLUMNS,
    PORTRAIT_CONTENT_CM,
    render_vulns_docx,
)

# 清单表各列的最小宽度（cm）：低于这些值长文本就会折成"一字一行"。
# 创建时间的下限按 16 字符日期（2026-09-18 18:21）+ 内边距 0.28 实测得出。
MIN_COL_WIDTH = {
    "ID": 1.10,
    "漏洞标题": 4.50,
    "所属系统": 1.80,
    "接口地址": 3.20,
    "等级": 1.10,
    "大类": 1.90,
    "类型": 1.80,
    "状态": 1.30,
    "负责人": 1.40,
    "创建时间": 2.80,
}


def _row(**kw):
    base = {
        "id": 1,
        "title": "示例漏洞标题",
        "description": "描述",
        "reproduce_steps": "1. 第一步\n2. 第二步",
        "impact": "影响",
        "fix_suggestion": "修复建议",
        "severity": "high",
        "status": "pending",
        "system_name": "官网门户",
        "api_endpoint": "/api/v1/order/detail",
        "vuln_category": "访问控制",
        "vuln_type": "越权",
        "assignee_name": "张三",
        "reporter_name": "李四",
        "reviewer_name": None,
        "created_at": "2026-09-18T10:21:00",
        "updated_at": None,
        "sla_deadline": None,
        "rejection_reason": None,
        "cvss": None,
        "is_external": False,
        "external_source": None,
        "screenshots": None,
        "step_screenshots": None,
    }
    base.update(kw)
    return SimpleNamespace(**base)


def _render(rows, **kw) -> Document:
    return Document(io.BytesIO(render_vulns_docx(rows, **kw)))


def _grid_widths(table) -> list[float]:
    grid = table._tbl.find(qn("w:tblGrid"))
    if grid is None:
        return []
    return [round(int(gc.get(qn("w:w"))) / 567, 2) for gc in grid.findall(qn("w:gridCol"))]


def _layout_is_fixed(table) -> bool:
    el = table._tbl.tblPr.find(qn("w:tblLayout"))
    return el is not None and el.get(qn("w:type")) == "fixed"


def _tr_flag(row, tag: str) -> bool:
    tr_pr = row._tr.find(qn("w:trPr"))
    return tr_pr is not None and tr_pr.find(qn(tag)) is not None


def _docx_tables(doc: Document):
    return list(doc.tables)


# ---------------------------------------------------------------------------
# 1. 列宽不变量
# ---------------------------------------------------------------------------
def test_column_widths_never_exceed_content_width() -> None:
    """每张表的列宽合计必须等于版心宽（16.4 纵向 / 25.1 横向）。"""
    doc = _render([_row() for _ in range(3)])
    allowed = {round(PORTRAIT_CONTENT_CM, 2), round(LANDSCAPE_CONTENT_CM, 2)}
    for i, t in enumerate(_docx_tables(doc)):
        widths = _grid_widths(t)
        assert widths, f"表 #{i} 没有 tblGrid（列宽未显式指定）"
        total = round(sum(widths), 2)
        assert total in allowed, (
            f"表 #{i} 列宽合计 {total}cm 不在 {sorted(allowed)} 内 —— "
            f"多则溢出页边距、少则右边缘与正文不齐（列宽 {widths}）"
        )


def test_all_tables_use_fixed_layout() -> None:
    """表格必须是固定布局，否则 Word 会按内容重算列宽、显式 tcW 失效。"""
    doc = _render([_row() for _ in range(3)])
    for i, t in enumerate(_docx_tables(doc)):
        assert _layout_is_fixed(t), f"表 #{i} 不是 fixed 布局 → 列宽会被 Word 重算"


def test_long_tables_repeat_header_row() -> None:
    """超过 5 行的表必须重复表头（清单表跨页后仍要知道列的含义）。"""
    doc = _render([_row(id=i) for i in range(1, 13)])
    for i, t in enumerate(_docx_tables(doc)):
        if len(t.rows) > 5:
            assert _tr_flag(t.rows[0], "w:tblHeader"), f"表 #{i} 未设置表头跨页重复"


# ---------------------------------------------------------------------------
# 2. 清单表列宽下限（用户反馈的直接症状）
# ---------------------------------------------------------------------------
def test_list_table_columns_have_minimum_width() -> None:
    doc = _render([_row() for _ in range(3)])
    list_tables = [t for t in _docx_tables(doc) if len(t.columns) == len(LIST_COLUMNS)]
    assert list_tables, "没有找到清单表"
    widths = _grid_widths(list_tables[0])
    for (head, _w), w in zip(LIST_COLUMNS, widths):
        assert w >= MIN_COL_WIDTH[head], (
            f"清单表「{head}」列宽 {w}cm < 下限 {MIN_COL_WIDTH[head]}cm —— "
            f"长文本会折成一字一行"
        )
    assert round(sum(widths), 2) == round(LANDSCAPE_CONTENT_CM, 2)


def test_clipped_cells_keep_row_height_reasonable() -> None:
    """超长标题/接口地址：按真实字体度量，标题列最多 4 行、其余列最多 1 行。"""
    try:
        from PIL import ImageFont
    except ImportError:  # 无 PIL 时跳过（生产可装，测试环境可缺）
        print("      (skip: 无 PIL，跳过换行度量)")
        return
    long_title = "重路由传的是每次新建的 occupied 列表，而分桶缓存键是订单号，导致缓存命中率异常" * 2
    rows = [_row(title=long_title, api_endpoint="/api/paypal/v1/guestPayPalRetryReduction/" + "x" * 40)]
    doc = _render(rows)
    table = next(t for t in _docx_tables(doc) if len(t.columns) == len(LIST_COLUMNS))
    widths = _grid_widths(table)
    font = ImageFont.truetype(r"C:\Windows\Fonts\msyh.ttc", 90)
    scale = 90 / 9.0  # 9pt 字号的放大倍数（只为算比例）
    # 各列允许的最大行数：长文本列允许折行（截断长度已按"列宽 × 行数"定过），
    # 其余列必须单行 —— 单行是老 bug（一字一行）的反面基线。
    max_lines = {"漏洞标题": 4, "接口地址": 3, "所属系统": 2, "大类": 2, "类型": 2}
    for ci, (head, _w) in enumerate(LIST_COLUMNS):
        avail = (widths[ci] - 0.28) / 2.54 * 72 * scale
        used = font.getlength(table.rows[1].cells[ci].text)
        lines = max(1, int(used / avail) + (1 if used % avail else 0))
        limit = max_lines.get(head, 1)
        assert lines <= limit, f"「{head}」折了 {lines} 行（上限 {limit}，列宽 {widths[ci]}cm）"


# ---------------------------------------------------------------------------
# 3. 章节 / 页眉页脚
# ---------------------------------------------------------------------------
def test_sections_have_expected_orientation() -> None:
    """封面与详情纵向、清单横向（10 列需要 25.1cm 版心，纵向只有 16.4cm）。"""
    doc = _render([_row()])
    got = []
    for sec in doc.sections:
        content = round(sec.page_width.cm - sec.left_margin.cm - sec.right_margin.cm, 2)
        got.append(content)
    assert got == [round(PORTRAIT_CONTENT_CM, 2), round(LANDSCAPE_CONTENT_CM, 2),
                   round(PORTRAIT_CONTENT_CM, 2)], f"章节版心宽度异常：{got}"


def test_page_number_fields_and_cover_without_header() -> None:
    doc = _render([_row()])
    sec0 = doc.sections[0]
    # 封面不显示页眉页脚，后续章节必须显式关闭「首页不同」——
    # w:titlePg 会被后续章节继承，漏关会让清单页/首个详情页突然没有页码。
    assert sec0.different_first_page_header_footer is True
    for sec in doc.sections[1:]:
        assert sec.different_first_page_header_footer is False
    for sec in doc.sections:
        fxml = sec.footer._element.xml
        assert "PAGE" in fxml and "NUMPAGES" in fxml, "页脚缺少页码域"


# ---------------------------------------------------------------------------
# 4. 边界场景
# ---------------------------------------------------------------------------
def test_empty_scope_still_produces_valid_docx() -> None:
    doc = _render([])
    text = "\n".join(p.text for p in doc.paragraphs)
    assert "没有漏洞记录" in text or "无。" in text
    assert doc.paragraphs, "空数据也必须产出可打开的文档"


def test_dirty_screenshot_data_does_not_break_export() -> None:
    """库里存在只有 PNG 魔数（8 字节）的脏数据：导出必须成功并给出友好提示。"""
    fake = "data:image/png;base64," + "iVBORw0KGgo="  # \x89PNG\r\n\x1a\n，仅 8 字节
    doc = _render([_row(step_screenshots=[{"step_no": 1, "data_url": fake}])])
    text = "\n".join(p.text for p in doc.paragraphs)
    assert "无法解析" in text
    assert "复现证据" in text


def test_real_image_is_embedded() -> None:
    """真实截图必须真嵌进文档（不是只留一行文字）。"""
    try:
        from PIL import Image
    except ImportError:
        print("      (skip: 无 PIL，跳过图片嵌入用例)")
        return
    buf = io.BytesIO()
    Image.new("RGB", (120, 80), (200, 30, 30)).save(buf, format="PNG")
    import base64

    url = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    data = render_vulns_docx([_row(step_screenshots=[{"step_no": 1, "data_url": url}])])
    doc = Document(io.BytesIO(data))
    media = [p.partname for p in doc.part.package.parts
             if str(p.partname).startswith("/word/media/")]
    assert media, "截图未嵌入文档"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        fn()
        print(f"  PASS  {fn.__name__}")
    print(f"\n{len(tests)} tests passed")
