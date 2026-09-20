"""漏洞清单 CSV 导出回归测试。

用法（在 backend 目录下）：
    python -m pytest tests/test_vuln_export_csv.py -v
    python tests/test_vuln_export_csv.py          # 无 pytest 时直接跑

为什么要有它：
    CSV 是"拿出去用"的表格（筛选/排序/进工单），两个点最容易在改动中被悄悄弄坏：
      1. **详情链接**：每行必须带一条能点回平台的深链 —— 链接拼错（少了 ?id=、
         基地址多了斜杠、id 挂错行）在本地看不出来，发出去才发现点不开；
      2. **UTF-8 BOM**：去掉 BOM 后 Excel 双击打开中文全乱码。
    另外锁住"CSV 只放清单级字段"这条口径（长文本属于 Word 报告），
    避免以后有人顺手把描述/复现步骤塞进来，让表格变得没法筛选。
"""

from __future__ import annotations

import csv
import io
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.utils.vuln_csv import CSV_HEADERS, DETAIL_PATH, detail_link, render_vulns_csv  # noqa: E402


def _row(**kw):
    base = {
        "id": 12,
        "title": "商城订单接口存在越权查询",
        "system_name": "VeSync 商城",
        "api_endpoint": "/api/order/detail",
        "severity": "high",
        "vuln_category": "访问控制",
        "vuln_type": "越权",
        "status": "rejected",
        "reporter_name": "李四",
        "assignee_name": "王五",
        "reviewer_name": "赵六",
        "created_at": "2026-09-18T10:21:00",
    }
    base.update(kw)
    return SimpleNamespace(**base)


def _parse(data: bytes) -> list[list[str]]:
    text = data.decode("utf-8-sig")
    return list(csv.reader(io.StringIO(text)))


def test_headers_and_row_count() -> None:
    data = render_vulns_csv([_row(id=1), _row(id=2)], base_url="https://sdlc.example.com")
    rows = _parse(data)
    assert rows[0] == CSV_HEADERS
    assert rows[0][-1] == "详情链接", "详情链接应在最后一列"
    assert len(rows) == 3


def test_each_row_links_to_its_own_vuln() -> None:
    """每行的链接必须指向**自己**那条漏洞（最容易串行的地方）。"""
    data = render_vulns_csv([_row(id=7), _row(id=25)], base_url="https://sdlc.example.com")
    rows = _parse(data)
    assert rows[1][0] == "7" and rows[1][-1] == f"https://sdlc.example.com{DETAIL_PATH}?id=7"
    assert rows[2][0] == "25" and rows[2][-1] == f"https://sdlc.example.com{DETAIL_PATH}?id=25"


def test_base_url_trailing_slash_and_missing_base() -> None:
    # 末尾带斜杠不能拼出双斜杠（"https://x.com//vulnerabilities/..." 多数浏览器能跳，
    # 但工单/邮件客户端里常被当成非法地址）
    assert detail_link("https://sdlc.example.com/", 3) == f"https://sdlc.example.com{DETAIL_PATH}?id=3"
    # 拿不到基地址时退化为站内相对路径，且**不编造域名**
    assert detail_link(None, 3) == f"{DETAIL_PATH}?id=3"
    rows = _parse(render_vulns_csv([_row(id=3)], base_url=None))
    assert rows[1][-1] == f"{DETAIL_PATH}?id=3"


def test_bom_and_field_mapping() -> None:
    data = render_vulns_csv([_row()], base_url="https://x.cn")
    assert data[:3] == b"\xef\xbb\xbf", "缺少 UTF-8 BOM（Excel 会乱码）"
    rows = _parse(data)
    row = rows[1]
    assert row[4] == "高危" and row[7] == "已驳回", (row[4], row[7])
    assert row[8] == "李四" and row[9] == "王五" and row[10] == "赵六"
    assert row[11].startswith("2026-09-18 18:21"), f"时间未按东八区：{row[11]}"


def test_missing_fields_do_not_break_row() -> None:
    """空字段不能把整行搞崩（历史数据大量字段为空）。"""
    row = SimpleNamespace(id=9, title="只有标题", severity="medium", status="pending")
    rows = _parse(render_vulns_csv([row], base_url="https://x.cn"))
    assert len(rows[1]) == len(CSV_HEADERS)
    assert rows[1][9] == "未指派", "负责人为空时应显示未指派"
    assert rows[1][-1] == f"https://x.cn{DETAIL_PATH}?id=9"


def test_commas_and_quotes_are_escaped() -> None:
    """标题里的逗号/引号/换行必须被正确转义（否则整张表的列会错位）。"""
    tricky = '存在 SQL 注入, 且 "引号" 与\n换行'
    rows = _parse(render_vulns_csv([_row(title=tricky)], base_url="https://x.cn"))
    assert rows[1][1] == tricky
    assert len(rows[1]) == len(CSV_HEADERS)


def test_no_long_text_columns() -> None:
    """只放清单级字段：描述/复现步骤/影响/修复建议不进 CSV（去 Word 报告里读）。"""
    forbidden = ("描述", "复现", "影响", "修复建议", "详情内容")
    for head in CSV_HEADERS:
        assert not any(word in head for word in forbidden), f"CSV 混入了长文本列：{head}"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        fn()
        print(f"  PASS  {fn.__name__}")
    print(f"\n{len(tests)} tests passed")
