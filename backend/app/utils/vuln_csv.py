"""漏洞清单 CSV 导出渲染。

两条原则
--------
1. **清单级字段，不放长文本**：CSV 是拿去筛选/排序/二次加工/进工单的表格，
   描述、复现步骤、影响范围、修复建议这类"要读的长文"留在 Word 报告里
   （Word 才是给人读的）。列与页面列表口径保持一致。
2. **每行带一条能点回平台的详情链接**：CSV 一旦离开平台（邮件、工单、评审附件），
   读者最需要的动作就是"回到平台看这条漏洞的证据与流转"。链接指向平台自身的
   漏洞详情深链 ``/vulnerabilities/submit?id=<id>``（前端已支持 ``?id=`` 直接
   打开该漏洞的详情抽屉）。

其它约定
--------
· UTF-8 **BOM**：Excel / WPS 双击打开不乱码（不带 BOM 时 Excel 按本地编码解，全乱）；
· 超链接写**裸 URL**而不是 ``=HYPERLINK()`` 公式：裸 URL 在 Excel / WPS / Numbers /
  Google Sheets 里都会被自动识别成可点击链接，也不怕导出后被人误当公式计算。

本模块只依赖标准库（外加同项目的标签映射），可脱离 FastAPI / 数据库单独测试。
"""

from __future__ import annotations

import csv
import io
from typing import Any, Iterable

from ..state_machine import STATUS_NAMES
from .vuln_docx import SEV_ZH

# 平台内漏洞详情深链（前端路由 + 查询参数）。
# 前端 Vulnerabilities.vue 的 onMounted 会读 ?id= 并直接打开该漏洞抽屉，
# 路由守卫对非管理员会转发到「漏洞修复」页（同一套 ?id= 语义）。
DETAIL_PATH = "/vulnerabilities/submit"

CSV_HEADERS = [
    "ID", "标题", "所属系统", "接口地址", "等级", "大类", "类型", "状态",
    "提交人", "负责人", "复测人", "创建时间", "详情链接",
]


def detail_link(base_url: str | None, vuln_id: Any, path: str = DETAIL_PATH) -> str:
    """拼平台内漏洞详情链接。

    ``base_url`` 为空时退化成站内相对路径：仍可读、可 grep，但点不动 ——
    宁可给出"半截路径"，也不要凭空编一个域名（编错了会把人引到别的系统）。
    """
    rel = f"{path}?id={vuln_id}"
    if not base_url:
        return rel
    return f"{str(base_url).rstrip('/')}{rel}"


def render_vulns_csv(rows: Iterable[Any], *, base_url: str | None = None) -> bytes:
    """把漏洞列表渲染成 CSV 字节（含 BOM）。

    Args:
        rows: 漏洞记录（按属性访问即可，VulnOut / ORM 对象均可）
        base_url: 平台基地址（形如 ``https://sdlc.example.com``），用于详情链接
    """

    def _v(row: Any, name: str, default: Any = "") -> Any:
        value = getattr(row, name, None)
        return default if value is None else value

    buf = io.StringIO()
    buf.write("\ufeff")  # BOM：Excel 识别 UTF-8
    writer = csv.writer(buf)
    writer.writerow(CSV_HEADERS)
    for r in rows:
        vid = _v(r, "id")
        writer.writerow([
            vid,
            _v(r, "title"),
            _v(r, "system_name"),
            _v(r, "api_endpoint"),
            SEV_ZH.get(str(_v(r, "severity")), _v(r, "severity")),
            _v(r, "vuln_category"),
            _v(r, "vuln_type"),
            STATUS_NAMES.get(str(_v(r, "status")), _v(r, "status")),
            _v(r, "reporter_name"),
            _v(r, "assignee_name", "未指派") or "未指派",
            _v(r, "reviewer_name"),
            _fmt_time(_v(r, "created_at")),
            detail_link(base_url, vid),
        ])
    return buf.getvalue().encode("utf-8")


def _fmt_time(value: Any) -> str:
    """时间统一按东八区展示（库里存 naive UTC，与页面一致）。"""
    if not value:
        return ""
    try:
        from zoneinfo import ZoneInfo

        import datetime as _dt

        tz = ZoneInfo("Asia/Shanghai")
        if isinstance(value, _dt.datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=_dt.timezone.utc)
            return value.astimezone(tz).strftime("%Y-%m-%d %H:%M")
        parsed = _dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_dt.timezone.utc)
        return parsed.astimezone(tz).strftime("%Y-%m-%d %H:%M")
    except Exception:  # noqa: BLE001
        return str(value)
