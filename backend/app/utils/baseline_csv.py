"""基线评估明细 CSV 导出渲染。

与漏洞清单 CSV（``utils.vuln_csv``）同一套约定：

· UTF-8 **BOM**：Excel / WPS 双击打开不乱码；
· 时间按**东八区**展示（库里存 naive UTC，与页面一致）；
· 纯标准库 + 纯函数：可脱离 FastAPI / 数据库单独测试。

列的选择围绕"这一条结论能不能自证"：**哪条基线 → 哪个控制模块 → 哪条要求 →
结论是什么 → 依据是什么 → 谁在什么时候判的**。审计要的就是这一串；少任何一列，
拿到文件的人都得回平台再查一遍。
"""

from __future__ import annotations

import csv
import io
from typing import Any, Iterable

# 与页面同一套中文名（前端 resultName 的同义表；导出文件不出现英文状态值）
STATUS_ZH = {"pending": "未评估", "pass": "通过", "fail": "不通过", "na": "不适用"}

CSV_HEADERS = [
    "系统", "需求", "基线", "控制模块", "检查项", "要求",
    "评估结果", "说明与证据", "评估人", "评估时间",
]


def render_baseline_csv(rows: Iterable[dict[str, Any]], *, system_name: str = "",
                        requirement_name: str = "") -> bytes:
    """把某需求的评估明细渲染成 CSV 字节（含 BOM）。

    Args:
        rows: 每条 = 一个检查项 + 它的结论，键见 ``CSV_HEADERS`` 的对应关系：
            ``baseline / category / item / description / status / evidence / checker / checked_at``
        system_name: 系统名（每行都带，方便把多份导出拼到一起后在 Excel 里筛选）
        requirement_name: 需求名（同上）
    """
    buf = io.StringIO()
    buf.write("\ufeff")  # BOM：Excel 识别 UTF-8
    writer = csv.writer(buf)
    writer.writerow(CSV_HEADERS)
    for r in rows:
        status = str(r.get("status") or "pending")
        writer.writerow([
            system_name,
            requirement_name,
            r.get("baseline", ""),
            r.get("category", ""),
            r.get("item", ""),
            r.get("description", ""),
            STATUS_ZH.get(status, status),
            r.get("evidence", ""),
            r.get("checker", ""),
            _fmt_time(r.get("checked_at")),
        ])
    return buf.getvalue().encode("utf-8")


def _fmt_time(value: Any) -> str:
    """时间统一按东八区（与漏洞导出、页面展示同一个口径）。

    复用 ``vuln_csv._fmt_time``：时区换算这种东西**只能有一份实现** ——
    两份迟早会在夏令时/无时区数据上给出不一样的结果，而两个导出文件是要放在
    一起看的。
    """
    from .vuln_csv import _fmt_time as fmt

    return fmt(value)
