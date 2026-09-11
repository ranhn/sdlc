"""两次威胁建模结果的版本对比（diff）。

对应 Threat Modeling Manifesto 原则 2「威胁建模必须随设计变更在迭代中跟进」：
架构改了一版之后，用户需要回答"相比上次，威胁有什么变化"。

## 为什么不能直接用 ID 比对

- 威胁的 ``threatId`` 是 ``uuid4()``（``model_builder._make_threat``），每次都不同；
- 威胁的 ``number`` 是递增计数器，新增一个组件就会整体位移；
- cell 的 ``id`` 同样是 ``uuid4()``。

因此威胁的稳定身份只能靠**内容组合键**：``(组件稳定ID, 威胁类型, 归一化标题)``。
组件的稳定 ID 由 ``document_analyzer._stable_component_id`` 生成
（``SHA1(规范化名称|类型)[:8]``），跨次建模保持稳定。

## 对比结果分类

- ``added``：本次新增（旧版本没有）
- ``removed``：本次消失（旧版本有、本次没有）
- ``changed``：两侧都有但属性变化（严重度/状态/范围外/组件）
- ``unchanged``：完全一致
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# 参与"变化"判定的威胁属性
_COMPARE_FIELDS = ("severity", "status", "type")


# ---------------------------------------------------------------------------
# 从模型提取威胁清单
# ---------------------------------------------------------------------------
def _norm_title(text: Any) -> str:
    """标题归一化：去空白、去标点、转小写，用于跨版本匹配。"""
    s = str(text or "").strip().lower()
    s = re.sub(r"[\s\u3000]+", "", s)
    # 去掉常见中英文标点，避免"攻击者伪造身份。"与"攻击者伪造身份"被当成两条
    s = re.sub(r"[，。；：、,.;:!?！？\"'“”‘’()（）\[\]【】<>《》/\\|~`@#$%^&*+=_-]+", "", s)
    return s


def _norm_name(text: Any) -> str:
    """组件名归一化，与 ``document_analyzer._norm_name`` 保持一致的思路。"""
    s = str(text or "").strip()
    s = re.sub(r"\s+", "", s)
    s = s.replace("（", "(").replace("）", ")").replace("，", ",").replace("、", ",")
    return s.lower()


def extract_threats(model: dict[str, Any] | None) -> list[dict[str, Any]]:
    """从 Threat Dragon 模型中提取全部威胁，并补上所属元素信息。

    威胁可能挂在组件 cell 上，也可能挂在数据流（边）cell 上，
    两者都存在 ``cell["threats"]``，因此这里统一遍历所有 cell。
    """
    if not isinstance(model, dict):
        return []
    diagrams = ((model.get("detail") or {}).get("diagrams")) or []
    rows: list[dict[str, Any]] = []
    for diagram in diagrams:
        for cell in diagram.get("cells") or []:
            threats = cell.get("threats") or []
            if not threats:
                continue
            data = cell.get("data") or {}
            # 边（数据流）用 source/target 表达，节点则没有
            is_edge = bool(cell.get("source") or cell.get("target"))
            elem_name = data.get("name") or cell.get("id") or ""
            elem_type = data.get("type") or ("dataflow" if is_edge else "process")
            for t in threats:
                if not isinstance(t, dict):
                    continue
                rows.append(
                    {
                        "threatId": t.get("id") or t.get("threatId"),
                        "number": t.get("number"),
                        "title": t.get("title") or "",
                        "type": t.get("type") or "",
                        "severity": t.get("severity") or "",
                        "status": t.get("status") or "Open",
                        "outOfScope": bool(t.get("outOfScope")),
                        "description": t.get("description") or "",
                        "mitigation": t.get("mitigation") or "",
                        "cwe": t.get("cwe") or "",
                        "elementId": cell.get("id") or "",
                        "elementName": elem_name,
                        "elementType": elem_type,
                        "isEdge": is_edge,
                    }
                )
    return rows


def threat_key(threat: dict[str, Any]) -> str:
    """构造威胁的跨版本稳定匹配键。

    组件的 ``cell.data.name`` 跨次建模稳定（名称由 LLM 从同一文档提取），
    因此用「元素名 + 威胁类型 + 归一化标题」组合。
    """
    return "|".join(
        (
            _norm_name(threat.get("elementName")),
            str(threat.get("type") or "").strip().lower(),
            _norm_title(threat.get("title")),
        )
    )


# ---------------------------------------------------------------------------
# 主对比逻辑
# ---------------------------------------------------------------------------
def _public_view(row: dict[str, Any]) -> dict[str, Any]:
    """输出给前端的威胁精简视图。"""
    return {
        "threatId": row.get("threatId"),
        "number": row.get("number"),
        "title": row.get("title"),
        "type": row.get("type"),
        "severity": row.get("severity"),
        "status": row.get("status"),
        "outOfScope": row.get("outOfScope"),
        "elementName": row.get("elementName"),
        "elementType": row.get("elementType"),
        "cwe": row.get("cwe"),
    }


def diff_models(
    old_model: dict[str, Any] | None,
    new_model: dict[str, Any] | None,
) -> dict[str, Any]:
    """对比两份模型，返回新增 / 消失 / 变化 / 未变 的威胁清单。

    Args:
        old_model: 基线（较早）的 Threat Dragon 模型。
        new_model: 当前（较新）的 Threat Dragon 模型。

    Returns:
        含 ``added`` / ``removed`` / ``changed`` / ``unchanged`` 与统计摘要的字典。
    """
    old_rows = extract_threats(old_model)
    new_rows = extract_threats(new_model)

    # 键冲突（同名同类型同标题的重复威胁）时只保留第一条，避免误判为"变化"
    old_map: dict[str, dict[str, Any]] = {}
    for r in old_rows:
        old_map.setdefault(threat_key(r), r)
    new_map: dict[str, dict[str, Any]] = {}
    for r in new_rows:
        new_map.setdefault(threat_key(r), r)

    added: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    unchanged: list[dict[str, Any]] = []

    for key, row in new_map.items():
        prev = old_map.get(key)
        if prev is None:
            added.append(_public_view(row))
            continue
        # 逐字段比对，收集实际变化的属性
        deltas: dict[str, dict[str, Any]] = {}
        for field in _COMPARE_FIELDS:
            before, after = prev.get(field), row.get(field)
            if str(before or "") != str(after or ""):
                deltas[field] = {"from": before, "to": after}
        if bool(prev.get("outOfScope")) != bool(row.get("outOfScope")):
            deltas["outOfScope"] = {
                "from": bool(prev.get("outOfScope")),
                "to": bool(row.get("outOfScope")),
            }
        if deltas:
            item = _public_view(row)
            item["changes"] = deltas
            changed.append(item)
        else:
            unchanged.append(_public_view(row))

    removed = [
        _public_view(row) for key, row in old_map.items() if key not in new_map
    ]

    # 严重度变化统计：用于回答"风险是变好了还是变差了"
    sev_up = sum(
        1
        for c in changed
        if "severity" in c["changes"]
        and _sev_rank(c["changes"]["severity"]["to"]) > _sev_rank(c["changes"]["severity"]["from"])
    )
    sev_down = sum(
        1
        for c in changed
        if "severity" in c["changes"]
        and _sev_rank(c["changes"]["severity"]["to"]) < _sev_rank(c["changes"]["severity"]["from"])
    )

    return {
        "summary": {
            "oldTotal": len(old_map),
            "newTotal": len(new_map),
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "unchanged": len(unchanged),
            "severityEscalated": sev_up,
            "severityDeescalated": sev_down,
            # 净增威胁数：>0 说明本次架构引入了更多风险
            "netChange": len(new_map) - len(old_map),
        },
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged": unchanged,
    }


_SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _sev_rank(sev: Any) -> int:
    return _SEV_ORDER.get(str(sev or "").strip().lower(), 0)
