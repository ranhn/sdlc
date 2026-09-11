"""威胁 → 漏洞工单 的转换桥接层。

威胁建模的产出（威胁条目）与漏洞管理模块（``Vuln``）此前完全割裂：安全工程师
在威胁建模里识别出风险后，需要人工到漏洞页面重新录一遍。本模块负责把一条威胁
映射为一条可入库的漏洞记录，打通平台内的闭环。

设计要点：
1. **纯映射函数与落库分离** —— ``map_threat_to_vuln`` 不做任何 IO，便于单测；
   ``create_vuln_from_threat`` 才接触数据库。
2. **严重度大小写转换** —— 威胁侧是 ``Critical/High/Medium/Low``，
   漏洞侧是小写 ``critical/high/medium/low``。
3. **类型映射到平台分类体系** —— 威胁的 STRIDE / LINDDUN 等类型映射到
   ``vuln_taxonomy.py`` 的「一级大类 + 二级子类」，保证 dashboard 聚合一致。
4. **CWE 兜底** —— ``Vuln`` 表没有 cwe 列，CWE 会被拼进修复建议。
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 严重度映射：威胁侧（首字母大写） -> 漏洞侧（小写）
# ---------------------------------------------------------------------------
SEVERITY_TO_VULN: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}
# 兜底：威胁侧可能出现 Unknown / TBD / N/A 等非标准值
SEVERITY_FALLBACK = "medium"


def normalize_severity(severity: Any) -> str:
    """把威胁的严重度转换为漏洞模块使用的枚举值。"""
    key = str(severity or "").strip().lower()
    return SEVERITY_TO_VULN.get(key, SEVERITY_FALLBACK)


# ---------------------------------------------------------------------------
# 威胁类型 -> 平台漏洞分类（一级大类, 二级子类）
# 键为小写归一化后的威胁类型名，兼容 STRIDE / STRIDE-AI / LINDDUN / PLOT4ai / CIA 等
# ---------------------------------------------------------------------------
_TYPE_MAP: dict[str, tuple[str, str]] = {
    # ---- STRIDE ----
    "spoofing": ("认证与会话", "认证绕过"),
    "tampering": ("注入类", "反序列化"),
    "repudiation": ("服务端与配置", "安全配置错误"),
    "information disclosure": ("信息泄露", "信息泄露"),
    "denial of service": ("服务端与配置", "拒绝服务(DoS)"),
    "elevation of privilege": ("访问控制", "垂直越权/提权"),
    # ---- STRIDE-AI / OWASP LLM 常见表述 ----
    "prompt injection": ("AI/LLM安全", "提示注入"),
    "system prompt leakage": ("AI/LLM安全", "系统提示泄露"),
    "training data poisoning": ("AI/LLM安全", "训练数据投毒"),
    "model denial of service": ("AI/LLM安全", "无限Token消耗"),
    "insecure output handling": ("AI/LLM安全", "Agent过度代理"),
    "vector store poisoning": ("AI/LLM安全", "RAG知识库投毒"),
    "rag poisoning": ("AI/LLM安全", "RAG知识库投毒"),
    "excessive agency": ("AI/LLM安全", "Agent过度代理"),
    "model theft": ("AI/LLM安全", "模型越权调用"),
    "supply chain": ("服务端与配置", "供应链投毒"),
    "insecure plugin design": ("AI/LLM安全", "模型越权调用"),
    # ---- LINDDUN（隐私） ----
    "linking": ("信息泄露", "信息泄露"),
    "identifying": ("信息泄露", "信息泄露"),
    "non-repudiation": ("认证与会话", "会话管理缺陷"),
    "detecting": ("信息泄露", "信息泄露"),
    "data disclosure": ("信息泄露", "敏感数据明文存储"),
    "unawareness": ("其他", "其他"),
    "non-compliance": ("其他", "其他"),
    # ---- MAESTRO（多智能体系统）----
    # 键为小写归一化后的威胁类型名；MAESTRO_TYPES 用 camelCase，
    # 这里必须写成小写无连字符形式才能被精确匹配命中。
    "goalhijacking": ("AI/LLM安全", "提示注入"),
    "toolmisuse": ("AI/LLM安全", "Agent过度代理"),
    "privilegeamplification": ("访问控制", "垂直越权/提权"),
    "memorypoisoning": ("AI/LLM安全", "RAG知识库投毒"),
    "interagentdeception": ("认证与会话", "认证绕过"),
    "autonomyrunaway": ("AI/LLM安全", "Agent过度代理"),
    "insecureorchestration": ("服务端与配置", "安全配置错误"),
    "observabilitygap": ("服务端与配置", "日志与监控不足"),
    "supplychaincompromise": ("服务端与配置", "供应链投毒"),
    "dataleakage": ("信息泄露", "信息泄露"),
    # ---- PLOT4ai 常见项 ----
    "unreliable": ("AI/LLM安全", "模型越权调用"),
    "unsafe": ("其他", "其他"),
    "unexplainable": ("其他", "其他"),
    "unfair": ("其他", "其他"),
    "uncontrollable": ("AI/LLM安全", "Agent过度代理"),
    "unpredictable": ("AI/LLM安全", "Agent过度代理"),
    "unaware": ("其他", "其他"),
    "untrustworthy": ("AI/LLM安全", "模型越权调用"),
    # ---- CIA / CIADIE ----
    "confidentiality": ("信息泄露", "信息泄露"),
    "integrity": ("注入类", "反序列化"),
    "availability": ("服务端与配置", "拒绝服务(DoS)"),
    "distributed": ("服务端与配置", "容器/K8s配置缺陷"),
    "immutable": ("其他", "其他"),
    "ephemeral": ("其他", "其他"),
}

# 关键词兜底：威胁类型名没命中精确表时，按子串猜测大类
_KEYWORD_MAP: list[tuple[str, tuple[str, str]]] = [
    ("injection", ("AI/LLM安全", "提示注入")),
    ("prompt", ("AI/LLM安全", "提示注入")),
    ("llm", ("AI/LLM安全", "模型越权调用")),
    ("agent", ("AI/LLM安全", "Agent过度代理")),
    ("model", ("AI/LLM安全", "模型越权调用")),
    ("vector", ("AI/LLM安全", "RAG知识库投毒")),
    ("training", ("AI/LLM安全", "训练数据投毒")),
    ("spoof", ("认证与会话", "认证绕过")),
    ("auth", ("认证与会话", "认证绕过")),
    ("privilege", ("访问控制", "垂直越权/提权")),
    ("disclosure", ("信息泄露", "信息泄露")),
    ("leak", ("信息泄露", "信息泄露")),
    ("denial", ("服务端与配置", "拒绝服务(DoS)")),
    ("dos", ("服务端与配置", "拒绝服务(DoS)")),
    ("tamper", ("注入类", "反序列化")),
]


def map_threat_type_to_category(threat_type: Any) -> tuple[str, str]:
    """把威胁类型映射为平台漏洞分类 ``(一级大类, 二级子类)``。

    未命中时返回 ``("其他", "其他")``，保证总能产出合法的分类值
    （与 ``vuln_taxonomy.py`` 的枚举保持一致）。
    """
    raw = str(threat_type or "").strip()
    if not raw:
        return ("其他", "其他")
    key = re.sub(r"\s+", " ", raw.lower())
    # 1) 精确匹配
    hit = _TYPE_MAP.get(key)
    if hit:
        return hit
    # 2) 关键词子串匹配
    for kw, mapped in _KEYWORD_MAP:
        if kw in key:
            return mapped
    # 3) 兜底
    return ("其他", "其他")


# ---------------------------------------------------------------------------
# 文本组装
# ---------------------------------------------------------------------------
def build_vuln_title(threat: dict[str, Any], max_len: int = 200) -> str:
    """生成漏洞标题。

    漏洞侧 ``title`` 必填且长度 2~200（见 ``schemas.VulnCreate``），
    这里做足截断与兜底，避免因标题过短/过长导致入库失败。
    """
    title = str(threat.get("title") or "").strip()
    if not title:
        t = str(threat.get("type") or "").strip()
        title = f"{t}风险" if t else "威胁建模识别的风险"
    # 折叠空白并截断（预留省略号空间）
    title = re.sub(r"\s+", " ", title)
    if len(title) > max_len:
        title = title[: max_len - 1] + "…"
    if len(title) < 2:
        title = f"{title}风险" if title else "威胁建模识别的风险"
    return title


def build_vuln_description(
    threat: dict[str, Any],
    result_meta: dict[str, Any] | None = None,
) -> str:
    """组装漏洞描述：威胁描述 + 来源建模信息 + CWE 等附加值。"""
    parts: list[str] = []
    desc = str(threat.get("description") or "").strip()
    if desc:
        parts.append(desc)

    # 来源信息：让研发知道这条漏洞是怎么来的，便于回溯建模报告
    src_lines = ["", "---", "**来源：AI 威胁建模**"]
    if result_meta:
        rid = result_meta.get("id")
        title = result_meta.get("title")
        method = result_meta.get("methodology")
        if title:
            src_lines.append(f"- 建模结果：{title}" + (f"（`{rid}`）" if rid else ""))
        elif rid:
            src_lines.append(f"- 建模结果：`{rid}`")
        if method:
            src_lines.append(f"- 方法论：{method}")
    if result_meta and result_meta.get("threat_id"):
        src_lines.append(f"- 威胁 ID：`{result_meta['threat_id']}`")
    component = str(threat.get("componentName") or threat.get("componentId") or "").strip()
    if component:
        src_lines.append(f"- 涉及组件：{component}")
    threat_type = str(threat.get("type") or "").strip()
    if threat_type:
        src_lines.append(f"- 威胁类型：{threat_type}")
    if len(src_lines) > 3:
        parts.extend(src_lines)

    # CWE 无处存放（Vuln 表无该列），拼进描述便于追溯
    cwe = str(threat.get("cwe") or "").strip()
    if cwe:
        parts.extend(["", f"**关联 CWE**：{cwe}"])

    return "\n".join(parts).strip()


def build_vuln_fix_suggestion(threat: dict[str, Any]) -> str | None:
    """组装修复建议：威胁的 mitigation + 参考资料。"""
    parts: list[str] = []
    mitigation = str(threat.get("mitigation") or "").strip()
    if mitigation:
        parts.append(mitigation)
    refs = threat.get("references") or []
    if isinstance(refs, list) and refs:
        clean = [str(r).strip() for r in refs if str(r).strip()]
        if clean:
            parts.append("")
            parts.append("**参考资料**：")
            parts.extend(f"- {r}" for r in clean)
    text = "\n".join(parts).strip()
    return text or None


def map_threat_to_vuln(
    threat: dict[str, Any],
    result_meta: dict[str, Any] | None = None,
    system_id: int | None = None,
    api_endpoint: str | None = None,
    assignee_id: int | None = None,
) -> dict[str, Any]:
    """把一条威胁映射为 ``Vuln`` 的构造参数（纯函数，不接触数据库）。

    Args:
        threat: 威胁条目（来自 Threat Dragon 模型的 cell.threats[]）。
        result_meta: 来源建模结果元数据（id / title / methodology / threat_id）。
        system_id: 关联的系统资产 ID。
        api_endpoint: 受影响接口；威胁通常没有该信息，为空时用占位值
            （漏洞侧 ``api_endpoint`` 必填，长度 1~500）。
        assignee_id: 修复负责人。

    Returns:
        可直接用于 ``Vuln(**kwargs)`` 的字典。
    """
    category, vuln_type = map_threat_type_to_category(threat.get("type"))

    # api_endpoint 必填：威胁建模不产出接口路径，用占位值明确表示"待研发补充"
    endpoint = str(api_endpoint or "").strip()
    if not endpoint:
        component = str(threat.get("componentName") or "").strip()
        endpoint = f"待补充（威胁建模·组件：{component}）" if component else "待补充"
    endpoint = endpoint[:500]

    return {
        "title": build_vuln_title(threat),
        "description": build_vuln_description(threat, result_meta),
        "severity": normalize_severity(threat.get("severity")),
        "vuln_category": category,
        "vuln_type": vuln_type,
        "system_id": system_id,
        "assignee_id": assignee_id,
        "api_endpoint": endpoint,
        "fix_suggestion": build_vuln_fix_suggestion(threat),
    }


# ---------------------------------------------------------------------------
# 落库
# ---------------------------------------------------------------------------
# 未关闭的漏洞状态（用于重复转单检测）
_OPEN_VULN_STATUSES = ("pending", "confirmed", "fixing", "retest")


def find_existing_vuln(db: Any, title: str) -> Any | None:
    """查找是否已存在同名且未关闭的漏洞单，避免重复转单。"""
    try:
        from app.models import Vuln
    except ImportError:  # pragma: no cover - 独立部署时不存在主应用
        return None
    return (
        db.query(Vuln)
        .filter(Vuln.title == title, Vuln.status.in_(_OPEN_VULN_STATUSES))
        .first()
    )


def create_vuln_from_threat(
    db: Any,
    threat: dict[str, Any],
    reporter_id: int,
    result_meta: dict[str, Any] | None = None,
    system_id: int | None = None,
    api_endpoint: str | None = None,
    assignee_id: int | None = None,
    skip_duplicate: bool = True,
) -> tuple[Any | None, bool]:
    """把一条威胁落库为漏洞单。

    Args:
        db: SQLAlchemy Session（与主应用的 ``get_db`` 同源）。
        threat: 威胁条目。
        reporter_id: 提交人用户 ID（``Vuln.reporter_id`` 非空）。
        result_meta: 来源建模结果元数据。
        system_id: 关联系统资产 ID。
        api_endpoint: 受影响接口。
        assignee_id: 修复负责人。
        skip_duplicate: 命中同名未关闭漏洞时是否直接返回既有单（默认 True）。

    Returns:
        ``(vuln_or_None, created)``：
        - 新建成功 -> ``(vuln, True)``
        - 命中重复且 skip_duplicate -> ``(existing_vuln, False)``
        - 无法导入主应用模型（独立部署） -> ``(None, False)``
    """
    try:
        from app.models import Vuln
    except ImportError:  # pragma: no cover
        logger.warning("未找到主应用的 Vuln 模型，威胁转漏洞功能不可用")
        return (None, False)

    payload = map_threat_to_vuln(
        threat,
        result_meta=result_meta,
        system_id=system_id,
        api_endpoint=api_endpoint,
        assignee_id=assignee_id,
    )

    if skip_duplicate:
        existing = find_existing_vuln(db, payload["title"])
        if existing is not None:
            logger.info("威胁已存在同名未关闭漏洞单 #%s，跳过创建", existing.id)
            return (existing, False)

    vuln = Vuln(
        title=payload["title"],
        description=payload["description"],
        severity=payload["severity"],
        vuln_category=payload["vuln_category"],
        vuln_type=payload["vuln_type"],
        system_id=payload["system_id"],
        assignee_id=payload["assignee_id"],
        api_endpoint=payload["api_endpoint"],
        fix_suggestion=payload["fix_suggestion"],
        reporter_id=reporter_id,
        status="pending",
        # 来源于威胁建模，与 scanner 的 manual_scan / ci_scan 区分
        source="threat_model",
    )
    db.add(vuln)
    db.flush()
    vuln_id = vuln.id
    logger.info("威胁「%s」已转为漏洞单 #%s", payload["title"], vuln_id)
    return (vuln, True)
