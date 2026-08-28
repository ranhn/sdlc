"""严重度规则化评分器。

用确定性规则（组件类型 × 威胁类型 × 元素属性）替代 LLM 的"自由评估"，
保证同一组件 + 同一威胁类型的严重度永远一致。
"""
from __future__ import annotations

from typing import Any

_SEV_ORDER = ["Low", "Medium", "High", "Critical"]
_SEV_RANK = {s: i for i, s in enumerate(_SEV_ORDER)}


def _bump(sev: str) -> str:
    return _SEV_ORDER[min(_SEV_RANK[sev] + 1, len(_SEV_ORDER) - 1)]


def _truthy(props: dict[str, Any], key: str) -> bool:
    v = props.get(key)
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("true", "yes", "1")
    return False


def _severity_by_data_sensitivity(props: dict[str, Any], base: str) -> str:
    """数据敏感度升级：含凭证/支付/PII 自动升档。"""
    sev = base
    if _truthy(props, "storesCredentials"):
        sev = _bump(sev)
    if _truthy(props, "handlesCardPayment"):
        sev = _bump(sev)
    if _truthy(props, "isALog"):
        sev = _bump(sev)
    return sev


def _severity_by_exposure(props: dict[str, Any], sev: str, threat_type: str) -> str:
    """暴露面升级：公网可达 + 破坏性威胁类型自动升档。"""
    t = threat_type.strip().lower()
    if _truthy(props, "isPublicNetwork") and t in ("tampering", "elevation of privilege", "spoofing"):
        sev = _bump(sev)
    return sev


def _norm(t: str) -> str:
    """归一化类型名：小写、去空格与特殊字符，用于跨方法论稳定匹配。"""
    return "".join(ch for ch in (t or "").strip().lower() if ch.isalnum())


# 各方法论类型的归一化键集合
# STRIDE（保留显式 STRIDE 分支以维持既有稳定行为）
_NC = _norm  # 便捷别名

# 有实质风险的非 STRIDE 维度：隐私(CIA/LINDDUN)、合规(PLOT4ai)、Cornucopia(EOP)
_PRIVACY_DIMS = {
    _NC("Confidentiality"), _NC("Integrity"), _NC("Availability"),
    _NC("Linkability"), _NC("Identifiability"), _NC("Non-Repudiation"),
    _NC("Detectability"), _NC("Disclosure of Information"), _NC("Unawareness"),
    _NC("Non-Compliance"),
}
_ARCH_DIMS = {_NC("Distributed"), _NC("Immutable"), _NC("Ephemeral")}
_AI_DIMS = {
    _NC("Technique & Processes"), _NC("Accessibility"),
    _NC("Identifiability & Linkability"), _NC("Security"), _NC("Safety"),
    _NC("Ethics & Human Rights"),
}
_EOP_DIMS = {
    _NC("Authentication"), _NC("Authorization"), _NC("Cryptography"),
    _NC("Data Validation & Encoding"), _NC("Session Management"),
}


def score_severity(
    elem_type: str,
    threat_type: str,
    properties: dict[str, Any] | None = None,
    methodology: str = "STRIDE",
) -> str:
    """按（元素类型 × 威胁类型）查表得到基础严重度，再叠加属性修正。"""
    props = properties or {}
    t = threat_type.strip().lower()
    tn = _norm(threat_type)
    e = (elem_type or "").strip().lower()

    if e in ("flow", "dataflow"):
        kind = "flow"
    elif e in ("datastore", "store", "db", "database"):
        kind = "datastore"
    elif e in ("actor", "externalentity", "user", "human"):
        kind = "actor"
    elif e in ("trustboundary", "boundary"):
        kind = "trustboundary"
    else:
        kind = "process"  # process / model / prompt / tool 等 AI 元素按 process 基准

    # ---- 基础矩阵 ----
    # STRIDE 六类（现有规则，保持既有稳定行为）
    stride_high = {_norm("Spoofing"), _norm("Tampering"), _norm("Elevation of Privilege")}
    stride_med = {_norm("Information Disclosure"), _norm("Denial of Service")}
    stride_repudiation = _norm("Repudiation")

    # 非 STRIDE 有实质风险维度（跨方法论统一识别）
    privacy = _PRIVACY_DIMS          # CIA / LINDDUN
    arch = _ARCH_DIMS                # CIADIE 附加
    ai_dim = _AI_DIMS                # PLOT4ai
    eop = _EOP_DIMS                  # Cornucopia

    if kind == "datastore":
        if tn in (_norm("Tampering"), _norm("Spoofing")):
            base = "Critical"
        elif tn in (_norm("Information Disclosure"), _norm("Denial of Service"),
                    _norm("Elevation of Privilege")):
            base = "High"
        elif tn in (privacy | ai_dim | eop):
            # 数据存储上的机密性/隐私/合规/密码学维度为高
            base = "High"
        elif tn in arch:
            base = "Medium"
        else:
            base = "Medium"  # Repudiation 等默认 Medium
    elif kind == "flow":
        if tn in (_norm("Tampering"), _norm("Information Disclosure"), _norm("Denial of Service")):
            base = "High"
        elif tn in (_norm("Spoofing"), _norm("Elevation of Privilege")):
            base = "Medium"
        elif tn in (privacy | ai_dim | eop | arch):
            base = "Medium"
        else:
            base = "Low"
    elif kind == "actor":
        if tn in stride_high:
            base = "Medium"
        elif tn in (privacy | eop | ai_dim | arch):
            base = "Medium"
        else:
            base = "Low"
    elif kind == "trustboundary":
        base = "Medium"
    else:  # process / AI 元素
        if tn in stride_high:
            base = "High"
        elif tn in stride_med:
            base = "Medium"
        elif tn == stride_repudiation:
            # 普通 process 无审计诉求时抵赖为 Low；含日志(isALog)会在属性修正中升档
            base = "Low"
        elif tn in (privacy | ai_dim | eop | arch):
            base = "Medium"
        else:
            base = "Low"

    # ---- 属性修正 ----
    sev = _severity_by_data_sensitivity(props, base)
    sev = _severity_by_exposure(props, sev, threat_type)
    return sev
