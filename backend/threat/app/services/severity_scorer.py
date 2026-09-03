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


def _severity_by_data_sensitivity(props: dict[str, Any], base: str, threat_type: str) -> str:
    """数据敏感度升级：仅在『敏感属性 + 高破坏性威胁』叠加时才升档。

    设计原则：默认不升档；只有 storesCredentials/handlesCardPayment/isALog
    同时配对 Tampering/Spoofing/EoP 这类高破坏性维度时升一档。
    避免一刀切地给所有 datastore 升到 Critical，导致严重度柱状图
    「严重 100% / 高危 0%」的失衡。
    """
    t = _norm(threat_type)
    high_impact = {t in {
        _norm("Tampering"), _norm("Spoofing"), _norm("Elevation of Privilege"),
        _norm("Information Disclosure"),
    }}
    sev = base
    if high_impact:
        if _truthy(props, "storesCredentials"):
            sev = _bump(sev)
        if _truthy(props, "handlesCardPayment"):
            sev = _bump(sev)
        if _truthy(props, "isALog"):
            sev = _bump(sev)
    return sev


def _severity_by_exposure(props: dict[str, Any], sev: str, threat_type: str) -> str:
    """暴露面升级：仅在公网 + 强破坏性威胁（Tampering/EoP）时升一档。

    原本对 tampering/EoP/spoofing 三类都升档过于激进，spooﬁng
    经常出现在内部认证场景，并不算最严重；改为只对真正能从公网
    触达数据/权限的 Tampering/EoP 升档。
    """
    t = _norm(threat_type)
    if _truthy(props, "isPublicNetwork") and t in {
        _norm("Tampering"), _norm("Elevation of Privilege"),
    }:
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
    """按（元素类型 × 威胁类型）查表得到基础严重度，再叠加属性修正。

    P0-2 / P1-9 修复：
    - STRIDE-AI 元素（model/prompt/vectorstore/tool/trainingdata/agentconfig）
      不再统一归为 process，而是按各自语义有独立严重度矩阵：
        * vectorstore ≈ datastore（投毒/泄露后果严重）
        * trainingdata ≈ datastore（投毒影响模型）
        * model：模型窃取/提示注入独立高
        * prompt：提示注入/系统提示泄露独立高
        * tool：越权调用/调用风暴独立高
        * agentconfig：配置篡改/过度授权独立高
    - methodology 参数实际生效（非 STRIDE 维度下隐私/合规/架构维度不偏离基准）
    """
    props = properties or {}
    t = threat_type.strip().lower()
    tn = _norm(threat_type)
    e = (elem_type or "").strip().lower()
    method = (methodology or "STRIDE").strip().upper()

    # ---- kind 分类（按 AI 元素类型细分） ----
    if e in ("flow", "dataflow"):
        kind = "flow"
    elif e in ("datastore", "store", "db", "database"):
        kind = "datastore"
    elif e in ("actor", "externalentity", "user", "human"):
        kind = "actor"
    elif e in ("trustboundary", "boundary"):
        kind = "trustboundary"
    elif e == "vectorstore":
        kind = "vectorstore"          # AI 专用：RAG 知识库
    elif e == "trainingdata":
        kind = "trainingdata"         # AI 专用：训练/微调数据
    elif e == "model":
        kind = "model"                # AI 专用：大模型/推理服务
    elif e == "prompt":
        kind = "prompt"               # AI 专用：提示词
    elif e == "tool":
        kind = "tool"                 # AI 专用：工具/Agent 能力
    elif e == "agentconfig":
        kind = "agentconfig"          # AI 专用：Agent 配置
    else:
        kind = "process"

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

    # ---- 矩阵分支（按 kind） ----
    # P3 修复：基础矩阵降一档。Critical 仅留给「显式高破坏+敏感属性」组合；
    # 默认 datastore 维度落到 Medium/High，再由 _severity_by_data_sensitivity
    # 在同时有 storesCredentials/handlesCardPayment/isALog 时升档。
    if kind == "datastore":
        if tn in (_norm("Tampering"), _norm("Spoofing")):
            base = "High"  # 原 Critical → 需叠加 storesCredentials 才升 Critical
        elif tn in (_norm("Information Disclosure"), _norm("Denial of Service"),
                    _norm("Elevation of Privilege")):
            base = "Medium"  # 原 High → 需属性修正才升 High
        elif tn in (privacy | ai_dim | eop):
            # 数据存储上的机密性/隐私/合规/密码学维度默认中危
            base = "Medium"
        elif tn in arch:
            base = "Low"
        else:
            base = "Low"  # Repudiation 等默认低
    elif kind == "vectorstore":
        # RAG 知识库：投毒/泄露比 datastore 略高，但也不再无差别 Critical
        if tn in (_norm("Tampering"),):                 # RAG 投毒
            base = "High"
        elif tn in (_norm("Information Disclosure"),):  # 向量库泄露
            base = "Medium"
        elif tn in (_norm("Denial of Service"),):       # 击穿
            base = "Medium"
        elif tn in (privacy | ai_dim | eop):
            base = "Medium"
        else:
            base = "Low"
    elif kind == "trainingdata":
        # 训练/微调数据
        if tn in (_norm("Tampering"),):                 # 数据投毒
            base = "High"
        elif tn in (_norm("Information Disclosure"),):  # 成员推断泄露
            base = "Medium"
        elif tn in (privacy | ai_dim | eop):
            base = "Medium"
        else:
            base = "Low"
    elif kind == "model":
        # 大模型：默认中危，破坏性维度升一档
        if tn in (_norm("Tampering"), _norm("Information Disclosure"),
                  _norm("Spoofing"), _norm("Elevation of Privilege")):
            base = "Medium"
        elif tn in (_norm("Denial of Service"), _norm("Repudiation")):
            base = "Medium"
        elif tn in (privacy | ai_dim | eop):
            base = "Low"
        else:
            base = "Low"
    elif kind == "prompt":
        # 提示词：注入/泄露为中危（不再默认 Critical）
        if tn in (_norm("Tampering"),):                 # 提示注入
            base = "High"
        elif tn in (_norm("Information Disclosure"),):  # 系统提示/上下文泄露
            base = "Medium"
        elif tn in (privacy | ai_dim | eop):
            base = "Medium"
        else:
            base = "Low"
    elif kind == "tool":
        # 工具/Agent 能力
        if tn in (_norm("Elevation of Privilege"),):    # 越权工具调用
            base = "High"
        elif tn in (_norm("Denial of Service"),):       # 工具调用风暴
            base = "Medium"
        elif tn in (_norm("Information Disclosure"),):  # 工具滥用泄露
            base = "Medium"
        elif tn in (privacy | ai_dim | eop):
            base = "Low"
        else:
            base = "Low"
    elif kind == "agentconfig":
        # Agent 配置
        if tn in (_norm("Tampering"),):                 # 配置篡改
            base = "High"
        elif tn in (_norm("Elevation of Privilege"),):  # 过度授权
            base = "Medium"
        elif tn in (privacy | ai_dim | eop):
            base = "Low"
        else:
            base = "Low"
    elif kind == "flow":
        if tn in (_norm("Tampering"), _norm("Information Disclosure"), _norm("Denial of Service")):
            base = "Medium"  # 原 High → Medium
        elif tn in (_norm("Spoofing"), _norm("Elevation of Privilege")):
            base = "Low"  # 原 Medium → Low
        elif tn in (privacy | ai_dim | eop | arch):
            base = "Low"
        else:
            base = "Low"
    elif kind == "actor":
        if tn in stride_high:
            base = "Low"
        elif tn in (privacy | eop | ai_dim | arch):
            base = "Low"
        else:
            base = "Low"
    elif kind == "trustboundary":
        base = "Low"
    else:  # process
        if tn in stride_high:
            base = "Medium"  # 原 High → Medium
        elif tn in stride_med:
            base = "Low"  # 原 Medium → Low
        elif tn == stride_repudiation:
            base = "Low"
        elif tn in (privacy | ai_dim | eop | arch):
            base = "Low"
        else:
            base = "Low"

    # ---- 属性修正 ----
    sev = _severity_by_data_sensitivity(props, base, threat_type)
    sev = _severity_by_exposure(props, sev, threat_type)

    # ---- 方法论相关：非 STRIDE 方法论下，对纯 STRIDE 维度（不在该方法论允许范围内）
    #     的严重度做轻量化处理（不会比同方法论实际维度更高），避免越界夸大风**
    sev = _adjust_for_methodology(sev, tn, kind, method)
    return sev


# 各方法论下，该方法论实际关注的维度集合（用于避免越界夸大）
def _methodology_dims(method: str) -> set[str]:
    """返回某方法论实际关注的维度集合（归一化形式）。"""
    if method == "STRIDE" or method == "STRIDE-AI":
        return {
            _norm("Spoofing"), _norm("Tampering"), _norm("Repudiation"),
            _norm("Information Disclosure"), _norm("Denial of Service"),
            _norm("Elevation of Privilege"),
        }
    if method == "CIA":
        return {
            _norm("Confidentiality"), _norm("Integrity"), _norm("Availability"),
        }
    if method == "CIADIE":
        return {
            _norm("Confidentiality"), _norm("Integrity"), _norm("Availability"),
            _norm("Distributed"), _norm("Immutable"), _norm("Ephemeral"),
        }
    if method == "LINDDUN":
        return {
            _norm("Linkability"), _norm("Identifiability"), _norm("Non-Repudiation"),
            _norm("Detectability"), _norm("Disclosure of Information"),
            _norm("Unawareness"), _norm("Non-Compliance"),
        }
    if method == "PLOT4AI":
        return {
            _norm("Technique & Processes"), _norm("Accessibility"),
            _norm("Identifiability & Linkability"), _norm("Security"),
            _norm("Safety"), _norm("Unawareness"),
            _norm("Ethics & Human Rights"), _norm("Non-Compliance"),
        }
    if method == "EOP":
        return {
            _norm("Authentication"), _norm("Authorization"), _norm("Cryptography"),
            _norm("Data Validation & Encoding"), _norm("Session Management"),
        }
    # 兜底：所有维度都允许
    return {
        _norm("Spoofing"), _norm("Tampering"), _norm("Repudiation"),
        _norm("Information Disclosure"), _norm("Denial of Service"),
        _norm("Elevation of Privilege"),
        _norm("Confidentiality"), _norm("Integrity"), _norm("Availability"),
        _norm("Linkability"), _norm("Identifiability"), _norm("Non-Repudiation"),
        _norm("Detectability"), _norm("Disclosure of Information"),
        _norm("Unawareness"), _norm("Non-Compliance"),
        _norm("Distributed"), _norm("Immutable"), _norm("Ephemeral"),
        _norm("Technique & Processes"), _norm("Accessibility"),
        _norm("Identifiability & Linkability"), _norm("Security"),
        _norm("Safety"), _norm("Ethics & Human Rights"),
        _norm("Authentication"), _norm("Authorization"), _norm("Cryptography"),
        _norm("Data Validation & Encoding"), _norm("Session Management"),
    }


def _adjust_for_methodology(sev: str, tn: str, kind: str, method: str) -> str:
    """方法论相关性微调。

    设计：默认矩阵已对各维度有合理基础值；这里仅在"非 STRIDE 方法论下
    出现了纯 STRIDE 维度威胁"时做一次轻量化（避免给 LINDDUN 用户看到
    Spoofing=Critical 这种越界结果）。STRIDE 维度在 CIA/LINDDUN/PLOT4ai
    等方法论下其实是次要的"附带"维度，不会比方法论主维度更显眼。
    """
    if method in ("STRIDE", "STRIDE-AI"):
        return sev
    # 纯 STRIDE 维度：在这类方法论下属"附带维度"，下调一档（不会下调到 Low 以下）
    pure_stride = {
        _norm("Spoofing"), _norm("Tampering"), _norm("Repudiation"),
        _norm("Denial of Service"), _norm("Elevation of Privilege"),
    }
    if tn in pure_stride:
        return _downgrade_one(sev)
    return sev


def _downgrade_one(sev: str) -> str:
    """严重度下调一档（不会低于 Low）。"""
    rank = _SEV_RANK.get(sev, 2)
    return _SEV_ORDER[max(0, rank - 1)]
