"""合规影响面映射目录（可配置数据层）。

## 这个模块解决什么问题

早期实现把「合规映射」硬编码在 ``ai_knowledge.COMPLIANCE_MAPPING`` 里，且
``threat_types`` 只写了 STRIDE 六词汇。平台支持 8 种方法论，各自有独立词表：

    STRIDE / STRIDE-AI  → Spoofing / Tampering / ...
    CIA / CIADIE        → Confidentiality / Integrity / Availability
    LINDDUN             → Linkability / Identifiability / ...
    PLOT4ai             → Technique & Processes / Ethics & Human Rights / ...
    EOP (Cornucopia)    → Authentication / Authorization / Cryptography / ...
    MAESTRO             → GoalHijacking / ToolMisuse / MemoryPoisoning / ...

于是除 STRIDE 系之外的方法论，威胁类型集合与合规清单**交集恒为空**，
合规判定一律 ``0/4`` —— 属于纯 bug，不是数据问题。

## 语义修正（重要）

旧字段 ``covered`` 的含义是「本次建模的威胁类型里出现过该合规项关联的类型」，
这与「是否合规」没有任何因果关系：一次建模识别出越多种类威胁，反而被判成
「合规覆盖越多」，逻辑是反的；而 ``Information Disclosure`` 同时挂在 4 个
合规项下，导致任意 STRIDE 建模只要有一条信息泄露威胁就 4 项全绿。

因此本模块输出的是 **「合规影响面」**（哪些法规域被本次建模的威胁触达、
各域命中多少条），字段命名同步改为 ``hit`` / ``relatedThreatCount``，
UI 文案必须明确"不代表合规结论"。

## 数据与判定分离

- 目录数据：``COMPLIANCE_DOMAINS``（纯数据，含 ``basis`` / ``version`` 依据字段）
- 类型归一：``normalize_threat_type``（把各方法论词汇归一到 STRIDE 六维）
- 判定逻辑：``build_compliance_impact``（纯函数，便于单测）

如需替换为外部配置（YAML / DB），只需让 ``get_compliance_domains()`` 改为
读取外部源即可，其余调用方无需改动。
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# 类型归一：各方法论威胁类型 -> STRIDE 六维
# ---------------------------------------------------------------------------
# 键为「小写、去空格/连字符/下划线」后的类型名，与 vuln_bridge._TYPE_MAP 的
# 归一策略保持一致，便于两处互相印证。
#
# 归一目标只有 6 个 STRIDE 维度：
#   Spoofing / Tampering / Repudiation / Information Disclosure /
#   Denial of Service / Elevation of Privilege
TYPE_TO_STRIDE: Dict[str, str] = {
    # ---- STRIDE 自身（恒等映射） ----
    "spoofing": "Spoofing",
    "tampering": "Tampering",
    "repudiation": "Repudiation",
    "informationdisclosure": "Information Disclosure",
    "denialofservice": "Denial of Service",
    "elevationofprivilege": "Elevation of Privilege",

    # ---- CIA / CIADIE ----
    # 机密性 → 信息泄露；完整性 → 篡改；可用性 → 拒绝服务
    "confidentiality": "Information Disclosure",
    "integrity": "Tampering",
    "availability": "Denial of Service",
    "distributed": "Denial of Service",
    "immutable": "Tampering",
    "ephemeral": "Denial of Service",

    # ---- LINDDUN（隐私）----
    "linkability": "Information Disclosure",
    "identifiability": "Information Disclosure",
    "nonrepudiation": "Repudiation",
    "detectability": "Information Disclosure",
    "disclosureofinformation": "Information Disclosure",
    "unawareness": "Information Disclosure",
    "noncompliance": "Repudiation",

    # ---- EOP (Cornucopia) ----
    "authentication": "Spoofing",
    "authorization": "Elevation of Privilege",
    "cryptography": "Information Disclosure",
    "datavalidationencoding": "Tampering",
    "sessionmanagement": "Spoofing",

    # ---- PLOT4ai ----
    "techniqueprocesses": "Tampering",
    "accessibility": "Denial of Service",
    "identifiabilitylinkability": "Information Disclosure",
    "security": "Elevation of Privilege",
    "safety": "Tampering",
    "ethicshumanrights": "Elevation of Privilege",
    # PLOT4ai 的 Unawareness / Non-Compliance 与 LINDDUN 同名，已在上方覆盖

    # ---- MAESTRO（多智能体）----
    # MAESTRO_TYPES 的值形如 "Goal Hijacking 目标劫持"（英文名 + 中文后缀），
    # _norm_key 会先剥离中文字符，因此这里只写英文名。
    "goalhijacking": "Tampering",
    "toolmisuse": "Elevation of Privilege",
    "privilegeamplification": "Elevation of Privilege",
    "memorypoisoning": "Tampering",
    "interagentdeception": "Spoofing",
    "runawayautonomy": "Elevation of Privilege",
    "autonomyrunaway": "Elevation of Privilege",
    "insecureorchestration": "Tampering",
    "observabilitygap": "Repudiation",
    "supplychaincompromise": "Tampering",
    "dataleakage": "Information Disclosure",
}


def _norm_key(raw: str) -> str:
    """归一化类型名为查表键。

    处理三类噪声，使不同来源的同一类型收敛到同一键：

    1. **大小写 / 分隔符**：'Information Disclosure' / 'information-disclosure'
       / 'InformationDisclosure' 统一得到 'informationdisclosure'。
    2. **中文后缀**：MAESTRO_TYPES、EOP_SUITS 等的值形如
       'Goal Hijacking 目标劫持'，需剥离中文部分只留英文名。
    3. **' & ' 连接词**：PLOT4ai 的 'Technique & Processes' 归一为
       'techniqueprocesses'，'Identifiability & Linkability' 归一为
       'identifiabilitylinkability'。
    """
    text = str(raw or "").strip()
    # 2. 剥离中文字符（含中文标点），MAESTRO / EOP 的展示名带中文后缀
    text = re.sub(r"[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]+", "", text)
    # 3. 去掉 '&'（PLOT4ai 的复合类型名），再统一去分隔符
    text = text.replace("&", "")
    return (
        text.lower()
        .replace(" ", "")
        .replace("-", "")
        .replace("_", "")
        .replace("&", "")
    )


def normalize_threat_type(raw: str) -> str | None:
    """把任意方法论的威胁类型归一到 STRIDE 六维之一。

    未收录的类型返回 ``None``（调用方按"未归类"处理，不参与合规影响面判定，
    避免猜错语义造成误报）。
    """
    return TYPE_TO_STRIDE.get(_norm_key(raw))


# ---------------------------------------------------------------------------
# 合规域目录（纯数据）
# ---------------------------------------------------------------------------
# 字段说明：
#   code        简短编号，用于 chip 展示与稳定引用
#   label       人类可读名称
#   stride_types 该合规域关注的 STRIDE 维度（归一后语义），判定时求交集
#   basis       法规/标准依据（条款或文件名），回答"依据什么"
#   version     依据版本或生效信息，避免"依据哪一版"无据可查
#   note        一句话说明该域关注什么
COMPLIANCE_DOMAINS: List[Dict[str, Any]] = [
    {
        "code": "CN-AI",
        "label": "算法备案与深度合成标识（境内）",
        "stride_types": ["Spoofing", "Information Disclosure", "Tampering"],
        "basis": "《互联网信息服务算法推荐管理规定》《互联网信息服务深度合成管理规定》",
        "version": "2022 版（现行）",
        "note": "关注 AI 生成内容标识、深度合成检测，规避仿冒与误导。",
    },
    {
        "code": "CN-DATA",
        "label": "数据安全与个人信息保护合规（境内）",
        "stride_types": ["Information Disclosure"],
        "basis": "《数据安全法》《个人信息保护法》(PIPL)",
        "version": "2021 版（现行）",
        "note": "关注越权检索、训练数据与个人信息泄露。",
    },
    {
        "code": "EU-AIA",
        "label": "EU AI Act 分级治理",
        "stride_types": ["Information Disclosure", "Tampering", "Repudiation"],
        "basis": "Regulation (EU) 2024/1689 (AI Act)",
        "version": "2024 通过，分级义务分阶段生效",
        "note": "关注高风险 AI 系统的可审计、可追溯能力。",
    },
    {
        "code": "NIST-RMF",
        "label": "NIST AI RMF 风险管理",
        "stride_types": [
            "Information Disclosure",
            "Elevation of Privilege",
            "Denial of Service",
        ],
        "basis": "NIST AI Risk Management Framework (AI 100-1)",
        "version": "1.0 (2023-01)",
        "note": "覆盖 AI 系统的衡量、治理、映射、管理全过程。",
    },
]


def get_compliance_domains() -> List[Dict[str, Any]]:
    """返回合规域目录。

    当前为模块内静态数据；若需改为外部配置（YAML / DB / 远程字典），
    只需在此函数内替换数据来源，所有调用方无需改动。
    """
    return COMPLIANCE_DOMAINS


# ---------------------------------------------------------------------------
# 影响面判定
# ---------------------------------------------------------------------------
def build_compliance_impact(threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """把本次建模的威胁映射到合规影响面。

    Args:
        threats: 威胁条目列表，每条至少含 ``type`` 字段。

    Returns:
        每个合规域一条记录：

        - ``code`` / ``label`` / ``basis`` / ``version`` / ``note``：目录字段
        - ``hit``：本次建模是否有威胁触达该域（**不等于合规达标**）
        - ``relatedThreatCount``：触达该域的威胁条数
        - ``relatedTypes``：触达该域的方法论原生类型（去重，便于下钻）
        - ``normalizedTypes``：命中的 STRIDE 维度（去重）

    判定规则：把每条威胁的类型归一为 STRIDE 维度，与该域的 ``stride_types``
    求交集，非空即视为触达。
    """
    # 先做一次全量归一，避免每个合规域重复归一。
    # 结构：{stride 维度: {"count": n, "rawTypes": set(...)}}
    stride_hits: Dict[str, Dict[str, Any]] = {}
    for t in threats or []:
        raw = str((t or {}).get("type") or "").strip()
        stride = normalize_threat_type(raw)
        if not stride:
            continue
        bucket = stride_hits.setdefault(
            stride, {"count": 0, "rawTypes": set()}
        )
        bucket["count"] += 1
        if raw:
            bucket["rawTypes"].add(raw)

    impact: List[Dict[str, Any]] = []
    for domain in get_compliance_domains():
        wanted = list(domain.get("stride_types") or [])
        related_types: set[str] = set()
        normalized: List[str] = []
        count = 0
        for stride in wanted:
            bucket = stride_hits.get(stride)
            if not bucket:
                continue
            count += bucket["count"]
            related_types |= bucket["rawTypes"]
            normalized.append(stride)
        impact.append({
            "code": domain.get("code", ""),
            "label": domain.get("label", ""),
            "basis": domain.get("basis", ""),
            "version": domain.get("version", ""),
            "note": domain.get("note", ""),
            "hit": count > 0,
            "relatedThreatCount": count,
            "relatedTypes": sorted(related_types),
            "normalizedTypes": normalized,
        })
    return impact


def summarize_compliance_impact(
    impact: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """把影响面列表聚合成一句可读结论，供列表/导出复用。

    Returns:
        ``{"hitDomains": n, "totalDomains": m, "text": "触达 4/4 合规域"}``
        无目录数据时 ``text`` 为 ``""``。
    """
    if not impact:
        return {"hitDomains": 0, "totalDomains": 0, "text": ""}
    hit = [d for d in impact if d.get("hit")]
    return {
        "hitDomains": len(hit),
        "totalDomains": len(impact),
        "text": f"触达 {len(hit)}/{len(impact)} 合规域",
    }
