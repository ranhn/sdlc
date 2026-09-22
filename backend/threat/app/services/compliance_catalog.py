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

## 地区目录与开关

目录以**公司主要市场（美国 + 欧洲）**为准，每个域带 ``region`` 字段（US / EU / CN）。
启用哪些地区由环境变量 ``COMPLIANCE_REGIONS`` 决定（逗号分隔、大小写不敏感）：

    COMPLIANCE_REGIONS=US,EU      # 默认（不设也是这个）
    COMPLIANCE_REGIONS=US,EU,CN   # 需要境内条目时再打开

为什么默认不含 CN：合规影响面是给业务方/客户看的，列一批不适用地区的法规只会稀释
报告可信度；境内条目保留在目录里，需要时一个环境变量即可打开。
设成无法识别的地区 → 目录为空 → 报告与页面自动省略该节
（Word 侧有 ``if compliance:`` 守卫），并打一条 WARNING 说明可用值。

## 数据与判定分离

- 目录数据：``COMPLIANCE_DOMAINS``（纯数据，含 ``region`` / ``basis`` / ``version``）
- 地区开关：``enabled_regions()``（读 ``COMPLIANCE_REGIONS``）
- 类型归一：``normalize_threat_type``（把各方法论词汇归一到 STRIDE 六维）
- 判定逻辑：``build_compliance_impact``（纯函数，便于单测）

如需替换为外部配置（YAML / DB），只需让 ``get_compliance_domains()`` 改为
读取外部源即可，其余调用方无需改动。

## 「适用性」三态（为什么要有它）

只看"威胁类型是否命中"会把两件事混为一谈：
**该法规对你这个系统是否适用**（适用前提，如"是不是 AI 系统"），
与**本次建模的威胁是否触达它的关注点**（影响面）。前者不成立时给个 ● 就是错的，
最典型的例子是把一个没有 AI 的系统标成"触及 EU AI Act"。

因此每个域输出三态，报告/页面据此渲染：

    ● 适用 且 有威胁触达        ○ 适用 但本次未触达        — 不适用

适用性判据（**只做能可靠判断的，其余保守判为适用** —— 宁可多列，不能漏）：

- ``requires="ai_elements"``：AI 专项域（``EU-AIA`` / ``US-AIRMF``）。
  建模输入里出现 AI 元素（``model`` / ``prompt`` / ``vectorstore`` / ``tool`` /
  ``trainingdata`` / ``agentconfig``，或组件带 ``isLLMService``/``hasRAG``/
  ``hasTools``/``isVectorStore``/``storesTrainingData`` 等属性）才算适用。
- ``applicable_reason``：固定判为适用并给出理由（如 ``US-HIPAA``：已确认公司在范围内）。
- 其余（GDPR / CCPA / FTC / SOC 2 / NIST CSF / CRA / RED）：保守判为适用。

⚠️ 调用方**不传** components/flows 时（例如只做纯函数单测），AI 专项域按"无法判断
→ 保守适用"处理，避免静默丢域。
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

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
#   code         简短编号，用于 chip 展示与稳定引用
#   region       归属地区（US / EU / CN），由 COMPLIANCE_REGIONS 开关筛选
#   label        人类可读名称
#   stride_types 该合规域关注的 STRIDE 维度（归一后语义），判定时求交集
#   basis        法规/标准依据（条款或文件名），回答"依据什么"
#   version      依据版本或生效信息，避免"依据哪一版"无据可查
#   note         一句话说明该域关注什么
#
# 目录以公司主要市场（美国 + 欧洲）为准，按"最可能被客户/审计问到"排序。
# 生效时间线以 2026-09 为准，改动前请先核对官方文本（版本字段就是给这件事用的）。
COMPLIANCE_DOMAINS: List[Dict[str, Any]] = [
    # ======================== 美国 ========================
    {
        "code": "US-FTC",
        "region": "US",
        "label": "FTC Act §5 数据安全执法（美国）",
        "stride_types": ["Information Disclosure", "Elevation of Privilege"],
        "basis": "15 U.S.C. §45（FTC Act Section 5，不公平/欺骗性行为）",
        "version": "现行（对联网设备的持续执法）",
        "note": "关注安全能力与对外宣称不符、以及不合理的数据安全实践导致的越权访问与泄露。",
    },
    {
        "code": "US-PRIV",
        "region": "US",
        "label": "美国消费者隐私（CCPA / CPRA 等州法）",
        "stride_types": ["Information Disclosure"],
        "basis": "California CCPA（经 CPRA 修订），Cal. Civ. Code §1798.100 等",
        "version": "CCPA 2020-01-01 生效；CPRA 修订 2023-01-01 生效",
        "note": "关注个人信息收集/共享限制，以及数据泄露的法定责任（含私人诉权）。",
    },
    {
        "code": "US-AIRMF",
        "region": "US",
        "label": "NIST AI RMF 风险管理（美国）",
        "stride_types": [
            "Information Disclosure",
            "Elevation of Privilege",
            "Denial of Service",
        ],
        # 条件适用：只有本次建模真的涉及 AI 元素时才成立（见模块 docstring「适用性」）
        "requires": "ai_elements",
        "basis": "NIST AI Risk Management Framework (AI 100-1)",
        "version": "1.0（2023-01）",
        "note": "覆盖 AI 系统的治理、映射、度量、管理全过程；属自愿性框架（非强制性法规）。",
    },
    {
        "code": "US-NIST-CSF",
        "region": "US",
        "label": "NIST CSF 网络安全框架 2.0",
        "stride_types": ["Tampering", "Information Disclosure", "Elevation of Privilege"],
        "basis": "NIST Cybersecurity Framework (CSF) 2.0, NIST CSWP 29",
        "version": "2.0（2024-02 发布，新增 Govern 功能）",
        "note": "自愿性框架，六功能 Govern/Identify/Protect/Detect/Respond/Recover；"
                "这里取其「保护」类核心目标（数据安全 PR.DS / 身份与访问控制 PR.AA）。",
    },
    {
        "code": "US-SOC2",
        "region": "US",
        "label": "SOC 2 信任服务准则（AICPA）",
        "stride_types": [
            "Spoofing",
            "Information Disclosure",
            "Elevation of Privilege",
            "Denial of Service",
        ],
        "basis": "AICPA Trust Services Criteria（TSC 2017，含 2022 修订要点）",
        "version": "TSC 2017（2022 修订）",
        "note": "审计/认证标准而非法规：Security（CC 系列）为必选，其余四类按范围可选。"
                "这里取 Security + Confidentiality + Availability；"
                "客户尽调与招标常把它作为准入要求。",
    },
    {
        "code": "US-HIPAA",
        "region": "US",
        "label": "HIPAA 健康信息保护（美国）",
        "stride_types": [
            "Information Disclosure",
            "Tampering",
            "Denial of Service",
            "Elevation of Privilege",
        ],
        "basis": "HIPAA 安全规则 45 CFR Part 164 Subpart C（§164.306 / 308–312）"
                 " + HITECH 泄露通知规则 45 CFR §164.400–414",
        "version": "安全规则 2003 起；HITECH 泄露通知 2009 起",
        # 固定适用：已与业务确认公司在范围内（涉及 PHI / BAA 场景），
        # 因此不做自动判定，避免"把在范围内的法规判成不适用"这种更糟的错。
        "applicable_reason": "适用（已确认公司在 HIPAA 适用范围内：涉及 PHI / BAA 场景）",
        "note": "依据 §164.306(d)(1) 的保密性/完整性/可用性三性 + 访问控制；"
                "**适用范围**（已确认为在范围内）：涉及受保护健康信息（PHI）、"
                "属受保护实体或业务伙伴（通常签 BAA）的场景。",
    },
    # ======================== 欧洲 ========================
    {
        "code": "EU-GDPR",
        "region": "EU",
        "label": "GDPR 个人数据保护（欧盟）",
        "stride_types": ["Information Disclosure", "Tampering", "Denial of Service"],
        "basis": "Regulation (EU) 2016/679 (GDPR) Art.5 / 25 / 32–34",
        "version": "2018-05-25 起适用",
        "note": "Art.32 明确要求个人数据的保密性、完整性、可用性；泄露需按 Art.33/34 通知。",
    },
    {
        "code": "EU-CRA",
        "region": "EU",
        "label": "网络弹性法案 CRA（含数字元素产品）",
        "stride_types": [
            "Spoofing",
            "Tampering",
            "Information Disclosure",
            "Elevation of Privilege",
        ],
        "basis": "Regulation (EU) 2024/2847 (CRA) Annex I",
        "version": "2024-12-10 生效；漏洞/事件上报义务 2026-09-11 起；全面适用 2027-12-11",
        "note": "关注安全默认配置、访问控制、加密、漏洞与更新机制（智能家电/IoT 直接适用）。",
    },
    {
        "code": "EU-RED",
        "region": "EU",
        "label": "无线设备网络安全（RED 3(3)(d)(e)(f)）",
        "stride_types": ["Spoofing", "Tampering", "Information Disclosure"],
        "basis": "Directive 2014/53/EU Art.3(3)(d)(e)(f) + 委托条例 (EU) 2022/30",
        "version": "网络安全条款 2025-08-01 起强制适用",
        "note": "关注设备不得危害网络、个人数据与隐私保护、防欺诈（Wi-Fi/BLE 联网产品适用）。",
    },
    {
        "code": "EU-AIA",
        "region": "EU",
        "label": "EU AI Act 分级治理（欧盟）",
        "stride_types": ["Information Disclosure", "Tampering", "Repudiation"],
        # 条件适用：只有本次建模真的涉及 AI 元素时才成立（AI Act Art.2 的适用对象是 AI 系统）
        "requires": "ai_elements",
        "basis": "Regulation (EU) 2024/1689 (AI Act)",
        "version": "2024-08-01 生效；透明度/通用模型义务 2026-08-02 起；"
                   "高风险义务经综合法 (EU) 2026/1744 推至 2027-12",
        "note": "关注高风险 AI 系统的可审计、可追溯、鲁棒性与透明度（Art.15 / 50）。",
    },
    # ============ 境内（默认关闭，COMPLIANCE_REGIONS 打开） ============
    {
        "code": "CN-AI",
        "region": "CN",
        "label": "算法备案与深度合成标识（境内）",
        "stride_types": ["Spoofing", "Information Disclosure", "Tampering"],
        "basis": "《互联网信息服务算法推荐管理规定》《互联网信息服务深度合成管理规定》",
        "version": "2022 版（现行）",
        "note": "关注 AI 生成内容标识、深度合成检测，规避仿冒与误导。",
    },
    {
        "code": "CN-DATA",
        "region": "CN",
        "label": "数据安全与个人信息保护合规（境内）",
        "stride_types": ["Information Disclosure"],
        "basis": "《数据安全法》《个人信息保护法》(PIPL)",
        "version": "2021 版（现行）",
        "note": "关注越权检索、训练数据与个人信息泄露。",
    },
]

# 默认启用的地区：公司主要市场。设 COMPLIANCE_REGIONS 可覆盖（见模块 docstring）。
_DEFAULT_REGIONS = "US,EU"


def enabled_regions() -> set[str]:
    """当前启用的合规域地区集合（来自 ``COMPLIANCE_REGIONS``，默认 ``US,EU``）。"""
    raw = (os.getenv("COMPLIANCE_REGIONS") or "").strip() or _DEFAULT_REGIONS
    return {p.strip().upper() for p in raw.split(",") if p.strip()}


def get_compliance_domains() -> List[Dict[str, Any]]:
    """返回**当前地区启用**的合规域目录。

    - 数据仍取自模块内静态列表 ``COMPLIANCE_DOMAINS``；
    - 按 ``COMPLIANCE_REGIONS`` 过滤（默认 US,EU）；
    - 若需改为外部配置（YAML / DB / 远程字典），只需在此函数内替换数据来源，
      所有调用方无需改动。

    目录为空时打一条 WARNING：多半是环境变量写错了地名（如 ``COMPLIANCE_REGIONS=US,EUA``），
    现象是"报告里整节消失"，日志里直接给出可用值就能定位。
    """
    regions = enabled_regions()
    domains = [
        d for d in COMPLIANCE_DOMAINS
        if str(d.get("region", "")).upper() in regions
    ]
    if not domains:
        logger.warning(
            "合规域目录为空：COMPLIANCE_REGIONS=%r 未匹配到任何条目（可用地区：%s）",
            os.getenv("COMPLIANCE_REGIONS"),
            "/".join(sorted({str(d.get("region", "")) for d in COMPLIANCE_DOMAINS})),
        )
    return domains


# ---------------------------------------------------------------------------
# 适用性判定（AI 元素）
# ---------------------------------------------------------------------------
# 组件属性名：AI 能力经常挂在普通 process 上（提示词里就是这么要求的：
# "为 process 补充 AI 相关属性 isLLMService / hasRAG / hasTools / privilegeLevel"），
# 只按 type 判断会漏掉相当一部分 AI 系统，所以属性一起看。
_AI_PROPS = (
    "isLLMService", "hasRAG", "hasTools",
    "isVectorStore", "storesTrainingData",
)


def _ai_element_types() -> set:
    """AI 专用元素类型集合。

    口径以 ``document_analyzer.AI_ELEMENT_TYPES`` 为**唯一来源**（那里是提示词与
    骨架归一共用的定义），此处惰性导入：本模块要能被导出/单测轻量引用，
    不该在 import 期把整个分析器（含 LLM 客户端）拉起来。
    """
    try:
        from .document_analyzer import AI_ELEMENT_TYPES

        return set(AI_ELEMENT_TYPES)
    except Exception:  # pragma: no cover - 导入异常时兜底，避免漏判 AI 系统
        return {"model", "prompt", "vectorstore", "tool", "trainingdata", "agentconfig"}


def _is_truthy(val: Any) -> bool:
    return val is True or str(val).strip().lower() in ("true", "1", "yes")


def ai_element_names(components: Optional[List[Dict[str, Any]]] = None) -> List[str]:
    """列出本次建模里出现的 AI 元素（用于"适用/不适用"的理由文案）。

    判据（任一命中即视为涉及 AI）：
      1. 组件 ``type`` 属于 AI 专用类型（model / prompt / vectorstore / tool /
         trainingdata / agentconfig）；
      2. 组件带 AI 能力属性（isLLMService / hasRAG / hasTools / isVectorStore /
         storesTrainingData）—— 提示词里要求把这些属性补在普通 process 上，
         所以只按 type 判断会漏掉一部分真实 AI 系统。

    返回人类可读的名字列表（如 ``["LLM 服务（type=model）", "召回服务（hasRAG=true）"]``），
    空列表 = 判为"未涉及 AI"。只判断组件：AI 元素必然是组件（流只是连接）。
    """
    types = _ai_element_types()
    found: List[str] = []
    seen: set[str] = set()
    for c in components or []:
        if not isinstance(c, dict):
            continue
        props = c.get("properties") if isinstance(c.get("properties"), dict) else {}
        ctype = str(c.get("type") or "").strip().lower()
        reason = ""
        if ctype in types:
            reason = f"type={ctype}"
        else:
            for k in _AI_PROPS:
                if _is_truthy(props.get(k)):
                    reason = f"{k}=true"
                    break
        if not reason:
            continue
        label = f"{str(c.get('name') or c.get('id') or '未命名组件').strip()}（{reason}）"
        if label not in seen:
            seen.add(label)
            found.append(label)
    return found


# ---------------------------------------------------------------------------
# 适用性判定（按域）
# ---------------------------------------------------------------------------
def _applicability(
    domain: Dict[str, Any],
    has_ai: bool,
    ai_names: List[str],
) -> tuple:
    """判断某合规域对本次建模是否适用，返回 ``(applicable, 理由文案)``。

    - ``requires="ai_elements"``：AI 专项域。涉及 AI 才适用；不涉及时给"不适用 + 原因"，
      而不是把命中数清零后仍标 ●（那正是要修的问题：无 AI 的系统被标成触及 AI Act）。
    - ``applicable_reason``：目录里写死"已确认在范围内"的域（如 HIPAA）。
    - 其余：**保守判为适用** —— 从建模输入无法排除该法规，宁可多列不能漏。
    """
    if domain.get("requires") == "ai_elements":
        if not has_ai:
            return False, (
                "不适用（本次建模未涉及 AI 元素：无 model / prompt / 向量库 / tool / "
                "agent 配置 / 训练数据）"
            )
        if ai_names:
            detail = "、".join(ai_names[:3]) + ("…" if len(ai_names) > 3 else "")
            return True, f"适用（本次建模涉及 AI 元素：{detail}）"
        return True, "适用（未提供元素信息，保守判为适用）"
    return True, domain.get("applicable_reason") or "适用（保守判定：未发现排除依据）"


# ---------------------------------------------------------------------------
# 影响面判定
# ---------------------------------------------------------------------------
def build_compliance_impact(
    threats: List[Dict[str, Any]],
    components: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """把本次建模的威胁映射到合规影响面（含「适用性」三态）。

    Args:
        threats: 威胁条目列表，每条至少含 ``type`` 字段。
        components: 本次建模的组件列表（用于判断是否涉及 AI 元素）。
            **不传 = 无法判断 → AI 专项域保守判为适用**（宁可多列，不能漏）。

    Returns:
        每个合规域一条记录：

        - ``code`` / ``label`` / ``region`` / ``basis`` / ``version`` / ``note``：目录字段
        - ``applicable``：该法规对本系统**是否适用**（适用前提，如"是不是 AI 系统"）
        - ``applicabilityReason``：适用/不适用的理由（报告与页面直接展示）
        - ``hit``：**适用 且** 本次建模有威胁触达该域（不等于合规达标）
        - ``relatedThreatCount``：触达该域的威胁条数（不适用时为 0）
        - ``relatedTypes``：触达该域的方法论原生类型（去重，便于下钻）
        - ``normalizedTypes``：命中的 STRIDE 维度（去重）

    判定规则：先判适用性；适用时把每条威胁的类型归一为 STRIDE 维度，与该域的
    ``stride_types`` 求交集，非空即视为触达。
    """
    # 适用性判定的前提：本次建模是否涉及 AI 元素。
    # components 缺省（None）表示调用方没给元素信息 → 无法判断 → 保守判为涉及，
    # 避免"静默把 AI 法规域整个标成不适用"这种更糟的错误。
    if components is None:
        has_ai, ai_names = True, []
    else:
        ai_names = ai_element_names(components)
        has_ai = bool(ai_names)

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
        # 先判适用性：不适用时**不计入威胁数**（否则报告会出现"— 不适用 关联威胁 3"这种自相矛盾的格子）
        applicable, applicable_reason = _applicability(domain, has_ai, ai_names)
        wanted = list(domain.get("stride_types") or [])
        related_types: set[str] = set()
        normalized: List[str] = []
        count = 0
        if applicable:
            for stride in wanted:
                bucket = stride_hits.get(stride)
                if not bucket:
                    continue
                count += bucket["count"]
                related_types |= bucket["rawTypes"]
                normalized.append(stride)
        impact.append({
            "code": domain.get("code", ""),
            # 地区一并带出：报告/页面按需分组或标注，前端对未知字段是忽略的，加它不影响兼容
            "region": domain.get("region", ""),
            "label": domain.get("label", ""),
            "basis": domain.get("basis", ""),
            "version": domain.get("version", ""),
            "note": domain.get("note", ""),
            # 适用性三态：applicable=False → 报告/页面渲染为"— 不适用"（灰色，不参与命中统计）
            "applicable": applicable,
            "applicabilityReason": applicable_reason,
            "hit": applicable and count > 0,
            "relatedThreatCount": count,
            "relatedTypes": sorted(related_types),
            "normalizedTypes": normalized,
        })
    return impact


def summarize_compliance_impact(
    impact: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """把影响面列表聚合成一句可读结论，供列表/导出复用。

    分母是**适用的域数**（不适用的一律排除）—— 否则"7/10"里混着 3 个不适用的，
    读者会以为"还有 3 个没覆盖到"。

    Returns:
        ``{"hitDomains": n, "totalDomains": m, "notApplicable": k,
           "text": "触达 3/7 适用合规域（3 项不适用）"}``
        无目录数据时 ``text`` 为 ``""``。
    """
    if not impact:
        return {"hitDomains": 0, "totalDomains": 0, "notApplicable": 0, "text": ""}
    applicable = [d for d in impact if d.get("applicable", True)]
    hit = [d for d in applicable if d.get("hit")]
    na = len(impact) - len(applicable)
    text = f"触达 {len(hit)}/{len(applicable)} 适用合规域"
    if na:
        text += f"（{na} 项不适用）"
    return {
        "hitDomains": len(hit),
        "totalDomains": len(applicable),
        "notApplicable": na,
        "text": text,
    }
