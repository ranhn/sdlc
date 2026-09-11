"""AI 威胁建模知识库：OWASP Top 10 for LLM (2025) 与 MITRE ATLAS。

用于 STRIDE-AI 方法论下：
- 提供 LLM 应用常见攻击面清单（可被威胁分析器作为判定规则参考）
- 提供合规映射（算法备案 / 数据合规 / 内容标识 / AI 治理）
- 提供各条目的 MITRE ATLAS 技术编号

该模块是纯数据层，不依赖 LLM，供 threat_analyzer / result_exporter 复用。
"""
from __future__ import annotations

from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# OWASP Top 10 for LLM Applications (2025)
# ---------------------------------------------------------------------------
OWASP_LLM_2025: List[Dict[str, str]] = [
    {
        "code": "LLM01",
        "title": "Prompt Injection 提示注入",
        "description": "通过精心构造的输入操纵 LLM 输出，实现越权、信息泄露或工具滥用。",
        "atlas": "AML.T0040.002",
        "stride": ["Tampering", "Elevation of Privilege", "Information Disclosure"],
    },
    {
        "code": "LLM02",
        "title": "Sensitive Information Disclosure 敏感信息泄露",
        "description": "LLM 在响应中泄露训练数据、系统提示、业务敏感信息。",
        "atlas": "AML.T0024",
        "stride": ["Information Disclosure"],
    },
    {
        "code": "LLM03",
        "title": "Supply Chain 供应链漏洞",
        "description": "恶意/存在漏洞的模型、插件、依赖组件进入系统。",
        "atlas": "AML.T0008",
        "stride": ["Spoofing", "Tampering"],
    },
    {
        "code": "LLM04",
        "title": "Data and Model Poisoning 数据与模型投毒",
        "description": "训练数据或微调过程被污染，导致模型行为被操纵。",
        "atlas": "AML.T0020",
        "stride": ["Tampering"],
    },
    {
        "code": "LLM05",
        "title": "Improper Output Handling 不当输出处理",
        "description": "对 LLM 输出未做校验/清洗，导致注入下游系统（XSS、SQLi、命令执行）。",
        "atlas": "AML.T0043",
        "stride": ["Tampering", "Elevation of Privilege"],
    },
    {
        "code": "LLM06",
        "title": "Excessive Agency 过度代理",
        "description": "Agent/工具被赋予过高权限，执行非预期的高危动作。",
        "atlas": "AML.T0044",
        "stride": ["Elevation of Privilege"],
    },
    {
        "code": "LLM07",
        "title": "System Prompt Leakage 系统提示泄露",
        "description": "系统提示词或内部指令被诱导泄露。",
        "atlas": "AML.T0024",
        "stride": ["Information Disclosure"],
    },
    {
        "code": "LLM08",
        "title": "Vector and Embedding Weaknesses 向量与嵌入弱点",
        "description": "RAG 向量库投毒、语义越权检索、嵌入向量泄露。",
        "atlas": "AML.T0021",
        "stride": ["Tampering", "Information Disclosure", "Denial of Service"],
    },
    {
        "code": "LLM09",
        "title": "Misinformation 错误信息",
        "description": "模型产生幻觉、错误决策，导致业务风险。",
        "atlas": "AML.T0047",
        "stride": ["Tampering", "Repudiation"],
    },
    {
        "code": "LLM10",
        "title": "Unbounded Consumption 无界消耗",
        "description": "无限 token 消耗、递归工具调用、资源耗尽导致的成本与可用性风险。",
        "atlas": "AML.T0034",
        "stride": ["Denial of Service"],
    },
]

# ---------------------------------------------------------------------------
# 行业场景模板（跨境健康产品线：面向美欧市场的健康/保健电商业务）
# ---------------------------------------------------------------------------
INDUSTRY_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "health": {
        "label": "跨境健康产品线（美欧市场）",
        "prompt_hint": (
            "本系统为面向美国/欧洲市场的跨境电商健康产品线业务，研发与数据中心在国内，"
            "重点关注以下合规与威胁维度：\n"
            "1) 跨境数据合规：用户健康相关个人信息（健康档案、身体指标、购买记录、用药/"
            "营养补充偏好）需符合 GDPR（欧盟）、CCPA/健康隐私法规（美国）与境内 PIPL 出境"
            "评估，防范跨域越权访问与个人信息出境泄露；\n"
            "2) 支付与订单安全：美欧支付渠道（信用卡/Apple Pay/Stripe/PayPal）应遵循"
            "PCI-DSS，防范支付接口伪造、订单篡改、欺诈下单与拒付风险；\n"
            "3) 产品安全与合规声明：健康功效宣传、成分/剂量/过敏原信息、批号与溯源数据"
            "不得被篡改或伪造，防范虚假宣称、假冒伪劣、召回与 FDA/CE 监管风险；\n"
            "4) 供应链与跨境物流：仓库/物流/海关数据被篡改、伪造发货、库存操纵、跨境"
            "转运信息泄露；\n"
            "5) 本地化多语言内容：多语言站点/客服机器人/智能问答提示注入与内容误导，"
            "影响美欧消费者信任。\n"
            "请在 DFD 中补充：智能客服机器人、RAG 健康知识问答、个性化推荐模型、"
            "跨境风控/反欺诈模型、合规审查 AI 等 AI 组件。"
        ),
        "ai_props": {
            "hasRAG": True,
            "isLLMService": True,
            "handlesPII": True,
            "handlesHealthData": True,
            "privilegeLevel": "high",
        },
        "priority_threats": [
            "Information Disclosure",
            "Spoofing",
            "Tampering",
            "Elevation of Privilege",
        ],
    },
}

# ---------------------------------------------------------------------------
# 合规映射（AI 治理 / 数据 / 内容标识）
# ---------------------------------------------------------------------------
COMPLIANCE_MAPPING: List[Dict[str, str]] = [
    {
        "code": "CN-AI",
        "label": "算法备案与深度合成标识（境内）",
        "threat_types": ["Spoofing", "Information Disclosure", "Tampering"],
        "note": "提供 AI 生成内容标识、深度合成检测，规避仿冒与误导。",
    },
    {
        "code": "CN-DATA",
        "label": "数据安全与个人信息保护合规（境内）",
        "threat_types": ["Information Disclosure", "Identifiability", "Linkability"],
        "note": "限制 RAG 越权检索，保护训练数据与个人信息。",
    },
    {
        "code": "EU-AIA",
        "label": "EU AI Act 分级治理",
        "threat_types": ["Information Disclosure", "Tampering", "Repudiation"],
        "note": "高风险 AI 系统需可审计、可追溯、缓解偏见。",
    },
    {
        "code": "NIST-RMF",
        "label": "NIST AI RMF 风险管理",
        "threat_types": ["Information Disclosure", "Elevation of Privilege", "Denial of Service"],
        "note": "覆盖 AI 系统的衡量、治理、映射、管理全过程。",
    },
]


def get_owasp_llm_list() -> List[Dict[str, str]]:
    """返回 OWASP Top 10 for LLM 清单。"""
    return OWASP_LLM_2025


# ---------------------------------------------------------------------------
# MITRE ATLAS 技术目录
# ---------------------------------------------------------------------------
# ATLAS（Adversarial Threat Landscape for AI Systems）是 MITRE 面向 AI/ML 系统的
# 对抗战术与技术知识库，相当于 AI 领域的 ATT&CK。
#
# 与 OWASP LLM 清单的关系：OWASP 条目回答「有哪些风险类别」，
# ATLAS 技术回答「攻击者具体怎么打」。两者互补，威胁条目标注 ATLAS 技术编号后，
# 可以对齐到业界通用的攻击语言，便于跨团队沟通与红队验证。
#
# 仅收录与平台 STRIDE-AI 威胁类型直接相关的核心技术，避免引入庞大清单造成噪音。
MITRE_ATLAS: List[Dict[str, Any]] = [
    {
        "id": "AML.T0000",
        "tactic": "reconnaissance",
        "tactic_label": "侦察",
        "name": "Search Open Technical Databases",
        "name_zh": "检索公开技术资料",
        "description": "搜集目标 AI 系统的模型、数据集、API 文档等公开信息，为后续攻击做准备。",
        "stride": ["Information Disclosure"],
        "owasp_llm": [],
    },
    {
        "id": "AML.T0008",
        "tactic": "resource-development",
        "tactic_label": "资源准备",
        "name": "Acquire Infrastructures",
        "name_zh": "获取攻击基础设施",
        "description": "获取用于投递恶意模型/插件的算力与分发渠道。",
        "stride": ["Spoofing", "Tampering"],
        "owasp_llm": ["LLM03"],
    },
    {
        "id": "AML.T0010",
        "tactic": "resource-development",
        "tactic_label": "资源准备",
        "name": "AI Supply Chain Compromise",
        "name_zh": "AI 供应链投毒",
        "description": "在预训练模型、第三方插件、依赖包中植入后门或恶意逻辑。",
        "stride": ["Tampering", "Spoofing"],
        "owasp_llm": ["LLM03"],
    },
    {
        "id": "AML.T0018",
        "tactic": "persistence",
        "tactic_label": "持久化",
        "name": "Backdoor ML Model",
        "name_zh": "模型后门",
        "description": "在模型权重中植入触发式后门，特定输入下产生攻击者期望的输出。",
        "stride": ["Tampering"],
        "owasp_llm": ["LLM04"],
    },
    {
        "id": "AML.T0020",
        "tactic": "poisoning",
        "tactic_label": "投毒",
        "name": "Poison Training Data",
        "name_zh": "训练数据投毒",
        "description": "污染训练/微调数据，使模型在特定场景下行为异常或泄露信息。",
        "stride": ["Tampering", "Information Disclosure"],
        "owasp_llm": ["LLM04"],
    },
    {
        "id": "AML.T0024",
        "tactic": "exfiltration",
        "tactic_label": "数据外泄",
        "name": "Exfiltration via ML Inference API",
        "name_zh": "通过推理接口窃取数据",
        "description": "利用推理接口的返回内容反推训练数据、系统提示或业务敏感信息。",
        "stride": ["Information Disclosure"],
        "owasp_llm": ["LLM02", "LLM07"],
    },
    {
        "id": "AML.T0040.002",
        "tactic": "ml-attack-staging",
        "tactic_label": "攻击准备",
        "name": "Craft Adversarial Prompt",
        "name_zh": "构造对抗性提示",
        "description": "通过精心设计的提示词绕过模型的指令边界或安全对齐。",
        "stride": ["Tampering", "Elevation of Privilege"],
        "owasp_llm": ["LLM01"],
    },
    {
        "id": "AML.T0043",
        "tactic": "defense-evasion",
        "tactic_label": "防御规避",
        "name": "Craft Adversarial Data",
        "name_zh": "构造对抗样本",
        "description": "对输入做微小扰动使其绕过检测，或在输出中夹带可执行载荷。",
        "stride": ["Tampering", "Elevation of Privilege"],
        "owasp_llm": ["LLM05"],
    },
    {
        "id": "AML.T0044",
        "tactic": "impact",
        "tactic_label": "影响",
        "name": "Full ML Model Access",
        "name_zh": "完全控制模型",
        "description": "借助过度授权的工具/插件，让模型执行非预期的写操作或命令。",
        "stride": ["Elevation of Privilege"],
        "owasp_llm": ["LLM06"],
    },
    {
        "id": "AML.T0051",
        "tactic": "ml-attack-staging",
        "tactic_label": "攻击准备",
        "name": "LLM Prompt Injection",
        "name_zh": "提示注入",
        "description": "在外部数据源（文档、网页、检索结果）中埋入指令，诱导模型越权执行。",
        "stride": ["Tampering", "Elevation of Privilege"],
        "owasp_llm": ["LLM01"],
    },
    {
        "id": "AML.T0054",
        "tactic": "exfiltration",
        "tactic_label": "数据外泄",
        "name": "LLM Jailbreak",
        "name_zh": "越狱绕过安全限制",
        "description": "通过角色扮演、多轮诱导绕过模型安全策略，输出被禁止的内容或执行受限操作。",
        "stride": ["Elevation of Privilege", "Repudiation"],
        "owasp_llm": ["LLM01", "LLM06"],
    },
    {
        "id": "AML.T0057",
        "tactic": "impact",
        "tactic_label": "影响",
        "name": "Data from Local System",
        "name_zh": "窃取本机数据",
        "description": "通过被劫持的工具链读取宿主机的凭据、配置与业务数据。",
        "stride": ["Information Disclosure"],
        "owasp_llm": ["LLM02", "LLM06"],
    },
]


def get_atlas_techniques() -> List[Dict[str, Any]]:
    """返回 MITRE ATLAS 技术清单。"""
    return MITRE_ATLAS


def get_atlas_by_id(technique_id: str) -> Dict[str, Any] | None:
    """按技术编号（如 ``AML.T0051``）查询 ATLAS 技术。"""
    wanted = str(technique_id or "").strip().upper()
    if not wanted:
        return None
    for item in MITRE_ATLAS:
        if item["id"].upper() == wanted:
            return item
    return None


def map_threat_to_atlas(threat_type: str, text_blob: str = "") -> List[Dict[str, Any]]:
    """把一条威胁映射到 MITRE ATLAS 技术。

    映射策略（纯确定性，不依赖 LLM）：
    1. 先按 STRIDE 类型粗筛候选技术；
    2. 若提供了威胁描述文本，再用技术名/中文名关键词做二次收敛，
       避免同一 STRIDE 类型下的全部技术都塞给一条威胁。

    Args:
        threat_type: 威胁的 STRIDE 类型（如 ``Tampering``）。
        text_blob: 威胁标题 + 描述 + 缓解措施拼成的文本，用于关键词命中判断。

    Returns:
        命中的 ATLAS 技术列表（最多 3 条，按清单顺序）。
    """
    ttype = str(threat_type or "").strip()
    candidates = [t for t in MITRE_ATLAS if ttype in t.get("stride", [])]
    if not candidates:
        return []
    blob = str(text_blob or "").lower()
    if not blob:
        return candidates[:3]

    # 关键词表：覆盖中英文常见表述，命中越多排越前
    keywords = {
        "AML.T0000": ["公开", "文档", "reconnaissance", "搜集", "信息收集"],
        "AML.T0008": ["供应链", "supply", "依赖", "插件", "第三方"],
        "AML.T0010": ["供应链", "投毒", "supply chain", "模型仓库", "插件"],
        "AML.T0018": ["后门", "backdoor", "权重", "微调"],
        "AML.T0020": ["投毒", "训练数据", "poison", "数据集污染"],
        "AML.T0024": ["泄露", "训练数据", "系统提示", "exfiltrat", "反推", "推理接口"],
        "AML.T0040.002": ["提示", "prompt", "诱导", "指令"],
        "AML.T0043": ["对抗", "扰动", "adversarial", "输出处理", "xss", "sql"],
        "AML.T0044": ["权限", "工具", "代理", "agent", "命令", "写操作"],
        "AML.T0051": ["注入", "injection", "检索", "外部数据", "rag", "文档注入"],
        "AML.T0054": ["越狱", "jailbreak", "绕过", "角色扮演", "安全策略"],
        "AML.T0057": ["本机", "宿主机", "凭据", "配置文件", "本地文件"],
    }
    scored: list[tuple[int, Dict[str, Any]]] = []
    for tech in candidates:
        kws = keywords.get(tech["id"], [])
        score = sum(1 for kw in kws if kw in blob)
        scored.append((score, tech))
    scored.sort(key=lambda x: x[0], reverse=True)
    # 完全没有关键词命中时，退化为按 STRIDE 类型返回前 3 条
    return [t for _, t in scored[:3]]


def get_compliance_mapping() -> List[Dict[str, str]]:
    """返回合规映射清单。"""
    return COMPLIANCE_MAPPING


def get_industry_template(key: str | None) -> Dict[str, Any] | None:
    """返回指定行业的场景模板，未命中返回 None。"""
    if not key:
        return None
    return INDUSTRY_TEMPLATES.get(str(key).lower())
