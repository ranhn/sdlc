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


def get_compliance_mapping() -> List[Dict[str, str]]:
    """返回合规映射清单。"""
    return COMPLIANCE_MAPPING


def get_industry_template(key: str | None) -> Dict[str, Any] | None:
    """返回指定行业的场景模板，未命中返回 None。"""
    if not key:
        return None
    return INDUSTRY_TEMPLATES.get(str(key).lower())
