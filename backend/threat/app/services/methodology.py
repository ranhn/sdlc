"""
威胁建模方法论模型层。

精确复刻 OWASP Threat Dragon v2.6.2 的六种方法论：
- STRIDE  / CIA / CIADIE / LINDDUN / PLOT4ai / EOP(Cornucopia)

每个方法论定义了"元素类型 -> 允许的威胁类型"映射，以及威胁频率均衡
(threatFrequency) 推荐逻辑，与官方 models/index.js 的
getThreatTypesByElement / getFrequencyMapByElement 对齐。
"""
from __future__ import annotations

from typing import Dict, List

# ---------------------------------------------------------------------------
# 元素类型（与官方 tm.Actor / tm.Process / tm.Store / tm.Flow 对齐）
# ---------------------------------------------------------------------------
ACTOR = "tm.Actor"
PROCESS = "tm.Process"
STORE = "tm.Store"
FLOW = "tm.Flow"

CELL_TYPES = [ACTOR, PROCESS, STORE, FLOW]

# AI 专用元素类型（STRIDE-AI / LLM 威胁建模扩展）
# 这些元素映射到 Process（视觉上以 Process 承载），但在内部标识其 AI 语义，
# 以便威胁分析器应用 AI 特有的判定规则（提示注入/RAG 投毒/工具滥用等）。
MODEL = "tm.Model"
PROMPT = "tm.Prompt"
VECTORSTORE = "tm.VectorStore"
TOOL = "tm.Tool"
TRAININGDATA = "tm.TrainingData"
AGENTCONFIG = "tm.AgentConfig"

AI_CELL_TYPES = [MODEL, PROMPT, VECTORSTORE, TOOL, TRAININGDATA, AGENTCONFIG]
ALL_CELL_TYPES = CELL_TYPES + AI_CELL_TYPES

# 本平台自定义的等价类型名（用于从模型 JSON 中归一化）
# document_analyzer / model_builder 使用的小写键名
ELEMENT_KEY_ACTOR = "actor"
ELEMENT_KEY_PROCESS = "process"
ELEMENT_KEY_STORE = "datastore"
ELEMENT_KEY_FLOW = "flow"
ELEMENT_KEY_MODEL = "model"
ELEMENT_KEY_PROMPT = "prompt"
ELEMENT_KEY_VECTORSTORE = "vectorstore"
ELEMENT_KEY_TOOL = "tool"
ELEMENT_KEY_TRAININGDATA = "trainingdata"
ELEMENT_KEY_AGENTCONFIG = "agentconfig"

# AI 元素映射到官方 cellType（视觉上以 Process 承载）
AI_KEY_TO_CELL = {
    ELEMENT_KEY_MODEL: MODEL,
    ELEMENT_KEY_PROMPT: PROMPT,
    ELEMENT_KEY_VECTORSTORE: VECTORSTORE,
    ELEMENT_KEY_TOOL: TOOL,
    ELEMENT_KEY_TRAININGDATA: TRAININGDATA,
    ELEMENT_KEY_AGENTCONFIG: AGENTCONFIG,
}

# 平台内部小写键名 -> 官方 cellType
KEY_TO_CELL = {
    ELEMENT_KEY_ACTOR: ACTOR,
    ELEMENT_KEY_PROCESS: PROCESS,
    ELEMENT_KEY_STORE: STORE,
    ELEMENT_KEY_FLOW: FLOW,
    **AI_KEY_TO_CELL,
}
CELL_TO_KEY = {v: k for k, v in KEY_TO_CELL.items()}


# ---------------------------------------------------------------------------
# STRIDE
# ---------------------------------------------------------------------------
STRIDE_TYPES = {
    "spoofing": "Spoofing",
    "tampering": "Tampering",
    "repudiation": "Repudiation",
    "informationDisclosure": "Information Disclosure",
    "denialOfService": "Denial of Service",
    "elevationOfPrivilege": "Elevation of Privilege",
}

STRIDE_BY_ELEMENT = {
    ACTOR: ["Spoofing", "Repudiation"],
    PROCESS: [
        "Spoofing",
        "Tampering",
        "Repudiation",
        "Information Disclosure",
        "Denial of Service",
        "Elevation of Privilege",
    ],
    STORE: ["Tampering", "Repudiation", "Information Disclosure", "Denial of Service"],
    FLOW: ["Tampering", "Information Disclosure", "Denial of Service"],
}

# 向后兼容：保留 document_analyzer 引用的小写键名 STRIDE_RULES
STRIDE_RULES = {
    ELEMENT_KEY_ACTOR: STRIDE_BY_ELEMENT[ACTOR],
    ELEMENT_KEY_PROCESS: STRIDE_BY_ELEMENT[PROCESS],
    ELEMENT_KEY_STORE: STRIDE_BY_ELEMENT[STORE],
    ELEMENT_KEY_FLOW: STRIDE_BY_ELEMENT[FLOW],
}

# ---------------------------------------------------------------------------
# STRIDE-AI（AI 威胁建模扩展）
# 在 STRIDE 六维之上，为 AI 元素类型补充针对性映射：
# - model（大模型）          -> 全部六维（模型窃取/投毒/抵赖/泄露/耗尽/提权）
# - prompt（提示词）         -> 篡改(注入)/信息泄露(系统提示泄露)
# - vectorstore（向量库/RAG）-> 篡改(投毒)/泄露/拒绝服务(击穿)
# - tool（工具/Agent 能力）  -> 提权(越权调用)/泄露/拒绝服务(调用风暴)
# - trainingdata（训练数据） -> 篡改(投毒)/信息泄露(成员推断)
# - agentconfig（Agent 配置）-> 提权(过度授权)/篡改(配置篡改)
# ---------------------------------------------------------------------------
STRIDE_AI_BY_ELEMENT = {
    **STRIDE_BY_ELEMENT,
    MODEL: [
        "Spoofing",          # 仿冒模型 API / 供应链恶意模型
        "Tampering",         # 权重篡改 / 模型投毒
        "Repudiation",       # AI 决策无溯源
        "Information Disclosure",  # 模型窃取 / 训练数据泄露
        "Denial of Service",       # 算力耗尽 / 无限消耗
        "Elevation of Privilege",  # 模型能力滥用
    ],
    PROMPT: [
        "Tampering",             # 提示注入
        "Information Disclosure",# 系统提示/上下文泄露
    ],
    VECTORSTORE: [
        "Tampering",             # RAG 知识库投毒
        "Information Disclosure",# 语义越权检索 / 向量泄露
        "Denial of Service",     # 向量库击穿
    ],
    TOOL: [
        "Information Disclosure",# 工具滥用泄露数据
        "Denial of Service",     # 工具调用风暴
        "Elevation of Privilege",# 越权工具调用
    ],
    TRAININGDATA: [
        "Tampering",             # 训练数据投毒
        "Information Disclosure",# 成员推断 / 数据泄露
    ],
    AGENTCONFIG: [
        "Tampering",             # 配置篡改
        "Elevation of Privilege",# 过度授权
    ],
}

# 向后兼容：小写键名 -> STRIDE-AI 映射
STRIDE_AI_RULES = {
    ELEMENT_KEY_ACTOR: STRIDE_AI_BY_ELEMENT[ACTOR],
    ELEMENT_KEY_PROCESS: STRIDE_AI_BY_ELEMENT[PROCESS],
    ELEMENT_KEY_STORE: STRIDE_AI_BY_ELEMENT[STORE],
    ELEMENT_KEY_FLOW: STRIDE_AI_BY_ELEMENT[FLOW],
    ELEMENT_KEY_MODEL: STRIDE_AI_BY_ELEMENT[MODEL],
    ELEMENT_KEY_PROMPT: STRIDE_AI_BY_ELEMENT[PROMPT],
    ELEMENT_KEY_VECTORSTORE: STRIDE_AI_BY_ELEMENT[VECTORSTORE],
    ELEMENT_KEY_TOOL: STRIDE_AI_BY_ELEMENT[TOOL],
    ELEMENT_KEY_TRAININGDATA: STRIDE_AI_BY_ELEMENT[TRAININGDATA],
    ELEMENT_KEY_AGENTCONFIG: STRIDE_AI_BY_ELEMENT[AGENTCONFIG],
}

# ---------------------------------------------------------------------------
# CIA
# ---------------------------------------------------------------------------
CIA_TYPES = {
    "confidentiality": "Confidentiality",
    "integrity": "Integrity",
    "availability": "Availability",
}

# 官方矩阵：actor/store/flow/process 全部覆盖 CIA
CIA_BY_ELEMENT = {
    ACTOR: ["Confidentiality", "Integrity", "Availability"],
    PROCESS: ["Confidentiality", "Integrity", "Availability"],
    STORE: ["Confidentiality", "Integrity", "Availability"],
    FLOW: ["Confidentiality", "Integrity", "Availability"],
}

# ---------------------------------------------------------------------------
# CIADIE
# ---------------------------------------------------------------------------
CIADIE_TYPES = {
    "confidentiality": "Confidentiality",
    "integrity": "Integrity",
    "availability": "Availability",
    "distributed": "Distributed",
    "immutable": "Immutable",
    "ephemeral": "Ephemeral",
}

# 官方矩阵：全部 X
CIADIE_BY_ELEMENT = {
    ACTOR: [
        "Confidentiality", "Integrity", "Availability",
        "Distributed", "Immutable", "Ephemeral",
    ],
    PROCESS: [
        "Confidentiality", "Integrity", "Availability",
        "Distributed", "Immutable", "Ephemeral",
    ],
    STORE: [
        "Confidentiality", "Integrity", "Availability",
        "Distributed", "Immutable", "Ephemeral",
    ],
    FLOW: [
        "Confidentiality", "Integrity", "Availability",
        "Distributed", "Immutable", "Ephemeral",
    ],
}

# ---------------------------------------------------------------------------
# LINDDUN
# ---------------------------------------------------------------------------
LINDDUN_TYPES = {
    "linkability": "Linkability",
    "identifiability": "Identifiability",
    "nonRepudiation": "Non-Repudiation",
    "detectability": "Detectability",
    "disclosureOfInformation": "Disclosure of Information",
    "unawareness": "Unawareness",
    "nonCompliance": "Non-Compliance",
}

LINDDUN_BY_ELEMENT = {
    ACTOR: ["Linkability", "Identifiability", "Unawareness"],
    PROCESS: [
        "Linkability", "Identifiability", "Non-Repudiation",
        "Detectability", "Disclosure of Information", "Non-Compliance",
    ],
    STORE: [
        "Linkability", "Identifiability", "Non-Repudiation",
        "Detectability", "Disclosure of Information", "Non-Compliance",
    ],
    FLOW: [
        "Linkability", "Identifiability", "Non-Repudiation",
        "Detectability", "Disclosure of Information", "Non-Compliance",
    ],
}

# ---------------------------------------------------------------------------
# PLOT4ai
# ---------------------------------------------------------------------------
PLOT4AI_TYPES = {
    "techniqueProcesses": "Technique & Processes",
    "accessibility": "Accessibility",
    "identifiabilityLinkability": "Identifiability & Linkability",
    "security": "Security",
    "safety": "Safety",
    "unawareness": "Unawareness",
    "ethicsHumanRights": "Ethics & Human Rights",
    "nonCompliance": "Non-Compliance",
}

PLOT4AI_BY_ELEMENT = {
    ACTOR: [
        "Accessibility", "Identifiability & Linkability", "Security",
        "Safety", "Unawareness", "Ethics & Human Rights",
    ],
    FLOW: [
        "Technique & Processes", "Identifiability & Linkability",
        "Security", "Non-Compliance",
    ],
    STORE: [
        "Technique & Processes", "Accessibility",
        "Identifiability & Linkability", "Security", "Non-Compliance",
    ],
    PROCESS: [
        "Technique & Processes", "Accessibility",
        "Identifiability & Linkability", "Security", "Non-Compliance",
    ],
}

# ---------------------------------------------------------------------------
# EOP / Cornucopia
# ---------------------------------------------------------------------------
# 官方 Cornucopia 的 suits（卡片分类），非标准威胁类型，作为 AI 分析时的提示维度
EOP_SUITS = [
    "Authentication",
    "Authorization",
    "Cryptography",
    "Data Validation & Encoding",
    "Session Management",
]

EOP_BY_ELEMENT = {
    # 每个元素类型都能触发 Cornucopia 的各类 suits，这里给出与元素最相关的推荐维度
    ACTOR: ["Authentication", "Session Management"],
    PROCESS: [
        "Authentication", "Authorization", "Cryptography",
        "Data Validation & Encoding", "Session Management",
    ],
    STORE: ["Authorization", "Cryptography", "Data Validation & Encoding"],
    FLOW: ["Cryptography", "Data Validation & Encoding"],
}

# ---------------------------------------------------------------------------
# 方法论注册表
# ---------------------------------------------------------------------------
METHODOLOGIES: Dict[str, Dict] = {
    "STRIDE": {
        "label": "STRIDE",
        "description": "Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege",
        "types": STRIDE_TYPES,
        "by_element": STRIDE_BY_ELEMENT,
        "frequency": lambda cell: {t: 0 for t in STRIDE_BY_ELEMENT.get(cell, STRIDE_BY_ELEMENT[PROCESS])},
    },
    "STRIDE-AI": {
        "label": "STRIDE-AI",
        "description": "AI 威胁建模扩展：在 STRIDE 六维上叠加 model/prompt/vectorstore/tool/trainingdata/agentconfig 六类 AI 元素",
        "types": STRIDE_TYPES,
        "by_element": STRIDE_AI_BY_ELEMENT,
        "frequency": lambda cell: {t: 0 for t in STRIDE_AI_BY_ELEMENT.get(cell, STRIDE_AI_BY_ELEMENT[PROCESS])},
        "ai_elements": True,
    },
    "CIA": {
        "label": "CIA",
        "description": "Confidentiality, Integrity, Availability",
        "types": CIA_TYPES,
        "by_element": CIA_BY_ELEMENT,
        "frequency": lambda cell: {"Confidentiality": 0, "Integrity": 0, "Availability": 0},
    },
    "CIADIE": {
        "label": "CIADIE",
        "description": "Confidentiality, Integrity, Availability, Distributed, Immutable, Ephemeral",
        "types": CIADIE_TYPES,
        "by_element": CIADIE_BY_ELEMENT,
        "frequency": lambda cell: {
            "Confidentiality": 0, "Integrity": 0, "Availability": 0,
            "Distributed": 0, "Immutable": 0, "Ephemeral": 0,
        },
    },
    "LINDDUN": {
        "label": "LINDDUN",
        "description": "Privacy: Linkability, Identifiability, Non-Repudiation, Detectability, Disclosure of Information, Unawareness, Non-Compliance",
        "types": LINDDUN_TYPES,
        "by_element": LINDDUN_BY_ELEMENT,
        "frequency": lambda cell: {t: 0 for t in LINDDUN_BY_ELEMENT.get(cell, LINDDUN_BY_ELEMENT[PROCESS])},
    },
    "PLOT4ai": {
        "label": "PLOT4ai",
        "description": "Technique & Processes, Accessibility, Identifiability & Linkability, Security, Safety, Unawareness, Ethics & Human Rights, Non-Compliance",
        "types": PLOT4AI_TYPES,
        "by_element": PLOT4AI_BY_ELEMENT,
        "frequency": lambda cell: {t: 0 for t in PLOT4AI_BY_ELEMENT.get(cell, PLOT4AI_BY_ELEMENT[PROCESS])},
    },
    "EOP": {
        "label": "EOP (Cornucopia)",
        "description": "Cornucopia suits: Authentication, Authorization, Cryptography, Data Validation & Encoding, Session Management",
        "types": {s: s for s in EOP_SUITS},
        "by_element": EOP_BY_ELEMENT,
        "frequency": lambda cell: {t: 0 for t in EOP_BY_ELEMENT.get(cell, EOP_BY_ELEMENT[PROCESS])},
    },
}

ALL_METHODOLOGIES: List[str] = ["STRIDE", "STRIDE-AI", "CIA", "CIADIE", "LINDDUN", "PLOT4ai", "EOP"]


# ---------------------------------------------------------------------------
# 公共接口
# ---------------------------------------------------------------------------
def normalize_methodology(name: str) -> str:
    """将用户输入的方法论名称归一化为标准名（兼容大小写/别名）。"""
    if not name:
        return "STRIDE"
    n = name.strip().upper().replace(" ", "").replace("_", "")
    if n in ("EOP", "CORNUCOPIA", "EOPCORNUCCOPIA"):
        return "EOP"
    for m in ALL_METHODOLOGIES:
        if n == m.upper():
            return m
    # 模糊匹配
    for m in ALL_METHODOLOGIES:
        if m.upper() in n or n in m.upper():
            return m
    return "STRIDE"


def is_valid_methodology(name: str) -> bool:
    return normalize_methodology(name) in ALL_METHODOLOGIES


def get_threat_types_by_element(methodology: str, cell_key: str) -> List[str]:
    """返回某方法论下、某元素类型允许的威胁类型列表。

    cell_key 为平台内部小写键名（actor/process/datastore/flow）或官方 tm.* 名。
    对齐官方 getThreatTypesByElement。
    """
    m = normalize_methodology(methodology)
    cell = KEY_TO_CELL.get(cell_key, cell_key)
    mapping = METHODOLOGIES[m]["by_element"]
    if cell in mapping:
        return list(mapping[cell])
    # 兜底：PROCESS
    return list(mapping.get(PROCESS, []))


def get_frequency_map_by_element(methodology: str, cell_key: str) -> Dict[str, int]:
    """返回某方法论下、某元素类型的初始频率映射（全部为 0）。

    对齐官方 getFrequencyMapByElement。
    """
    m = normalize_methodology(methodology)
    cell = KEY_TO_CELL.get(cell_key, cell_key)
    return METHODOLOGIES[m]["frequency"](cell)


def suggest_least_used_type(methodology: str, cell_key: str, frequency: Dict[str, int]) -> str:
    """基于威胁频率均衡，推荐"使用频率最低"的威胁类型。

    对齐官方 threats/index.js 的 threatFrequency 推荐逻辑：
    在元素允许的类型中，选择当前已用频率最低的那个，避免某一类型被过度使用。
    """
    m = normalize_methodology(methodology)
    allowed = get_threat_types_by_element(m, cell_key)
    if not allowed:
        return ""
    if not frequency:
        return allowed[0]
    # 找到最小频率
    min_freq = min(frequency.get(t, 0) for t in allowed)
    candidates = [t for t in allowed if frequency.get(t, 0) == min_freq]
    return candidates[0] if candidates else allowed[0]


def methodology_description(methodology: str) -> str:
    m = normalize_methodology(methodology)
    return METHODOLOGIES[m]["description"]
