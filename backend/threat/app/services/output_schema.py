"""威胁建模输出 JSON Schema（稳定性核心）。

通过结构化输出（json_schema）把 LLM 的自由生成约束为确定性的
字段结构、枚举值与数量上下界，消除字段随机性与类型漂移。
"""
from __future__ import annotations

from typing import Any

# 允许的元素类型
COMPONENT_TYPE_ENUM = [
    "actor", "process", "datastore", "externalentity", "trustboundary",
    "model", "prompt", "vectorstore", "tool", "trainingdata", "agentconfig",
]

# 数据生命周期阶段（数据收集 → 数据存储 → 数据使用 → 数据交换 → 数据删除）
# DFD 组件可标注生命周期阶段，布局时按泳道分组展示，使数据流向更清晰。
LIFECYCLE_ENUM = ["collect", "store", "use", "exchange", "delete"]

PROTOCOL_ENUM = ["HTTPS", "HTTP", "gRPC", "MQTT", "DB", "Internal", "Other"]

SEVERITY_ENUM = ["Low", "Medium", "High", "Critical"]

# P0-1 软限制：DFD 元素数量上限
# - 这是给 LLM 的目标量级（schema maxItems 也保持一致）
# - 真正的兜底截断在 document_analyzer._validate 里执行（不报错、只截断 + 日志）
DFD_MAX_COMPONENTS = 20
DFD_MAX_FLOWS = 60

BOOLEAN_PROPERTIES = [
    "isWebApplication", "isALog", "storesCredentials", "handlesCardPayment",
    "isEncrypted", "isPublicNetwork", "isTrustBoundary",
    "isLLMService", "hasRAG", "hasTools", "isSystemPrompt",
    "isVectorStore", "storesTrainingData",
]

# 组件属性 schema（布尔 + 自由文本）
COMPONENT_PROPERTIES_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": True,
    "properties": {
        **{p: {"type": "boolean"} for p in BOOLEAN_PROPERTIES},
        "privilegeLevel": {"type": "string"},
        "protocol": {"type": "string"},
    },
}

# DFD 提取输出的 JSON Schema
DFD_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["summary", "diagram", "components", "flows"],
    "additionalProperties": True,
    "properties": {
        "summary": {
            "type": "object",
            "required": ["title", "description"],
            "additionalProperties": True,
            "properties": {
                "title": {"type": "string", "minLength": 1},
                "description": {"type": "string"},
                "owner": {"type": "string"},
            },
        },
        "diagram": {
            "type": "object",
            "required": ["title", "description", "diagramType"],
            "additionalProperties": True,
            "properties": {
                "title": {"type": "string"},
                "description": {"type": "string"},
                "diagramType": {"type": "string"},
            },
        },
        "components": {
            "type": "array",
            "minItems": 3,
            "maxItems": 20,
            "items": {
                "type": "object",
                "required": ["id", "type", "name"],
                "additionalProperties": True,
                "properties": {
                    "id": {"type": "string", "minLength": 1},
                    "type": {"type": "string", "enum": COMPONENT_TYPE_ENUM},
                    "name": {"type": "string", "minLength": 1},
                    "description": {"type": "string"},
                    "lifecycle": {
                        "type": "string",
                        "enum": LIFECYCLE_ENUM,
                        "description": "数据生命周期阶段：collect 数据收集 / store 数据存储 / use 数据使用 / exchange 数据交换 / delete 数据删除",
                    },
                    "properties": COMPONENT_PROPERTIES_SCHEMA,
                },
            },
        },
        "flows": {
            "type": "array",
            "minItems": 0,
            "maxItems": 60,
            "items": {
                "type": "object",
                "required": ["id", "sourceId", "targetId", "name"],
                "additionalProperties": True,
                "properties": {
                    "id": {"type": "string", "minLength": 1},
                    "sourceId": {"type": "string", "minLength": 1},
                    "targetId": {"type": "string", "minLength": 1},
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                    "properties": COMPONENT_PROPERTIES_SCHEMA,
                },
            },
        },
    },
}


def build_threat_schema(methodology: str, allowed_types: list[str]) -> dict[str, Any]:
    """构造某方法论下威胁列表输出的 JSON Schema。
    Args:
        methodology: 方法论名（STRIDE/CIA/…/STRIDE-AI）。
        allowed_types: 该方法论全部允许的威胁类型（展示名列表）。
    """
    # 各方法论威胁条目是否含 DREAD 字段
    is_ai = methodology == "STRIDE-AI"
    threat_props: dict[str, Any] = {
        "componentId": {"type": "string", "minLength": 1},
        "type": {"type": "string", "enum": allowed_types},
        "title": {"type": "string", "minLength": 1},
        "severity": {"type": "string", "enum": SEVERITY_ENUM},
        "status": {"type": "string", "enum": ["Open", "Mitigated", "NotApplicable"]},
        "description": {"type": "string"},
        "mitigation": {"type": "string"},
        "score": {"type": "string", "enum": SEVERITY_ENUM},
        "cwe": {"type": "string"},
        "references": {"type": "array", "items": {"type": "string"}},
    }
    if is_ai:
        threat_props["dread"] = {
            "type": "object",
            "additionalProperties": True,
            "properties": {
                "damage": {"type": "integer", "minimum": 0, "maximum": 10},
                "reproducibility": {"type": "integer", "minimum": 0, "maximum": 10},
                "exploitability": {"type": "integer", "minimum": 0, "maximum": 10},
                "affectedUsers": {"type": "integer", "minimum": 0, "maximum": 10},
                "discoverability": {"type": "integer", "minimum": 0, "maximum": 10},
            },
        }
        threat_props["dreadScore"] = {"type": "integer", "minimum": 0, "maximum": 50}

    return {
        "type": "object",
        "required": ["threats"],
        "additionalProperties": True,
        "properties": {
            "threats": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "required": ["componentId", "type", "title", "severity"],
                    "additionalProperties": True,
                    "properties": threat_props,
                },
            }
        },
    }


# DFD 自省补全输出 Schema（两阶段提取的第二阶段）
#
# 第一阶段已提取 DFD 骨架；本 schema 让 LLM 基于原文与结构缺陷，
# 输出「需要补全/修正」的增量，避免全量重生成导致结构漂移。
# 组件的 id 由调用方用 stable id 生成，LLM 只需给 name/type 等语义字段。
COMPONENT_REFINE_ITEM = {
    "type": "object",
    "required": ["name", "type"],
    "additionalProperties": True,
    "properties": {
        "name": {"type": "string", "minLength": 1},
        "type": {"type": "string", "enum": COMPONENT_TYPE_ENUM},
        "description": {"type": "string"},
        "lifecycle": {
            "type": "string",
            "enum": LIFECYCLE_ENUM,
        },
        "properties": COMPONENT_PROPERTIES_SCHEMA,
    },
}

DFD_REFINE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["newComponents", "newFlows", "explanation"],
    "additionalProperties": True,
    "properties": {
        "newComponents": {
            "type": "array",
            "items": COMPONENT_REFINE_ITEM,
        },
        "newFlows": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["sourceName", "targetName", "name"],
                "additionalProperties": True,
                "properties": {
                    "sourceName": {"type": "string", "minLength": 1},
                    "targetName": {"type": "string", "minLength": 1},
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                    "properties": COMPONENT_PROPERTIES_SCHEMA,
                },
            },
        },
        "explanation": {"type": "string"},
    },
}
