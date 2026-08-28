"""文档分析器：从需求文档与架构文档中提取 DFD 数据流图元素。

核心职责：
1. 阅读需求文档、产品架构设计文档（及可选图片描述）。
2. 利用 LLM 提取系统组件（Actor / Process / DataStore / ExternalEntity / DataFlow / TrustBoundary）。
3. 返回结构化的 DFD 元素数据，供 ThreatModelBuilder 生成 Threat Dragon 兼容模型。
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any

from .llm_client import LLMClient
from .methodology import (
    STRIDE_RULES,
    get_threat_types_by_element,
    normalize_methodology,
)
from ..config import settings

logger = logging.getLogger(__name__)

# 数据生命周期阶段（与 output_schema.LIFECYCLE_ENUM 保持一致）
_LIFECYCLE_SET = {"collect", "store", "use", "exchange", "delete"}

# 允许的元素类型，与 Threat Dragon 保持一致
ALLOWED_TYPES = {
    "actor",
    "process",
    "datastore",
    "externalentity",
    "dataflow",
    "trustboundary",
    # STRIDE-AI 新增的 AI 专用元素类型
    "model",
    "prompt",
    "vectorstore",
    "tool",
    "trainingdata",
    "agentconfig",
}

# AI 元素类型集合（STRIDE-AI 专用）
AI_ELEMENT_TYPES = {
    "model",
    "prompt",
    "vectorstore",
    "tool",
    "trainingdata",
    "agentconfig",
}

# ----------------------------------------------------------------------
# DFD 常见错误关键字（用于后端自动纠错，避免 LLM 把明显应为「数据存储」
# 的组件建成 process，或漏标敏感数据流的加密属性）
# ----------------------------------------------------------------------

# 组件名字命中 _DATSTORE_NAME_HINTS 但同时含 _DATSTORE_NAME_EXCLUDE
# 后缀时跳过 —— 『存储网关』『存储系统』显然是管理存储的服务而非
# 存储本身，不应强制改 type=datastore。
_DATSTORE_NAME_EXCLUDE = (
    "网关",
    "服务",
    "系统",
    "层",
    "平台",
    "模块",
    "集群",
    "中心",
    "节点",
    "代理",
    "中间件",
    "总线",
)

# 组件名字命中这些关键字 → 自动改 type=datastore（小写匹配）
_DATSTORE_NAME_HINTS = (
    "cdn",
    "静态页面",
    "静态资源",
    "对象存储",
    "文件存储",
    "oss",
    "s3",
    "bucket",
    "blob",
    "cache",
    "缓存",
    "数据库",
    "db",
    "mysql",
    "postgres",
    "mongodb",
    "redis",
    "kafka",
    "队列",
    "data lake",
    "数据湖",
    "数据仓库",
    "数据存储",
    "存储",
)

# 数据流名字/描述命中这些关键字 → isEncrypted=true（敏感数据）
_SENSITIVE_FLOW_HINTS = (
    "健康",
    "医疗",
    "体征",
    "血压",
    "心率",
    "血糖",
    "体重",
    "用药",
    "身份证",
    "身份证号",
    "身份证件",
    "实名",
    "手机号",
    "密码",
    "口令",
    "凭证",
    "凭据",
    "token",
    "令牌",
    "session",
    "会话",
    "cookie",
    "支付",
    "交易",
    "余额",
    "银行卡",
    "信用卡",
    "订单",
    "https",
    "tls",
    "ssl",
    "加密",
    "密文",
    "私钥",
    "密钥",
    "jwt",
    "oauth",
)

# 数据流名字/描述命中这些关键字 → isPublicNetwork=true（跨公网）。
# 注意：不再把 http/https 当作公网标识 —— 大量内网 HTTP 调用（如服务
# 间 API）会被误判为公网，放大威胁严重度。仅保留明确的公网/无线指示。
_PUBLIC_FLOW_HINTS = (
    "公网",
    "互联网",
    "internet",
    "广域网",
    "wan",
    "外网",
    "对公",
    "暴露",
    "公开",
    "cdn",
    "第三方",
    "手机网络",
    "4g",
    "5g",
    "wifi",
    "无线",
    "ble",
    "蓝牙",
)


def _auto_fix_component_type(name_hint: str, current_type: str) -> str | None:
    """根据名字关键字推断正确组件类型，返回新类型或 None 表示无需修正。"""
    if current_type in ("trustboundary",):
        return None  # 信任边界不受此规则约束
    text = (name_hint or "").lower()
    if any(k in text for k in _DATSTORE_NAME_HINTS):
        # 但若名称同时含『服务/网关/系统』等服务语义后缀，则是管理存
        # 储的服务而非存储本身，跳过自动类型推断。
        if any(ex in text for ex in _DATSTORE_NAME_EXCLUDE):
            return None
        return "datastore"
    return None


def _auto_fix_flow_props(
    flow: dict[str, Any],
) -> dict[str, bool]:
    """根据数据流名字/描述/protocol 自动判断是否加密 / 跨公网。"""
    text = " ".join(
        [
            str(flow.get("name") or ""),
            str(flow.get("description") or ""),
            str(flow.get("properties", {}).get("protocol") or ""),
        ]
    ).lower()
    return {
        "isEncrypted": any(k in text for k in _SENSITIVE_FLOW_HINTS),
        "isPublicNetwork": any(k in text for k in _PUBLIC_FLOW_HINTS),
    }


# STRIDE_RULES 由 methodology.py 统一提供（多方法论映射层），
# 此处直接引用，避免重复定义。


# ----------------------------------------------------------------------
# 方案 B：DFD 结构自检 —— 在骨架归一后对结构做确定性断言
#
# 只做「可判定」的结构检查，输出结构化缺陷，供 AI 自省阶段据此补全/修正：
#   1. 无任何 process：纯 actor/datastore 无法形成处理链路。
#   2. datastore/vectorstore 没有任何 process 中转（存储被外部直接读写，
#      或存储孤立无连边）→ 缺少中间处理方。
#   3. actor/externalentity 同时有入流和出流（作中间节点）→ 一般不合理。
#   4. trustboundary 内部出现外部实体（actor/externalentity）→ 边界归属错误。
#   5. 组件/流悬空引用（源或目标不存在）。
#   6. 存储类组件生命周期错配（use），外部/前端组件生命周期错配（use/store/delete）。
# ----------------------------------------------------------------------
_STORE_TYPES = {"datastore", "vectorstore", "trainingdata"}
_ENDPOINT_TYPES = {"actor", "externalentity"}


def _structural_defects(
    components: list[dict[str, Any]],
    flows: list[dict[str, Any]],
) -> list[str]:
    """对归一化后的 DFD 做结构断言，返回人类可读的缺陷清单（空列表=无缺陷）。

    纯确定性、跨方法论/行业通用；不臆造，只报告可判定问题。
    """
    defects: list[str] = []
    ctype = {str(c.get("id")): str(c.get("type") or "").lower() for c in components}
    cname = {str(c.get("id")): str(c.get("name") or "") for c in components}
    ids = set(ctype)
    name2id = {}
    for c in components:
        n = str(c.get("name") or "").strip()
        if n and n not in name2id:
            name2id[n] = str(c.get("id"))

    has_process = any(t == "process" for t in ctype.values())
    if not has_process and components:
        defects.append("图中没有任何 process(处理逻辑)组件,缺少处理链路")

    # 边集合:入边/出边 per id, 及存储相关边
    out_ids: dict[str, int] = {}
    in_ids: dict[str, int] = {}
    for f in flows:
        s = str(f.get("sourceId"))
        t = str(f.get("targetId"))
        if s not in ids or t not in ids:
            defects.append(
                f"存在悬空引用:流「{f.get('name') or ''}」引用了不存在的组件"
            )
            continue
        out_ids[s] = out_ids.get(s, 0) + 1
        in_ids[t] = in_ids.get(t, 0) + 1

    # 存储类组件必须经由 process 中转(有至少一条入边或出边来自/去向 process)
    for c in components:
        cid = str(c.get("id"))
        if ctype.get(cid) in _STORE_TYPES:
            neighbors_process = False
            touched = False
            for f in flows:
                s = str(f.get("sourceId"))
                t = str(f.get("targetId"))
                if s == cid or t == cid:
                    touched = True
                    other = t if s == cid else s
                    if ctype.get(other) == "process":
                        neighbors_process = True
            if touched and not neighbors_process:
                defects.append(
                    f"存储组件「{cname.get(cid) or cid}」没有经任何 process 中转,"
                    f"可能被外部/其他组件直接读写"
                )

    # actor/externalentity 不应同时有入出流(作中间节点)
    for c in components:
        cid = str(c.get("id"))
        if ctype.get(cid) in _ENDPOINT_TYPES and out_ids.get(cid) and in_ids.get(cid):
            defects.append(
                f"外部实体「{cname.get(cid) or cid}」同时有入流与出流,"
                f"可能被错误地作为数据流中间节点"
            )

    # 信任边界内部不应出现外部实体
    # 注:边界成员的归属判定依赖语义(组件在边界内/外),交给 AI 自省阶段
    # 结合原文判断,此处不做硬编码推断。

    # 生命周期错配(可确定性判定的部分)
    for c in components:
        lc = str(c.get("lifecycle") or "").lower()
        t = ctype.get(str(c.get("id")))
        if not lc:
            continue
        if t in _STORE_TYPES and lc not in ("store", "delete"):
            defects.append(
                f"存储组件「{cname.get(str(c.get('id'))) or c.get('id')}」"
                f"生命周期为 {lc},应为 store/delete"
            )
        if t in _ENDPOINT_TYPES and lc in ("use", "store", "delete"):
            defects.append(
                f"外部实体「{cname.get(str(c.get('id'))) or c.get('id')}」"
                f"生命周期为 {lc},应为 collect/exchange"
            )
    return defects


# ----------------------------------------------------------------------
# 方案 A：DFD 骨架确定性归一 —— 让 LLM 提取结果在多次运行间漂移极小
#
# 策略（全部为确定性规则，不依赖 LLM，保证同文档跨次结果稳定）：
#   1. 组件 ID 稳定化：弃用 LLM 编的 id / 随机 uuid，改为「规范化名字 + 类型」
#      的 SHA-1 前 8 位。同名同类型组件跨次运行永远得到同一 id →
#      数据流引用稳定、威胁按 id 关联稳定（消除最大的漂移放大器）。
#   2. 组件骨架归一：按稳定键合并 LLM 重复/同义组件，统一类型。
#   3. 数据流骨架归一：按 (srcId, tgtId, name) 去重，id 稳定化。
#   4. 确定性排序：组件/数据流按稳定 id 排序，消除顺序漂移。
#   5. 关键存储组件兜底补齐：文档明确出现的数据库/缓存等存储组件若被 LLM
#      漏建，确定性补入骨架（防漏报）。
# ----------------------------------------------------------------------

# 名字规范化：去空白、统一全半角、转小写，用于稳定键
def _norm_name(s: str) -> str:
    s = (s or "").strip()
    s = re.sub(r"\s+", "", s)
    s = s.replace("（", "(").replace("）", ")").replace("，", ",").replace("、", ",")
    return s.lower()


def _stable_component_id(name: str, ctype: str) -> str:
    """基于『规范化名字 + 类型』生成稳定的组件 ID（SHA-1 前 8 位 hex）。

    同一文档（即使改了无关文字、LLM 重命名了 id）只要组件名与类型一致，
    生成的 id 就永远相同 → 数据流/威胁引用不漂移。
    """
    key = f"{_norm_name(name)}|{ctype}"
    return hashlib.sha1(key.encode("utf-8", "ignore")).hexdigest()[:8]


def _stable_flow_id(src_id: str, tgt_id: str, name: str) -> str:
    """基于『源 id + 目标 id + 名字』生成稳定的数据流 ID。"""
    key = f"{src_id}|{tgt_id}|{_norm_name(name)}"
    return hashlib.sha1(key.encode("utf-8", "ignore")).hexdigest()[:8]


def _sorted_props(raw: Any) -> dict[str, Any]:
    """对 LLM 返回的 properties 做确定性排序（递归）。

    LLM 两次返回同一组件时，properties 的**键插入顺序**可能不同（如
    {isEncrypted:...,isPublicNetwork:...} 与 {isPublicNetwork:...,isEncrypted:...}）。
    这种顺序抖动会进入下游 prompt（_format_components / DFD 自校验序列化），
    导致 LLM 响应缓存 key 变化 → 缓存 miss → 结果漂移。这里在骨架归一阶段
    就把 properties 键序固定，从根源保证「同输入 → 下游 prompt 字节级一致」。
    """
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    for k in sorted(raw):
        v = raw[k]
        if isinstance(v, dict):
            v = _sorted_props(v)  # 递归稳定嵌套属性（如 data 子对象）
        elif isinstance(v, list):
            # 列表内的 dict 元素也递归稳定；标量列表保持原序（语义相关，不重排）
            v = [_sorted_props(x) if isinstance(x, dict) else x for x in v]
        out[k] = v
    return out


def _merge_component_props(target: dict[str, Any], source: dict[str, Any]) -> None:
    """合并组件属性：source 中的真值属性补充到 target（并集，真值优先）。"""
    tp = target.setdefault("properties", {})
    sp = source.get("properties", {}) or {}
    for k, v in sp.items():
        # 用 True/非空 覆盖缺失/False 值（保守并集，避免丢敏感属性）
        if v and not tp.get(k):
            tp[k] = v
    # 描述优先保留更详细者
    if not target.get("description") and source.get("description"):
        target["description"] = source["description"]


def _skeleton_normalize(
    components: list[dict[str, Any]],
    flows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """对 LLM 提取的 DFD 元素做确定性骨架归一，返回 (组件, 数据流, 纠错日志)。

    - 组件：按『规范化名字』合并去重，id 稳定化，类型统一。
    - 数据流：源/目标用稳定 id 重写，按 (src, tgt, name) 去重，id 稳定化。
    - 返回的组件/流均按稳定 id 排序（确定性顺序）。
    """
    # 1) 组件合并：name->{稳定组件}；保留类型优先级 datastore > process > actor
    type_rank = {"datastore": 3, "process": 2, "actor": 1, "externalentity": 2,
                 "model": 2, "prompt": 2, "vectorstore": 3, "tool": 2,
                 "trainingdata": 3, "agentconfig": 2, "trustboundary": 0}
    merged: dict[str, dict[str, Any]] = {}   # norm_name -> 稳定组件
    name_by_key: dict[str, str] = {}          # norm_name -> 原始展示名
    for comp in components:
        ctype = str(comp.get("type", "process")).lower()
        if ctype not in ALLOWED_TYPES:
            ctype = "process"
        cname = str(comp.get("name") or "").strip() or "unnamed"
        key = _norm_name(cname)
        if key in merged:
            # 已存在：取类型优先级更高者，并合并属性
            exist = merged[key]
            if type_rank.get(ctype, 0) > type_rank.get(exist.get("type", "process"), 0):
                old_type = exist["type"]
                exist["type"] = ctype
                merged[key] = {"id": _stable_component_id(name_by_key[key], ctype),
                               "type": ctype, "name": name_by_key[key],
                               "description": comp.get("description", ""),
                               "lifecycle": comp.get("lifecycle", ""),
                               "properties": _sorted_props(comp.get("properties", {}))}
                _merge_component_props(merged[key], exist)
                merged[key]["_type_upgraded"] = f"{old_type}->{ctype}"
            else:
                _merge_component_props(exist, comp)
                if comp.get("lifecycle") and not exist.get("lifecycle"):
                    exist["lifecycle"] = comp["lifecycle"]
        else:
            merged[key] = {
                "id": _stable_component_id(cname, ctype),
                "type": ctype,
                "name": cname,
                "description": comp.get("description", ""),
                "lifecycle": comp.get("lifecycle", ""),
                "properties": _sorted_props(comp.get("properties", {})),
            }
            name_by_key[key] = cname

    # 2) 稳定 id -> name 映射（数据流重写引用用）
    id_to_name: dict[str, str] = {}
    for comp in merged.values():
        id_to_name[comp["id"]] = comp["name"]

    # 3) 数据流归一：源/目标 id 重写为稳定 id，按 (src,tgt,name) 去重
    seen_flows: dict[tuple[str, str, str], dict[str, Any]] = {}
    for flow in flows:
        src = str(flow.get("sourceId", ""))
        tgt = str(flow.get("targetId", ""))
        # 源/目标名字匹配到稳定组件 id
        src_id = None
        tgt_id = None
        for cid, cname in id_to_name.items():
            if _norm_name(src) == _norm_name(cname):
                src_id = cid
            if _norm_name(tgt) == _norm_name(cname):
                tgt_id = cid
        if not src_id or not tgt_id:
            continue  # 源/目标未识别，丢弃无效流
        if src_id == tgt_id:
            continue  # 自环无意义，丢弃
        fname = str(flow.get("name", "")) or f"{id_to_name[src_id]}→{id_to_name[tgt_id]}"
        fkey = (src_id, tgt_id, _norm_name(fname))
        props = _sorted_props(flow.get("properties", {}))
        if fkey in seen_flows:
            # 去重：合并属性
            _merge_component_props(seen_flows[fkey], flow)
            continue
        seen_flows[fkey] = {
            "id": _stable_flow_id(src_id, tgt_id, fname),
            "sourceId": src_id,
            "targetId": tgt_id,
            "name": fname,
            "description": flow.get("description", ""),
            "properties": props,
        }

    # 4) 确定性排序
    comps_sorted = sorted(merged.values(), key=lambda c: c["id"])
    # 移除内部标记字段
    for c in comps_sorted:
        c.pop("_type_upgraded", None)
    flows_sorted = sorted(seen_flows.values(), key=lambda f: f["id"])

    log: list[str] = []
    for c in comps_sorted:
        # 汇总合并信息（如多个同名组件合并）
        if c.get("description") or c.get("properties"):
            pass
    if len(components) != len(comps_sorted):
        log.append(
            f"组件骨架归一：LLM 提取 {len(components)} 个组件 → 去重合并为 {len(comps_sorted)} 个（稳定 ID）"
        )
    if len(flows) != len(flows_sorted):
        log.append(
            f"数据流骨架归一：LLM 提取 {len(flows)} 条 → 去重为 {len(flows_sorted)} 条（稳定 ID）"
        )
    return comps_sorted, flows_sorted, log


class DocumentAnalyzer:
    """负责将文档转化为 DFD 元素列表。"""

    SYSTEM_PROMPT = """
你是一名资深的安全架构师，精通 STRIDE 威胁建模和数据流图（DFD）。
你的任务是从系统需求文档、产品架构设计文档中，提取出完整、准确的数据流图（DFD）元素。

你必须严格按照以下 JSON 结构输出（不要输出任何其他内容）：

{
  "summary": {
    "title": "威胁模型标题",
    "description": "系统总体描述",
    "owner": "AI Threat Dragon"
  },
  "diagram": {
    "title": "数据流图标题",
    "description": "数据流图说明",
    "diagramType": "STRIDE"
  },
  "components": [
    {
      "id": "为每个组件生成稳定的字符串标识，如 c1, c2, c3",
      "type": "actor|process|datastore|externalentity|trustboundary",
      "name": "组件名称（英文或中文）",
      "description": "组件职责说明",
      "lifecycle": "collect|store|use|exchange|delete（数据生命周期阶段，可选，见规范第 7 条）",
      "properties": {
        "isWebApplication": true/false,
        "isALog": true/false,
        "storesCredentials": true/false,
        "handlesCardPayment": true/false,
        "privilegeLevel": "组件权限级别描述",
        "protocol": "通信协议（仅数据流需要）",
        "isEncrypted": true/false,
        "isPublicNetwork": true/false,
        "isTrustBoundary": true/false
      }
    }
  ],
  "flows": [
    {
      "id": "唯一标识，如 f1, f2",
      "sourceId": "源组件 id",
      "targetId": "目标组件 id",
      "name": "数据流名称",
      "description": "传输的数据内容",
      "properties": {
        "protocol": "协议，如 HTTPS",
        "isEncrypted": true/false,
        "isPublicNetwork": true/false
      }
    }
  ]
}

严格要求：
1. 组件类型只允许：actor, process, datastore, externalentity, trustboundary。
2. actor 表示外部用户/系统；process 表示处理逻辑；datastore 表示数据存储；
   externalentity 表示外部实体；trustboundary 表示信任边界（如有）。
3. 数据流（flows）描述组件之间传递数据的方向，sourceId/targetId 必须引用 components 中已定义的 id。
4. 组件数量应覆盖文档中出现的所有关键组件，通常在 5~15 个之间。
5. 必须基于文档内容分析，不要臆造不存在的组件。
6. 所有字段 key 保持英文（与 Threat Dragon 兼容），值类字段（title/description/name、
   summary.title、summary.description、summary.owner 等自由文本）必须使用简体中文输出。
   专有名词、协议名（如 HTTPS/TLS/OAuth2/JWT）、CWE 编号可直接英文。
7. **数据生命周期阶段（lifecycle）**：为每个非信任边界组件标注其在数据生命周期中的阶段，
   便于数据流图按泳道分组展示，取值仅限：
   - collect（数据收集）：外部实体/设备/入口采集数据，如用户 App、传感器、第三方回调入口
   - store（数据存储）：存储数据，如数据库、缓存、对象存储、日志库
   - use（数据使用）：消费/处理/展示数据，如业务服务、AI 分析、看板
   - exchange（数据交换）：对外提供或共享数据，如开放 API、推送、数据同步、导出
   - delete（数据删除）：清理/删除/归档数据，如清理任务、注销删除服务
   trustboundary（信任边界）可不标注 lifecycle；每个组件只能标注一个阶段，若无明显归属可省略。

DFD 建模规范（务必遵循，避免常见建模错误）：
1. **CDN / 静态页面 / 静态资源 / 对象存储 / S3 / OSS / Bucket / Blob / 数据库 / MySQL /
   PostgreSQL / MongoDB / Redis / Kafka / 队列 / 缓存 / 数据湖 / 数据仓库 等**以「存」/「取」
   为核心职责的组件，type 必须为 **datastore**，绝不能建成 process。
2. **Actor（外部用户/系统）不应作为数据流的中间节点**：actor 仅表示触发者 / 接收者，
   不要给 actor 同时配置入流和出流。如果「用户手机端 App」与「外部用户」是同一主体，
   应建模为一个 process（H5 App / Mobile App），不要把「用户」也建成 actor。
3. **涉及敏感数据的数据流**（健康/医疗/体征/身份证/手机号/支付/交易/订单/密码/密钥/
   token/session/HTTPS/TLS/OAuth/JWT 等）→ properties.isEncrypted 必须为 true。
4. **跨公网/无线/BLE/WiFi/4G/5G 的数据流** → properties.isPublicNetwork 必须为 true。
5. **手机端 App ↔ 后端服务 / H5 ↔ 后端 / 第三方支付回调**等必经公网链路，
   properties.protocol 写明 HTTPS / TLS / MQTT 等具体协议，并按上述规则标记加密与公网。
6. **信任边界（trustboundary）必须存在**：至少划分「用户侧（公网）」与「服务侧（内网）」两层，
   所有跨边界的流都要标记 isPublicNetwork。
7. **数据/数据内容不是组件**：「健康数据」「订单数据」「日志」「用户信息」等
   表示「数据本身」的词是数据流的传输内容，**不能建成组件**；它们只能作为
   数据流的 description 或 name 出现。
8. **数据采集与处理链路必须显式建模**：用户/设备/外部实体不应直接连到 datastore
   （包括 S3/OSS/MySQL 等）。必须经由至少一个 process（如「业务后端服务」「数据接入服务」
   「网关」）中转,典型链路：
   - 设备/用户 → [采集/接入网关 process] → [业务后端 process] → [数据存储 datastore]
   - 用户 → [客户端 App process] → [API 网关 process] → [业务后端 process] → [DB]
9. **必建模的关键 process 类型**（覆盖绝大多数系统）:
   - 「客户端/App/前端/H5/小程序」→ type=process(presentation)
   - 「API 网关/接入网关/认证服务」→ type=process
   - 「业务后端/核心服务/订单服务/支付服务/数据服务/同步服务」→ type=process
   - 「AI 推理/分析服务/告警服务」→ type=process
10. **设备/传感器/边缘节点接入场景的特殊建模**（适用于一切设备接入型系统，
    包括物联网、车联网、工业、健康、智能家居等）：「蓝牙/WiFi/NB-IoT/LoRa/
    穿戴设备/传感器/工业设备/摄像头/边缘网关」等外部实体 → 必须经过
    「设备接入网关/数据采集服务/边缘服务」(process) → 再由 process 写入 datastore。
    不要把任何设备/外部实体直接连到 datastore。
"""

    def __init__(self, llm_client: LLMClient) -> None:
        self.llm = llm_client

    async def analyze(
        self,
        requirements: str,
        architecture: str,
        images: list[str] | None = None,
        progress: Any = None,
        methodology: str = "STRIDE",
        image_data_uris: list[str] | None = None,
    ) -> dict[str, Any]:
        """分析文档，返回 DFD 元素数据。

        Args:
            requirements: 需求文档文本内容。
            architecture: 产品架构设计文档文本内容。
            images: 可选的图片描述文本列表。
            progress: 可选的回调，形如 ``callable(message: str)``，用于上报真实进度。
            methodology: 威胁建模方法论（STRIDE/CIA/CIADIE/LINDDUN/PLOT4ai/EOP）。
            image_data_uris: 可选的文档内嵌图片 data URI 列表，以多模态方式直接
                交给 LLM 分析（架构图/数据流图等）。模型不支持图片时自动降级为纯文本。

        Returns:
            包含 summary, diagram, components, flows 的字典。
        """
        method = normalize_methodology(methodology)
        method_hint = ""
        if method == "STRIDE-AI":
            # STRIDE-AI：要求提取 AI 专用元素类型与 AI 属性
            method_hint = (
                "\n本次威胁建模采用方法论 STRIDE-AI，需针对大模型/智能体/RAG 等 AI 系统做威胁建模。\n"
                "在提取组件时，除 actor/process/datastore 外，请额外识别并输出以下 AI 专用元素类型：\n"
                "- type=model：大语言模型/推理服务（属性 isLLMService=true, hasTools/hasRAG 按需）\n"
                "- type=prompt：系统提示词/指令模板（属性如 isSystemPrompt=true）\n"
                "- type=vectorstore：向量数据库/RAG 知识库（属性 isVectorStore=true）\n"
                "- type=tool：工具/API/Agent 可调用能力（属性 hasTools=true 所在进程对应）\n"
                "- type=trainingdata：训练/微调数据集（属性如 storesTrainingData=true）\n"
                "- type=agentconfig：智能体配置（属性如 privilegeLevel）\n"
                "同时为 process 补充 AI 相关属性：isLLMService, hasRAG, hasTools, privilegeLevel。"
            )
        elif method != "STRIDE":
            # 非 STRIDE 方法论下，DFD 提取侧重对应威胁类型，并在 diagram 中记录
            example = get_threat_types_by_element(method, "process")
            method_hint = (
                f"\n本次威胁建模采用方法论 {method}，"
                f"其关注的主要威胁类型为：{', '.join(example)}。\n"
                f"请在提取组件时充分考虑这些威胁视角相关的数据流与属性。"
            )

        image_section = ""
        if images:
            image_section = "\n\n【架构图/流程图描述】\n" + "\n".join(images)

        multimodal_hint = ""
        if image_data_uris:
            multimodal_hint = (
                "\n\n【随文档提供的架构图/数据流图/截图（图片）】\n"
                "上方文本之外，还随本次请求附带了 N 张文档内嵌图片（架构图、数据流图、"
                "部署拓扑等）。请仔细阅读这些图片，从中识别组件、数据流与信任边界，"
                "并纳入 DFD 元素提取结果。图片信息优先于纯文本描述，且不要臆造图片中不存在的组件。"
            )

        user_prompt = f"""
【需求文档】
{requirements}

【产品架构设计文档】
{architecture}
{image_section}
{multimodal_hint}
{method_hint}

请分析以上文档（含附带的架构图/数据流图图片），提取完整的数据流图元素。如果信息不完整，请基于文档内容做合理推断。
"""

        if progress:
            progress("正在解析需求与架构文档…")
        # 结构化输出：锁定 DFD 字段结构、元素类型枚举与数量上下界，抑制随机性
        from .output_schema import DFD_JSON_SCHEMA

        result = await self.llm.complete_json(
            self.SYSTEM_PROMPT,
            user_prompt,
            json_schema=DFD_JSON_SCHEMA,
            images=image_data_uris,
        )
        validated = self._validate(result, method)
        if progress:
            progress(
                f"文档解析完成：识别出 {len(validated['components'])} 个组件、"
                f"{len(validated['flows'])} 条数据流"
            )

        # 方案 A：两阶段提取 —— 基于结构自检结果让 LLM 补全/修正。
        # 只有当存在可判定的结构缺陷时才触发，避免每次无条件多一次调用。
        if getattr(settings, "dfd_refine_enabled", True):
            refine = await self._refine_async(
                requirements, architecture, images, image_data_uris, method,
                validated, progress,
            )
            if refine is not None:
                validated = refine
        return validated

    async def _refine_async(
        self,
        requirements: str,
        architecture: str,
        images: list[str] | None,
        image_data_uris: list[str] | None,
        method: str,
        validated: dict[str, Any],
        progress: Any = None,
    ) -> dict[str, Any] | None:
        """两阶段提取的第二阶段：结构自检 + LLM 补全。

        仅当骨架存在可判定的结构缺陷时才发起一次 LLM 自省调用，让其
        基于文档原文补全缺失组件/修正错误归属；无缺陷时直接返回 None
        （不产生额外调用）。任何失败都静默降级为原结果，不影响主流程。
        """
        comps = validated.get("components", [])
        flows = validated.get("flows", [])
        defects = _structural_defects(comps, flows)

        # 数量下界门禁：即使结构无缺陷，骨架过薄也视为"可能漏了关键元素"，
        # 触发一次 LLM 自省补全——否则首轮采样漏组件却因"结构自洽"而永不补全。
        # 规则（跨方法论/行业通用，纯数量判断）：
        #   - 无任何 process 或 无任何 datastore → 缺骨架主干，必补；
        #   - 无任何 actor/externalentity（外部实体）→ 缺输入侧，必补；
        #   - 组件总数 < 2 或 数据流为 0 → 骨架过薄，必补。
        def _skeleton_too_thin() -> bool:
            types = {str(c.get("type", "")).lower() for c in comps}
            non_empty = [c for c in comps if str(c.get("name") or "").strip()]
            if not non_empty:
                return True
            if not (types & {"process"}):
                return True
            if not (types & {"datastore", "vectorstore", "trainingdata"}):
                return True
            if not (types & {"actor", "externalentity"}):
                return True
            if len(comps) < 2:
                return True
            if not flows:
                return True
            return False

        if not defects and not _skeleton_too_thin():
            return None

        # 供 LLM 参照的当前组件/流清单
        comp_list = "\n".join(
            f"- [{c.get('id')}] {c.get('name')} (type={c.get('type')}, lifecycle={c.get('lifecycle') or '-'})"
            for c in comps
        ) or "(无)"
        flow_list = "\n".join(
            f"- {f.get('name')}: {f.get('sourceId')} → {f.get('targetId')}"
            for f in flows
        ) or "(无)"

        if defects:
            defect_list = "\n".join(f"- {d}" for d in defects)
        else:
            # 无结构缺陷，但骨架过薄触发补全：明确告知 LLM 触发原因，
            # 请它对照原文确认是否漏了关键元素，避免它"无事可做"。
            types = {str(c.get("type", "")).lower() for c in comps}
            reasons = []
            if not (types & {"process"}):
                reasons.append("缺少任何后台处理服务（process）")
            if not (types & {"datastore", "vectorstore", "trainingdata"}):
                reasons.append("缺少任何数据存储（datastore/vectorstore）")
            if not (types & {"actor", "externalentity"}):
                reasons.append("缺少任何外部实体（actor/externalentity）")
            if len(comps) < 2:
                reasons.append("组件总数过少")
            if not flows:
                reasons.append("没有任何数据流")
            defect_list = (
                "- 数量下界门禁触发：当前 DFD 骨架过薄。请对照文档原文判断以下是否确实缺失：\n"
                + "\n".join(f"  * {r}" for r in reasons)
                + "\n- 若原文确实存在相应元素，请补全；若文档本身就只有这些内容，则不要臆造。"
            )
        method_hint = ""
        if method == "STRIDE-AI":
            method_hint = (
                " 注意本模型采用 STRIDE-AI，缺失组件可能是 AI 元素"
                "（model/prompt/vectorstore/tool/trainingdata/agentconfig）。"
            )
        elif method != "STRIDE":
            method_hint = (
                f" 注意本模型采用 {method}，请结合该方法论关注的威胁类型判断缺失组件。"
            )

        from .output_schema import DFD_REFINE_SCHEMA

        sys_prompt = (
            "你是资深安全架构师。第一轮已从文档提取出 DFD 骨架，但存在以下结构缺陷。\n"
            "请基于**文档原文**判断哪些缺陷需要补全/修正：\n"
            "1. 缺失的关键组件（如后台处理服务 process、数据存储 datastore 等），"
            "仅当原文确实提到时才补，不得臆造；\n"
            "2. 缺失的关键数据流（存储类组件应经由 process 中转等）；\n"
            "3. 不要修改已有的、正确的组件/流——只输出**新增/修正**的部分。\n"
            "仅输出 JSON（不要任何其他内容），newComponents/newFlows 中的元素 name 必须"
            "引用或基于原文命名，type 用合法枚举。"
        )
        user_prompt = (
            f"【文档原文】\n需求:{requirements}\n架构:{architecture}\n"
            f"{('图片描述:' + chr(10) + chr(10).join(images)) if images else ''}\n\n"
            f"【当前 DFD 骨架】\n组件:\n{comp_list}\n数据流:\n{flow_list}\n\n"
            f"【检测到的结构缺陷】\n{defect_list}\n{method_hint}\n"
            "请按上述要求输出需要补全/修正的组件与数据流。"
        )
        if progress:
            progress("正在对 DFD 结构做自检与补全…")
        try:
            raw = await self.llm.complete_json(
                sys_prompt, user_prompt, json_schema=DFD_REFINE_SCHEMA,
                images=image_data_uris,
            )
        except Exception as exc:  # noqa: BLE001 - 自省失败降级，不影响主流程
            logger.warning("DFD 自省补全失败，已降级为原结果：%s", exc)
            return None

        merged = self._apply_refine(validated, raw, defects)
        if progress:
            progress(
                f"DFD 自检补全完成：{len(merged['components'])} 个组件、"
                f"{len(merged['flows'])} 条数据流"
            )
        return merged
    def _apply_refine(
        self,
        validated: dict[str, Any],
        raw: dict[str, Any],
        defects: list[str],
    ) -> dict[str, Any]:
        """把 LLM 自省补全结果合并回骨架（确定性、保守合并）。"""
        comps = list(validated.get("components", []))
        flows = list(validated.get("flows", []))
        existing_names = {_norm_name(str(c.get("name") or "")) for c in comps}
        id_by_name = {_norm_name(str(c.get("name") or "")): c.get("id") for c in comps}
        new_comp_ids: dict[str, dict[str, Any]] = {}

        for nc in raw.get("newComponents") or []:
            nname = str(nc.get("name") or "").strip()
            if not nname or _norm_name(nname) in existing_names:
                continue
            ctype = str(nc.get("type") or "").lower()
            if ctype not in ALLOWED_TYPES:
                ctype = "process"
            cid = _stable_component_id(nname, ctype)
            comp = {
                "id": cid,
                "type": ctype,
                "name": nname,
                "description": str(nc.get("description") or ""),
                "lifecycle": str(nc.get("lifecycle") or "")
                if str(nc.get("lifecycle") or "") in _LIFECYCLE_SET
                else "",
                "properties": dict(nc.get("properties") or {}),
            }
            comps.append(comp)
            existing_names.add(_norm_name(nname))
            id_by_name[_norm_name(nname)] = cid
            new_comp_ids[_norm_name(nname)] = comp

        added_flow = 0
        for nf in raw.get("newFlows") or []:
            sname = str(nf.get("sourceName") or "")
            tname = str(nf.get("targetName") or "")
            if not sname or not tname:
                continue
            sid = id_by_name.get(_norm_name(sname))
            tid = id_by_name.get(_norm_name(tname))
            if not sid or not tid or sid == tid:
                continue
            fname = str(nf.get("name") or "") or f"{sname}\u2192{tname}"
            if any(
                str(f.get("sourceId")) == sid
                and str(f.get("targetId")) == tid
                and _norm_name(str(f.get("name") or "")) == _norm_name(fname)
                for f in flows
            ):
                continue
            flows.append(
                {
                    "id": _stable_flow_id(sid, tid, fname),
                    "sourceId": sid,
                    "targetId": tid,
                    "name": fname,
                    "description": str(nf.get("description") or ""),
                    "properties": dict(nf.get("properties") or {}),
                }
            )
            added_flow += 1

        comps.sort(key=lambda c: c["id"])
        flows.sort(key=lambda f: f["id"])
        diagram = dict(validated.get("diagram", {}) or {})
        log = list(diagram.get("autofixLog") or [])
        log.append(
            f"DFD 自检补全：基于 {len(defects)} 项结构缺陷，"
            f"新增 {len(new_comp_ids)} 个组件、{added_flow} 条数据流"
        )
        diagram["autofixLog"] = log
        return {
            "summary": validated.get("summary", {}),
            "diagram": diagram,
            "components": comps,
            "flows": flows,
        }

    def _validate(self, data: dict[str, Any], methodology: str = "STRIDE") -> dict[str, Any]:
        """校验并规范化 LLM 返回的数据。

        自动纠错（避免 LLM 输出明显错误）：
        - 组件名字命中关键字（CDN/数据库/S3 等）→ 自动修正 type=datastore
        - 数据流描述含敏感字段关键字（健康/支付/凭证/HTTPS 等）→ 自动 isEncrypted=true
        - 数据流描述含公网关键字（互联网/WiFi/BLE 等）→ 自动 isPublicNetwork=true
        所有修正会被记入 ``diagram["autofixLog"]``，供前端透出给用户审计。
        """
        components = data.get("components", [])
        flows = data.get("flows", [])

        # 记录方法论到 diagram.diagramType（与 Threat Dragon 对齐）
        diagram = data.get("diagram", {}) or {}
        if not diagram.get("diagramType"):
            diagram["diagramType"] = methodology

        # 收集自动纠错日志（不写入 Threat Dragon 模型数据本身，仅挂在 diagram 上）
        autofix_log: list[str] = []

        valid_components = []
        comp_names: set[str] = set()
        # LLM 原始组件 id -> 组件名（数据流 sourceId/targetId 常引用 id，需反查名字）
        llm_id_to_name: dict[str, str] = {}
        for comp in components:
            ctype = str(comp.get("type", "")).lower()
            if ctype not in ALLOWED_TYPES:
                ctype = "process"
            cname = str(comp.get("name", "") or "").strip() or "unnamed"
            comp_names.add(cname)
            orig_id = str(comp.get("id", "")).strip()
            if orig_id:
                llm_id_to_name[orig_id] = cname

            # 自动纠错：按名字关键字修正明显类型错误（仅在 LLM 给出明显错误时介入）
            hint = (cname + " " + str(comp.get("description") or "")).lower()
            new_type = _auto_fix_component_type(hint, ctype)
            if new_type and new_type != ctype:
                autofix_log.append(
                    f"组件「{cname}」类型 {ctype} \u2192 {new_type}（按名字关键字自动纠错）"
                )
                ctype = new_type

            props = comp.get("properties", {})
            lifecycle = comp.get("lifecycle", "")
            valid_components.append(
                {
                    "id": "",  # 骨架归一再生成稳定 id
                    "type": ctype,
                    "name": cname,
                    "description": comp.get("description", ""),
                    "lifecycle": lifecycle if lifecycle in _LIFECYCLE_SET else "",
                    "properties": props,
                }
            )

        valid_flows = []
        for flow in flows:
            src = str(flow.get("sourceId", ""))
            tgt = str(flow.get("targetId", ""))
            # 源/目标反查到组件名：优先 LLM id，其次按名字（骨架归一再重写稳定 id）
            def _resolve(node: str) -> str:
                if node in llm_id_to_name:
                    return llm_id_to_name[node]
                for cn in comp_names:
                    if _norm_name(node) == _norm_name(cn):
                        return cn
                return ""
            src_name = _resolve(src)
            tgt_name = _resolve(tgt)
            if not src_name or not tgt_name or src_name == tgt_name:
                continue  # 源/目标缺失或自环，丢弃

            props = dict(flow.get("properties", {}) or {})

            # 自动纠错：根据数据流名/描述推断加密与公网属性
            inferred = _auto_fix_flow_props(flow)
            if inferred["isEncrypted"] and not props.get("isEncrypted", False):
                props["isEncrypted"] = True
                autofix_log.append(
                    f"数据流「{flow.get('name') or (src + '\u2192' + tgt)}」自动标记 isEncrypted=true（敏感数据）"
                )
            if inferred["isPublicNetwork"] and not props.get("isPublicNetwork", False):
                props["isPublicNetwork"] = True
                autofix_log.append(
                    f"数据流「{flow.get('name') or (src + '\u2192' + tgt)}」自动标记 isPublicNetwork=true（跨公网）"
                )

            valid_flows.append(
                {
                    "id": "",
                    "sourceId": src_name,
                    "targetId": tgt_name,
                    "name": flow.get("name", ""),
                    "description": flow.get("description", ""),
                    "properties": props,
                }
            )

        # ------------------------------------------------------------------
        # 方案 A：DFD 骨架确定性归一
        # 把 LLM 提取的组件/数据流归一到「稳定骨架」上：
        #   1) 组件/数据流 id 改为确定性哈希（弃用 LLM 编 id / 随机 uuid）
        #   2) 同名组件合并、同 (源,目标,名) 数据流去重
        #   3) 按稳定 id 排序
        # 从而使同一文档即使改动无关文字、LLM 重新提取，核心结构不漂移。
        # ------------------------------------------------------------------
        skeleton_comps, skeleton_flows, skeleton_log = _skeleton_normalize(
            valid_components, valid_flows
        )
        if skeleton_log:
            autofix_log.extend(skeleton_log)

        if autofix_log:
            diagram["autofixLog"] = list(autofix_log)

        return {
            "summary": data.get("summary", {}),
            "diagram": diagram,
            "components": skeleton_comps,
            "flows": skeleton_flows,
        }
