"""DFD AI 自校验服务（DFDReviewer）。

在 Threat Dragon 模型构建完成后，对 LLM 首次生成的 components + flows 做一次
「AI 二次自查 + 确定性纠偏」：

1. 把 components/flows 序列化为 JSON 交给 LLM，要求按一套固定规则自查；
2. 模型返回 issues[]（发现的问题）与 fixed_components/fixed_flows（建议修正）；
3. 本服务只采纳满足确定性约束的修正（id 必须存在、类型/lifecycle 必须合法、
   数据流不得自环），其余字段原样保留 —— 防止 AI 乱改结构；
4. 校验发现的问题与修正动作写入 reviewLog，随 dfd_autofix 透出前端审计。

设计原则：
- 自校验是「增强」而非「阻塞」：任何异常 / 超时 / 非法返回都静默降级为
  原始 components/flows，绝不让该步骤拖垮主流程；
- 修正只做「收敛」：类型非法→process、lifecycle 非法→删除、自环流→删除、
  重复流→去重。不新增/不删除未要求的实体，保持与 document_analyzer._validate
  一致的口径，避免二次漂移。
"""
from __future__ import annotations

import logging
import re
from typing import Any

from .llm_client import LLMClient
from .output_schema import COMPONENT_TYPE_ENUM, LIFECYCLE_ENUM

logger = logging.getLogger(__name__)

# 允许 AI 自查修正的组件类型 / 生命周期（与 DFD 提取 schema 一致）
_REVIEW_TYPES: set[str] = set(COMPONENT_TYPE_ENUM)
_REVIEW_LIFECYCLE: set[str] = set(LIFECYCLE_ENUM)

# ---------------------------------------------------------------------------
# 通用「组件角色 × 生命周期」归一化规则（纯编程、零 LLM、跨方法论 / 行业通用）
#
# 这些规则只依赖 DFD 语义（组件类型 + 名字里的角色词），不含任何具体业务 /
# 场景关键词，因此对所有方法论（STRIDE / STRIDE-AI / CIA / LINDDUN / VAST …）
# 与所有行业生成的数据流图都适用。作用是收敛 LLM 首次生成时常见的
# 「组件被标到了错误的数据生命周期阶段」问题，使布局泳道更合理。
# ---------------------------------------------------------------------------

def _re(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# 前端 / 客户端类角色词（这类 process 是交互发起方，不应落在后端处理阶段）
_FRONTEND_NAME = _re(
    r"前端|客户端|app|web|h5|小程序|浏览器|dashboard|portal|sdk|终端应用|"
    r"frontend|client"
)
# 外部实体 / 参与者（用户、浏览器、第三方、设备等），作为数据流端点
_EXTERNAL_NAME = _re(
    r"用户|浏览器|顾客|访客|患者|公民|管理员|操作员|消费者|商户|司机|"
    r"设备|传感器|穿戴|摄像头|终端|iot|第三方|供应商|合作伙伴|银行|支付|"
    r"user|browser|customer|patient|citizen|admin|operator|consumer|"
    r"merchant|driver|device|sensor|camera|wearable|terminal|iot|"
    r"third.?party|supplier|partner|bank|payment"
)
# 存储 / 数据库类角色词
_STORE_NAME = _re(
    r"数据库|存储|缓存|仓库|存档|备份|湖|库|dwh|db|mysql|postgres|redis|"
    r"sqlserver|oracle|mongodb|s3|bucket|warehouse|cache|repository|archive"
)

# 内部处理阶段（不应分配给「外部实体 / 前端」的 lifecycle）
# 7 阶段：transit/process/use/store/delete 都是"内网/内部"语义，
# 外部实体/前端被误标到这些阶段时统一回退到 collect。
_INTERNAL_LIFECYCLES = {"transit", "store", "process", "use", "delete"}
# 外部实体 / 前端这类「端点型」组件应归属的阶段（交互起点）
_ENDPOINT_LIFECYCLE = "collect"
# 存储类组件应归属的阶段（缺省落到 store）
_STORE_LIFECYCLE = "store"

# DFD 自校验输出的 JSON Schema（结构化输出强约束）
DFD_REVIEW_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["issues", "fixed_components", "fixed_flows"],
    "additionalProperties": True,
    "properties": {
        "issues": {
            "type": "array",
            "description": "自查发现的问题清单（每条含 组件/流 引用 + 问题描述 + 严重程度）",
            "items": {
                "type": "object",
                "required": ["type", "description"],
                "additionalProperties": True,
                "properties": {
                    "type": {
                        "type": "string",
                        "enum": [
                            "component_type",
                            "component_lifecycle",
                            "flow_self_loop",
                            "flow_duplicate",
                            "flow_dangling",
                            "missing_component",
                            "boundary_scope",
                            "semantic",
                        ],
                    },
                    "ref": {"type": "string", "description": "组件或流的 id"},
                    "name": {"type": "string", "description": "组件或流的名字（便于阅读）"},
                    "severity": {"type": "string", "enum": ["info", "warning", "error"]},
                    "description": {"type": "string"},
                    "suggestion": {"type": "string"},
                },
            },
        },
        "fixed_components": {
            "type": "array",
            "description": "修正后的组件（只填要修正的字段；id 必须来自原 components）",
            "items": {
                "type": "object",
                "required": ["id", "type", "name"],
                "additionalProperties": True,
                "properties": {
                    "id": {"type": "string", "minLength": 1},
                    "type": {"type": "string", "enum": COMPONENT_TYPE_ENUM},
                    "name": {"type": "string", "minLength": 1},
                    "description": {"type": "string"},
                    "lifecycle": {"type": "string", "enum": LIFECYCLE_ENUM},
                    "properties": {"type": "object", "additionalProperties": True},
                },
            },
        },
        "fixed_flows": {
            "type": "array",
            "description": "修正后的流（只填要修正的字段；id 必须来自原 flows）",
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
                    "properties": {"type": "object", "additionalProperties": True},
                },
            },
        },
    },
}

SYSTEM_PROMPT = (
    "你是一名资深的安全架构评审专家，负责对 AI 生成的数据流图（DFD）做最终合理性自查。"
    "你会收到一份 components（组件）和 flows（数据流）的 JSON。"
    "请按以下规则逐项检查，并把发现的问题和修正建议用 JSON 返回。\n\n"
    "检查规则：\n"
    "1. component_type：组件 type 是否语义合理。例如名字含『数据库/缓存/存储』的组件"
    "   type 应为 datastore；含『API 网关/前端/服务』的应为 process；含『用户/浏览器/设备』"
    "   的应为 actor/externalentity。若明显错配，请在 fixed_components 里给出正确 type。\n"
    "2. component_lifecycle：lifecycle 是否与该组件的数据生命周期阶段匹配"
    "   （collect 采集 / transit 传输 / store 存储 / process 处理 / use 使用 /"
    " exchange 交换 / delete 删除）。"
    "   明显不符的可修正，但不要对没有 lifecyclc 的组件凭空补。\n"
    "3. flow_self_loop：数据流的 sourceId == targetId（自环）应报告。\n"
    "4. flow_duplicate：多条流 sourceId+targetId+name 完全相同时应报告，仅保留一条。\n"
    "5. flow_dangling：流的 sourceId/targetId 在 components 中不存在时，应报告该悬空引用。\n"
    "6. missing_component：数据流两端明显应当存在的关键组件缺失时报告。典型情形：\n"
    "   - 有 datastore/vectorstore 存储组件，但没有任何 process 作为中间处理方，存储被"
    "     外部实体直接读写（存储必须经由一个内部 process 中转）；\n"
    "   - 数据采集（collect）侧的外部实体与数据存储（store）之间缺少应有的内部 process。\n"
    "7. boundary_scope：信任边界（trustboundary）是其内部子系统/进程的容器。\n"
    "   - 不应把 actor/externalentity（用户、浏览器、第三方、设备等外部实体）放进任何"
    "     trustboundary —— 外部实体在信任边界之外；\n"
    "   - 若某 trustboundary 包含了外部实体，请报告，并建议其正确的归属。\n"
    "8. semantic：其余影响图合理性的语义问题（如明显不该连通的组件之间有直连流）。\n\n"
    "输出要求：\n"
    "- issues 列出所有发现的问题，每条含 type/ref/name/severity/description/suggestion。\n"
    "  severity 用 info（轻微）/warning（应修）/error（必须修）。\n"
    "- fixed_components / fixed_flows：只列出你需要修正的对象，且每个对象的 id 必须是"
    "  原数据中存在的 id，字段用『修正后的完整值』（id/name/type/lifecycle 等）。\n"
    "  没有修正需求的就留空数组。\n"
    "- 不要随意新增或删除组件/流；不要改动 id；不要改 properties 里的业务字段。\n"
)

REVIEW_PROMPT = (
    "请对下面的数据流图元素做合理性自查。\n"
    "组件与数据流的 JSON 如下：\n\n{json}\n\n"
    "请输出 issues（问题清单）与修正后的 fixed_components / fixed_flows。"
)


class DFDReviewer:
    """DFD 生成后的 AI 自校验 + 确定性纠偏。"""

    def __init__(self, llm: LLMClient) -> None:
        self._llm = llm

    async def review(
        self,
        components: list[dict[str, Any]],
        flows: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """对 components + flows 做 AI 自校验。

        Returns:
            {"components": <修正后的组件列表>, "flows": <修正后的流列表>,
             "log": [<自校验日志条目 str>]}
            任何异常都返回原始 components/flows 与一条错误日志（不抛出）。
        """
        original = (components, flows)
        try:
            payload = self._serialize(components, flows)
            raw = await self._llm.complete_json(
                SYSTEM_PROMPT,
                REVIEW_PROMPT.format(json=payload),
                # DFD 元素序列化可能远超默认 12000 字符，必须调大避免截断
                max_input_chars=60000,
                json_schema=DFD_REVIEW_SCHEMA,
            )
        except Exception as exc:  # 自校验失败不影响主流程
            logger.warning("DFD AI 自校验失败，使用原结果：%s", exc)
            return {
                "components": components,
                "flows": flows,
                "log": [f"[自校验] 执行失败，已跳过（{type(exc).__name__}）"],
            }

        if not isinstance(raw, dict):
            return {
                "components": components,
                "flows": flows,
                "log": ["[自校验] 返回格式非法，已跳过"],
            }

        # 确定性纠偏：只采纳满足约束的修正
        comps = self._apply_component_fixes(components, raw.get("fixed_components"))
        flows_fixed = self._apply_flow_fixes(flows, raw.get("fixed_flows"), comps)
        flows_fixed = self._drop_self_loops(flows_fixed)
        flows_fixed = self._drop_duplicates(flows_fixed)
        # 通用角色×生命周期归一化兜底：纯编程、拓扑感知，确保「前端/外部/存储」
        # 类组件不落在错配的生命周期阶段，并用数据流方向补全缺省生命周期
        # （AI 修正可能遗漏，这里是确定性保证）
        comps = self._normalize_roles(comps, flows_fixed)

        # 生成日志：问题 + 实际采纳的修正
        log = self._build_log(raw.get("issues"), components, flows, comps, flows_fixed)
        changed = (comps, flows_fixed) != original
        logger.info(
            "DFD AI 自校验完成：%d 条问题，%s（%d 组件 %d 流）",
            len(log),
            "已修正" if changed else "无需修正",
            len(comps),
            len(flows_fixed),
        )
        return {"components": comps, "flows": flows_fixed, "log": log}

    # ---- 序列化 ----
    def _serialize(
        self,
        components: list[dict[str, Any]],
        flows: list[dict[str, Any]],
    ) -> str:
        import json

        # sort_keys=True：即使上游组件/流内 properties 键序不一致，序列化结果
        # 也按字典序稳定 → 保证同输入下 DFD 自校验 prompt 字节级一致 → 缓存稳定命中。
        return json.dumps(
            {"components": components, "flows": flows},
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )

    # ---- 确定性纠偏 ----
    def _apply_component_fixes(
        self,
        components: list[dict[str, Any]],
        fixes: Any,
    ) -> list[dict[str, Any]]:
        if not isinstance(fixes, list):
            return components
        fix_by_id: dict[str, dict[str, Any]] = {}
        for fx in fixes:
            if isinstance(fx, dict):
                cid = fx.get("id")
                if cid:
                    fix_by_id[cid] = fx

        out: list[dict[str, Any]] = []
        for c in components:
            cid = c.get("id")
            fx = fix_by_id.get(cid)
            if not fx:
                out.append(c)
                continue
            fixed = dict(c)
            # 类型：只接受合法枚举
            if fx.get("type") in _REVIEW_TYPES:
                fixed["type"] = fx["type"]
            # lifecycle：只接受合法枚举（缺失/非法则保留原值）
            if fx.get("lifecycle") in _REVIEW_LIFECYCLE:
                fixed["lifecycle"] = fx["lifecycle"]
            # name/description：仅当 AI 给出的非空值才采纳
            for field in ("name", "description"):
                if isinstance(fx.get(field), str) and fx[field].strip():
                    fixed[field] = fx[field]
            out.append(fixed)
        return out

    def _apply_flow_fixes(
        self,
        flows: list[dict[str, Any]],
        fixes: Any,
        components: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        comp_ids = {c.get("id") for c in components}
        if not isinstance(fixes, list):
            return flows
        fix_by_id: dict[str, dict[str, Any]] = {}
        for fx in fixes:
            if isinstance(fx, dict):
                fid = fx.get("id")
                if fid:
                    fix_by_id[fid] = fx

        out: list[dict[str, Any]] = []
        for f in flows:
            fid = f.get("id")
            fx = fix_by_id.get(fid)
            if not fx:
                # 悬空引用兜底：若源/目标在组件中不存在则丢弃（确定性收敛）
                if (f.get("sourceId") in comp_ids) and (f.get("targetId") in comp_ids):
                    out.append(f)
                continue
            fixed = dict(f)
            # 只采纳指向真实存在组件的源/目标修正
            for field in ("sourceId", "targetId"):
                v = fx.get(field)
                if isinstance(v, str) and v in comp_ids:
                    fixed[field] = v
            if isinstance(fx.get("name"), str) and fx["name"].strip():
                fixed["name"] = fx["name"]
            out.append(fixed)
        return out

    def _drop_self_loops(self, flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [f for f in flows if f.get("sourceId") != f.get("targetId")]

    def _drop_duplicates(self, flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[tuple[str, str, str]] = set()
        out: list[dict[str, Any]] = []
        for f in flows:
            key = (f.get("sourceId") or "", f.get("targetId") or "", f.get("name") or "")
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out

    def _normalize_roles(
        self,
        components: list[dict[str, Any]],
        flows: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """通用「组件角色 × 生命周期」确定性归一化（零 LLM，拓扑感知）。

        只做收敛/补全：把错配或缺省的 lifecycle 归到合理阶段；不改 type（type
        由 AI 修正负责）；不新增/删除组件。依据优先级从高到低：

          1. 类型 + 名字角色词（前端/外部/存储）——确定性硬规则；
          2. 数据流拓扑方向（数据源端点→collect、汇聚端点→store、
             中间转发→exchange、前端→exchange）——让泳道服从真实数据流；
          3. 仅当既无角色词、拓扑又能唯一判定时才推断，否则保留原值。

        跨方法论 / 行业通用，保证同输入结果完全确定。
        """
        # 拓扑统计：每组件入边/出边数
        out_deg: dict[str, int] = {}
        in_deg: dict[str, int] = {}
        for f in flows:
            s = str(f.get("sourceId") or "")
            t = str(f.get("targetId") or "")
            if s:
                out_deg[s] = out_deg.get(s, 0) + 1
            if t:
                in_deg[t] = in_deg.get(t, 0) + 1

        def _infer(
            ctype: str, name: str,
            lifecycle: str | None, cid: str,
        ) -> str | None:
            """返回应采用的 lifecycle；None 表示保持现状/跳过。"""
            lc = lifecycle.lower() if lifecycle else None

            if ctype == "trustboundary":
                return ""  # 容器，不落生命周期

            # 1) 硬规则：类型 + 角色词
            if ctype in ("actor", "externalentity"):
                if lc in _INTERNAL_LIFECYCLES or not lc:
                    return _ENDPOINT_LIFECYCLE
                return None  # 已是端点阶段（collect/exchange）
            if ctype in ("datastore", "vectorstore"):
                if lc not in ("store", "delete"):
                    return _STORE_LIFECYCLE
                return None

            # process 类
            if _FRONTEND_NAME.search(name):
                return "exchange"

            # 2) 拓扑推导（仅当能唯一判定且当前阶段不符）
            if lc is None:
                # 缺省生命周期：用拓扑补
                if cid in out_deg and cid in in_deg:
                    return "exchange"      # 中间转发
                if cid in in_deg and cid not in out_deg:
                    return "store"         # 汇聚端点（落库/使用）
                if cid in out_deg and cid not in in_deg:
                    return "collect"       # 数据源端点
                return None
            # 已有阶段但与拓扑冲突（确定性可判定的部分）
            if cid in out_deg and cid in in_deg and lc == "collect":
                return "exchange"
            return None

        out: list[dict[str, Any]] = []
        for c in components:
            cid = str(c.get("id") or "")
            ctype = str(c.get("type") or "").lower()
            name = str(c.get("name") or "")
            lifecycle = c.get("lifecycle")

            if ctype not in _REVIEW_TYPES:
                out.append(c)
                continue

            new_lc = _infer(ctype, name, lifecycle, cid)
            if new_lc == "":
                # trustboundary：去掉生命周期
                if lifecycle:
                    fixed = dict(c)
                    fixed.pop("lifecycle", None)
                    out.append(fixed)
                else:
                    out.append(c)
            elif new_lc and new_lc != (str(lifecycle).lower() if lifecycle else None):
                fixed = dict(c)
                fixed["lifecycle"] = new_lc
                out.append(fixed)
            else:
                out.append(c)
        return out

    # ---- 日志 ----
    def _build_log(
        self,
        issues: Any,
        orig_components: list[dict[str, Any]],
        orig_flows: list[dict[str, Any]],
        new_components: list[dict[str, Any]],
        new_flows: list[dict[str, Any]],
    ) -> list[str]:
        log: list[str] = []
        if isinstance(issues, list):
            for it in issues[:30]:  # 限制条数，避免日志膨胀
                if not isinstance(it, dict):
                    continue
                sev = it.get("severity") or "info"
                desc = str(it.get("description") or "").strip()
                if desc:
                    log.append(f"[自校验·{sev}] {desc}")

        # 记录实际采纳的组件修正
        for oc, nc in zip(orig_components, new_components):
            if oc.get("type") != nc.get("type"):
                log.append(
                    f"[自校验·修正] 组件「{oc.get('name', '')}」类型 "
                    f"{oc.get('type')} → {nc.get('type')}"
                )
            elif oc.get("lifecycle") != nc.get("lifecycle"):
                log.append(
                    f"[自校验·修正] 组件「{oc.get('name', '')}」生命周期 "
                    f"{oc.get('lifecycle')} → {nc.get('lifecycle')}"
                )

        # 记录流的修正（源/目标/名字变化）
        orig_by_id = {f.get("id"): f for f in orig_flows}
        for nf in new_flows:
            of = orig_by_id.get(nf.get("id"))
            if of is None:
                continue
            if (
                of.get("sourceId") != nf.get("sourceId")
                or of.get("targetId") != nf.get("targetId")
                or of.get("name") != nf.get("name")
            ):
                log.append(
                    f"[自校验·修正] 数据流「{nf.get('name', '')}」端点/名称已校正"
                )

        removed = len(orig_flows) - len(new_flows)
        if removed > 0:
            log.append(f"[自校验·修正] 移除 {removed} 条异常数据流（自环/悬空/重复）")
        return log
