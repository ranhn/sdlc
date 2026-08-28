"""威胁分析器：基于 DFD 数据流图自动识别威胁。

支持多种威胁建模方法论（STRIDE / CIA / CIADIE / LINDDUN / PLOT4ai / EOP），
结合方法论规则库与 LLM 推理，为每个组件与数据流生成威胁与缓解措施。
数据字段完全兼容 Threat Dragon v2 威胁模型格式。
"""

from __future__ import annotations

import difflib
import logging
import re
import string
import uuid
from typing import Any

from ..config import settings
from .llm_client import LLMClient
from .methodology import (
    get_threat_types_by_element,
    normalize_methodology,
)
from .output_schema import build_threat_schema
from .rule_templates import get_rule_threat_template
from .severity_scorer import score_severity

logger = logging.getLogger(__name__)

# 风险等级（按严重度升序）：四档
SEVERITIES = ["Low", "Medium", "High", "Critical"]
SEVERITY_WEIGHT = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}

# 官方 Threat Dragon 威胁状态机
STATUSES = ["Open", "Mitigated", "NotApplicable"]

# 方法论 -> 各威胁类型的 CWE 关联提示（供 prompt 使用，提升威胁质量）
CWE_BY_METHODOLOGY = {
    "STRIDE": {
        "Spoofing": "CWE-287 (Improper Authentication), CWE-290 (Authentication Bypass)",
        "Tampering": "CWE-20 (Improper Input Validation), CWE-345 (Data Integrity)",
        "Repudiation": "CWE-778 (Insufficient Logging), CWE-353 (Integrity Check)",
        "Information Disclosure": "CWE-200 (Exposure of Sensitive Information), CWE-319 (Cleartext Transmission)",
        "Denial of Service": "CWE-400 (Resource Exhaustion), CWE-404 (Improper Resource Shutdown)",
        "Elevation of Privilege": "CWE-269 (Improper Privilege Management), CWE-732 (Incorrect Permission)",
    },
    "CIA": {
        "Confidentiality": "CWE-200 (Exposure of Sensitive Information), CWE-311 (Missing Encryption)",
        "Integrity": "CWE-20 (Improper Input Validation), CWE-345 (Data Integrity)",
        "Availability": "CWE-400 (Resource Exhaustion), CWE-404 (Improper Resource Shutdown)",
    },
    "CIADIE": {
        "Confidentiality": "CWE-200 (Exposure of Sensitive Information)",
        "Integrity": "CWE-345 (Data Integrity)",
        "Availability": "CWE-400 (Resource Exhaustion)",
        "Distributed": "CWE-1057 (Data Access without Authorization)",
        "Immutable": "CWE-690 (Unchecked Return Value)",
        "Ephemeral": "CWE-404 (Improper Resource Shutdown)",
    },
    "LINDDUN": {
        "Linkability": "CWE-359 (Exposure of Private Information)",
        "Identifiability": "CWE-200 (Exposure of Sensitive Information)",
        "Non-Repudiation": "CWE-778 (Insufficient Logging)",
        "Detectability": "CWE-404 (Improper Resource Shutdown)",
        "Disclosure of Information": "CWE-200 (Exposure of Sensitive Information)",
        "Unawareness": "CWE-1021 (Improper Handling of Exceptional Conditions)",
        "Non-Compliance": "CWE-1104 (Use of Unmaintained Third Party Components)",
    },
    "PLOT4ai": {
        "Technique & Processes": "CWE-16 (Configuration), CWE-1004 (Sensitive Cookie)",
        "Accessibility": "CWE-200 (Exposure of Sensitive Information)",
        "Identifiability & Linkability": "CWE-359 (Exposure of Private Information)",
        "Security": "CWE-693 (Protection Mechanism Failure)",
        "Safety": "CWE-1188 (Insecure Default Initialization of Resource)",
        "Unawareness": "CWE-1021 (Improper Handling of Exceptional Conditions)",
        "Ethics & Human Rights": "CWE-250 (Execution with Unnecessary Privileges)",
        "Non-Compliance": "CWE-1104 (Use of Unmaintained Third Party Components)",
    },
    "EOP": {
        "Authentication": "CWE-287 (Improper Authentication), CWE-306 (Missing Authentication)",
        "Authorization": "CWE-862 (Missing Authorization), CWE-863 (Incorrect Authorization)",
        "Cryptography": "CWE-327 (Use of Broken Crypto), CWE-311 (Missing Encryption)",
        "Data Validation & Encoding": "CWE-79 (XSS), CWE-89 (SQL Injection), CWE-20 (Improper Input Validation)",
        "Session Management": "CWE-613 (Insufficient Session Expiration), CWE-384 (Session Fixation)",
    },
    "STRIDE-AI": {
        "Spoofing": "CWE-287 (Improper Authentication), CWE-290 (Authentication Bypass), OWASP LLM03 (供应链)",
        "Tampering": "CWE-20 (Improper Input Validation), CWE-345 (Data Integrity), OWASP LLM01/LLM04 (提示注入/投毒)",
        "Repudiation": "CWE-778 (Insufficient Logging), OWASP LLM09 (AI 决策无溯源)",
        "Information Disclosure": "CWE-200 (Exposure of Sensitive Information), OWASP LLM02/LLM07/LLM08 (泄露)",
        "Denial of Service": "CWE-400 (Resource Exhaustion), OWASP LLM10 (无界消耗)",
        "Elevation of Privilege": "CWE-269 (Improper Privilege Management), OWASP LLM05/LLM06 (输出处理/过度代理)",
    },
}


_SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


def _sort_threats(threats: list[dict]) -> list[dict]:
    """确定性排序威胁列表。

    去重后 threat 顺序仍受 LLM 输出顺序影响，前端渲染/导出会随采样波动。
    这里按 (componentId, type, severity, title) 稳定排序——内容不变、仅锁顺序，
    保证同输入 → 威胁列表字节级一致（缓存稳定 + 渲染顺序可复现）。
    """
    return sorted(
        threats,
        key=lambda t: (
            str(t.get("componentId", "")),
            str(t.get("type", "")),
            _SEV_ORDER.get(str(t.get("severity", "")), 5),
            str(t.get("title", "")),
        ),
    )


class ThreatAnalyzer:
    """基于组件属性和方法论规则，借助 LLM 生成威胁条目。"""

    def __init__(self, llm_client: LLMClient) -> None:
        self.llm = llm_client

    # ------------------------------------------------------------------
    # Prompt 构建
    # ------------------------------------------------------------------
    def _build_system_prompt(
        self, methodology: str, industry_hint: str | None = None
    ) -> str:
        """按方法论动态构建系统提示。"""
        method = normalize_methodology(methodology)
        types_map = self._types_section(method)
        ai_rules = self._ai_rules_section(method)
        dread_section = self._dread_section(method)
        owasp_llm = self._owasp_llm_section(method)
        dread_field = (
            ', "dread": {"damage": 0, "reproducibility": 0, '
            '"exploitability": 0, "affectedUsers": 0, "discoverability": 0}, '
            '"dreadScore": 0'
            if method == "STRIDE-AI"
            else ""
        )
        dread_score_note = (
            "9. 对 STRIDE-AI 威胁必须给出 DREAD 五维评分（各 0~10，整数）："
            "damage 危害 / reproducibility 可重复性 / exploitability 可利用性 / "
            "affectedUsers 受影响面 / discoverability 可发现性，并计算 dreadScore=五维总和(0~50)。"
        )
        industry_block = (
            f"\n## 四、行业场景上下文\n{industry_hint}\n" if industry_hint else ""
        )
        return f"""
你是一名经验丰富的应用安全专家，精通 {method} 威胁建模，并遵循 OWASP Threat Dragon、OWASP Automated Threats 与 OWASP Top 10 for LLM 的方法论。
你将获得一个系统的数据流图（DFD）的组件（components）与数据流（flows）及其属性，需要为每个元素识别适用的 {method} 威胁。

## 一、{method} 威胁类型与元素类型的对应关系
{types_map}

## 二、元素属性驱动威胁判定（参考 OWASP Threat Dragon 上下文建议引擎）
根据元素的业务属性，主动触发对应的威胁类别（OWASP Automated Threats OAT 编号供参考，可不输出）：
- process.isPublicNetwork=true 且未加密：增加 Footprinting(OAT-006)/Eavesdropping/中间人攻击
- process.isWebApplication=true：增加 Web 注入/扫描/暴力破解类威胁（如 Content Injection OAT-014）
- process.handlesCardPayment=true：增加卡信息窃取类威胁（Carding OAT-001, Payment bypass）
- process.handlesGoodsOrServices=true：增加抢购/库存类威胁（Sniping OAT-017, Denial of Inventory OAT-018）
- process.privilegeLevel 较高（如 admin/root）：关注提权（Elevation of Privilege）与越权
- datastore.storesCredentials=true：增加凭据破解/撞库（Credential stuffing OAT-007）
- datastore.isALog=true：关注日志篡改/删除，破坏审计证据（破坏 Repudiation 防线）
- datastore.handlesCardPayment=true：增加支付敏感数据泄露
- flow.isPublicNetwork=true 且 isEncrypted=false：强烈提示数据明文在公网传输，信息泄露/篡改
- flow.isEncrypted=true：降低窃听风险，但仍应提示密钥管理与弱加密风险
- flow 跨信任边界：提示身份与完整性校验
- trustboundary 边界：识别跨越不同信任级别的数据流，重点检查越权与数据泄露
{ai_rules}
## 三、CWE 关联
每条威胁应尽量给出对应的 CWE（Common Weakness Enumeration）编号，例如：
{self._cwe_section(method)}
{owasp_llm}
{industry_block}
你必须严格按照以下 JSON 结构输出（不要输出任何其他内容）：

{{
  "threats": [
    {{
      "componentId": "元素 id（组件或数据流 id）",
      "type": "{method} 下该元素允许的威胁类型之一",
      "title": "威胁标题（简洁）",
      "severity": "Low | Medium | High | Critical",
      "status": "Open",
      "description": "详细的威胁描述，包括攻击场景",
      "mitigation": "具体的缓解措施，给出可操作的方案",
      "score": "风险评估（与 severity 一致的英文名）",
      "cwe": "CWE 编号，如 CWE-287；不确定时可留空字符串",
      "references": ["可选的参考资料链接，如 OWASP 文档；没有则留空数组"]
      {dread_field}
    }}
  ]
}}

严格要求：
1. 只为元素类型对应可用的 {method} 类型生成威胁，type 必须严格来自上述允许列表。
2. 威胁要贴合元素的实际职责和属性，主动运用上面的"属性驱动威胁判定"，不要泛泛而谈。
3. 数据流（flows）也要分析威胁，重点检查传输中的明文、公网、跨信任边界。
4. 每个元素生成 2~5 个高价值威胁，不必覆盖所有类型；尽量覆盖不同威胁类型而非堆砌单一类型。
5. severity 使用四档：Low/Medium/High/Critical，能导致数据泄露/提权/支付损失的通常为 High 或 Critical。
6. mitigation 必须具体、可执行，说明如何缓解该威胁。
7. componentId 必须使用输入中给出的元素 id（组件 id 或数据流 id）。
8. 自由文本类字段（title/description/mitigation）必须使用简体中文输出。
   仅以下三类内容允许保留英文：(a) severity/status/type 等枚举字段的英文值；
   (b) CWE 编号与缩写协议名；(c) references 数组中的合法 URL。
{dread_score_note}
"""

    @staticmethod
    def _types_section(methodology: str) -> str:
        method = normalize_methodology(methodology)
        base_keys = ["actor", "process", "datastore", "flow"]
        lines = []
        for cell_key in base_keys:
            types = get_threat_types_by_element(method, cell_key)
            lines.append(f"- {cell_key}: {', '.join(types)}")
        ext = get_threat_types_by_element(method, "actor")
        lines.append(f"- externalentity: {', '.join(ext)}")
        if method == "STRIDE-AI":
            for cell_key in [
                "model", "prompt", "vectorstore", "tool",
                "trainingdata", "agentconfig",
            ]:
                types = get_threat_types_by_element(method, cell_key)
                lines.append(f"- {cell_key}: {', '.join(types)}")
        return "\n".join(lines)

    @staticmethod
    def _cwe_section(methodology: str) -> str:
        method = normalize_methodology(methodology)
        mapping = CWE_BY_METHODOLOGY.get(method, CWE_BY_METHODOLOGY["STRIDE"])
        return "\n".join(f"- {k}: {v}" for k, v in mapping.items())

    @staticmethod
    def _ai_rules_section(methodology: str) -> str:
        """STRIDE-AI 下补充 AI 属性驱动判定规则。"""
        method = normalize_methodology(methodology)
        if method != "STRIDE-AI":
            return ""
        return (
            "\n### AI 特定威胁判定规则（STRIDE-AI，参考 OWASP Top 10 for LLM）\n"
            "- process.isLLMService=true 或 type=model：提示注入(LLM01)、模型窃取/权重篡改、无限 token 消耗(LLM10)、决策无溯源\n"
            "- process.hasRAG=true 或 type=vectorstore：RAG 知识库投毒(LLM08)、语义越权检索、向量库击穿导致拒绝服务\n"
            "- process.hasTools=true 或 type=tool：工具调用风暴、越权工具滥用(LLM06)、Agent 过度代理(LLM06)\n"
            "- process.hasTools=true 且 privilegeLevel 高：提示注入提权至工具/系统权限(LLM05/LLM06)\n"
            "- type=prompt：系统提示泄露(LLM07)、提示注入(Tampering)\n"
            "- type=trainingdata：训练数据投毒(LLM04)、成员推断/数据泄露\n"
            "- datastore.isVectorStore=true：向量库投毒、语义越权检索、嵌入向量泄露(LLM08)\n"
            "- 流(source/target)涉及 AI 组件：LLM 输出未校验进入下游系统(LLM05)，可能导致注入下游\n"
        )

    @staticmethod
    def _dread_section(methodology: str) -> str:
        """STRIDE-AI 下输出 DREAD 评级说明。"""
        method = normalize_methodology(methodology)
        if method != "STRIDE-AI":
            return ""
        return (
            "### DREAD 评级说明（STRIDE-AI）\n"
            "每条威胁给出五维 0~10 整数评分：\n"
            "- damage：若被利用造成的危害程度\n"
            "- reproducibility：复现的难易程度（越易复现分越高）\n"
            "- exploitability：被利用的难易程度（越易利用分越高）\n"
            "- affectedUsers：受影响用户/资产范围\n"
            "- discoverability：被发现/发现的难易程度\n"
        )

    @staticmethod
    def _owasp_llm_section(methodology: str) -> str:
        """STRIDE-AI 下输出 OWASP Top 10 for LLM 清单供参考。"""
        method = normalize_methodology(methodology)
        if method != "STRIDE-AI":
            return ""
        try:
            from .ai_knowledge import get_owasp_llm_list

            items = get_owasp_llm_list()
        except Exception:
            items = []
        if not items:
            return ""
        lines = ["\n### OWASP Top 10 for LLM (2025) 参考清单\n"]
        for it in items:
            lines.append(f"- {it['code']} {it['title']}：{it['description']}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 威胁分析入口
    # ------------------------------------------------------------------
    async def analyze_components(
        self,
        components: list[dict[str, Any]],
        flows: list[dict[str, Any]] | None = None,
        progress: Any = None,
        methodology: str = "STRIDE",
        industry_hint: str | None = None,
    ) -> list[dict[str, Any]]:
        """为所有组件与数据流生成威胁。

        Args:
            components: DFD 组件列表（来自 DocumentAnalyzer）。
            flows: 可选的 DFD 数据流列表。传入后数据流也会参与威胁分析。
            progress: 可选的回调，形如 ``callable(message: str)``，用于上报真实进度。
            methodology: 威胁建模方法论（STRIDE/CIA/CIADIE/LINDDUN/PLOT4ai/EOP/STRIDE-AI）。
            industry_hint: 可选的行业场景提示（来自行业模板），注入 prompt 提升针对性。

        Returns:
            威胁列表，每条包含 componentId 及其他威胁字段。
        """
        method = normalize_methodology(methodology)
        flows = flows or []
        comps_for_llm = [
            {
                "id": c["id"],
                "type": c["type"],
                "name": c["name"],
                "description": c["description"],
                "properties": c.get("properties", {}),
            }
            for c in components
        ]

        sections = [
            f"以下是系统的数据流图元素列表，请为每个元素生成适用的 {method} 威胁和缓解措施：\n\n【组件】"
        ]
        sections.append(self._format_components(comps_for_llm))
        if flows:
            sections.append("\n【数据流】")
            sections.append(self._format_flows(flows))
        user_prompt = "\n".join(sections)

        total = len(components) + len(flows)
        if progress:
            progress(f"正在对 {len(components)} 个组件、{len(flows)} 条数据流进行 {method} 威胁分析…")
        # 结构化输出：锁定威胁字段、类型枚举、严重度枚举，压制随机性
        allowed_types = self._all_types_for_method(method)
        threat_schema = build_threat_schema(method, allowed_types)
        result = await self.llm.complete_json(
            self._build_system_prompt(method, industry_hint),
            user_prompt,
            json_schema=threat_schema,
        )
        threats = result.get("threats", [])
        logger.info("LLM 返回 %d 条威胁", len(threats))
        if progress:
            progress(f"威胁识别完成：LLM 初步生成 {len(threats)} 条威胁")

        # 兜底规则：即使 LLM 遗漏，也确保符合方法论类型约束
        allowed = self._build_allowed_map(components, flows, method)
        # 元素类型/属性索引（用于严重度规则化）
        elem_types: dict[str, str] = {c["id"]: c.get("type", "process") for c in components}
        elem_types.update({f["id"]: "flow" for f in flows or []})
        properties_map: dict[str, dict[str, Any]] = {
            c["id"]: c.get("properties", {}) for c in components
        }
        properties_map.update({f["id"]: f.get("properties", {}) for f in flows or []})
        valid: list[dict[str, Any]] = []
        unmatched = 0
        unknown_type = 0
        # 名称索引：LLM 可能直接用组件/流名称而不是稳定 id
        name_lookup: dict[str, str] = {}
        for c in components:
            name_lookup[ThreatAnalyzer._norm_key(c.get("name", ""))] = c["id"]
        for f in flows or []:
            name_lookup[ThreatAnalyzer._norm_key(f.get("name", ""))] = f["id"]
        for t in threats:
            raw_cid = str(t.get("componentId", "")).strip()
            cid = self._resolve_component_id(raw_cid, allowed, name_lookup)
            if cid is None:
                unmatched += 1
                logger.warning(
                    "跳过威胁（无法匹配 componentId=%r）：%s",
                    raw_cid,
                    t.get("title", "")[:50],
                )
                continue
            ttype = str(t.get("type", ""))
            # 标准化类型，避免大小写/格式问题
            normalized = self._normalize_type(ttype, method)
            if not normalized:
                unknown_type += 1
                logger.warning(
                    "跳过威胁（未知 %s 类型=%r）：%s",
                    method,
                    ttype,
                    t.get("title", "")[:50],
                )
                continue
            # 强制符合该组件允许的类型
            if normalized not in allowed[cid]:
                # 尝试找到最接近的允许类型
                fallback = self._closest_type(normalized, allowed[cid], method)
                if not fallback:
                    logger.warning(
                        "跳过威胁（%s 类型 %s 不适用于组件 %s）：%s",
                        method,
                        normalized,
                        cid,
                        t.get("title", "")[:50],
                    )
                    continue
                logger.info(
                    "%s 类型 %s 不在组件 %s 允许集合中，自动降级为 %s",
                    method,
                    normalized,
                    cid,
                    fallback,
                )
                normalized = fallback
            t["componentId"] = cid
            t["type"] = normalized
            # 严重度规则化：用确定性规则覆盖 LLM 的自由评估，保证可复现
            self._apply_rule_severity(t, elem_types.get(cid, "process"), properties_map.get(cid, {}))
            self._finalize_threat(t)
            # 标记来源为 LLM（便于审计 / 与骨架威胁区分 / 后续按来源优化）
            t["source"] = "llm"
            valid.append(t)

        # 确定性覆盖：补齐 LLM 遗漏的威胁类型。
        # auto 模式：默认仅当属性规则判定该风险真实存在（严重度 >= High）时才用骨架补齐，
        #   避免"每个元素所有允许类型都被塞满"造成的 100+ 条膨胀；LLM 已识别的威胁不受影响。
        # full 模式：强制覆盖方法论允许的全部威胁类型。
        # 智能 fallback：auto 模式下当 LLM 实际产出严重不足（平均每元素不足 1 条）时，
        #   自动升格为 full 模式，保证威胁总量与"方法论覆盖范围 × 元素数量"成正比——
        #   该方法论无关、场景无关，任何行业文档都适用。
        mode = self._resolve_coverage_mode(len(valid), len(components) + len(flows or []))
        valid = self._ensure_coverage(
            valid, allowed, elem_types, properties_map, method, mode=mode
        )

        # 终极去重：跨 LLM+骨架 的合并去重，解决「同一元素同类型同严重度多次生成」
        # 的膨胀问题（典型表现：每个组件都被分配了全部 STRIDE 类型 → 14×6≈84 + flow 同理
        # → 出现「4 个类型各 33 条」之类的整齐重复）。三层去重：
        #   L1 完全相同 (componentId, type, severity) → 合并
        #   L2 标题语义指纹近似 (componentId, type, fingerprint) → 合并
        #   L3 单元素威胁总数上限制（每组件/流最多 MAX_PER_ELEMENT 条，
        #        保留 description/mitigation 最长的那条）
        valid = self._deduplicate_threats(valid)

        logger.info(
            "威胁过滤结果：LLM返回=%d，匹配=%d，未匹配ID=%d，未知类型=%d，去重后最终=%d",
            len(threats),
            len(valid),
            unmatched,
            unknown_type,
            len(valid),
        )

        # 确定性排序：去重后 threat 顺序仍受 LLM 输出顺序影响，前端渲染/导出会随采样波动。
        # 这里按 (componentId, type, severity, title) 稳定排序，内容不变、仅锁顺序，
        # 保证同输入 → 威胁列表字节级一致。
        valid = _sort_threats(valid)
        return valid

    # ------------------------------------------------------------------
    # 威胁去重
    # ------------------------------------------------------------------
    # 单元素最大威胁数（防御性上限）：
    # - 默认 6 ≈ STRIDE 6 类全集，留 1 条冗余防漏；
    # - auto 模式期望均 < 10，full 模式会随 STRIDE 触发但仍控总量。
    _MAX_THREATS_PER_ELEMENT = 6
    # 标题语义指纹的「最长公共字符片段长度」阈值（>= 触发近似合并）
    _SEMANTIC_MERGE_RATIO = 0.75

    def _deduplicate_threats(
        self, valid: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """终极去重：L1 主键 + L2 语义指纹 + L3 单元素上限。

        - L1：完全相同的 (componentId, type, severity) 视为同一威胁，保留
          「信息量最大」者（description + mitigation + title 长度最长），并列时
          取原序最靠前者；
        - L2：同一 (componentId, type) 下，标题语义指纹
          （中文连续子串 LCS 重叠率 >= ``_SEMANTIC_MERGE_RATIO``）视为近似
          重复，仅**与同(cid, type) 中首个保留者**比对再合并一次；
        - L3：单元素（componentId）威胁总数超过 ``_MAX_THREATS_PER_ELEMENT``
          时，按信息量降序截断，保留高质量威胁、丢弃冗余威胁。

        返回新列表（顺序：保留原始出现顺序，便于审计）。
        """
        if not valid:
            return valid

        # 0. 信息量预计算 + 原始位置映射
        richness_by_idx: dict[int, float] = {}
        for i, t in enumerate(valid):
            richness_by_idx[i] = self._threat_richness(t)

        # 1. 按 (cid, type, severity) 与 (cid, type) 分组
        key_to_indices: dict[tuple[str, str, str], list[int]] = {}
        cid_type_to_indices: dict[tuple[str, str], list[int]] = {}
        for i, t in enumerate(valid):
            cid = str(t.get("componentId", "")).strip()
            ttype = str(t.get("type", "")).strip()
            sev = str(t.get("severity", "")).strip().lower()
            key_to_indices.setdefault((cid, ttype, sev), []).append(i)
            cid_type_to_indices.setdefault((cid, ttype), []).append(i)

        # 2. L1：每主键保留「原序最靠前者」(FIFO)，保留最早被发现的威胁
        #    有利于审计（诊断序）与确定性展示。
        #    放弃「信息量大胜出」是 trade-off：① 与 LLM 自然生成顺序耦合，
        #    ② 用户最直观的认知是「首次生成就是它」；后续 L3 阶段仍按信息量
        #    截断以避免冗余堆叠。
        kept_after_l1: set[int] = set()
        for _key, idx_list in key_to_indices.items():
            sorted_idx = sorted(idx_list, key=lambda i: i)
            kept_after_l1.add(sorted_idx[0])

        # 3. L2：同 (cid, type) 下与「首个保留者」做指纹近似合并。
        #    注意：仅在同一 L1 主键（cid, type, severity）之内做合并。不同 severity
        #    的「同主题」威胁是独立威胁（高风险与中风险分开计），不应合并。
        final_kept: set[int] = set(kept_after_l1)
        for (cid, ttype), idx_list in cid_type_to_indices.items():
            # 找 (cid, type) 中 final_kept 中原序最小的作为锚
            anchor_i = None
            for i in sorted(idx_list):
                if i in final_kept:
                    anchor_i = i
                    break
            if anchor_i is None:
                continue
            anchor_t = valid[anchor_i]
            anchor_cid = str(anchor_t.get("componentId", "")).strip()
            anchor_type = str(anchor_t.get("type", "")).strip()
            anchor_sev = str(anchor_t.get("severity", "")).strip().lower()
            anchor_key = (anchor_cid, anchor_type, anchor_sev)
            anchor_fp = self._semantic_fingerprint(
                str(anchor_t.get("title", ""))
            )
            if not anchor_fp:
                continue
            for i in idx_list:
                if i == anchor_i:
                    continue
                if i not in kept_after_l1:
                    continue
                # 只与同 L1 主键（cid+type+severity）的其他条目比对
                t = valid[i]
                other_key = (
                    str(t.get("componentId", "")).strip(),
                    str(t.get("type", "")).strip(),
                    str(t.get("severity", "")).strip().lower(),
                )
                if other_key != anchor_key:
                    # 不同 severity 视为不同威胁，不参与 L2 合并
                    continue
                fp = self._semantic_fingerprint(str(t.get("title", "")))
                if fp and self._fingerprint_overlap(fp, anchor_fp):
                    final_kept.discard(i)

        # 4. 按原始出现顺序收集保留条目
        kept = [valid[i] for i in range(len(valid)) if i in final_kept]

        # 5. L3：单元素上限，按信息量降序截断
        per_elem: dict[str, list[tuple[int, dict[str, Any]]]] = {}
        for i, t in enumerate(valid):
            if i not in final_kept:
                continue
            cid = str(t.get("componentId", "")).strip()
            per_elem.setdefault(cid, []).append((i, t))

        result: list[dict[str, Any]] = []
        truncated = 0
        for cid, items in per_elem.items():
            if len(items) <= self._MAX_THREATS_PER_ELEMENT:
                # 内部保持原序
                for _, t in items:
                    result.append(t)
                continue
            # 信息量降序截断（并列取原序小的）
            items.sort(key=lambda x: (-richness_by_idx[x[0]], x[0]))
            truncated += len(items) - self._MAX_THREATS_PER_ELEMENT
            # 对被截断掉的：它们是 *这个 cid* 内的多出项，不参与最终顺序
            truncated_set: set[int] = set(i for i, _t in items[self._MAX_THREATS_PER_ELEMENT:])
            for i, t in items[: self._MAX_THREATS_PER_ELEMENT]:
                if i not in truncated_set:
                    result.append(t)
                    # 标记后续截断时，原始 item 集合里超过上限的最末几位丢弃

        # 6. 全局按原始出现顺序重排（保留 L3 截断结果）
        #    通过最终的 (L3 截断标记) 决定性的检查：再过一次过滤
        #    - 任何超出 MAX 的 cid 取 max_richness 排序靠前 N 个
        # 然后统一按 orig_i 升序输出
        final_orig_i_order = sorted(
            [i for i in range(len(valid)) if i in final_kept],
            key=lambda i: i,
        )
        # 但 L3 已经把超出 MAX 的 cid 内的某些丢弃；这些丢弃并不在 final_kept 中
        # final_kept 仍包含所有 L2 通过的 idx；这里需要二次过滤
        # 实现方式：直接根据 L3 的「保留 cid 内的哪些 idx」作为最终结果
        kept_by_cid_l3: set[int] = set()
        per_elem_counts: dict[str, int] = {cid: 0 for cid in per_elem}
        ordered_items: list[tuple[int, dict[str, Any]]] = []
        for cid, items in per_elem.items():
            items.sort(key=lambda x: (-richness_by_idx[x[0]], x[0]))
            for rank, (i, t) in enumerate(items):
                if rank < self._MAX_THREATS_PER_ELEMENT:
                    kept_by_cid_l3.add(i)
                    ordered_items.append((i, t))
        # 重新按 orig_i 输出
        ordered_items.sort(key=lambda x: x[0])
        result = [t for _, t in ordered_items]

        if truncated:
            logger.info(
                "威胁 L3 单元素上限截断 %d 条（每元素最多 %d 条）",
                truncated,
                self._MAX_THREATS_PER_ELEMENT,
            )
        return result

    @staticmethod
    def _threat_richness(t: dict[str, Any]) -> float:
        """威胁「信息量」打分：description + mitigation + title 长度之和。

        长度更长者更具体，去重时优先保留。
        """
        score = 0.0
        for field in ("description", "mitigation", "title"):
            v = t.get(field)
            if isinstance(v, str):
                score += min(len(v), 2000)  # 防御性封顶
        return score

    @staticmethod
    def _semantic_fingerprint(title: str) -> str:
        """从威胁标题生成「语义指纹」。

        去除标点 / 空白 / 常见动词 / 程度副词后保留关键名词短语，幂等且对
        「未授权信息泄露」「敏感数据明文泄露」「数据库凭据泄露」等近似标题能
        给出足够接近的指纹。
        """
        if not title:
            return ""
        s = str(title).strip()
        # 去空白 + 中文/ASCII 标点（用 codepoint 构造避免 GBK 解析问题）
        punct = [chr(c) for c in (
            0xFF0C, 0x3002, 0xFF1B,             # fullwidth commas
            0x002C, 0x002E, 0x003B, 0x003A,     # comma period semicolon colon
            0x3001,                              # 、
            0x0021, 0x003F, 0xFF01, 0xFF1F,     # ! ? ! ?
            0x0022, 0x0027,                      # double/single quote
            0x0028, 0x0029,                      # ( )
            0x3010, 0x3011, 0x300A, 0x300B,     # brackets
            0x005B, 0x005D, 0x007B, 0x007D,     # square curly
            0x003C, 0x003E,                      # <>
            0x005C, 0x002F, 0x007C,              # \ / |
            0x005F, 0x002D, 0x2014,             # _ - em-dash
        )]
        s = re.sub(r"[\s　]", "", s)
        for ch in punct:
            s = s.replace(ch, "")
        # 去常见无意义动词/副词/介词/连词
        stop = (
            "未授权", "未经授权", "缺乏", "缺失", "缺少", "可能", "存在",
            "易", "易被", "易遭受", "可能会", "有", "将会", "为", "的",
            "在", "或", "及", "与", "和", "由", "通过", "进行", "发生",
            "导致", "从而", "不", "不进行", "不足", "容易", "可能造成",
        )
        for word in stop:
            s = s.replace(word, "")
        # 取中文连续段（2~12 字）作为指纹候选
        segs = re.findall(r"[\u4e00-\u9fff]{2,12}", s)
        return "".join(sorted(segs))

    @staticmethod
    def _fingerprint_overlap(a: str, b: str) -> bool:
        """判断两个语义指纹是否「近似相等」。

        采用最长公共子串 / 较短串长度的比例，超阈值则视为近似。
        """
        if not a or not b:
            return False
        if a == b:
            return True
        n, m = len(a), len(b)
        shorter = min(n, m)
        if shorter < 4:
            return False
        # O(n*m) LCS，长度通常较小，开销可接受
        lcs_len = 0
        dp = [[0] * (m + 1) for _ in range(n + 1)]
        for i in range(n - 1, -1, -1):
            for j in range(m - 1, -1, -1):
                if a[i] == b[j]:
                    dp[i][j] = dp[i + 1][j + 1] + 1
                    if dp[i][j] > lcs_len:
                        lcs_len = dp[i][j]
        return lcs_len >= ThreatAnalyzer._SEMANTIC_MERGE_RATIO * shorter

    @staticmethod
    def _resolve_coverage_mode(valid_count: int, element_count: int, mode: str = "auto") -> str:
        """auto 模式下 LLM 输出严重不足时的覆盖模式决策。

        规则与场景/行业无关：只要 LLM 产出的有效威胁平均每个元素不足 1 条，
        即认为输出不足，升格为 full 模式做确定性全覆盖，避免"图很大但威胁很少"。

        - 返回 "auto"：LLM 输出已足够，按属性规则兜底高危漏项即可。
        - 返回 "full"：强制覆盖方法论允许的全部威胁类型，保证威胁总量充分。
        """
        if mode != "auto":
            return mode
        if valid_count < element_count:
            return "full"
        return "auto"

    def _ensure_coverage(
        self,
        valid: list[dict[str, Any]],
        allowed: dict[str, set[str]],
        elem_types: dict[str, str],
        properties_map: dict[str, dict[str, Any]],
        methodology: str,
        mode: str = "auto",
    ) -> list[dict[str, Any]]:
        """确定性补齐：为每个元素尚未覆盖的允许类型生成规则骨架威胁。

        - mode="full"：旧行为，强制覆盖方法论允许的全部类型。
        - mode="auto"：骨架补齐仅用于"兜底真实高危漏项"——即 LLM 遗漏、且经属性
          规则判定严重度为 High/Critical 的类型才会补骨架；Low/Medium 维度依赖
          LLM 输出（LLM 已识别的威胁无论严重度一律保留），从而在"不丢真实威胁"
          与"控制威胁数量、避免 100+ 膨胀"之间取得平衡。

        补齐过程同时进行：
        1) 跨组件标题短语级去重（同一短语模板多次出现只保留一次）；
        2) 宽泛模板句式过滤（如"存在敏感信息泄露风险"等无具体攻击面的标题直接丢弃）；
        3) 骨架威胁严重度封顶为 High（不允许 Critical），避免过度风险化。

        返回新的威胁列表（保持已有顺序，追加骨架）。
        """
        method = normalize_methodology(methodology)
        # 每个元素已覆盖的类型
        covered: dict[str, set[str]] = {}
        for t in valid:
            covered.setdefault(str(t["componentId"]), set()).add(str(t["type"]))
        # 确定性的类型顺序（按方法论定义顺序，非字典序，消除随机性）
        order = self._all_types_for_method(method)

        added = 0
        skipped = 0
        deduped = 0
        broad_filtered = 0
        # 已落入有效集合的"短语指纹"（用于跨组件标题短语级去重）
        used_phrase_keys: set[str] = set()
        for t in valid:
            key = self._phrase_fingerprint(str(t.get("title", "")))
            if key:
                used_phrase_keys.add(key)
        for cid in allowed:
            elem_type = elem_types.get(cid, "process")
            props = properties_map.get(cid, {})
            have = covered.get(cid, set())
            for ttype in order:
                if ttype not in allowed[cid]:
                    continue
                if ttype in have:
                    continue
                # auto 模式：骨架补齐只兜底 High/Critical 的真实高危漏项。
                # 其余维度依赖 LLM 输出（LLM 已识别的威胁无论严重度一律保留，
                # 不会进入此补齐分支），从而不塞满低价值骨架、也不丢高危真实威胁。
                if mode == "auto":
                    probe = {"type": ttype}
                    self._apply_rule_severity(probe, elem_type, props)
                    sev = str(probe.get("severity", "")).strip().lower()
                    if sev not in ("high", "critical"):
                        skipped += 1
                        continue
                skeleton = self._build_skeleton_threat(
                    cid, elem_type, ttype, props, method
                )
                # 语义过滤：宽泛模板句式（如"存在 X 风险"）直接丢弃
                if self._is_broad_template_title(str(skeleton.get("title", ""))):
                    broad_filtered += 1
                    have.add(ttype)
                    continue
                # 跨组件标题短语级去重：同一短语指纹已存在则跳过
                phrase_key = self._phrase_fingerprint(str(skeleton.get("title", "")))
                if phrase_key and phrase_key in used_phrase_keys:
                    deduped += 1
                    have.add(ttype)
                    continue
                # 严重度校准：骨架威胁不允许 Critical，封顶为 High
                self._apply_rule_severity(skeleton, elem_type, props)
                self._cap_skeleton_severity(skeleton)
                self._finalize_threat(skeleton)
                # 标记来源为骨架（便于审计 / 前端差异化展示 / 后续单独优化）
                skeleton["source"] = "skeleton"
                valid.append(skeleton)
                have.add(ttype)
                if phrase_key:
                    used_phrase_keys.add(phrase_key)
                added += 1
        if added:
            logger.info("确定性覆盖补齐 %d 条规则骨架威胁", added)
        if skipped:
            logger.info("auto 模式跳过 %d 条无实质风险的骨架补齐", skipped)
        if deduped:
            logger.info("骨架补齐跨组件标题短语级去重 %d 条", deduped)
        if broad_filtered:
            logger.info("骨架补齐宽泛模板过滤 %d 条", broad_filtered)
        return valid

    @staticmethod
    def _phrase_fingerprint(title: str) -> str:
        """从威胁标题提取"短语指纹"用于跨组件去重。

        规则：取标题尾部"存在 X 风险" / "被 X" / "导致 X" 等固定模板短语，
        去除组件名/数据流名等变量部分后归一化。空字符串表示无法提取。
        """
        if not title:
            return ""
        # 统一空白与全/半角
        s = re.sub(r"\s+", "", str(title))
        # 优先匹配"存在X风险"类尾段
        m = re.search(r"(存在[^，。；,;\n]{2,30}风险)$", s)
        if m:
            return f"has:{m.group(1)}"
        # 其次匹配"被X"结尾
        m = re.search(r"(被[^，。；,;\n]{2,30})$", s)
        if m:
            return f"verb:{m.group(1)}"
        # 其次匹配"导致X"结尾
        m = re.search(r"(导致[^，。；,;\n]{2,30})$", s)
        if m:
            return f"cause:{m.group(1)}"
        return ""

    @staticmethod
    def _is_broad_template_title(title: str) -> bool:
        """识别"宽泛模板"威胁标题——仅含"存在X风险"且无具体攻击面。

        这些条目对开发整改无指导价值，直接丢弃。
        """
        if not title:
            return False
        s = re.sub(r"\s+", "", str(title))
        # 命中"存在…风险"且总长度很短（说明是无具体攻击面描述）
        if re.search(r"存在[^，。；,;\n]{2,15}风险$", s) and len(s) <= 18:
            return True
        # 命中常见宽泛句式黑名单
        broad_phrases = (
            "存在敏感信息泄露风险",
            "存在权限提升风险",
            "存在抵赖风险",
            "存在越权风险",
            "存在注入风险",
            "存在中断风险",
        )
        return any(p in s for p in broad_phrases)

    @staticmethod
    def _cap_skeleton_severity(t: dict[str, Any]) -> None:
        """骨架威胁严重度校准：封顶为 High（不允许 Critical）。

        原因：骨架由模板生成、未结合上下文具体化，直接沿用严重度矩阵的
        Critical 判定会"过度风险化"；同时保留 High 仍可作为 auto 模式
        "兜底高危漏项"的有效信号，不会让骨架威胁完全失去高危标记。
        """
        sev = str(t.get("severity", "") or "").strip().lower()
        if sev == "critical":
            t["severity"] = "High"
            if t.get("score"):
                t["score"] = "High"

    @staticmethod
    def _title_similarity(a: str, b: str) -> float:
        """基于 SequenceMatcher 的标题相似度（0~1）。"""
        if not a or not b:
            return 0.0
        return difflib.SequenceMatcher(None, a, b).ratio()

    def _build_skeleton_threat(
        self,
        cid: str,
        elem_type: str,
        ttype: str,
        props: dict[str, Any],
        methodology: str,
    ) -> dict[str, Any]:
        """生成一条规则骨架威胁（标题/描述/缓解来自方法论模板库）。"""
        method = normalize_methodology(methodology)
        title, desc, mitigation = get_rule_threat_template(method, ttype, elem_type, props)
        return {
            "componentId": cid,
            "type": ttype,
            "title": title,
            "description": desc,
            "mitigation": mitigation,
            "status": "Open",
            "severity": "Medium",
        }

    @staticmethod
    def _apply_rule_severity(
        t: dict[str, Any],
        elem_type: str,
        properties: dict[str, Any],
    ) -> None:
        """用确定性规则覆盖严重度（替代 LLM 自由评估）。

        同一组件 + 同一威胁类型 => 永远相同的严重度，消除跨 run 波动。
        """
        sev = score_severity(elem_type, str(t.get("type", "")), properties)
        t["severity"] = sev
        # score 字段同步（若存在），保证前端展示一致
        if t.get("score"):
            t["score"] = sev

    @staticmethod
    def _finalize_threat(t: dict[str, Any]) -> None:
        """补齐威胁的默认字段（severity 四档 / status / score）。"""
        t.setdefault("status", "Open")
        # 规范化 severity 到四档
        sev = str(t.get("severity", "") or "").strip()
        sev = ThreatAnalyzer._normalize_severity(sev)
        t["severity"] = sev
        if not t.get("score"):
            t["score"] = sev
        # 补默认值
        t.setdefault("description", t.get("description", ""))
        t.setdefault("mitigation", t.get("mitigation", ""))
        t.setdefault("cwe", t.get("cwe", ""))
        t.setdefault("references", t.get("references", []) or [])
        # 状态机字段
        status = str(t.get("status", "") or "").strip()
        if status not in STATUSES:
            t["status"] = "Open"
        # outOfScope：默认不置位，交给前端/用户管理
        t.setdefault("outOfScope", False)
        # DREAD 评级（STRIDE-AI）：若存在则规范化，否则不生成默认 DREAD
        dread = t.get("dread")
        if isinstance(dread, dict):
            cleaned = ThreatAnalyzer._normalize_dread(dread)
            t["dread"] = cleaned
            t["dreadScore"] = sum(cleaned.values())

    @staticmethod
    def _normalize_dread(dread: dict[str, Any]) -> dict[str, int]:
        """规范化 DREAD 五维评分到 0~10 整数，并补齐缺失维度。"""
        keys = ["damage", "reproducibility", "exploitability", "affectedUsers", "discoverability"]
        out: dict[str, int] = {}
        for k in keys:
            v = dread.get(k)
            try:
                iv = int(v)
            except (TypeError, ValueError):
                iv = 0
            out[k] = max(0, min(10, iv))
        return out

    @staticmethod
    def _normalize_severity(sev: str) -> str:
        """将 severity 归一化为四档（Low/Medium/High/Critical）。"""
        if not sev:
            return "Medium"
        s = sev.strip().lower()
        if "critical" in s:
            return "Critical"
        if "high" in s:
            return "High"
        if "medium" in s or "med" in s:
            return "Medium"
        if "low" in s:
            return "Low"
        # 旧五档里的 TBD / 未赋值，一律收敛为 Medium
        return "Medium"

    # ------------------------------------------------------------------
    # 匹配与映射
    # ------------------------------------------------------------------
    @staticmethod
    def _norm_key(s: str) -> str:
        """规范化名称/ID 键用于模糊匹配：去空白/方括号/标点并小写。"""
        return re.sub(r"[\s_\-\[\]（）()【】]+", "", str(s).lower())

    @staticmethod
    def _resolve_component_id(
        raw_id: str,
        allowed: dict[str, set[str]],
        name_lookup: dict[str, str] | None = None,
    ) -> str | None:
        """把 LLM 返回的 componentId 尽量匹配回真实组件 id。

        匹配优先级：稳定 id 精确匹配 → 数字后缀匹配 → 组件/流名称匹配（含子串）。
        全部失败时返回 None（由调用方丢弃并计数），避免把威胁错误归因到无关组件。
        """
        if not raw_id:
            return None
        if raw_id in allowed:
            return raw_id

        m = re.search(r"(\d+)", raw_id)
        if m:
            num = m.group(1)
            for cid in allowed:
                if str(cid).rstrip(string.digits) == "" and cid.endswith(num):
                    return cid
                tail = re.search(r"(\d+)$", cid)
                if tail and tail.group(1) == num:
                    return cid
        # 名称匹配：LLM 可能直接写组件/流名称而不是稳定 id（如 "用户" / "[用户登录]"）
        if name_lookup:
            key = ThreatAnalyzer._norm_key(raw_id)
            if key in name_lookup:
                return name_lookup[key]
            # 子串匹配：LLM 可能输出更长的描述性名称（如 "用户登录请求"），只要
            # 规范化后包含某个已知名称即视为命中，提升 LLM 文本到 id 的召回率。
            for nkey, cid in name_lookup.items():
                if not nkey:
                    continue
                if nkey in key or key in nkey:
                    return cid
                # 双向最长公共子串比例 ≥ 0.7 视为同一组件（处理同义改写）。
                if ThreatAnalyzer._norm_key_overlap(key, nkey) >= 0.7:
                    return cid
        return None

    @staticmethod
    def _norm_key_overlap(a: str, b: str) -> float:
        """两规范化键的最长公共子串长度 / 较短者长度，用于近似命中判定。"""
        if not a or not b:
            return 0.0
        shorter, longer = (a, b) if len(a) <= len(b) else (b, a)
        m = len(shorter)
        best = 0
        for size in range(m, 0, -1):
            for i in range(0, m - size + 1):
                sub = shorter[i:i + size]
                if sub in longer:
                    return size / m
            best = size
            if best / m < 0.5:
                break
        return best / m if m else 0.0

    # 平台元素类型 -> methodology 查询键名（含 AI 元素类型）
    _CELL_KEY_ALIAS = {
        "actor": "actor",
        "externalentity": "actor",
        "process": "process",
        "datastore": "datastore",
        "dataflow": "flow",
        "flow": "flow",
        "model": "model",
        "prompt": "prompt",
        "vectorstore": "vectorstore",
        "tool": "tool",
        "trainingdata": "trainingdata",
        "agentconfig": "agentconfig",
    }

    def _build_allowed_map(
        self,
        components: list[dict[str, Any]],
        flows: list[dict[str, Any]] | None = None,
        methodology: str = "STRIDE",
    ) -> dict[str, set[str]]:
        """构建元素 id -> 允许的威胁类型集合的映射（含数据流与 AI 元素）。"""
        method = normalize_methodology(methodology)
        allowed = {}
        for c in components:
            ctype = c["type"]
            # 平台组件类型：actor/process/datastore/externalentity + AI 元素类型
            cell_key = self._CELL_KEY_ALIAS.get(ctype, ctype)
            types = get_threat_types_by_element(method, cell_key)
            allowed[c["id"]] = set(types)
        for f in flows or []:
            allowed[f["id"]] = set(get_threat_types_by_element(method, "flow"))
        return allowed

    def _normalize_type(self, t: str, methodology: str = "STRIDE") -> str | None:
        """标准化方法论下的威胁类型名称。"""
        method = normalize_methodology(methodology)
        if not t:
            return None
        # 收集该方法论所有合法类型（英文全名）
        all_types = self._all_types_for_method(method)
        # 先精确/大小写不敏感匹配
        key = t.strip().lower()
        for tt in all_types:
            if tt.lower() == key:
                return tt
        # 子串匹配（兼容 "Spoofing of source user" 这类描述）
        for tt in all_types:
            if tt.lower() in key or key in tt.lower():
                return tt
        # 兼容按内部小写键名（如 "spoofing"）匹配
        if method in CWE_BY_METHODOLOGY:
            mapping = self._camel_keys(method)
            if key in mapping:
                return mapping[key]
        return None

    @staticmethod
    def _camel_keys(methodology: str) -> dict[str, str]:
        """内部 camelCase 键名 -> 展示名（用于兼容 LINDDUN/PLOT4ai 等内部键）。"""
        camel_map = {
            "STRIDE-AI": {
                "spoofing": "Spoofing",
                "tampering": "Tampering",
                "repudiation": "Repudiation",
                "informationdisclosure": "Information Disclosure",
                "denialofservice": "Denial of Service",
                "elevationofprivilege": "Elevation of Privilege",
            },
            "STRIDE": {
                "spoofing": "Spoofing",
                "tampering": "Tampering",
                "repudiation": "Repudiation",
                "informationdisclosure": "Information Disclosure",
                "denialofservice": "Denial of Service",
                "elevationofprivilege": "Elevation of Privilege",
            },
            "CIA": {
                "confidentiality": "Confidentiality",
                "integrity": "Integrity",
                "availability": "Availability",
            },
            "CIADIE": {
                "confidentiality": "Confidentiality",
                "integrity": "Integrity",
                "availability": "Availability",
                "distributed": "Distributed",
                "immutable": "Immutable",
                "ephemeral": "Ephemeral",
            },
            "LINDDUN": {
                "linkability": "Linkability",
                "identifiability": "Identifiability",
                "nonrepudiation": "Non-Repudiation",
                "detectability": "Detectability",
                "disclosureofinformation": "Disclosure of Information",
                "unawareness": "Unawareness",
                "noncompliance": "Non-Compliance",
            },
            "PLOT4ai": {
                "techniqueprocesses": "Technique & Processes",
                "accessibility": "Accessibility",
                "identifiabilitylinkability": "Identifiability & Linkability",
                "security": "Security",
                "safety": "Safety",
                "unawareness": "Unawareness",
                "ethicshumanrights": "Ethics & Human Rights",
                "noncompliance": "Non-Compliance",
            },
            "EOP": {
                "authentication": "Authentication",
                "authorization": "Authorization",
                "cryptography": "Cryptography",
                "datavalidationencoding": "Data Validation & Encoding",
                "sessionmanagement": "Session Management",
            },
        }
        return camel_map.get(methodology, camel_map["STRIDE"])

    def _all_types_for_method(self, methodology: str) -> list[str]:
        """返回某方法论全部合法威胁类型（去重，保持方法论定义顺序）。

        注意：必须保持 METHODOLOGIES 中声明的稳定顺序（不可用 set/list 转换，
        否则 Python hash 随机化会导致子串匹配歧义时跨进程结果不稳定）。
        """
        method = normalize_methodology(methodology)
        from .methodology import METHODOLOGIES

        types_map = METHODOLOGIES[method]["types"]
        order: list[str] = []
        seen: set[str] = set()
        for v in types_map.values():
            if v not in seen:
                seen.add(v)
                order.append(v)
        # 补充允许映射里的展示名
        for cell_types in METHODOLOGIES[method]["by_element"].values():
            for v in cell_types:
                if v not in seen:
                    seen.add(v)
                    order.append(v)
        return order

    def _closest_type(
        self, raw: str, allowed: set[str], methodology: str = "STRIDE"
    ) -> str | None:
        """在允许的集合中寻找最接近的类型。"""
        method = normalize_methodology(methodology)
        # 按方法论自身的顺序做优先级排序
        order = self._all_types_for_method(method)
        for t in order:
            if t in allowed:
                return t
        return None

    # ------------------------------------------------------------------
    # 格式化
    # ------------------------------------------------------------------
    def _format_components(
        self, components: list[dict[str, Any]]
    ) -> str:
        lines = []
        for c in components:
            props = c.get("properties", {})
            # 键排序：保证同输入 → 序列化字节级一致 → LLM 响应缓存稳定命中
            prop_str = ", ".join(
                f"{k}={props[k]}" for k in sorted(props) if props[k]
            ) or "无特殊属性"
            lines.append(
                f"- [{c['id']}] 类型={c['type']} 名称={c['name']} "
                f"描述={c['description']} 属性=[{prop_str}]"
            )
        return "\n".join(lines)

    def _format_flows(self, flows: list[dict[str, Any]]) -> str:
        lines = []
        for f in flows:
            props = f.get("properties", {})
            # 键排序：同输入 → 序列化字节级一致 → LLM 响应缓存稳定命中
            prop_str = ", ".join(
                f"{k}={props[k]}" for k in sorted(props) if props[k]
            ) or "无特殊属性"
            lines.append(
                f"- [{f['id']}] 数据流 源={f.get('sourceId')} → 目标={f.get('targetId')} "
                f"名称={f.get('name')} 描述={f.get('description')} 属性=[{prop_str}]"
            )
        return "\n".join(lines)
