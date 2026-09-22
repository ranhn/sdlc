"""合规影响面目录（compliance_catalog）的回归测试。

守住四件事：
    1. **默认地区 = 美国 + 欧洲**（公司主要市场），境内条目默认不参与判定；
    2. ``COMPLIANCE_REGIONS`` 开关真的能切（含切开、关掉、写错值的边界）；
    3. 判定口径：威胁类型先归一到 STRIDE 六维，再与各域声明的维度求交集；
       未收录的类型被忽略（不猜语义），跨方法论类型能正确归一；
    4. **"一条信息泄露 → 全绿"是设计语义而非 bug** —— 这条用测试钉住，
       将来若有人收窄映射，测试会失败，提醒他同步更新文档与文案。

跑法：python -m pytest threat/tests/test_compliance_catalog.py -v   或直接 python 本文件。
"""

from __future__ import annotations

import os
import sys
from contextlib import contextmanager

# 与运行时一致：backend/ 在 sys.path 上，威胁子应用以 threat.app.* 导入
_BACKEND_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from threat.app.services.compliance_catalog import (  # noqa: E402
    COMPLIANCE_DOMAINS,
    build_compliance_impact,
    enabled_regions,
    get_compliance_domains,
    normalize_threat_type,
    summarize_compliance_impact,
)


@contextmanager
def _regions(value: str | None):
    """临时设置 COMPLIANCE_REGIONS（None = 删除，回到默认值），退出时还原。"""
    saved = os.environ.get("COMPLIANCE_REGIONS")
    try:
        if value is None:
            os.environ.pop("COMPLIANCE_REGIONS", None)
        else:
            os.environ["COMPLIANCE_REGIONS"] = value
        yield
    finally:
        if saved is None:
            os.environ.pop("COMPLIANCE_REGIONS", None)
        else:
            os.environ["COMPLIANCE_REGIONS"] = saved


def _threats(*types: str) -> list[dict]:
    return [{"type": t, "title": f"{t} 相关威胁"} for t in types]


def _hits(impact: list[dict]) -> set[str]:
    return {d["code"] for d in impact if d.get("hit")}


# ---------------------------------------------------------------------------
# 1. 默认地区：美国 + 欧洲
# ---------------------------------------------------------------------------
def test_default_regions_are_us_and_eu() -> None:
    """不设环境变量时，启用的地区必须是 US + EU，境内条目默认**不出现**。"""
    with _regions(None):
        assert enabled_regions() == {"US", "EU"}, enabled_regions()
        codes = [d["code"] for d in get_compliance_domains()]

    assert len(codes) == 10, codes
    # 主要市场两边的关键法规/框架/审计标准都在
    for must in ("US-FTC", "US-PRIV", "US-AIRMF", "US-NIST-CSF", "US-SOC2", "US-HIPAA",
                 "EU-GDPR", "EU-CRA", "EU-RED", "EU-AIA"):
        assert must in codes, f"缺少 {must}：{codes}"
    # 境内两条默认不参与判定（要开就设 COMPLIANCE_REGIONS=US,EU,CN）
    assert not [c for c in codes if c.startswith("CN-")], codes
    # 每个域都要有依据与版本，否则报告里"依据什么"这一列会空
    for d in get_compliance_domains():
        assert d.get("basis"), d
        assert d.get("version"), d
        assert d.get("label"), d
        assert d.get("stride_types"), d


# ---------------------------------------------------------------------------
# 2. 地区开关
# ---------------------------------------------------------------------------
def test_region_switch_controls_catalog() -> None:
    """COMPLIANCE_REGIONS 能切开/关掉各地区，写错值时目录为空（报告自动省略该节）。"""
    with _regions("CN"):
        codes = [d["code"] for d in get_compliance_domains()]
        assert codes == ["CN-AI", "CN-DATA"], codes

    with _regions("us,eu,cn"):          # 大小写与空格都应容忍
        codes = [d["code"] for d in get_compliance_domains()]
        assert len(codes) == 12, codes
        assert {"US-FTC", "EU-GDPR", "CN-DATA"} <= set(codes), codes

    with _regions(" US , EU "):
        assert enabled_regions() == {"US", "EU"}, enabled_regions()

    with _regions("APAC"):              # 目录里没有的地区 → 空目录（并会打 WARNING）
        assert get_compliance_domains() == []

    with _regions(""):                  # 空值视为未设置 → 回落默认
        assert enabled_regions() == {"US", "EU"}, enabled_regions()


def test_domain_catalog_regions_are_known() -> None:
    """目录里的 region 只能取 US / EU / CN —— 拼错会让条目永远筛不出来。"""
    regions = {str(d.get("region", "")).upper() for d in COMPLIANCE_DOMAINS}
    assert regions == {"US", "EU", "CN"}, regions


# ---------------------------------------------------------------------------
# 3. 判定口径
# ---------------------------------------------------------------------------
def test_impact_maps_stride_dimension_to_domains() -> None:
    """按 STRIDE 维度求交集：不同维度命中不同域，未命中域 hit=False。"""
    with _regions("US,EU"):
        # 防仿冒：RED（3(3)(f) 防欺诈）、CRA 与 SOC 2 的访问控制关注，纯隐私域不关注
        spoof = build_compliance_impact(_threats("Spoofing"))
        assert _hits(spoof) == {"EU-CRA", "EU-RED", "US-SOC2"}, _hits(spoof)

        # 拒绝服务：GDPR Art.32 的"可用性"、HIPAA 的可用性、AI RMF 与 SOC 2 关注
        dos = build_compliance_impact(_threats("Denial of Service"))
        assert _hits(dos) == {"EU-GDPR", "US-AIRMF", "US-SOC2", "US-HIPAA"}, _hits(dos)

        # 抵赖（不可追溯）：只有 AI Act 的可追溯要求落在这一维
        rep = build_compliance_impact(_threats("Repudiation"))
        assert _hits(rep) == {"EU-AIA"}, _hits(rep)

        # 无威胁 → 全不命中，计数为 0（列表/页面据此渲染"未触达"）
        empty = build_compliance_impact([])
        assert all(not d["hit"] and d["relatedThreatCount"] == 0 for d in empty), empty
        assert len(empty) == 10, [d["code"] for d in empty]


def test_related_threat_count_sums_over_declared_dimensions() -> None:
    """计数口径：该域命中的各维度下威胁条数之和，且同一条威胁只归一个维度。"""
    with _regions("US,EU"):
        # CRA 声明 4 个维度（Spoofing/Tampering/Information Disclosure/EoP）。
        # 这里刻意混用三种方法论的写法：Spoofing（STRIDE）、Confidentiality（CIA，
        # 归一为信息泄露）、Elevation of Privilege（STRIDE）→ 三条都应计入 CRA。
        impact = {d["code"]: d for d in build_compliance_impact(
            _threats("Spoofing", "Confidentiality", "Elevation of Privilege")
        )}
        cra = impact["EU-CRA"]
        assert cra["relatedThreatCount"] == 3, cra
        assert cra["hit"] is True
        # 跨方法论词表的原生类型要能回显，便于下钻（不是只给个数字）
        assert "Confidentiality" in cra["relatedTypes"], cra["relatedTypes"]
        assert set(cra["normalizedTypes"]) == {
            "Spoofing", "Information Disclosure", "Elevation of Privilege"
        }, cra["normalizedTypes"]


def test_unknown_threat_types_are_ignored() -> None:
    """未收录的类型不参与判定（不猜语义），避免误报。"""
    with _regions("US,EU"):
        impact = build_compliance_impact(_threats("Unicorn Attack", ""))
        assert all(not d["hit"] for d in impact), [
            (d["code"], d["relatedThreatCount"]) for d in impact
        ]


def test_cross_methodology_types_normalize() -> None:
    """各方法论的词表都要能归一到 STRIDE 六维（含 MAESTRO 的"英文名 + 中文后缀"）。"""
    assert normalize_threat_type("Linkability") == "Information Disclosure"       # LINDDUN
    assert normalize_threat_type("Confidentiality") == "Information Disclosure"   # CIA
    assert normalize_threat_type("Authentication") == "Spoofing"                  # EOP
    assert normalize_threat_type("Tool Misuse 工具滥用") == "Elevation of Privilege"  # MAESTRO
    assert normalize_threat_type("Information Disclosure") == "Information Disclosure"
    assert normalize_threat_type("information-disclosure") == "Information Disclosure"


# ---------------------------------------------------------------------------
# 4. 语义钉住：一条信息泄露 → 全部域命中
# ---------------------------------------------------------------------------
def test_single_information_disclosure_hits_every_domain() -> None:
    """一条"信息泄露"威胁会命中**所有**域 —— 这是设计语义，不是 bug。

    理由：目录里每个域都以"个人信息/数据泄露"为共同关注点（GDPR Art.32、
    CCPA、FTC §5、CRA、RED、AI Act 的透明度/可追溯都涉及）。所以"影响面"
    在含信息泄露的建模上必然全绿；它表达的是"本次建模触及了这些法规的关注范围"，
    不代表合规达标 —— UI 与报告里都显式声明了这一点。
    若将来收窄映射（例如给 AI 类域加"涉及 AI 元素"前置条件），请连同
    本测试、模块 docstring 与页面文案一起改。
    """
    with _regions("US,EU"):
        impact = build_compliance_impact(_threats("Information Disclosure"))
        assert _hits(impact) == {d["code"] for d in get_compliance_domains()}, _hits(impact)


# ---------------------------------------------------------------------------
# 5. 框架/审计标准的"性质"必须写明（否则读者会把"命中"当成强制要求）
# ---------------------------------------------------------------------------
def test_frameworks_and_audit_standards_carry_applicability_notes() -> None:
    """NIST CSF / AI RMF 是自愿性框架、SOC 2 是审计标准、HIPAA 的适用前提要写明。

    这几条和 GDPR/CRA 那类法规性质完全不同：报告读者看到"命中 NIST CSF"
    容易误解成"被强制要求"。所以 note 里必须写清性质与边界 —— 这里用测试钉住。
    """
    with _regions("US,EU"):
        by_code = {d["code"]: d for d in get_compliance_domains()}

    assert "自愿性框架" in by_code["US-NIST-CSF"]["note"], by_code["US-NIST-CSF"]
    assert "自愿性框架" in by_code["US-AIRMF"]["note"], by_code["US-AIRMF"]
    assert "审计/认证标准而非法规" in by_code["US-SOC2"]["note"], by_code["US-SOC2"]
    # HIPAA 已与业务确认在范围内 → 固定判为适用并给出理由（不交给自动判定）
    hipaa = by_code["US-HIPAA"]
    assert "适用" in hipaa["applicable_reason"], hipaa
    assert "HIPAA" in hipaa["applicable_reason"], hipaa
    assert "BAA" in hipaa["note"], hipaa


# ---------------------------------------------------------------------------
# 6. 适用性三态
# ---------------------------------------------------------------------------
_AI_DOMAINS = {"EU-AIA", "US-AIRMF"}


def _applicable(impact: list[dict]) -> set[str]:
    return {d["code"] for d in impact if d.get("applicable", True)}


def test_ai_domains_not_applicable_without_ai_elements() -> None:
    """纯业务系统（只有 actor/process/datastore）→ AI 专项域必须是「不适用」。

    这是三态要解决的核心问题：以前无 AI 的系统也会被标成"触及 EU AI Act"。
    """
    comps = [
        {"id": "a1", "name": "用户", "type": "actor"},
        {"id": "p1", "name": "订单服务", "type": "process"},
        {"id": "d1", "name": "订单库", "type": "datastore"},
    ]
    impact = build_compliance_impact(_threats("Information Disclosure"), comps)
    by = {d["code"]: d for d in impact}

    for code in _AI_DOMAINS:
        assert by[code]["applicable"] is False, by[code]
        assert by[code]["hit"] is False, by[code]
        # 不适用时计数必须为 0，否则报告会出现"— 不适用 关联威胁 3"这种自相矛盾的格子
        assert by[code]["relatedThreatCount"] == 0, by[code]
        assert "不适用" in by[code]["applicabilityReason"], by[code]
    # 其余域仍按原口径：信息泄露会命中（说明收窄只作用于 AI 专项域）
    assert "EU-GDPR" in _hits(impact) and "US-SOC2" in _hits(impact), _hits(impact)


def test_ai_domains_applicable_when_ai_elements_present() -> None:
    """涉及 AI 元素 → AI 专项域适用，且理由里点名是哪个元素（便于复核判据）。"""
    # (a) 用 AI 专用 type
    comps_type = [
        {"id": "a1", "name": "用户", "type": "actor"},
        {"id": "m1", "name": "LLM 服务", "type": "model"},
    ]
    impact = build_compliance_impact(_threats("Information Disclosure"), comps_type)
    by = {d["code"]: d for d in impact}
    for code in _AI_DOMAINS:
        assert by[code]["applicable"] is True, by[code]
        assert "LLM 服务" in by[code]["applicabilityReason"], by[code]

    # (b) AI 能力挂在普通 process 上（提示词就是这么要求 LLM 标注的）→ 同样适用
    comps_prop = [
        {"id": "p1", "name": "推理网关", "type": "process",
         "properties": {"isLLMService": True, "hasRAG": True}},
    ]
    by_prop = {d["code"]: d for d in build_compliance_impact(_threats("Tampering"), comps_prop)}
    assert by_prop["EU-AIA"]["applicable"] is True, by_prop["EU-AIA"]
    assert "isLLMService" in by_prop["EU-AIA"]["applicabilityReason"], by_prop["EU-AIA"]
    # 文本型 "true" 也要认（属性经 JSON 往返后可能不是布尔）
    comps_str = [{"id": "d1", "name": "知识库", "type": "datastore",
                  "properties": {"isVectorStore": "true"}}]
    by_str = {d["code"]: d for d in build_compliance_impact(_threats("Tampering"), comps_str)}
    assert by_str["US-AIRMF"]["applicable"] is True, by_str["US-AIRMF"]


def test_missing_components_falls_back_to_conservative_applicable() -> None:
    """不传组件（无法判断）→ AI 专项域保守判为适用，避免静默丢域。"""
    impact = build_compliance_impact(_threats("Information Disclosure"))
    assert _AI_DOMAINS <= _applicable(impact), _applicable(impact)
    by = {d["code"]: d for d in impact}
    assert "保守判为适用" in by["EU-AIA"]["applicabilityReason"], by["EU-AIA"]


def test_summarize_counts_only_applicable_domains() -> None:
    """结论句的分母只含**适用**的域 —— 否则"7/10"里混着不适用项会被读成"没覆盖到"。"""
    comps = [{"id": "p1", "name": "订单服务", "type": "process"}]
    impact = build_compliance_impact(_threats("Information Disclosure"), comps)
    summary = summarize_compliance_impact(impact)

    assert summary["notApplicable"] == 2, summary          # EU-AIA / US-AIRMF
    assert summary["totalDomains"] == 8, summary           # 10 - 2
    assert summary["hitDomains"] == 8, summary             # 信息泄露命中全部适用域
    assert "适用合规域" in summary["text"] and "2 项不适用" in summary["text"], summary


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        fn()
        print(f"  PASS  {fn.__name__}")
    print(f"\n{len(tests)} tests passed")
