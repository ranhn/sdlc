"""数据流收敛：同向、同安全语义的数据流合并为一条（源头降噪的确定性一环）。

为什么需要它：
    提示词（document_analyzer 规范 11/12）已经要求"只画必要流、每对端点最多一条"，
    但 LLM 仍可能把同一段传输拆成多条平行线（「上传体征数据」+「设备鉴权」），
    自省补全阶段也可能再加回来。这里做一道**确定性**收敛，让落到模型里的数据流
    本身就干净 —— 而不是像"主图/全部""边界开关"那样只在视图层藏起来
    （视图层藏起来的东西，导出报告、威胁清单、元素编号里依然存在）。

合并规则（保守，只合并确定重复的）：
    · 键 = (sourceId, targetId, isEncrypted, isPublicNetwork)
      同向 + 同安全语义。安全语义不同**不合并**，否则会丢掉"这条是加密的 /
      这条走公网"的信息，威胁判定与配色都会跟着错；
    · 反向流（A→B 与 B→A）不合并：请求/响应必须画成两条平行线；
    · 代表流取信息最全的一条（描述最长 → 名称最长 → 原顺序最靠前，确定性），
      其余流的 name / description / protocol / 布尔属性合并进代表流，信息不丢；
    · 返回「被合并 id → 代表 id」映射，供调用方把**威胁**改挂到代表流上
      （威胁一条都不能丢，这是本模块的硬约束）。

不在这里做的事：不判断"重要性"（要看威胁严重度与跨边界归属，属于 model_builder
阶段，见 _mark_flow_importance）。
"""

from __future__ import annotations

from typing import Any

# 合并后多个名字/协议的分隔符（前端边标签与报告元素清单都要可读）
_SEP_TEXT = "；"
_SEP_NAME = " / "


def flow_semantic_key(flow: dict[str, Any]) -> tuple[str, str, bool, bool]:
    """收敛键：同向 + 同安全语义。"""
    props = flow.get("properties") or {}
    return (
        str(flow.get("sourceId") or ""),
        str(flow.get("targetId") or ""),
        bool(props.get("isEncrypted")),
        bool(props.get("isPublicNetwork")),
    )


def _unique_texts(items: list[Any]) -> list[str]:
    """去重（保序）后的非空文本列表。"""
    out: list[str] = []
    for it in items:
        t = str(it or "").strip()
        if t and t not in out:
            out.append(t)
    return out


def _pick_representative(group: list[dict[str, Any]]) -> dict[str, Any]:
    """代表流：信息最全的一条（确定性：长度 → 原顺序）。"""
    best = group[0]
    best_key = (
        len(str(best.get("description") or "")),
        len(str(best.get("name") or "")),
    )
    for f in group[1:]:
        key = (
            len(str(f.get("description") or "")),
            len(str(f.get("name") or "")),
        )
        if key > best_key:  # 严格大于 → 并列时保留更靠前的那条
            best, best_key = f, key
    return best


def converge_flows(
    flows: list[dict[str, Any]] | None,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """同向同语义的数据流合并为一条。

    Returns:
        (合并后的流列表（保持首次出现顺序）, {被合并的 flow id: 代表 flow id})
    """
    items = [f for f in (flows or []) if isinstance(f, dict)]
    if len(items) < 2:
        return items, {}

    groups: dict[tuple[str, str, bool, bool], list[dict[str, Any]]] = {}
    passthrough: list[dict[str, Any]] = []
    order: list[tuple[str, str, bool, bool]] = []
    for f in items:
        key = flow_semantic_key(f)
        # 缺端点 / 自环：不属于"可合并"的范畴，原样透传（上游校验负责处理）
        if not key[0] or not key[1] or key[0] == key[1]:
            passthrough.append(f)
            continue
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)

    merged: list[dict[str, Any]] = []
    remap: dict[str, str] = {}
    for key in order:
        group = groups[key]
        if len(group) == 1:
            merged.append(group[0])
            continue
        rep = _pick_representative(group)
        rep = dict(rep)  # 不原地改调用方的对象（router 里同一批流还会参与统计）
        props = dict(rep.get("properties") or {})
        # —— 文本合并：名字、描述、协议（保序去重） ——
        names = _unique_texts([f.get("name") for f in group])
        descs = _unique_texts([f.get("description") for f in group])
        protocols = _unique_texts([(f.get("properties") or {}).get("protocol") for f in group])
        if names:
            rep["name"] = _SEP_NAME.join(names)
        if descs:
            rep["description"] = _SEP_TEXT.join(descs)
        if protocols:
            props["protocol"] = _SEP_NAME.join(protocols)
        # —— 布尔/枚举属性：任一为真则真（安全语义同类，只做信息并集） ——
        for f in group:
            for k, v in (f.get("properties") or {}).items():
                if v is True:
                    props[k] = True
                elif k not in props:
                    props[k] = v
        rep["properties"] = props
        rep["mergedFrom"] = [str(f.get("id") or "") for f in group if f is not rep]
        merged.append(rep)
        rep_id = str(rep.get("id") or "")
        for f in group:
            fid = str(f.get("id") or "")
            if fid and fid != rep_id:
                remap[fid] = rep_id

    # 透传项插回原位置（保持"首次出现顺序"，元素编号与画布顺序才稳定）
    if passthrough:
        first_index: dict[int, int] = {}
        for i, f in enumerate(items):
            first_index[id(f)] = i
        merged.extend(passthrough)
        merged.sort(key=lambda f: first_index.get(id(f), 0))
    return merged, remap
