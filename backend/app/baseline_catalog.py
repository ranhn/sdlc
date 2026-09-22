"""安全基线类型目录（5 个基线类型的**唯一数据源**）。

存在的意义：这 5 个类型的 key/label 之前只写在前端 `Baseline.vue` 的 `typeNameMap` 里
（后端只有 `BaselineCategory.baseline_type` 这个自由字符串，谁都能写错）。现在"新增需求"
要勾选绑定哪几个基线，勾选列表、校验、展示三处都需要同一份口径，所以挪到后端来：

  - `routers/baseline.py`：/baseline/types 返回目录 + 各类条目数；创建/编辑需求时校验 key
  - `models.BaselineRequirement.baseline_types`：存 JSON 数组，解析时按本目录顺序归一
  - 前端：从 /baseline/types 取，不再自己维护一份（避免"后端加了类型、前端看不见"）

⚠️ 数据来源：这 5 类下的**分类与检查项**是靠 `scripts/import_baseline.py` 从
`L4-3x-…-含安全合规.xlsx` 导入的（内置 seed 只播种了安全需求基线的 18 条）。所以
"某类型 0 条"是很可能出现的情况 —— 接口照样返回它（前端把 0 条的置灰不可勾选），
把"数据没导入"暴露出来，比悄悄藏起来更容易定位。
"""
from __future__ import annotations

import json
from typing import Any, Iterable

# key -> 展示名。顺序即前端展示顺序（安全需求 → APP → 前端 → 后端 → 固件）
BASELINE_TYPES: dict[str, str] = {
    "security_requirement": "安全需求基线",
    "app_dev": "APP开发安全基线",
    "frontend_dev": "前端开发安全基线",
    "backend_dev": "后端开发安全基线",
    "firmware_dev": "固件开发安全基线",
}

# 目录顺序（归一/排序都用它，避免依赖 dict 字面量顺序之外的隐式行为）
TYPE_KEYS: list[str] = list(BASELINE_TYPES)


def label_of(key: str | None) -> str:
    """key → 展示名；未知 key 原样返回（宁可显示怪名字，也不要显示空白）。"""
    if not key:
        return ""
    return BASELINE_TYPES.get(key, key)


def parse_types(raw: Any) -> list[str]:
    """把库里存的 JSON 文本解析成**合法且去重**的 key 列表（按目录顺序）。

    - 兼容历史/脏数据：非 JSON 时退化成按逗号切分；未知 key 直接丢弃；
    - 顺序按 `TYPE_KEYS`，保证同一组绑定每次渲染顺序一致（前端分组就靠它）。
    """
    if not raw:
        return []
    if isinstance(raw, (list, tuple, set)):
        data: Iterable[Any] = raw
    else:
        try:
            data = json.loads(raw)
        except (TypeError, ValueError):
            data = str(raw).split(",")
        if not isinstance(data, (list, tuple, set)):
            data = [data]
    got = {str(x).strip() for x in data if str(x).strip()}
    return [k for k in TYPE_KEYS if k in got]


def normalize_types(types: Iterable[Any] | None) -> tuple[list[str], list[str]]:
    """校验 + 归一，返回 `(合法 key 列表[已去重且按目录顺序], 未知 key 列表)`。

    调用方（路由）负责把 `unknown` 非空变成 400 —— 这里不抛异常，是为了让
    "哪个值不合法"能原样回给用户（报错信息里能看到自己填错的那个词）。
    """
    keys: list[str] = []
    unknown: list[str] = []
    for t in types or []:
        s = str(t).strip()
        if not s:
            continue
        if s in BASELINE_TYPES:
            if s not in keys:
                keys.append(s)
        elif s not in unknown:
            unknown.append(s)
    return [k for k in TYPE_KEYS if k in keys], unknown


def dump_types(keys: Iterable[Any]) -> str:
    """归一后序列化入库（JSON 文本）。只写合法 key，脏值在入口就被挡掉了。"""
    valid, _ = normalize_types(keys)
    return json.dumps(valid, ensure_ascii=False)
