"""漏洞状态机定义与校验。

状态：
- draft      草稿
- pending    待确认
- confirmed  已确认
- fixing     修复中
- retest     待复测
- fixed      已修复
- closed     已关闭
- rejected   已驳回
- ignored    已忽略（**历史状态**，见下）

关键流转（动作）：
- submit     draft -> pending        提交人
- confirm    pending -> confirmed   安全专家
- reject     pending -> rejected    安全专家（驳回）
- start_fix  confirmed -> fixing    修复人
- finish_fix fixing -> retest       修复人
- pass_retest retest -> fixed       复测人
- close      fixed -> closed        安全专家

关于 ignored：**已从状态机移除动作**。页面上从来没有"忽略"入口（详情里的状态操作只有
确认/修复/复测/关闭/指派/驳回），实测库里也没有该状态的数据，留着动作只会让人能从 API
把漏洞改成页面上看不到、也筛不出来的状态。状态常量与中文名保留，仅为兼容历史数据。
"""


class VulnState:
    DRAFT = "draft"
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FIXING = "fixing"
    RETEST = "retest"
    FIXED = "fixed"
    CLOSED = "closed"
    REJECTED = "rejected"
    # ⚠️ 已废弃的状态：状态机不再提供 ignore 动作，仅保留常量与中文名，让老库里
    # status='ignored' 的历史漏洞在列表/导出里仍能正常显示「已忽略」而不是空白。
    IGNORED = "ignored"


# 状态 -> 中文名。**唯一来源**：路由层（提示文案）、导出报告都从这里取，
# 避免同一个状态在页面写「已修复」、在 Word 报告里写成别的（历史上有过一份
# 各自维护的副本，加状态时漏改一处就出现两种叫法）。
STATUS_NAMES = {
    VulnState.DRAFT: "草稿",
    VulnState.PENDING: "待确认",
    VulnState.CONFIRMED: "已确认",
    VulnState.FIXING: "修复中",
    VulnState.RETEST: "待复测",
    VulnState.FIXED: "已修复",
    VulnState.CLOSED: "已关闭",
    VulnState.REJECTED: "已驳回",
    # 仅用于展示历史数据（新流程不会再产生该状态）—— 去掉的话老数据会显示成英文原文
    VulnState.IGNORED: "已忽略",
}


# 每个动作允许的角色（使用角色 code）
# admin=超管, secops=安全专家, dev=研发人员, tester=测试人员, user=普通员工
ACTION_RULES = {
    "submit":        {"from": [VulnState.DRAFT], "roles": ["admin", "secops", "dev", "tester", "user"]},
    "confirm":       {"from": [VulnState.PENDING], "roles": ["admin", "secops"]},
    "reject":        {"from": [VulnState.PENDING], "roles": ["admin", "secops"]},
    "start_fix":     {"from": [VulnState.CONFIRMED], "roles": ["admin", "secops", "dev"]},
    "finish_fix":    {"from": [VulnState.FIXING], "roles": ["admin", "secops", "dev", "tester"]},
    "pass_retest":   {"from": [VulnState.RETEST], "roles": ["admin", "secops", "tester"]},
    "close":         {"from": [VulnState.FIXED], "roles": ["admin", "secops"]},
}

TRANSITIONS = {
    "submit": VulnState.PENDING,
    "confirm": VulnState.CONFIRMED,
    "reject": VulnState.REJECTED,
    "start_fix": VulnState.FIXING,
    "finish_fix": VulnState.RETEST,
    "pass_retest": VulnState.FIXED,
    "close": VulnState.CLOSED,
}


def validate_action(action: str, current_status: str, role_code: str) -> bool:
    rule = ACTION_RULES.get(action)
    if not rule:
        return False
    if current_status not in rule["from"]:
        return False
    return role_code in rule["roles"]
