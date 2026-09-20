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
- ignored    已忽略

关键流转（动作）：
- submit     draft -> pending        提交人
- confirm    pending -> confirmed   安全专家
- reject     pending -> rejected    安全专家（驳回）
- ignore     pending -> ignored     安全专家（忽略）
- start_fix  confirmed -> fixing    修复人
- finish_fix fixing -> retest       修复人
- pass_retest retest -> fixed       复测人
- close      fixed -> closed        安全专家
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
    VulnState.IGNORED: "已忽略",
}


# 每个动作允许的角色（使用角色 code）
# admin=超管, secops=安全专家, dev=研发人员, tester=测试人员, user=普通员工
ACTION_RULES = {
    "submit":        {"from": [VulnState.DRAFT], "roles": ["admin", "secops", "dev", "tester", "user"]},
    "confirm":       {"from": [VulnState.PENDING], "roles": ["admin", "secops"]},
    "reject":        {"from": [VulnState.PENDING], "roles": ["admin", "secops"]},
    "ignore":        {"from": [VulnState.PENDING, VulnState.CONFIRMED], "roles": ["admin", "secops"]},
    "start_fix":     {"from": [VulnState.CONFIRMED], "roles": ["admin", "secops", "dev"]},
    "finish_fix":    {"from": [VulnState.FIXING], "roles": ["admin", "secops", "dev", "tester"]},
    "pass_retest":   {"from": [VulnState.RETEST], "roles": ["admin", "secops", "tester"]},
    "close":         {"from": [VulnState.FIXED], "roles": ["admin", "secops"]},
}

TRANSITIONS = {
    "submit": VulnState.PENDING,
    "confirm": VulnState.CONFIRMED,
    "reject": VulnState.REJECTED,
    "ignore": VulnState.IGNORED,
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
