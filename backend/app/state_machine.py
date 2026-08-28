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


# 每个动作允许的角色（使用角色 code）
# admin=超管, secops=安全专家, dev=研发, tester=测试, user=普通员工
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
