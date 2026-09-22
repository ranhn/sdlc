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
- confirm    pending -> confirmed   安全专家 / **该漏洞负责人（修复人）本人**
- reject     pending -> rejected    安全专家 / **该漏洞负责人（修复人）本人**（驳回）
- start_fix  confirmed -> fixing    修复人
- finish_fix fixing -> retest       修复人
- pass_retest retest -> fixed       复测人
- fail_retest retest -> fixing      复测人（**不通过打回重修**，需写明原因）
- close      fixed -> closed        安全专家

关于「负责人（修复人）也能确认/驳回」（见 ASSIGNEE_ACTIONS）：
    修复人页面（前端「漏洞修复」）只列出"指派给我"的漏洞，他在拿到一条漏洞时先要判断
    "这条到底成不成立"——成立则确认后进入修复，不成立（误报/环境问题/已修复）则驳回并写明
    原因。此前 confirm/reject 只给 admin|secops，修复人在自己页面上**既确认不了也驳回不了**，
    只能线下找安全专家，链路卡在第一步。
    放开方式刻意**不按角色**（不是"dev/tester 都能确认"）：只有该漏洞的 assignee 本人
    对这些动作生效，避免任意研发改别人漏洞的状态。判定在路由层做（要看 assignee_id），
    状态机这里只声明"哪些动作允许负责人走"。

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
# admin=超管, secops=安全专家, dev=研发人员, tester=测试人员, user=普通权限（原「普通员工」）
ACTION_RULES = {
    "submit":        {"from": [VulnState.DRAFT], "roles": ["admin", "secops", "dev", "tester", "user"]},
    "confirm":       {"from": [VulnState.PENDING], "roles": ["admin", "secops"]},
    "reject":        {"from": [VulnState.PENDING], "roles": ["admin", "secops"]},
    "start_fix":     {"from": [VulnState.CONFIRMED], "roles": ["admin", "secops", "dev"]},
    "finish_fix":    {"from": [VulnState.FIXING], "roles": ["admin", "secops", "dev", "tester"]},
    "pass_retest":   {"from": [VulnState.RETEST], "roles": ["admin", "secops", "tester"]},
    # 复测不通过 → 打回「修复中」。角色与 pass_retest 完全一致：**只有复测方**（安全专家/测试）
    # 能判"没通过"，修复人不能自己判自己没修好（那等于绕过复测环节）。
    "fail_retest":   {"from": [VulnState.RETEST], "roles": ["admin", "secops", "tester"]},
    "close":         {"from": [VulnState.FIXED], "roles": ["admin", "secops"]},
}

# 「负责人（修复人）本人」额外可以执行的动作 —— 角色列表之外的第二条授权通道。
#
# 为什么是这两个：修复人拿到漏洞后首先要下"成不成立"的判断（确认 = 成立并开始处置；
# 驳回 = 误报/环境问题/重复，需写明原因）。后续的修复动作（start_fix/finish_fix）
# 本来就已经对 dev/tester 开放，不需要在这里重复声明。
#
# 为什么不放进 ACTION_RULES["roles"]：那样等于"任意 dev/tester 能确认/驳回任何漏洞"，
# 权限放得比需求大得多。这里只管"是否允许负责人走这个动作"，"是不是负责人"由路由层
# 用 assignee_id 判定后传进来（validate_action 的 is_assignee 参数）。
ASSIGNEE_ACTIONS = frozenset({"confirm", "reject"})

TRANSITIONS = {
    "submit": VulnState.PENDING,
    "confirm": VulnState.CONFIRMED,
    "reject": VulnState.REJECTED,
    "start_fix": VulnState.FIXING,
    "finish_fix": VulnState.RETEST,
    "pass_retest": VulnState.FIXED,
    # 打回重修：回到 fixing（`fixed_at` 保留，那是"研发自称修完"的时间点，
    # 复测结论与打回记录都在流转记录里，便于统计"反复修了几轮"）
    "fail_retest": VulnState.FIXING,
    "close": VulnState.CLOSED,
}


def validate_action(action: str, current_status: str, role_code: str,
                    *, is_assignee: bool = False) -> bool:
    """该角色（或该漏洞的负责人本人）能否在当前状态下执行 action。

    is_assignee 为关键字参数、默认 False：老调用方（以及历史测试）行为完全不变。
    路由层按 `v.assignee_id == current.id` 传入 —— 注意"未指派"时两者都是 None，
    绝不能算作负责人，否则任何人都能把没主漏洞当自己的（调用方要判 assignee_id 非空）。
    """
    rule = ACTION_RULES.get(action)
    if not rule:
        return False
    if current_status not in rule["from"]:
        return False
    if role_code in rule["roles"]:
        return True
    return bool(is_assignee and action in ASSIGNEE_ACTIONS)
