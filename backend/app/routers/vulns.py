"""漏洞管理路由：提交/确认/修复/复测/关闭 + 状态机 + 评论。"""
import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import inspect
from sqlalchemy.orm import Session, joinedload

from ..database import get_db
from ..models import AssetSystem, User, Vuln, VulnComment, VulnFlow
from ..schemas import (
    VulnAssign,
    VulnCommentOut,
    VulnCreate,
    VulnFlowOut,
    VulnListItem,
    VulnOut,
    VulnPage,
    VulnReject,
    VulnStatusAction,
    VulnUpdate,
)
from ..security import get_current_user, write_operation_log
from ..state_machine import STATUS_NAMES, TRANSITIONS, validate_action
from ..utils import network_clock as nc
from ..utils.vuln_csv import render_vulns_csv
from ..utils.vuln_docx import SEV_ZH, render_vulns_docx
# 飞书消息下发（指派通知）。import 的是模块而不是函数：调用点写成
# feishu_notify.send_text_in_background(...)，一眼能看出"这里在发飞书"。
from . import feishu as feishu_notify

# 导出的时间格式化（东八区）与 CSV/DOCX 渲染一起收敛到 utils.vuln_csv /
# utils.vuln_docx：路由层不再自己拼表格与时间字符串，只负责取数 + 包响应。

router = APIRouter(prefix="/api/vulns", tags=["漏洞管理"])

logger = logging.getLogger(__name__)

# STATUS_NAMES 已收敛到 state_machine（单一来源），此处不再本地维护一份副本。


# 列表接口返回的是 VulnListItem（VulnOut 去掉详情级大字段），见 schemas.VulnListItem：
# 列表响应从 416KB 降到个位数 KB，而详情/编辑/Word 导出仍走全量。


def _user_names(db: Session, ids) -> dict[int, str]:
    """一次性取回 {用户 id: 姓名}。

    为什么要批量取：列表/导出里每条漏洞都要填提交人/负责人/复测人，
    早期写法是 `_to_out` 里逐条 `query(User).filter(id==...)` —— 15 条漏洞要
    37 次查询，漏洞一多就线性放大（100 条 ≈ 250 次查询）。现在按需一次取完。
    """
    wanted = {i for i in ids if i is not None}
    if not wanted:
        return {}
    rows = db.query(User.id, User.full_name).filter(User.id.in_(wanted)).all()
    return {uid: name for uid, name in rows}


def _to_out(v: Vuln, db: Session, user_names: dict[int, str] | None = None) -> VulnOut:
    data = {c.key: getattr(v, c.key) for c in inspect(v).mapper.column_attrs}
    if data.get("screenshots"):
        try:
            data["screenshots"] = json.loads(data["screenshots"])
        except (TypeError, json.JSONDecodeError):
            data["screenshots"] = None
    else:
        data["screenshots"] = None
    if data.get("step_screenshots"):
        try:
            data["step_screenshots"] = json.loads(data["step_screenshots"])
        except (TypeError, json.JSONDecodeError):
            data["step_screenshots"] = None
    else:
        data["step_screenshots"] = None
    out = VulnOut.model_validate(data)
    # 调用方（列表/导出）已经批量取好姓名时直接查表；没有则退回按需查询（单条详情等场景）
    if user_names is None:
        user_names = _user_names(db, (v.reporter_id, v.assignee_id, v.reviewer_id))
    out.reporter_name = user_names.get(v.reporter_id)
    out.assignee_name = user_names.get(v.assignee_id) if v.assignee_id is not None else None
    out.reviewer_name = user_names.get(v.reviewer_id) if v.reviewer_id is not None else None
    if v.system:
        out.system_name = v.system.name
    return out


def _record_flow(db: Session, vuln_id: int, from_status: str | None, to_status: str,
                 operator: User, comment: str | None):
    db.add(VulnFlow(
        vuln_id=vuln_id,
        from_status=from_status,
        to_status=to_status,
        operator_id=operator.id,
        operator_name=operator.full_name,
        comment=comment,
    ))
    db.commit()


def _assign_change_text(db: Session, old_id: int | None, new_id: int | None) -> str:
    """把「负责人变更」写成一句人话（时间线的 comment 用）。

    为什么要分三种写法：直接拼 `{old} → {new}` 会产出「指派负责人：None → 张三」
    这种机器味文案，而这条记录是给人看的审计痕迹（漏洞详情「状态流转」区块）。
      · 原本没有负责人 → 「指派负责人：张三」
      · 换人           → 「变更负责人：李四 → 张三」
      · 清空           → 「取消指派：李四 → 未指派」
    指派不改变状态本身（from == to），因此前端对这类条目只显示一个状态 + 这句说明。
    """
    names = _user_names(db, (old_id, new_id))
    old = names.get(old_id) if old_id is not None else None
    new = names.get(new_id) if new_id is not None else None
    if old_id is None and new_id is not None:
        return f"指派负责人：{new or new_id}"
    if new_id is None:
        return f"取消指派：{old or old_id} → 未指派"
    return f"变更负责人：{old or old_id} → {new or new_id}"


def _is_assignee(v: Vuln, user: User) -> bool:
    """user 是不是这条漏洞的**当前负责人**（修复人）。

    必须同时判 `assignee_id is not None`：未指派时 `v.assignee_id` 与 `user.id`
    都可能落进"空值比较"的陷阱（历史上踩过 None == None 的坑），漏判会让任何人都
    把"没主的漏洞"当成自己负责的，从而拿到确认/驳回/转派权限。
    """
    return v.assignee_id is not None and user is not None and v.assignee_id == user.id


# 等级 → 卡片标题配色。与前端 severityType 同一套观感（红/橙/蓝/灰），
# 但**取的是深色档**：飞书的 blue/grey 渲染出来很淡，标题栏会显得空、不像"警告"。
# carmine/red/orange/indigo 更沉，跨端看到同一颜色即代表同一等级。
_SEV_CARD_TEMPLATE = {
    "critical": "carmine", "high": "orange", "medium": "indigo", "low": "grey",
}


def _assignee_notice_card(v: Vuln, assignee: User, operator: User, base_url: str,
                          initial_password: str | None = None) -> dict:
    """「漏洞已指派给你」的飞书**消息卡片**（纯函数，不含网络调用，便于单测）。

    为什么用卡片而不是纯文本：这条通知的读者是**刚被派活的研发**，他需要在 3 秒内看清
    "多严重 / 哪个系统 / 点哪里"。纯文本只能靠换行凑结构，链接还是一条裸 URL（移动端
    尤其不显眼）；卡片能给出等级配色标题 + 双列字段 + 一个明确的主按钮。

    链接用修复页 /vulnerabilities/fix?id=NN（与 CSV/Word 导出同一套 ?id= 语义：管理员被
    路由守卫留在 /submit、开发落到 /fix，两种角色点开都是这一条漏洞）。
    base_url 为空（拿不到请求上下文）时**不留死链**，退化成一句文字指引。

    initial_password 非空时追加一块"首次登录"信息（账号 + 初始口令 + 首登必改提示）。
    传入什么由调用方按 feishu.initial_password_for 判定 —— 已改过密码的账号恒为 None，
    所以**绝不会把口令发给已在用的账号**。
    """
    sev = v.severity or "medium"
    sev_zh = SEV_ZH.get(sev, sev)
    status_zh = STATUS_NAMES.get(v.status, v.status or "—")
    link = f"{base_url.rstrip('/')}/vulnerabilities/fix?id={v.id}" if base_url else ""
    elements: list[dict] = [
        feishu_notify.text_div(f"**#{v.id} {v.title}**"),
        # 2×2 两列网格（1.0 的 fields + is_short）。标签与值写在**同一行**：
        # 用 `\n` 拆成两行会被当成两个段落、被段间距撑散（上一版截图里最刺眼的问题）。
        feishu_notify.fields_div(
            f"**等级**：{sev_zh}",
            f"**当前状态**：{status_zh}",
            f"**所属系统**：{v.system.name if v.system else '—'}",
            f"**负责人**：{assignee.full_name or assignee.username}",
        ),
    ]
    if initial_password:
        # 只有"飞书同步来、且从没改过密码"的账号才会走到这里：他们手上还没有能用的密码，
        # 通知必须把账号和初始口令一起给他，否则等于把人派了活却不给他进门的钥匙。
        elements.append({"tag": "hr"})
        elements.append(feishu_notify.text_div(
            "**首次登录**：以下账号密码仅本次下发，登录后会强制要求修改密码"))
        elements.append(feishu_notify.credentials_div(assignee.username, initial_password))
    if link:
        elements += [{"tag": "hr"}, feishu_notify.primary_button("打开漏洞详情", link)]
    else:
        elements.append(feishu_notify.text_div("请登录 SDLC 安全平台 →「漏洞修复」处理"))
    elements.append(feishu_notify.note_div(
        f"由 {operator.full_name or operator.username} 指派给你"))
    return {
        "config": {"wide_screen_mode": True},
        "header": {
            # 1.0 的 header 没有副标题，等级只能进标题（2.0 才有 subtitle，见 feishu.py 说明）
            "template": _SEV_CARD_TEMPLATE.get(sev, "indigo"),
            "title": {"tag": "plain_text", "content": f"漏洞指派 · {sev_zh}"},
        },
        "elements": elements,
    }


def _notify_base_url(request: Request | None) -> str:
    """飞书通知里深链要用的基地址。

    与 CSV/Word 导出的 ``_resolve_base_url`` 有一个**关键区别**：导出文件是操作人自己下载的，
    用"他此刻访问的地址"永远是对的；而通知是发给**另一个人**的，必须是**别人也点得开**的地址。
    所以这里让显式配置 ``PUBLIC_BASE_URL`` 优先（生产配成对外域名），没配才退回请求上下文
    （Referer → Origin → CORS_ORIGINS → 请求自身 host，与导出一致）。

    没配、且解析出来的是回环/内网地址时打一条 WARNING：页面上的现象是"收件人点链接打不开"，
    这条日志把原因直接指到配置上（实测踩过：本机 127.0.0.1:5173 的链接发给了外部同事）。
    """
    import os
    from urllib.parse import urlsplit

    explicit = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")
    if explicit:
        return explicit
    if request is None:
        return ""
    base = _resolve_base_url(request)
    try:
        host = (urlsplit(base).hostname or "").lower()
    except Exception:  # noqa: BLE001
        host = ""
    # 粗判即可：这些地址只在本机/内网可达，收件人在外面就点不开
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1") or \
            host.startswith(("127.", "10.", "192.168.", "172.1", "172.2", "172.3")):
        logger.warning(
            "指派通知里的链接是内网/本机地址（%s）—— 收件人在别的网络下点不开。"
            "生产环境请配置 PUBLIC_BASE_URL=https://<对外域名>", base,
        )
    return base


def _notify_assignee(db: Session, v: Vuln, prev_assignee_id: int | None,
                     operator: User, request: Request | None = None) -> None:
    """指派之后给**新负责人**发一条飞书单聊消息（尽力而为：不抛错、不阻塞）。

    三个入口都会调它：提交漏洞时直接指定负责人、编辑表单里改了负责人、指派接口
    （含安全专家指派与修复人转派）。

    刻意的三条约束：
      · **只在换人时发**（assignee_id != prev）：重复指派同一个人、编辑时没动负责人，
        都不再打扰他 —— 与"时间线只在换人时记一条"同一口径；
      · **取消指派不发**（assignee_id 为空）：没有收件人；
      · **整体 try 包住 + 发送在后台线程**：飞书挂了/限流/权限没开/接收人不在可用范围，
        一律不能影响"指派"这个业务动作，也不能让他多等几秒。
    结果写日志（成功 INFO / 失败 WARNING，含飞书返回码），"他没收到"这类问题可查日志定位。
    """
    try:
        if v.assignee_id is None or v.assignee_id == prev_assignee_id:
            return
        if not feishu_notify.notify_enabled():
            return
        assignee = db.query(User).filter(User.id == v.assignee_id).first()
        if not assignee:
            return
        open_id = (assignee.feishu_open_id or "").strip()
        if not open_id:
            # 手工创建的账号（不是飞书同步来的）没有 open_id，没有可送达的地址。
            # 记一行日志而不是静默吞掉 —— "为什么他没收到通知"最常见的原因就是这个。
            logger.info("飞书指派通知跳过：负责人 #%s（%s）无 open_id（非飞书同步账号）",
                        assignee.id, assignee.full_name or assignee.username)
            return
        base_url = _notify_base_url(request)
        # 该账号还没拿到可用密码（飞书同步来 + 从没改过密码）→ 通知里附上账号与初始口令；
        # 已改密的账号恒为 None（见 feishu.initial_password_for），不会把口令发给在用账号。
        initial_password = feishu_notify.initial_password_for(assignee)
        feishu_notify.send_in_background(
            open_id,
            "interactive",                       # 消息卡片：等级配色标题 + 双列字段 + 主按钮
            _assignee_notice_card(v, assignee, operator, base_url, initial_password),
            tag=f"漏洞 #{v.id} 指派给 {assignee.full_name or assignee.username}",
        )
    except Exception as exc:  # noqa: BLE001 —— 通知是"尽力而为"，绝不打断指派
        logger.warning("飞书指派通知准备失败（不影响指派）：%s", exc)


# ============ 状态流转通知（确认/驳回/修复完成/复测通过/关闭）============
#
# 为什么只在这五个动作发、且只发给这两种人：
#   · 通知的判据是"这个动作之后**谁需要动起来**"，不是"所有相关人都广播一遍" ——
#     每一步都发给所有人，一周之后大家就会把这类消息静音，等于没有通知。
#   · start_fix（开始修复）刻意不发：提单人不需要知道每一小步，纯噪音。
#
# 收件人口径：
#   confirm / reject / finish_fix → 提单人（reporter）
#       · reject：提单人必须拿到**驳回原因**，否则漏洞无声消失（用户反馈的原始诉求）；
#       · finish_fix：请提单人复核/复测（内部漏洞的提单人通常就是提测试结论的人）。
#   pass_retest / close → 提单人 + 负责人（闭环，双方都该知道）
#
# 卡片标题与配色跟"指派通知"同一套观感（等级配色 + 双列字段 + 深链按钮）。
_STATUS_NOTICES: dict[str, dict[str, str]] = {
    "confirm": {
        "title": "漏洞已受理",
        "template": "green",
        "action_label": "确认受理",
    },
    "reject": {
        "title": "漏洞已驳回",
        "template": "red",
        "action_label": "驳回",
    },
    "finish_fix": {
        "title": "修复完成，待复测",
        "template": "blue",
        "action_label": "修复完成",
    },
    "pass_retest": {
        "title": "复测通过",
        "template": "green",
        "action_label": "复测通过",
    },
    "close": {
        "title": "漏洞已关闭",
        "template": "grey",
        "action_label": "关闭",
    },
}

# 各动作的收件人（"reporter"/"assignee"），去重与"跳过操作人"在 _notify_status_change 里统一处理
_STATUS_RECIPIENTS: dict[str, tuple[str, ...]] = {
    "confirm": ("reporter",),
    "reject": ("reporter",),
    "finish_fix": ("reporter",),
    "pass_retest": ("reporter", "assignee"),
    "close": ("reporter", "assignee"),
}


def _status_notice_card(v: Vuln, *, notice: dict[str, str], operator: User,
                        base_url: str, assignee_name: str | None = None,
                        reason: str | None = None,
                        comment: str | None = None) -> dict:
    """状态流转通知卡片（纯函数，便于单测）。

    与指派卡片的区别只有两处：标题按动作走、驳回时**必须带原因**（这是这张卡存在的理由）。

    assignee_name 由调用方查出后传入：``Vuln`` 上只有 ``system`` 关系，
    **没有** assignee 关系（见 models.py），所以这里不能靠 ``v.assignee`` 取名字。
    """
    sev = v.severity or "medium"
    sev_zh = SEV_ZH.get(sev, sev)
    status_zh = STATUS_NAMES.get(v.status, v.status or "—")
    link = f"{base_url.rstrip('/')}/vulnerabilities/fix?id={v.id}" if base_url else ""
    elements: list[dict] = [
        feishu_notify.text_div(f"**#{v.id} {v.title}**"),
        feishu_notify.fields_div(
            f"**等级**：{sev_zh}",
            f"**当前状态**：{status_zh}",
            f"**所属系统**：{v.system.name if getattr(v, 'system', None) else '—'}",
            f"**负责人**：{assignee_name or '未指派'}",
        ),
    ]
    # 驳回原因单独成块（换行展示，不塞进 fields —— 原因是长文本，塞进两列网格会被截断）
    if reason:
        elements += [{"tag": "hr"},
                     feishu_notify.text_div(f"**驳回原因**\n{reason}")]
    if comment:
        elements.append(feishu_notify.text_div(f"**备注**：{comment}"))
    if link:
        elements += [{"tag": "hr"}, feishu_notify.primary_button("查看漏洞详情", link)]
    else:
        elements.append(feishu_notify.text_div("请登录 SDLC 安全平台查看详情"))
    elements.append(feishu_notify.note_div(
        f"由 {operator.full_name or operator.username} {notice['action_label']}"))
    return {
        "config": {"wide_screen_mode": True},
        "header": {
            "template": notice["template"],
            "title": {"tag": "plain_text", "content": f"{notice['title']} · {sev_zh}"},
        },
        "elements": elements,
    }


def _notify_status_change(db: Session, v: Vuln, action: str, operator: User,
                          request: Request | None = None, *,
                          reason: str | None = None,
                          comment: str | None = None) -> None:
    """状态流转后通知相关人（尽力而为：不抛错、不阻塞业务动作）。

    逐条过滤，任一条不满足就跳过（并说明原因，便于回答"他怎么没收到"）：
      1. 该动作不在通知矩阵里（如 start_fix）→ 不发；
      2. FEISHU_NOTIFY=0 或未配 App 凭证 → 不发；
      3. **操作人自己不收**（安全专家提的单自己驳回、自己确认等）；
      4. 收件人没有 feishu_open_id（手工账号）→ 跳过并记日志。
    """
    try:
        notice = _STATUS_NOTICES.get(action)
        if not notice:
            return
        if not feishu_notify.notify_enabled():
            return
        base_url = _notify_base_url(request)
        # 负责人名字要显式查（Vuln 上没有 assignee 关系，见卡片函数说明）
        assignee = (db.query(User).filter(User.id == v.assignee_id).first()
                    if v.assignee_id else None)
        assignee_name = (assignee.full_name or assignee.username) if assignee else None

        wanted: list[tuple[str, int | None]] = []
        for who in _STATUS_RECIPIENTS.get(action, ()):
            uid = v.reporter_id if who == "reporter" else v.assignee_id
            if uid:
                wanted.append((who, uid))

        sent_to: set[int] = set()
        for who, uid in wanted:
            if uid in sent_to:
                continue                 # 提单人 == 负责人时只发一条
            sent_to.add(uid)
            if uid == operator.id:
                continue                 # 操作人自己不打扰
            user = db.query(User).filter(User.id == uid).first()
            if not user:
                continue
            open_id = (user.feishu_open_id or "").strip()
            if not open_id:
                logger.info(
                    "飞书流转通知跳过：%s #%s（%s）无 open_id（非飞书同步账号）",
                    who, user.id, user.full_name or user.username,
                )
                continue
            feishu_notify.send_in_background(
                open_id,
                "interactive",
                _status_notice_card(v, notice=notice, operator=operator,
                                    base_url=base_url, assignee_name=assignee_name,
                                    reason=reason, comment=comment),
                tag=f"漏洞 #{v.id} {notice['title']} → {user.full_name or user.username}",
            )
    except Exception as exc:  # noqa: BLE001 —— 通知绝不打断状态流转
        logger.warning("飞书流转通知准备失败（不影响流转）：%s", exc)


def _apply_status_filter(query, status: str | None):
    """按状态过滤（支持逗号分隔的多状态）。

    背景：rejected（已驳回）与 ignored（已忽略）都是"不修的终态"，前端把两者
    归成一个「已忽略 / 已驳回」选项，传 status=ignored,rejected —— 否则驳回的
    漏洞在状态筛选里根本搜不到（此前下拉里也没有「已驳回」项）。
    单值时行为与原来完全一致（精确匹配），历史调用方不受影响。
    """
    if not status:
        return query
    codes = [s.strip() for s in status.split(",") if s.strip()]
    if not codes:
        return query
    if len(codes) == 1:
        return query.filter(Vuln.status == codes[0])
    return query.filter(Vuln.status.in_(codes))


def _describe_scope(
    db: Session,
    *,
    status: str | None = None,
    severity: str | None = None,
    system_id: int | None = None,
    vuln_category: str | None = None,
    is_external: bool | None = None,
    mine: bool = False,
    assigned_to_me: bool = False,
    ids: str | None = None,
) -> str:
    """把导出筛选条件翻译成报告封面/附录用的自然语言范围描述。

    为什么要有：报告一旦离开系统（打印、外发），读者只能从文档本身判断
    "这份清单是哪一批数据"。不写清范围，几份不同筛选的报告混在一起就分不出来了。
    """
    parts: list[str] = []
    if ids:
        parts.append(f"指定漏洞（{len([x for x in ids.split(',') if x.strip()])} 条）")
    if status:
        names = " / ".join(
            STATUS_NAMES.get(s.strip(), s.strip())
            for s in status.split(",") if s.strip()
        )
        if names:
            parts.append(f"状态：{names}")
    if severity:
        parts.append(f"等级：{SEV_ZH.get(severity, severity)}")
    if system_id:
        row = db.query(AssetSystem).filter(AssetSystem.id == system_id).first()
        parts.append(f"所属系统：{row.name if row else system_id}")
    if vuln_category:
        parts.append(f"漏洞大类：{vuln_category}")
    # is_external 用 is not None 判定：False 是"只要内部提交"，也是一个筛选条件，
    # 不能跟"没传"混为一谈 —— 否则报告封面会把"仅内部"的报告写成"全部漏洞"。
    if is_external is not None:
        parts.append("来源：外部报告" if is_external else "来源：内部提交")
    if assigned_to_me:
        parts.append("指派给我的漏洞")
    elif mine:
        parts.append("与我相关（我提交或我负责）")
    return " · ".join(parts) if parts else "全部漏洞"


@router.get("", response_model=VulnPage)
def list_vulns(
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    system_id: int | None = Query(default=None),
    vuln_category: str | None = Query(default=None, description="一级大类过滤,如 注入类 / 访问控制"),
    vuln_type: str | None = Query(default=None, description="二级子类过滤,如 SQL注入"),
    mine: bool = Query(default=False),
    assigned_to_me: bool = Query(default=False),
    is_external: bool | None = Query(default=None, description="漏洞来源过滤：None=全部, True=外部, False=内部"),
    page: int = Query(default=1, ge=1, description="页码，从 1 开始"),
    page_size: int = Query(default=12, ge=1, le=200, description="每页条数（上限 200：别用一个参数把分页绕过去）"),
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    """漏洞列表（**服务端分页**，返回 {items, total, page, page_size}）。

    分页作用在**筛选之后**：先按筛选条件数出 total，再取当前页那一段。
    响应只含清单级字段（见 VulnListItem），详情/编辑/导出走各自的接口。
    """
    query = db.query(Vuln)
    query = _apply_status_filter(query, status)
    if severity:
        query = query.filter(Vuln.severity == severity)
    if system_id:
        query = query.filter(Vuln.system_id == system_id)
    if vuln_category:
        query = query.filter(Vuln.vuln_category == vuln_category)
    if vuln_type:
        query = query.filter(Vuln.vuln_type == vuln_type)
    if is_external is not None:
        query = query.filter(Vuln.is_external == is_external)
    if mine:
        query = query.filter((Vuln.reporter_id == current.id) | (Vuln.assignee_id == current.id))
    if assigned_to_me:
        query = query.filter(Vuln.assignee_id == current.id)
    # 总数要在**分页之前**算（前端分页组件靠它算页数），且不受 page/page_size 影响
    total = query.count()
    # 排序加 id 兜底：批量导入常出现 created_at 完全相同的数据，只按时间排时
    # 翻页顺序不稳定 —— 同一条可能在两页里都出现、或某条永远翻不到。
    # joinedload：本行要用 v.system.name，不预加载就是每条一次查询（N+1）
    vulns = (
        query.options(joinedload(Vuln.system))
        .order_by(Vuln.created_at.desc(), Vuln.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    names = _user_names(db, [i for v in vulns for i in (v.reporter_id, v.assignee_id, v.reviewer_id)])
    return VulnPage(
        items=[_to_out(v, db, names) for v in vulns],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/export")
def export_vulns(
    request: Request,
    fmt: str = Query(..., pattern="^(csv|docx)$"),
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    system_id: int | None = Query(default=None),
    vuln_category: str | None = Query(default=None, description="一级大类过滤,如 注入类 / 访问控制"),
    is_external: bool | None = Query(default=None, description="漏洞来源过滤：None=全部, True=外部, False=内部"),
    mine: bool = Query(default=False),
    assigned_to_me: bool = Query(default=False),
    ids: str | None = Query(default=None, description="可选,逗号分隔的漏洞 ID 列表；传了则只导出这些条(与其它筛选条件取交集)"),
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    """批量导出漏洞（CSV / Word）。仅管理员/安全专家可操作。"""
    if current.role is None or current.role.code not in ("admin", "secops"):
        raise HTTPException(status_code=403, detail="仅管理员/安全专家可导出漏洞")
    query = db.query(Vuln)
    # 与列表同一套状态过滤（含 ignored,rejected 这种"忽略组"），保证导出范围与列表所见一致
    query = _apply_status_filter(query, status)
    if severity:
        query = query.filter(Vuln.severity == severity)
    if system_id:
        query = query.filter(Vuln.system_id == system_id)
    # 漏洞大类 / 来源：页面筛选栏上有这两项，导出必须同样支持 ——
    # 导出按钮写的是"导出当前筛选结果"，这里少接一个参数就会出现
    # "页面上筛出 2 条、导出的文件里却是全部 15 条"这种对不上的情况。
    if vuln_category:
        query = query.filter(Vuln.vuln_category == vuln_category)
    if is_external is not None:
        query = query.filter(Vuln.is_external == is_external)
    if mine:
        query = query.filter((Vuln.reporter_id == current.id) | (Vuln.assignee_id == current.id))
    if assigned_to_me:
        query = query.filter(Vuln.assignee_id == current.id)
    if ids:
        # 解析逗号分隔的 ID 列表,过滤非法值
        try:
            id_list = [int(x) for x in ids.split(",") if x.strip()]
        except ValueError:
            raise HTTPException(status_code=400, detail="ids 参数格式错误,应为逗号分隔的整数")
        if not id_list:
            raise HTTPException(status_code=400, detail="ids 参数不能为空")
        query = query.filter(Vuln.id.in_(id_list))
    # 导出排序：**最早在前**（与页面列表相反）。
    # 页面列表是"最新优先"（便于日常处理），但导出报告是台账/留档：读者按时间顺序
    # 从头看整改脉络，最早的一条排在最前面，ID 也就自然从小到大（用户要求）。
    # 同时序（批量导入会有相同 created_at）再用 id 升序兜底，保证结果确定、可复现。
    vulns = query.order_by(Vuln.created_at.asc(), Vuln.id.asc()).all()
    names = _user_names(db, [i for v in vulns for i in (v.reporter_id, v.assignee_id, v.reviewer_id)])
    rows = [_to_out(v, db, names) for v in vulns]

    scope_desc = _describe_scope(
        db, status=status, severity=severity, system_id=system_id,
        vuln_category=vuln_category, is_external=is_external,
        mine=mine, assigned_to_me=assigned_to_me, ids=ids,
    )
    if fmt == "csv":
        # CSV 里的"详情链接"要用用户此刻访问的平台地址（见 _resolve_base_url）
        return _export_csv(rows, base_url=_resolve_base_url(request))
    return _export_docx(rows, exported_by=current.full_name, scope_desc=scope_desc)


def _resolve_base_url(request: Request) -> str:
    """解析导出文件里超链接要用的平台基地址（形如 https://sdlc.example.com）。

    优先级（从"用户实际在用哪个地址"到"部署配置"）：
      1. ``Referer``：导出必然发生在平台页面上（axios 的 blob 请求同源带 Referer），
         取它的 origin 就是用户此刻访问的地址 —— 多域名 / 内外网双入口都自适应；
      2. ``Origin``：部分客户端/代理会带（跨域 XHR 一定带）；
      3. ``CORS_ORIGINS`` 的第一条：部署时配置的前端白名单（生产由 run_dev/容器注入）；
      4. 请求自身的 scheme://host：生产环境前端由 FastAPI 托管（同源），此时一定正确。

    为什么不写死域名：同一份代码要跑在本地、内网、多套部署环境上，写死必然有一处是错的。
    """
    for raw in (request.headers.get("referer"), request.headers.get("origin")):
        if not raw:
            continue
        try:
            from urllib.parse import urlsplit

            parts = urlsplit(raw)
            if parts.scheme and parts.netloc:
                return f"{parts.scheme}://{parts.netloc}"
        except Exception:  # noqa: BLE001
            continue
    import os

    cors = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
    if cors:
        return cors[0].rstrip("/")
    return str(request.base_url).rstrip("/")


def _export_csv(rows: list[VulnOut], *, base_url: str | None = None):
    """导出 CSV：清单级字段 + 每行一条可点回平台的漏洞详情链接。

    早期版本只有数据列、没有链接，CSV 发出去后读者要自己回平台"按标题搜一遍"。
    现在每行都带 ``/vulnerabilities/submit?id=<id>`` 深链（点开直达该漏洞详情）。
    """
    data = render_vulns_csv(rows, base_url=base_url)
    return StreamingResponse(
        iter([data]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="vulns-{nc.now().strftime("%Y%m%d-%H%M")}.csv"'},
    )


def _export_docx(rows: list[VulnOut], *, exported_by: str | None = None,
                 scope_desc: str | None = None):
    """生成漏洞清单 Word 报告（商业级排版）。

    排版逻辑集中在 ``utils.vuln_docx``（封面 / 统计概览 / 横向清单表 / 逐条详情 /
    页眉页脚页码 / 附录），路由层只负责"渲染 + 包成下载响应"。

    为什么重写（用户反馈："批量导出的 word 报告格式有点问题"）：
        旧实现 ``doc.add_table(rows=1, cols=10)`` 且**不设列宽** —— A4 纵向版心
        16.4cm 被 10 等分，每列约 1.6cm，长文本被压成一字一行（标题竖排、ID 断成
        两行、接口地址只剩一列竖字）。Word 是固定表格布局，列宽必须显式写进
        tblGrid/tcW（见 ``vuln_docx._set_col_widths``），并且清单章改用**横向**
        版心 25.1cm，10 列才有合理宽度。
    """
    data = render_vulns_docx(rows, exported_by=exported_by, scope_desc=scope_desc)
    stamp = nc.now().strftime("%Y%m%d-%H%M")
    return StreamingResponse(
        iter([data]),
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="vulns-report-{stamp}.docx"'},
    )







@router.get("/{vuln_id}", response_model=VulnOut)
def get_vuln(vuln_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    v = db.query(Vuln).filter(Vuln.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    return _to_out(v, db)


@router.post("", response_model=VulnOut, status_code=201)
def create_vuln(request: Request, data: VulnCreate, db: Session = Depends(get_db),
                current: User = Depends(get_current_user)):
    v = Vuln(
        title=data.title,
        description=data.description,
        reproduce_steps=data.reproduce_steps,
        impact=data.impact,
        screenshots=json.dumps(data.screenshots, ensure_ascii=False) if data.screenshots else None,
        step_screenshots=json.dumps(data.step_screenshots, ensure_ascii=False) if data.step_screenshots else None,
        system_id=data.system_id,
        severity=data.severity,
        vuln_category=data.vuln_category,
        vuln_type=data.vuln_type,
        cvss=data.cvss,
        reporter_id=current.id,
        assignee_id=data.assignee_id,
        status="pending",
        source="manual",
        is_external=data.is_external,
        external_source=data.external_source,
        api_endpoint=data.api_endpoint,
        fix_suggestion=data.fix_suggestion,
    )
    db.add(v)
    db.commit()
    db.refresh(v)
    _record_flow(db, v.id, "draft", "pending", current, "漏洞提交")
    # 提交表单里就填了「修复负责人」→ 一并通知他（prev=None 表示这是首次指派）
    if v.assignee_id is not None:
        _notify_assignee(db, v, None, current, request)
    write_operation_log(db, current, "create_vuln", "vuln", f"提交漏洞 #{v.id} {v.title}")
    return _to_out(v, db)


@router.patch("/{vuln_id}", response_model=VulnOut)
def update_vuln(vuln_id: int, request: Request, data: VulnUpdate, db: Session = Depends(get_db),
                current: User = Depends(get_current_user)):
    """编辑漏洞字段。权限：提交人本人 / 管理员 / 安全专家。

    closed 状态下不可编辑（避免审计期改记录）；其他状态允许补充修正。
    只覆盖请求里实际携带的字段（schema 已全部 Optional）。
    """
    v = db.query(Vuln).filter(Vuln.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    role_code = current.role.code if current.role else "user"
    is_owner = v.reporter_id == current.id
    is_admin_or_secops = role_code in ("admin", "secops")
    if not (is_owner or is_admin_or_secops):
        raise HTTPException(status_code=403, detail="仅提交人本人或管理员/安全专家可编辑")
    if v.status == "closed":
        raise HTTPException(status_code=400, detail="已关闭的漏洞不可编辑")

    # 仅应用显式提供的字段，避免把未传的字段（如 assignee_id=None）误清空。
    updates = data.model_dump(exclude_unset=True)
    prev_assignee_id = v.assignee_id          # 变更前的人（指派留痕要用）
    # list/dict 字段单独序列化
    if "screenshots" in updates:
        v.screenshots = json.dumps(updates.pop("screenshots"), ensure_ascii=False) if updates["screenshots"] is not None else None
    if "step_screenshots" in updates:
        v.step_screenshots = json.dumps(updates.pop("step_screenshots"), ensure_ascii=False) if updates["step_screenshots"] is not None else None
    for key, val in updates.items():
        setattr(v, key, val)

    db.commit()
    db.refresh(v)
    # 编辑表单里带了「修复负责人」，改它同样是指派动作 → 一并写时间线。
    # 只在"显式传了 assignee_id 且真的变了"时记，避免每次编辑都往时间线里刷一条。
    if "assignee_id" in updates and prev_assignee_id != v.assignee_id:
        _record_flow(
            db, v.id, v.status, v.status, current,
            _assign_change_text(db, prev_assignee_id, v.assignee_id) + "（编辑时变更）",
        )
        # 编辑表单里改了负责人 = 一次指派动作 → 同样通知新负责人
        _notify_assignee(db, v, prev_assignee_id, current, request)
    write_operation_log(
        db, current, "update_vuln", "vuln",
        f"编辑漏洞 #{v.id}「{v.title}」（{role_code}）",
    )
    return _to_out(v, db)


@router.post("/{vuln_id}/assign", response_model=VulnOut)
def assign_vuln(vuln_id: int, request: Request, data: VulnAssign, db: Session = Depends(get_db),
                current: User = Depends(get_current_user)):
    """指派 / 转派负责人。权限：安全专家（admin/secops）**或该漏洞当前负责人本人**。

    为什么给负责人开这个口：「漏洞修复」页只显示"指派给我"的漏洞，修复人遇到
    "不该我修 / 不熟这块 / 需要转给模块负责人"时，此前页面上没有任何入口，只能线下
    找人改。这里给的是**转派**能力，判定仍是"仅当前负责人本人"，不按角色放开 ——
    否则任意 dev 都能改别人漏洞的负责人。
    """
    v = db.query(Vuln).filter(Vuln.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    role_code = current.role.code if current.role else "user"
    if role_code not in ("admin", "secops") and not _is_assignee(v, current):
        raise HTTPException(status_code=403, detail="仅安全专家或该漏洞负责人（修复人）可指派")
    assignee = db.query(User).filter(User.id == data.assignee_id).first()
    if not assignee:
        raise HTTPException(status_code=400, detail="负责人不存在")
    prev_assignee_id = v.assignee_id          # 变更前的人（时间线文案要用）
    v.assignee_id = data.assignee_id
    db.commit()
    db.refresh(v)
    # 时间线留痕：此前这里只写操作日志，详情「状态流转」里看不到任何指派记录
    # （用户反馈"每次指派的记录应该在下面打印出来"）。指派不改状态，from/to 都填
    # 当前状态，具体变更写在 comment 里（前端对 from==to 的条目只显示一个状态）。
    _record_flow(
        db, v.id, v.status, v.status, current,
        _assign_change_text(db, prev_assignee_id, v.assignee_id),
    )
    # 飞书通知新负责人（后台线程发送：飞书侧的问题不影响本次指派，见 _notify_assignee）
    _notify_assignee(db, v, prev_assignee_id, current, request)
    # 详情里同时记录「指派给 谁(中文名)[ID]」，便于审计日志辨识接收人
    assignee_desc = f"{assignee.username}({assignee.full_name})[ID={assignee.id}]"
    write_operation_log(
        db, current, "assign_vuln", "vuln",
        f"指派漏洞 #{v.id}「{v.title}」给 {assignee_desc}",
    )
    return _to_out(v, db)


@router.post("/{vuln_id}/action/{action}", response_model=VulnOut)
def vuln_action(vuln_id: int, action: str, request: Request, data: VulnStatusAction,
                db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    v = db.query(Vuln).filter(Vuln.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    role_code = current.role.code if current.role else "user"
    # 第二条授权通道：该漏洞的负责人（修复人）本人可对自己的漏洞走 ASSIGNEE_ACTIONS
    # （确认/驳回）—— 修复人页面上的「确认」「驳回」按钮就是走这里。
    if not validate_action(action, v.status, role_code, is_assignee=_is_assignee(v, current)):
        raise HTTPException(
            status_code=403,
            detail=(f"当前状态({STATUS_NAMES.get(v.status, v.status)})下，角色无权执行"
                    f"[{action}]操作；若该漏洞由你负责，需先由安全专家将该漏洞指派给你"),
        )

    to_status = TRANSITIONS[action]
    from_status = v.status
    v.status = to_status

    # ⚠️ 这里原来写的是 __import__("datetime").nc.utcnow() —— 导入的是 datetime 模块，
    # 上面根本没有 nc 属性，于是"修复完成"和"关闭"两个动作必崩 500
    # （AttributeError: module 'datetime' has no attribute 'nc'）。
    # 正确写法是直接用模块顶部 import 的网络时钟 nc（全项目统一用它取时间）。
    if action == "close":
        v.closed_at = nc.utcnow()
    if action == "finish_fix":
        v.fixed_at = nc.utcnow()
        v.reviewer_id = current.id
    if action == "pass_retest":
        v.reviewer_id = current.id

    db.commit()
    db.refresh(v)
    _record_flow(db, v.id, from_status, to_status, current, data.comment)
    write_operation_log(db, current, f"vuln_{action}", "vuln", f"漏洞 #{v.id} {from_status}->{to_status}")
    # 状态流转通知（确认/修复完成/复测通过/关闭；start_fix 不在矩阵里，会自动跳过）
    _notify_status_change(db, v, action, current, request, comment=data.comment)
    return _to_out(v, db)


@router.post("/{vuln_id}/reject", response_model=VulnOut)
def reject_vuln(vuln_id: int, request: Request, data: VulnReject, db: Session = Depends(get_db),
                current: User = Depends(get_current_user)):
    v = db.query(Vuln).filter(Vuln.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    role_code = current.role.code if current.role else "user"
    # 与 confirm 同一条通道：负责人（修复人）本人驳回自己负责的漏洞（误报/环境问题等）
    if not validate_action("reject", v.status, role_code, is_assignee=_is_assignee(v, current)):
        raise HTTPException(status_code=403, detail="仅安全专家或该漏洞负责人（修复人）可驳回")
    v.status = "rejected"
    v.rejection_reason = data.reason
    db.commit()
    db.refresh(v)
    _record_flow(db, v.id, "pending", "rejected", current, f"驳回：{data.reason}")
    write_operation_log(db, current, "vuln_reject", "vuln", f"漏洞 #{v.id} 驳回：{data.reason}")
    # 驳回必须让**提单人**知道原因：否则漏洞从他的视角无声消失了
    _notify_status_change(db, v, "reject", current, request, reason=data.reason)
    return _to_out(v, db)


@router.get("/{vuln_id}/flows", response_model=list[VulnFlowOut])
def vuln_flows(vuln_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    return db.query(VulnFlow).filter(VulnFlow.vuln_id == vuln_id).order_by(VulnFlow.created_at.asc()).all()


@router.get("/{vuln_id}/comments", response_model=list[VulnCommentOut])
def vuln_comments(vuln_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    return db.query(VulnComment).filter(VulnComment.vuln_id == vuln_id).order_by(VulnComment.created_at.asc()).all()


@router.post("/{vuln_id}/comments", response_model=VulnCommentOut)
def add_comment(vuln_id: int, content: VulnStatusAction, db: Session = Depends(get_db),
                current: User = Depends(get_current_user)):
    if not db.query(Vuln).filter(Vuln.id == vuln_id).first():
        raise HTTPException(status_code=404, detail="漏洞不存在")
    c = VulnComment(vuln_id=vuln_id, user_id=current.id, username=current.full_name, content=content.comment)
    db.add(c)
    db.commit()
    db.refresh(c)
    return c


@router.delete("/{vuln_id}")
def delete_vuln(vuln_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    """删除漏洞。仅管理员/安全专家可操作。"""
    if current.role is None or current.role.code not in ("admin", "secops"):
        raise HTTPException(status_code=403, detail="仅管理员/安全专家可删除漏洞")
    v = db.query(Vuln).filter(Vuln.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    title = v.title
    # 级联删除关联数据
    db.query(VulnFlow).filter(VulnFlow.vuln_id == vuln_id).delete()
    db.query(VulnComment).filter(VulnComment.vuln_id == vuln_id).delete()
    db.delete(v)
    db.commit()
    write_operation_log(db, current, "delete_vuln", "vuln", f"删除漏洞 #{vuln_id} {title}")
    return {"detail": "已删除"}
