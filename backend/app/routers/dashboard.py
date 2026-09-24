"""数据大盘统计接口。"""
from datetime import datetime, timedelta
from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, Vuln, VulnFlow
from ..security import get_current_user
from ..vuln_taxonomy import TYPE_TO_CATEGORY

from app.utils import network_clock as nc
router = APIRouter(prefix="/api/dashboard", tags=["数据大盘"])

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _pick_bucket(span: int) -> str:
    """趋势图粒度：跨度 ≤92 天按日、≤400 天按周、更久按月。

    为什么必须自适应：近一年按日打点会有 365 个 x 轴刻度，标签必然挤成一团
    （原来 180/365 天也是按日，图上就是一片糊）。
    """
    if span <= 92:
        return "day"
    if span <= 400:
        return "week"
    return "month"


def _bucket_key(d, bucket: str) -> str:
    """桶的唯一标识（内存分桶用，不进前端）。"""
    if bucket == "month":
        return f"{d.year:04d}-{d.month:02d}"
    if bucket == "week":
        iso = d.isocalendar()
        return f"{iso[0]:04d}-W{iso[1]:02d}"
    return d.strftime("%Y-%m-%d")


def _bucket_label(d, bucket: str, now) -> str:
    """桶的 x 轴标签。

    月 =「8月」；周/日 = MM-DD。**跨年的桶要带上年份**，否则同一根轴的
    首尾会写成"09-22 → 09-21"（其实是去年 9 月到今年 9 月），看着像 bug；
    月份同理（不加年份会同时出现两个"1月"）。
    """
    if bucket == "month":
        return f"{d.month}月" if d.year == now.year else f"{d.year}-{d.month:02d}"
    if d.year != now.year:
        return d.strftime("%y-%m-%d")
    return d.strftime("%m-%d")


def _next_bucket(d, bucket: str):
    if bucket == "month":
        return (d.replace(day=1) + timedelta(days=32)).replace(day=1)
    if bucket == "week":
        return d + timedelta(days=7)
    return d + timedelta(days=1)
# 终态（不修的）：已关闭 / 已驳回。这里仍保留 "ignored" —— 状态机已删掉 ignore 动作，
# 但老库里可能存着历史 ignored 数据，留着它这些旧数据才会被算作"已关闭"而不是挂在未处理里。
CLOSED_STATUSES = {"closed", "rejected", "ignored"}
# 「已修复」口径：待复测 / 已修复 / 已关闭 / 已驳回（+ 历史 ignored）都算已修复
# （漏洞列表状态列同口径）。把**待复测**算进来是因为它 = 研发已经修好了、等验收。
REPAIRED_STATUSES = {"retest", "fixed"} | CLOSED_STATUSES
# 「未修复」口径：还没修好的（待确认 / 已确认 / 修复中）。
#
# ⚠️ 首页两张卡**严格互补**：未修复 + 已修复 = 漏洞总数（overview 里直接用"总数 − 已修复"
# 求未修复，让这个恒等式在构造上成立）。
# 旧口径是「未闭环 = 非终态」（含已修复/待复测），于是同一页出现
# `未闭环 9 + 已修复 8 = 17 > 总数 16` —— "已修复但没关闭"的那条被两张卡都算了，
# 读者第一反应是"数字算错了"，只能靠解释。现在按"修好 / 没修好"这类互斥划分，
# 加法天然成立；首页卡片、分布图、趋势存量线、列表钻取筛选已全部改用这一套。
UNFIXED_STATUSES = {"pending", "confirmed", "fixing"}


def _snapshot(db: Session, vulns: list, days: int) -> dict:
    """`days` 天前那一刻的口径快照（首页环比用）—— 只靠时间戳推算，不需要历史表。

    口径与首页卡片一一对应（都是"修好 / 没修好"这套互补划分）：
      · unfixed  = 当时还没修好的（当时已创建，且修复时间晚于当时、或从未修复）；
      · repaired = 当时已经修好的（修复时间 <= 当时）；
      · severity = 当时未修复里的严重 + 高危；pending = 当时的待确认；
      · rate     = 当时的已修复 ÷ 当时的总数。

    判定只看**时间戳**、不看当前状态 —— 否则"现在已闭环"的老漏洞会被误判成当时也已修复。
    目前只有一个基数：30 天前（六张卡统一"较上月"）；将来要别的窗口加一行
    _snapshot(db, vulns, 7) 即可。
    """
    at = nc.utcnow() - timedelta(days=days)
    flow_ts: dict = {}
    for vid, ts in (db.query(VulnFlow.vuln_id, VulnFlow.created_at)
                    .filter(VulnFlow.to_status.in_(tuple(REPAIRED_STATUSES)))
                    .order_by(VulnFlow.created_at.asc()).all()):
        flow_ts.setdefault(vid, ts)

    # 「待确认」的 as-of 需要"什么时候离开第一步" = 确认/驳回那次流转的时间
    left_pending: dict = {}
    for vid, ts in (db.query(VulnFlow.vuln_id, VulnFlow.created_at)
                    .filter(VulnFlow.from_status == "pending")
                    .order_by(VulnFlow.created_at.asc()).all()):
        left_pending.setdefault(vid, ts)

    # 兜底：至少知道"它不是一直待确认"。种子/导入的历史数据没有规范的 from_status='pending'
    # 流转记录，只靠上面那张表会把"早就确认过"的漏洞永远算成待确认（实测把 2 条算成了 4 条）。
    first_flow: dict = {}
    for vid, ts in (db.query(VulnFlow.vuln_id, VulnFlow.created_at)
                    .order_by(VulnFlow.created_at.asc()).all()):
        first_flow.setdefault(vid, ts)

    total = unfixed = repaired = severe = pending = 0
    for v in vulns:
        if not v.created_at or v.created_at > at:
            continue          # N 天前还不存在的漏洞，不该出现在"N 天前"的口径里
        total += 1
        # 修复时间：fixed_at（研发点完成）→ closed_at → 流转记录里进入"已修复/待复测"的时间；
        # 兜底用 created_at —— 处于已修复状态却没有任何时间列（脏数据）时，按"创建当天就修好"
        # 处理，否则它会永远算在"未修复"里，与卡片（按状态数）对不上。
        rts = None
        if v.status in REPAIRED_STATUSES:
            rts = v.fixed_at or v.closed_at or flow_ts.get(v.id) or v.created_at
        if rts is not None and rts <= at:
            repaired += 1
        else:
            unfixed += 1
            if v.severity in ("critical", "high"):
                severe += 1
            # 当时还没离开"第一步"的（确认/驳回都还没发生的）就是当时的待确认
            lp = left_pending.get(v.id)
            if lp is None and v.status != "pending":
                lp = first_flow.get(v.id) or v.created_at   # 兜底（近似，见上）
            if lp is None or lp > at:
                pending += 1

    return {
        "total": total, "unfixed": unfixed, "repaired": repaired,
        "severity": severe, "pending": pending,
        "rate": round(repaired / total * 100, 1) if total else 0.0,
    }


@router.get("/overview")
def overview(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    vulns = db.query(Vuln).all()

    total = len(vulns)
    # 「已修复」按状态数：待复测 + 已修复 + 已关闭 + 已驳回（+ 历史 ignored）
    fixed_count = sum(1 for v in vulns if v.status in REPAIRED_STATUSES)
    # 「未修复」= 总数 − 已修复，让"两张卡相加 = 总数"在**构造上**必然成立
    # （这就是本次改口径的目的：旧口径是"非终态"，与已修复在"已修复未关闭"上重叠，
    #   同一页出现 9 + 8 = 17 > 总数 16）。
    unfixed = total - fixed_count
    # 高危卡只数**未修复**里的严重 + 高危（修好的不该再占"要不要人动手"的位置）
    critical = sum(1 for v in vulns if v.severity == "critical" and v.status in UNFIXED_STATUSES)
    high = sum(1 for v in vulns if v.severity == "high" and v.status in UNFIXED_STATUSES)
    fixing = sum(1 for v in vulns if v.status == "fixing")
    closed = sum(1 for v in vulns if v.status in CLOSED_STATUSES)
    # 流程卡点（首页「待确认」卡片用）：修复人还没确认/驳回的那一批。
    # 这些卡在整条链路的第一步（「漏洞修复」页的「确认 / 驳回」按钮就是处理它们），
    # 是最容易被漏掉、也最需要推动的一批，故单独给出而不是并入"待修复"。
    pending = sum(1 for v in vulns if v.status == "pending")
    retest = sum(1 for v in vulns if v.status == "retest")

    # 修复率 = (已修复 + 已关闭 + 已驳回) / 总数
    fixed_count = sum(1 for v in vulns if v.status in REPAIRED_STATUSES)
    fix_rate = round(fixed_count / total * 100, 1) if total else 0

    # 平均修复时长（小时）：只对**已闭环**的漏洞统计，取"进入终态"的时间点。
    #
    # 以前只认 fixed_at（研发点「修复完成」的那一刻）：
    #   · 被驳回 / 直接关闭的漏洞没有 fixed_at → 全部被排除在样本外；
    #   · 一套环境里若没人走过 finish_fix，样本数就是 0，卡片恒显示 **0h** ——
    #     而 0h 读起来像"修复飞快"，实际是"没有数据"（用户反馈"这个数字没有意义"就是这个）。
    # 现在与趋势图「修复」线同口径取时间点：fixed_at → closed_at → 流转记录里进入终态的时间；
    # 并且分母用**真正有时间的条数**（旧写法除以 len(fixed_vulns)，会把被跳过的也算进分母）。
    #
    # 说明：这条口径的样本天然等于"已闭环的数量"，闭环量少时数字偏差大，所以首页卡片位
    # 已改用「待确认」（见 Dashboard.vue）；这个字段保留给报表/后续做"修复时效"专题页。
    _closure_ids = set(REPAIRED_STATUSES)
    first_closure_ts: dict[int, datetime] = {}
    for vid, ts in (db.query(VulnFlow.vuln_id, VulnFlow.created_at)
                    .filter(VulnFlow.to_status.in_(_closure_ids))
                    .order_by(VulnFlow.created_at.asc()).all()):
        first_closure_ts.setdefault(vid, ts)      # 取最早一次进入终态的时间（与趋势图一致）
    durations = []
    for v in vulns:
        if v.status not in _closure_ids or not v.created_at:
            continue
        ts = v.fixed_at or v.closed_at or first_closure_ts.get(v.id)
        if ts and ts > v.created_at:
            durations.append((ts - v.created_at).total_seconds())
    avg_fix_hours = round(sum(durations) / len(durations) / 3600, 1) if durations else 0

    # 本月新增（首页趋势卡头部显示"本月新增 N"）
    now = nc.utcnow()
    month_start = datetime(now.year, now.month, 1)
    month_new = sum(1 for v in vulns if v.created_at and v.created_at >= month_start)

    # 组件/CVE/培训的统计**不在这里算**：它们各有归属页面与接口
    # （组件与 CVE 归「漏洞扫描」，培训有 /api/training/stats）。
    # 首页从来没渲染过这几项，但每次打开大盘都要多跑 6 条 count 查询（纯浪费）。

    return {
        "total": total,
        # 「未修复 / 已修复」是一对**互补**口径（相加 = total），首页两张卡分别用它俩；
        # 旧的 "open"（非终态）已删 —— 它与 fixed_total 在"已修复未关闭"上重叠，
        # 正是"看起来加不平"的来源。
        "unfixed": unfixed,
        "fixed_total": fixed_count,
        "critical": critical,
        "high": high,
        "fixing": fixing,
        # 首页「待确认」卡片的取值（流程第一步的卡点数，是「未修复」的子集）
        "pending": pending,
        "retest": retest,
        "closed": closed,
        "fix_rate": fix_rate,
        "avg_fix_hours": avg_fix_hours,
        "month_new": month_new,
        # 环比基数（口径在后端算好，前端只做减法/除法）：
        #   6 张卡统一用"较上月"= 30 天前那一刻的同一套口径。
        #   为什么不做"周环比"：这个数据量下周环比噪声太大（±1 更像抖动）。
        #   将来若要别的窗口（如 7 天），加一行 _snapshot(db, vulns, 7) 即可。
        "snapshot_30d": _snapshot(db, vulns, 30),
    }


@router.get("/trend")
def trend(days: int = 30, bucket: str = None, db: Session = Depends(get_db),
          current: User = Depends(get_current_user)):
    """近 N 天「新增 / 已修复 / 未修复存量」趋势。

    「新增」= created_at 落在该桶的漏洞数。
    「已修复」= 状态属于 REPAIRED_STATUSES 的漏洞（待复测 / 已修复 / 已关闭 / 已驳回 ——
    与首页「已修复」卡片同一套），按它**修好的时间**归桶：

      · 优先 `fixed_at`（研发点完成那一刻）→ `closed_at` → 流转记录里进入"待复测/已修复"
        等状态的时间；
      · 每条漏洞只算一次（取最早那个时间点），"修复后又关闭"不会被重复计数；
      · 已是已修复状态却没有任何时间列（脏数据）按"创建当天就修好"，否则会虚增存量。

    「未修复存量」= 期初余额 + 累计新增 − 累计已修复，取每个桶结束时的值。
      加这条线的原因：只看新增/已修复两条线，"欠债到底在涨还是在降"要读者自己做减法 ——
      存量曲线就是那个答案。它与「已修复」线**严格互补**：终点 = 首页「未修复」卡片的
      值 = 总数 − 已修复（旧口径是"非终态"，与已修复在"已修复未关闭"上重叠，
      同页出现过"卡片 8、曲线 7"这种自相矛盾）。

    粒度（bucket）自适应：跨度 ≤92 天按日、≤400 天按周、更久按月（可显式传
    bucket=day|week|month 覆盖）。days<=0 表示**全部历史**：从最早一条漏洞算起、默认按月 —
    原来的 `max(1, days)` 会把 days=0 变成"只看 1 天"，而前端选「全部」时传的就是 0。

    性能：原来是"每天 2 次 count 查询"（30 天 90 次），现在一次取回后在内存分桶（3 次查询）。
    """
    rows = db.query(Vuln.id, Vuln.status, Vuln.created_at, Vuln.fixed_at, Vuln.closed_at).all()
    if not rows:
        return []

    # 流转记录的兜底时间：某个漏洞没有任何时间列（如被驳回）时用它
    flow_ts: dict = {}
    for vid, ts in db.query(VulnFlow.vuln_id, VulnFlow.created_at).filter(
            VulnFlow.to_status.in_(tuple(REPAIRED_STATUSES))
    ).order_by(VulnFlow.created_at.asc()).all():
        if vid not in flow_ts and ts:
            flow_ts[vid] = ts

    created_ts: dict[int, datetime] = {}   # 创建时间 → 「新增」线
    repair_ts: dict[int, datetime] = {}    # 修好的时间（进入待复测/已修复/已关闭/已驳回）
    #   ↑ 同一个事件同时是「已修复」线的计数点与「未修复存量」的减项，
    #     所以两条线天然互补、加法一定平（旧实现里它们是两套不同的事件，必然对不上）
    for vid, status, created_at, fixed_at, closed_at in rows:
        if created_at:
            created_ts[vid] = created_at
        if status in REPAIRED_STATUSES:
            ts = fixed_at or closed_at or flow_ts.get(vid) or created_at
            if ts:
                repair_ts[vid] = ts

    now = nc.utcnow().date()
    if days and days > 0:
        day0 = now - timedelta(days=days - 1)
        bucket = bucket or _pick_bucket(days)
    else:
        day0 = min((t.date() for t in created_ts.values()), default=now)
        bucket = bucket or "month"
    if bucket not in ("day", "week", "month"):
        bucket = "day"
    # 起点对齐到桶边界：这样"周/月"的标签是桶的自然起点（周一 / 1 号），
    # 而不是窗口恰好落进来的那一天
    if bucket == "week":
        day0 -= timedelta(days=day0.weekday())
    elif bucket == "month":
        day0 = day0.replace(day=1)

    start = datetime(day0.year, day0.month, day0.day)
    end = datetime(now.year, now.month, now.day) + timedelta(days=1)

    buckets: list[tuple[str, str]] = []
    cur = day0
    while cur <= now:
        buckets.append((_bucket_key(cur, bucket), _bucket_label(cur, bucket, now)))
        cur = _next_bucket(cur, bucket)

    def _key_of(d) -> str:
        return _bucket_key(d, bucket)

    created_by: Counter = Counter()
    for ts in created_ts.values():
        if start <= ts < end:
            created_by[_key_of(ts.date())] += 1
    repaired_by: Counter = Counter()
    for ts in repair_ts.values():
        if start <= ts < end:
            repaired_by[_key_of(ts.date())] += 1

    # 期初余额：窗口之前创建、且到窗口开始时仍未闭环的条数
    # （不加这一项，窗口选短时存量线会从 0 起步，看起来像"欠债突然暴涨"）
    opening = 0
    for vid, ts in created_ts.items():
        if ts >= start:
            continue
        rts = repair_ts.get(vid)
        if rts is None or rts >= start:
            opening += 1

    balance = opening
    result = []
    for key, label in buckets:
        # 严格互补：未修复存量 = 期初 + 累计新增 − 累计已修复
        # （终点 = 首页「未修复」卡片的值，同页不会出现"卡片 9、曲线 8"）
        balance += created_by.get(key, 0) - repaired_by.get(key, 0)
        result.append({
            "date": label,
            "created": created_by.get(key, 0),
            "repaired": repaired_by.get(key, 0),
            "unfixed": max(0, balance),
        })
    return result


@router.get("/distribution")
def distribution(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    """**全部**漏洞的等级 / 大类分布（含已闭环）。

    为什么按全量：这是"漏洞长什么样"的构成图，读者会拿它跟「漏洞总数」核对 ——
    只统计未修复时各扇区之和（6）与总数（16）对不上，就得在标题里写口径去解释
    （用户反馈：展示上需要全量数据）。
    只返回页面真正使用的两组：by_type / by_status / by_system 前端一处都没用
    （已 grep 全前端确认），其中 by_system 还会逐条取 v.system.name（N+1 查询），
    删掉它顺带省掉这串懒加载。
    """
    vulns = db.query(Vuln).all()

    severity_counter = Counter(v.severity or "medium" for v in vulns)
    # 一级大类分布：历史数据无大类时按子类反查补全,避免出现"未分类"堆积
    category_counter = Counter(
        v.vuln_category or TYPE_TO_CATEGORY.get(v.vuln_type, "未分类") for v in vulns
    )

    return {
        "by_severity": [{"name": k, "value": v} for k, v in severity_counter.most_common()],
        # 一级大类共 10 项，不截断以保证饼图各扇区之和等于未闭环总数（历史脏数据可能产生"未分类"）
        "by_category": [{"name": k, "value": v} for k, v in category_counter.most_common()],
    }


@router.get("/top")
def top_systems(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    """系统风险排行：统计**全部**漏洞（含已闭环），加总与「漏洞总数」一致。

    风险分 = 按等级加权（严重 10 / 高危 7 / 中危 4 / 低危 1）求和，排序用它；柱长用条数。
    含已闭环即"该系统历史上被查出过多少、多严重"的视角（与"当前还欠多少"是两个问题，
    首页按需求展示全量）。
    """
    vulns = db.query(Vuln).all()

    # Top 系统（按风险分排序；含漏洞数便于直观展示）
    system_risk = {}
    system_count = {}
    for v in vulns:
        name = v.system.name if v.system else "未关联"
        score = 10 if v.severity == "critical" else 7 if v.severity == "high" else 4 if v.severity == "medium" else 1
        system_risk[name] = system_risk.get(name, 0) + score
        system_count[name] = system_count.get(name, 0) + 1

    top_systems = sorted(system_risk.items(), key=lambda x: x[1], reverse=True)[:10]
    top_systems = [{"name": k, "risk": v, "count": system_count[k]} for k, v in top_systems]

    # 待修复（未关闭）漏洞 Top 类型
    return {"top_systems": top_systems}
