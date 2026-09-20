"""数据大盘统计接口。"""
from datetime import datetime, timedelta
from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import CVEInfo, CourseProgress, QuizExam, ScanResult, SBOMComponent, TrainingCourse, User, Vuln, VulnFlow
from ..security import get_current_user
from ..vuln_taxonomy import TYPE_TO_CATEGORY

from app.utils import network_clock as nc
router = APIRouter(prefix="/api/dashboard", tags=["数据大盘"])

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
# 终态（不修的）：已关闭 / 已驳回。这里仍保留 "ignored" —— 状态机已删掉 ignore 动作，
# 但老库里可能存着历史 ignored 数据，留着它这些旧数据才会被算作"已关闭"而不是挂在未处理里。
CLOSED_STATUSES = {"closed", "rejected", "ignored"}
# 页面口径：已修复 / 已关闭 / 已驳回 都算「已修复」（漏洞列表状态列同口径）。
# 大盘的「已修复」卡片、修复率、趋势图的「修复」线统一用它，避免三处对不上。
CLOSURE_STATUSES = {"fixed"} | CLOSED_STATUSES


@router.get("/overview")
def overview(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    vulns = db.query(Vuln).all()

    total = len(vulns)
    open_vulns = [v for v in vulns if v.status not in CLOSED_STATUSES and v.status != "draft"]
    critical = sum(1 for v in vulns if v.severity == "critical" and v.status not in CLOSED_STATUSES)
    high = sum(1 for v in vulns if v.severity == "high" and v.status not in CLOSED_STATUSES)
    fixing = sum(1 for v in vulns if v.status == "fixing")
    closed = sum(1 for v in vulns if v.status in CLOSED_STATUSES)

    # 修复率 = (已修复 + 已关闭 + 已驳回) / 总数
    fixed_count = sum(1 for v in vulns if v.status in CLOSURE_STATUSES)
    fix_rate = round(fixed_count / total * 100, 1) if total else 0

    # 平均修复时长（小时），取有 fixed_at 的
    fixed_vulns = [v for v in vulns if v.fixed_at]
    avg_fix_hours = 0
    if fixed_vulns:
        total_hours = sum((v.fixed_at - v.created_at).total_seconds() for v in fixed_vulns if v.fixed_at > v.created_at)
        avg_fix_hours = round(total_hours / len(fixed_vulns) / 3600, 1)

    # 本月新增
    now = nc.utcnow()
    month_start = datetime(now.year, now.month, 1)
    month_new = sum(1 for v in vulns if v.created_at >= month_start)

    # 组件风险统计
    comp_total = db.query(SBOMComponent).count()
    comp_vuln = db.query(ScanResult).filter(ScanResult.is_false_positive == False).count()  # noqa: E712
    cve_total = db.query(CVEInfo).count()

    # 培训统计
    train_courses = db.query(TrainingCourse).filter(TrainingCourse.is_published == True).count()  # noqa: E712
    train_users = db.query(User).filter(User.is_active == True).count()  # noqa: E712
    train_completed = db.query(CourseProgress).filter(CourseProgress.completed_at.isnot(None)).count()
    train_completion_rate = round(train_completed / train_users * 100, 1) if train_users else 0
    train_exam_count = db.query(QuizExam).filter(
        QuizExam.status.in_(["passed", "failed"])).count()

    return {
        "total": total,
        "open": len(open_vulns),
        "critical": critical,
        "high": high,
        "fixing": fixing,
        "closed": closed,
        # 「已修复」卡片用的口径：已修复 + 已关闭 + 已驳回（与修复率、趋势图一致）
        "fixed_total": fixed_count,
        "fix_rate": fix_rate,
        "avg_fix_hours": avg_fix_hours,
        "month_new": month_new,
        "comp_total": comp_total,
        "comp_vuln": comp_vuln,
        "cve_total": cve_total,
        "train_courses": train_courses,
        "train_completion_rate": train_completion_rate,
        "train_exam_count": train_exam_count,
    }


@router.get("/trend")
def trend(days: int = 30, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    """近 N 天「新增 / 修复」趋势。

    「修复」= 状态属于 CLOSURE_STATUSES 的漏洞（已修复 / 已关闭 / 已驳回 ——
    也就是前端漏洞列表状态列里的这几种），按它**进入该状态的时间**归日：

      - 已修复 / 已关闭：优先 `fixed_at`（研发修复完成那一刻），退回 `closed_at`；
      - 已驳回：这个状态没有独立时间列，取流转记录里流转到该状态的时间。

    每条漏洞只算一次（取最早的那个时间点），所以"修复后又关闭"不会被重复计数。

    以前的写法是"只要 `fixed_at` 落在该天就算"，于是被驳回的漏洞在趋势图上永远
    看不到 —— KPI 卡显示「已修复 1」而趋势图是 0（用户反馈），现在两处同口径。
    另外把原来的"每天 2 次 count 查询"改成一次取回后在内存分桶（30 天 90 次 → 3 次）。
    """
    now = nc.utcnow().date()
    span = max(1, days)
    day0 = now - timedelta(days=span - 1)
    start = datetime(day0.year, day0.month, day0.day)
    end = datetime(now.year, now.month, now.day) + timedelta(days=1)

    created_by: Counter = Counter()
    for (ts,) in db.query(Vuln.created_at).filter(
            Vuln.created_at >= start, Vuln.created_at < end).all():
        if ts:
            created_by[ts.date()] += 1

    # 流转记录的兜底时间：某个漏洞没有任何时间列（如被驳回）时用它
    flow_ts: dict = {}
    for vid, ts in db.query(VulnFlow.vuln_id, VulnFlow.created_at).filter(
            VulnFlow.to_status.in_(tuple(CLOSURE_STATUSES))
    ).order_by(VulnFlow.created_at.asc()).all():
        if vid not in flow_ts and ts:
            flow_ts[vid] = ts

    fixed_by: Counter = Counter()
    for vid, status, fixed_at, closed_at in db.query(
            Vuln.id, Vuln.status, Vuln.fixed_at, Vuln.closed_at).all():
        if status not in CLOSURE_STATUSES:
            continue
        ts = fixed_at or closed_at or flow_ts.get(vid)
        if ts and start <= ts < end:
            fixed_by[ts.date()] += 1

    result = []
    for offset in range(span - 1, -1, -1):
        day = now - timedelta(days=offset)
        result.append({
            "date": day.strftime("%m-%d"),
            "created": created_by.get(day, 0),
            "fixed": fixed_by.get(day, 0),
        })
    return result


@router.get("/distribution")
def distribution(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    vulns = db.query(Vuln).all()
    active = [v for v in vulns if v.status not in CLOSED_STATUSES]

    severity_counter = Counter(v.severity for v in active)
    type_counter = Counter(v.vuln_type or "未分类" for v in active)
    # 一级大类分布：历史数据无大类时按子类反查补全,避免出现"未分类"堆积
    category_counter = Counter(
        v.vuln_category or TYPE_TO_CATEGORY.get(v.vuln_type, "未分类") for v in active
    )
    status_counter = Counter(v.status for v in vulns)

    # 系统分布
    system_counter = Counter(v.system.name if v.system else "未关联" for v in active)

    return {
        "by_severity": [{"name": k, "value": v} for k, v in severity_counter.most_common()],
        # 一级大类共 10 项，不截断以保证饼图各扇区之和等于漏洞总数（历史脏数据可能产生"未分类"）
        "by_category": [{"name": k, "value": v} for k, v in category_counter.most_common()],
        "by_type": [{"name": k, "value": v} for k, v in type_counter.most_common(10)],
        "by_status": [{"name": k, "value": v} for k, v in status_counter.most_common()],
        "by_system": [{"name": k, "value": v} for k, v in system_counter.most_common(10)],
    }


@router.get("/top")
def top_systems(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    vulns = db.query(Vuln).all()
    active = [v for v in vulns if v.status not in CLOSED_STATUSES]

    # Top 系统（按风险分排序；含漏洞数便于直观展示）
    system_risk = {}
    system_count = {}
    for v in active:
        name = v.system.name if v.system else "未关联"
        score = 10 if v.severity == "critical" else 7 if v.severity == "high" else 4 if v.severity == "medium" else 1
        system_risk[name] = system_risk.get(name, 0) + score
        system_count[name] = system_count.get(name, 0) + 1

    top_systems = sorted(system_risk.items(), key=lambda x: x[1], reverse=True)[:10]
    top_systems = [{"name": k, "risk": v, "count": system_count[k]} for k, v in top_systems]

    # 待修复（未关闭）漏洞 Top 类型
    return {"top_systems": top_systems}
