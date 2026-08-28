"""数据大盘统计接口。"""
from datetime import datetime, timedelta
from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import CVEInfo, CourseProgress, QuizExam, ScanResult, SBOMComponent, TrainingCourse, User, Vuln
from ..security import get_current_user

router = APIRouter(prefix="/api/dashboard", tags=["数据大盘"])

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
CLOSED_STATUSES = {"closed", "rejected", "ignored"}


@router.get("/overview")
def overview(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    vulns = db.query(Vuln).all()

    total = len(vulns)
    open_vulns = [v for v in vulns if v.status not in CLOSED_STATUSES and v.status != "draft"]
    critical = sum(1 for v in vulns if v.severity == "critical" and v.status not in CLOSED_STATUSES)
    high = sum(1 for v in vulns if v.severity == "high" and v.status not in CLOSED_STATUSES)
    fixing = sum(1 for v in vulns if v.status == "fixing")
    closed = sum(1 for v in vulns if v.status in CLOSED_STATUSES)

    # 修复率 = (已修复 + 已关闭 + 已驳回 + 已忽略) / 总数
    fixed_count = sum(1 for v in vulns if v.status in CLOSED_STATUSES or v.status == "fixed")
    fix_rate = round(fixed_count / total * 100, 1) if total else 0

    # 平均修复时长（小时），取有 fixed_at 的
    fixed_vulns = [v for v in vulns if v.fixed_at]
    avg_fix_hours = 0
    if fixed_vulns:
        total_hours = sum((v.fixed_at - v.created_at).total_seconds() for v in fixed_vulns if v.fixed_at > v.created_at)
        avg_fix_hours = round(total_hours / len(fixed_vulns) / 3600, 1)

    # 本月新增
    now = datetime.utcnow()
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
    """近 N 天新增与修复趋势。"""
    now = datetime.utcnow().date()
    result = []
    for offset in range(days - 1, -1, -1):
        day = now - timedelta(days=offset)
        day_start = datetime(day.year, day.month, day.day)
        day_end = day_start + timedelta(days=1)
        created = db.query(func.count(Vuln.id)).filter(
            Vuln.created_at >= day_start, Vuln.created_at < day_end).scalar()
        fixed = db.query(func.count(Vuln.id)).filter(
            Vuln.fixed_at >= day_start, Vuln.fixed_at < day_end).scalar()
        result.append({
            "date": day.strftime("%m-%d"),
            "created": created,
            "fixed": fixed,
        })
    return result


@router.get("/distribution")
def distribution(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    vulns = db.query(Vuln).all()
    active = [v for v in vulns if v.status not in CLOSED_STATUSES]

    severity_counter = Counter(v.severity for v in active)
    type_counter = Counter(v.vuln_type or "未分类" for v in active)
    status_counter = Counter(v.status for v in vulns)

    # 系统分布
    system_counter = Counter(v.system.name if v.system else "未关联" for v in active)

    return {
        "by_severity": [{"name": k, "value": v} for k, v in severity_counter.most_common()],
        "by_type": [{"name": k, "value": v} for k, v in type_counter.most_common(10)],
        "by_status": [{"name": k, "value": v} for k, v in status_counter.most_common()],
        "by_system": [{"name": k, "value": v} for k, v in system_counter.most_common(10)],
    }


@router.get("/top")
def top_systems(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    vulns = db.query(Vuln).all()
    active = [v for v in vulns if v.status not in CLOSED_STATUSES]

    # Top 系统
    system_risk = {}
    for v in active:
        name = v.system.name if v.system else "未关联"
        score = 10 if v.severity == "critical" else 7 if v.severity == "high" else 4 if v.severity == "medium" else 1
        system_risk[name] = system_risk.get(name, 0) + score

    top_systems = sorted(system_risk.items(), key=lambda x: x[1], reverse=True)[:10]
    top_systems = [{"name": k, "risk": v} for k, v in top_systems]

    # 待修复（未关闭）漏洞 Top 类型
    return {"top_systems": top_systems}
