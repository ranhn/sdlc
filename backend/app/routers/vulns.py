"""漏洞管理路由：提交/确认/修复/复测/关闭 + 状态机 + 评论。"""
import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import inspect
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, Vuln, VulnComment, VulnFlow
from ..schemas import (
    VulnAssign,
    VulnCommentOut,
    VulnCreate,
    VulnFlowOut,
    VulnOut,
    VulnReject,
    VulnStatusAction,
)
from ..security import get_current_user, write_operation_log
from ..state_machine import TRANSITIONS, validate_action

router = APIRouter(prefix="/api/vulns", tags=["漏洞管理"])

STATUS_NAMES = {
    "draft": "草稿", "pending": "待确认", "confirmed": "已确认", "fixing": "修复中",
    "retest": "待复测", "fixed": "已修复", "closed": "已关闭", "rejected": "已驳回", "ignored": "已忽略",
}


def _to_out(v: Vuln, db: Session) -> VulnOut:
    data = {c.key: getattr(v, c.key) for c in inspect(v).mapper.column_attrs}
    if data.get("screenshots"):
        try:
            data["screenshots"] = json.loads(data["screenshots"])
        except (TypeError, json.JSONDecodeError):
            data["screenshots"] = None
    else:
        data["screenshots"] = None
    out = VulnOut.model_validate(data)
    reporter = db.query(User).filter(User.id == v.reporter_id).first()
    assignee = db.query(User).filter(User.id == v.assignee_id).first() if v.assignee_id else None
    reviewer = db.query(User).filter(User.id == v.reviewer_id).first() if v.reviewer_id else None
    out.reporter_name = reporter.full_name if reporter else None
    out.assignee_name = assignee.full_name if assignee else None
    out.reviewer_name = reviewer.full_name if reviewer else None
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


@router.get("", response_model=list[VulnOut])
def list_vulns(
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    system_id: int | None = Query(default=None),
    mine: bool = Query(default=False),
    assigned_to_me: bool = Query(default=False),
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    query = db.query(Vuln)
    if status:
        query = query.filter(Vuln.status == status)
    if severity:
        query = query.filter(Vuln.severity == severity)
    if system_id:
        query = query.filter(Vuln.system_id == system_id)
    if mine:
        query = query.filter((Vuln.reporter_id == current.id) | (Vuln.assignee_id == current.id))
    if assigned_to_me:
        query = query.filter(Vuln.assignee_id == current.id)
    vulns = query.order_by(Vuln.created_at.desc()).all()
    return [_to_out(v, db) for v in vulns]


@router.get("/{vuln_id}", response_model=VulnOut)
def get_vuln(vuln_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    v = db.query(Vuln).filter(Vuln.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    return _to_out(v, db)


@router.post("", response_model=VulnOut, status_code=201)
def create_vuln(data: VulnCreate, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    v = Vuln(
        title=data.title,
        description=data.description,
        reproduce_steps=data.reproduce_steps,
        impact=data.impact,
        screenshots=json.dumps(data.screenshots, ensure_ascii=False) if data.screenshots else None,
        system_id=data.system_id,
        severity=data.severity,
        vuln_type=data.vuln_type,
        cvss=data.cvss,
        reporter_id=current.id,
        status="pending",
        source="manual",
    )
    db.add(v)
    db.commit()
    db.refresh(v)
    _record_flow(db, v.id, "draft", "pending", current, "漏洞提交")
    write_operation_log(db, current, "create_vuln", "vuln", f"提交漏洞 #{v.id} {v.title}")
    return _to_out(v, db)


@router.post("/{vuln_id}/assign", response_model=VulnOut)
def assign_vuln(vuln_id: int, data: VulnAssign, db: Session = Depends(get_db),
                current: User = Depends(get_current_user)):
    v = db.query(Vuln).filter(Vuln.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    if current.role is None or current.role.code not in ("admin", "secops"):
        raise HTTPException(status_code=403, detail="仅安全专家可指派")
    if not db.query(User).filter(User.id == data.assignee_id).first():
        raise HTTPException(status_code=400, detail="负责人不存在")
    v.assignee_id = data.assignee_id
    db.commit()
    db.refresh(v)
    write_operation_log(db, current, "assign_vuln", "vuln", f"指派漏洞 #{v.id} 给 {data.assignee_id}")
    return _to_out(v, db)


@router.post("/{vuln_id}/action/{action}", response_model=VulnOut)
def vuln_action(vuln_id: int, action: str, data: VulnStatusAction,
                db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    v = db.query(Vuln).filter(Vuln.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    role_code = current.role.code if current.role else "user"
    if not validate_action(action, v.status, role_code):
        raise HTTPException(status_code=403, detail=f"当前状态({STATUS_NAMES.get(v.status, v.status)})下，角色无权执行[{action}]操作")

    to_status = TRANSITIONS[action]
    from_status = v.status
    v.status = to_status

    if action == "close":
        v.closed_at = __import__("datetime").datetime.utcnow()
    if action == "finish_fix":
        v.fixed_at = __import__("datetime").datetime.utcnow()
        v.reviewer_id = current.id
    if action == "pass_retest":
        v.reviewer_id = current.id

    db.commit()
    db.refresh(v)
    _record_flow(db, v.id, from_status, to_status, current, data.comment)
    write_operation_log(db, current, f"vuln_{action}", "vuln", f"漏洞 #{v.id} {from_status}->{to_status}")
    return _to_out(v, db)


@router.post("/{vuln_id}/reject", response_model=VulnOut)
def reject_vuln(vuln_id: int, data: VulnReject, db: Session = Depends(get_db),
                current: User = Depends(get_current_user)):
    v = db.query(Vuln).filter(Vuln.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    role_code = current.role.code if current.role else "user"
    if not validate_action("reject", v.status, role_code):
        raise HTTPException(status_code=403, detail="无权限驳回")
    v.status = "rejected"
    v.rejection_reason = data.reason
    db.commit()
    db.refresh(v)
    _record_flow(db, v.id, "pending", "rejected", current, f"驳回：{data.reason}")
    write_operation_log(db, current, "vuln_reject", "vuln", f"漏洞 #{v.id} 驳回：{data.reason}")
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
