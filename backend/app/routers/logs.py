"""操作审计日志查询接口（仅超级管理员）。"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import OperationLog, User
from ..security import get_current_user

router = APIRouter(prefix="/api/logs", tags=["审计日志"])


def _require_admin(current: User):
    if current.role is None or current.role.code != "admin":
        raise HTTPException(status_code=403, detail="仅超级管理员可查看审计日志")
    return current


@router.get("")
def list_logs(
    operator: str | None = Query(default=None),
    action: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    _require_admin(current)
    query = db.query(OperationLog)
    if operator:
        query = query.filter(OperationLog.username.ilike(f"%{operator}%"))
    if action:
        query = query.filter(OperationLog.action.ilike(f"%{action}%"))
    total = query.count()
    logs = (
        query.order_by(OperationLog.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [
            {
                "id": l.id,
                "user_id": l.user_id,
                "username": l.username,
                "action": l.action,
                "module": l.module,
                "detail": l.detail,
                "created_at": l.created_at,
            }
            for l in logs
        ],
    }
