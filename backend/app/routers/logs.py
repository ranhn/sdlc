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


def _resolve_operator_names(db: Session, user_ids: list[int]) -> dict[int, tuple[str, str]]:
    """批量解析操作人 user_id -> (username, full_name)。

    审计日志的 OperationLog.username 是写入时的快照（用户改名/被删后日志仍可读），
    但若操作人已删除，username 可能仍为旧值。这里再用 user_id 反查一次，
    优先返回最新全名；查不到则按原 username 兜底。
    """
    if not user_ids:
        return {}
    rows = (
        db.query(User.id, User.username, User.full_name)
        .filter(User.id.in_(set(user_ids)))
        .all()
    )
    return {r[0]: (r[1], r[2]) for r in rows}


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
    # 批量解析操作人当前 full_name，UI 可与 OperationLog.username 组合展示
    name_map = _resolve_operator_names(db, [l.user_id for l in logs if l.user_id])
    items = []
    for l in logs:
        if l.user_id and l.user_id in name_map:
            cur_username, cur_full = name_map[l.user_id]
            username = cur_username or l.username
            full_name = cur_full
        else:
            # 用户已删除 / 老日志：仅以写入时的快照为准
            username = l.username
            full_name = ""
        items.append(
            {
                "id": l.id,
                "user_id": l.user_id,
                "username": username,
                "full_name": full_name or "",
                "action": l.action,
                "module": l.module,
                "detail": l.detail,
                "created_at": l.created_at,
            }
        )
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": items,
    }
