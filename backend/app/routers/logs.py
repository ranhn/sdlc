"""操作审计日志查询接口（管理员/安全专家）。"""
import re

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import OperationLog, User, Vuln
from ..security import get_current_user

router = APIRouter(prefix="/api/logs", tags=["审计日志"])


def _require_admin(current: User):
    if current.role is None or current.role.code not in ("admin", "secops"):
        raise HTTPException(status_code=403, detail="仅管理员/安全专家可查看审计日志")
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


# 匹配「指派漏洞 #N 给 M」老格式（M 是 assignee_id 数字），用于补全日志可读性
_ASSIGN_LEGACY_RE = re.compile(r"指派漏洞\s*#\s*(\d+)\s*给\s*(\d+)\s*$")
# 匹配「删除漏洞 #N xxx」老格式（不需处理，仅参考）


def _enrich_assign_detail(
    db: Session,
    detail: str,
    user_map: dict[int, tuple[str, str]],
    vuln_map: dict[int, str],
) -> str:
    """对 ``assign_vuln`` 类的历史 detail 做可读性增强。

    早期版本写入的 detail 形如 ``指派漏洞 #10 给 3``（仅 ID 无姓名），
    审计时看不出接收人。这里将 ID 反查成 ``给 username(全名)[ID=3]``，
    已知格式化好的新 detail（带 ``[ID=3]`` 标识）则原样返回。
    """
    if not detail:
        return detail
    m = _ASSIGN_LEGACY_RE.match(detail.strip())
    if not m:
        return detail
    vuln_id = int(m.group(1))
    assignee_id = int(m.group(2))
    title = vuln_map.get(vuln_id)
    if assignee_id in user_map:
        u_name, u_full = user_map[assignee_id]
        assignee_desc = f"{u_name}({u_full})[ID={assignee_id}]"
    else:
        assignee_desc = f"ID={assignee_id}（用户不存在）"
    title_part = f"「{title}」" if title else ""
    return f"指派漏洞 #{vuln_id}{title_part}给 {assignee_desc}"


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
    name_map = _resolve_operator_names(db, [l.user_id for l in logs if l.user_id is not None])
    # 收集 assign_vuln 类日志里的漏洞 id，用于反查标题（增强历史 detail 可读性）
    vuln_ids: set[int] = set()
    for l in logs:
        if l.action == "assign_vuln" and l.detail:
            m = _ASSIGN_LEGACY_RE.match(l.detail.strip())
            if m:
                try:
                    vuln_ids.add(int(m.group(1)))
                except (TypeError, ValueError):
                    pass
    vuln_map: dict[int, str] = {}
    if vuln_ids:
        for vid, vtitle in (
            db.query(Vuln.id, Vuln.title).filter(Vuln.id.in_(vuln_ids)).all()
        ):
            vuln_map[vid] = vtitle

    items = []
    for l in logs:
        if l.user_id is not None and l.user_id in name_map:
            cur_username, cur_full = name_map[l.user_id]
            username = cur_username or l.username
            full_name = cur_full
        else:
            # 用户已删除 / 老日志：仅以写入时的快照为准
            username = l.username
            full_name = ""
        detail = l.detail or ""
        if l.action == "assign_vuln":
            detail = _enrich_assign_detail(db, detail, name_map, vuln_map)
        items.append(
            {
                "id": l.id,
                "user_id": l.user_id,
                "username": username,
                "full_name": full_name or "",
                "action": l.action,
                "module": l.module,
                "detail": detail,
                "created_at": l.created_at,
            }
        )
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": items,
    }
