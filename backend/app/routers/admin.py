"""管理路由：用户/角色/部门/系统资产。"""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import (
    AssetSystem, Department, Role, User,
    Vuln, VulnFlow, VulnAttachment, VulnComment,
    ScanTask, ScanResult, BaselineResult, SBOMComponent,
)
from ..schemas import (
    AssetSystemCreate,
    AssetSystemOut,
    AssetSystemUpdate,
    DepartmentOut,
    RoleOut,
    UserCreate,
    UserOut,
    UserPickOut,
    UserUpdate,
    ChangePasswordIn,
)
from ..security import get_current_user, hash_password, write_operation_log
from ..utils.public_url import public_base_url
# 飞书：初始口令口径（default_password）与发消息都得跟同步/通知共用同一份实现
from . import feishu as feishu_notify

router = APIRouter(prefix="/api", tags=["管理"])


def require_admin(user: User):
    """admin + secops 均可操作（管理层共权）。"""
    if user.role is None or user.role.code not in ("admin", "secops"):
        raise HTTPException(status_code=403, detail="仅管理员/安全专家可操作")


def _ensure_can_target_admin(current: User, target: User, action: str = "操作"):
    """secops 不能对 admin 角色账号执行写操作（防提权）。admin 不受限。

    仅在写接口（create/toggle/delete/change-password）调用；read 接口无需此保护。
    """
    if (
        current.role
        and current.role.code == "secops"
        and target.role
        and target.role.code == "admin"
    ):
        raise HTTPException(
            status_code=403,
            detail=f"安全专家无权{action}超级管理员账号",
        )


# ============ 部门 ============
@router.get("/departments", response_model=list[DepartmentOut])
def list_departments(db: Session = Depends(get_db)):
    return db.query(Department).all()


# ============ 角色 ============
@router.get("/roles", response_model=list[RoleOut])
def list_roles(db: Session = Depends(get_db)):
    return db.query(Role).all()


# ============ 用户 ============
def _user_out(u: User, dept_names: dict) -> UserOut:
    """组装 UserOut：把角色名/角色码/部门名这些关联字段补上（列表与编辑接口共用）。"""
    out = UserOut.model_validate(u)
    out.role_name = u.role.name if u.role else None
    out.role_code = u.role.code if u.role else None
    out.department_name = dept_names.get(u.department_id)
    return out


@router.post("/users", response_model=UserOut)
def create_user(data: UserCreate, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    require_admin(current)
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=400, detail="用户名已存在")
    target_role = db.query(Role).filter(Role.id == data.role_id).first()
    if not target_role:
        raise HTTPException(status_code=400, detail="角色不存在")
    # secops 不能创建 admin 角色账号（防提权：避免 secops 自创 admin 后登录提权）
    if current.role.code == "secops" and target_role.code == "admin":
        raise HTTPException(status_code=403, detail="安全专家无权创建超级管理员账号")
    user = User(
        username=data.username,
        password_hash=hash_password(data.password),
        full_name=data.full_name,
        email=data.email,
        role_id=data.role_id,
        department_id=data.department_id,
        must_change_password=data.must_change_password,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    write_operation_log(db, current, "create_user", "admin", f"创建用户 {user.username}")
    return user


@router.put("/users/{user_id}", response_model=UserOut)
def update_user(user_id: int, data: UserUpdate, db: Session = Depends(get_db),
                current: User = Depends(get_current_user)):
    """编辑用户：姓名 / 邮箱 / 角色 / 部门（管理员、安全专家可用）。

    三处防护，都是"改错了很难恢复"的场景：
      1. secops 不能改**超级管理员**账号（防提权），也不能把人改成超级管理员；
      2. 不能把系统里**最后一个**超级管理员降级 —— 否则没人能再管理用户/角色；
      3. 只改传了值的字段，没传的保持原样（避免前端少传一个字段就把数据清空）。
    """
    require_admin(current)
    user = db.query(User).filter(User.id == user_id, User.is_deleted == False).first()  # noqa: E712
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    _ensure_can_target_admin(current, user, "修改")

    changes: list[str] = []
    if data.role_id is not None and data.role_id != user.role_id:
        new_role = db.query(Role).filter(Role.id == data.role_id).first()
        if not new_role:
            raise HTTPException(status_code=400, detail="角色不存在")
        if current.role.code == "secops" and new_role.code == "admin":
            raise HTTPException(status_code=403, detail="安全专家无权把账号提升为超级管理员")
        if user.role and user.role.code == "admin" and new_role.code != "admin":
            others = db.query(User).filter(
                User.is_deleted == False, User.is_active == True,  # noqa: E712
                User.role_id == user.role_id, User.id != user.id,
            ).count()
            if others == 0:
                raise HTTPException(
                    status_code=400,
                    detail="系统至少要保留一个超级管理员，不能把最后一个降级",
                )
        changes.append(f"角色 {user.role.name if user.role else '—'} → {new_role.name}")
        user.role_id = new_role.id

    if data.full_name is not None and data.full_name.strip() and data.full_name.strip() != user.full_name:
        changes.append(f"姓名 {user.full_name} → {data.full_name.strip()}")
        user.full_name = data.full_name.strip()

    if data.email is not None and (data.email.strip() or None) != user.email:
        new_email = data.email.strip() or None
        changes.append(f"邮箱 {user.email or '—'} → {new_email or '—'}")
        user.email = new_email

    if data.department_id is not None and data.department_id != user.department_id:
        dept = db.query(Department).filter(Department.id == data.department_id).first()
        if not dept:
            raise HTTPException(status_code=400, detail="部门不存在")
        changes.append(f"部门 → {dept.name}")
        user.department_id = dept.id

    dept_names = {d.id: d.name for d in db.query(Department).all()}
    if not changes:
        return _user_out(user, dept_names)

    db.commit()
    db.refresh(user)
    write_operation_log(db, current, "update_user", "admin",
                        f"编辑用户 {user.username}: " + "; ".join(changes))
    return _user_out(user, dept_names)


def _users_query(db: Session, q: str | None):
    """按关键词筛用户（用户名/姓名/邮箱，大小写不敏感）—— /users 与 /users/pick 共用。"""
    query = db.query(User).filter(User.is_deleted == False)  # noqa: E712
    if q:
        like = f"%{q.strip()}%"
        query = query.filter(
            (User.username.ilike(like))
            | (User.full_name.ilike(like))
            | (User.email.ilike(like))
        )
    return query


@router.get("/users/pick", response_model=list[UserPickOut])
def pick_users(
    q: str | None = None,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    """人员下拉数据源（各类"选择负责人 / 指派"用）。

    与 /users 的唯一差别：**只返回 id/用户名/姓名**。
    为什么单独一个接口：飞书通讯录同步后公司有 1600+ 人，全量 UserOut 一次约 580KB，
    而列表页每次刷新都会请求它 —— 里面大部分字段（邮箱/角色/部门/飞书 id）
    下拉根本用不到。这个接口一次约 60KB。
    不传 limit、不分页：前端是本地按关键词过滤，截断会让"某些人搜不到"。

    **权限：任何已登录用户** —— 此前这里是 require_admin(current)，那是错的。
    漏洞的负责人可以是**任何同事**，所以凡是"能指派"的人都得能列出全部人员；而"能指派"的人里
    包含**修复人本人**（他在「漏洞修复」页可以把自己的漏洞转派给同事，见 vulns.assign_vuln
    的负责人通道）。此前只给了他按钮、却没给他数据源：接口 403 → 前端 catch 后下拉空白，
    现象就是"点开指派弹窗里面没有内容"（实测踩过）。
    这里放开的**只有姓名/用户名这 3 个字段**；带邮箱/角色/部门/飞书 id 的 /users
    仍然只给 admin/secops（下面那个接口的 require_admin 不动）。

    current 只作"已登录"校验（Depends(get_current_user)），不参与过滤。
    """
    return _users_query(db, q).order_by(User.id.asc()).all()


@router.get("/users", response_model=list[UserOut])
def list_users(
    q: str | None = None,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    require_admin(current)
    users = _users_query(db, q).order_by(User.id.asc()).all()
    # 部门名一次性查表成字典，避免每行一次查询（N+1）
    dept_names = {d.id: d.name for d in db.query(Department).all()}
    return [_user_out(u, dept_names) for u in users]


@router.post("/users/{user_id}/toggle", response_model=UserOut)
def toggle_user(user_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    require_admin(current)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    _ensure_can_target_admin(current, user, "启停")
    if user.id == current.id:
        raise HTTPException(status_code=400, detail="不能禁用自己")
    user.is_active = not user.is_active
    db.commit()
    db.refresh(user)
    write_operation_log(db, current, "toggle_user", "admin", f"{'禁用' if not user.is_active else '启用'} {user.username}")
    return user


@router.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    require_admin(current)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    _ensure_can_target_admin(current, user, "删除")
    if user.id == current.id:
        raise HTTPException(status_code=400, detail="不能删除当前登录用户")
    if user.role and user.role.code == "admin":
        admin_count = db.query(User).join(Role).filter(Role.code == "admin", User.id != user_id).count()
        if admin_count == 0:
            raise HTTPException(status_code=400, detail="不能删除最后一个管理员")
    user.is_active = False
    user.is_deleted = True
    db.commit()
    write_operation_log(db, current, "delete_user", "admin", f"删除用户 {user.username}")
    return {"message": "删除成功"}


@router.post("/users/{user_id}/change-password")
def change_user_password(user_id: int, data: ChangePasswordIn, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    require_admin(current)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    _ensure_can_target_admin(current, user, "重置密码")
    user.password_hash = hash_password(data.new_password)
    db.commit()
    write_operation_log(db, current, "change_password", "admin", f"重置用户 {user.username} 密码")
    return {"message": "密码重置成功"}


@router.post("/users/{user_id}/reset-password")
def reset_user_password(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    """一键把账号重置为**初始口令**，并当场私信本人（与上面 change-password 分工不同）。

    · change-password：管理员自己拟一个新密码 —— 能不能告诉本人、怎么告诉，全靠线下；
    · 本接口：恢复到**初始口令**（取自 FEISHU_DEFAULT_PASSWORD，与"从飞书同步"建号同源），
      并把账号+口令**同步**发到本人飞书私信，首登强制改密。

    两个刻意的设计：
      1) **同步发送**（漏洞通知是丢后台线程的）：管理员是当面对着一个人在操作，他要的是
         确定答案 —— "发出去了没、失败原因是什么"，所以这里等结果并如实回报；
      2) **通知成败不影响"已重置"**：响应里分三种情况回报，失败时把初始口令回给管理员，
         便于线下告知（口令本来就是默认值，不算额外泄露）。
    """
    require_admin(current)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    _ensure_can_target_admin(current, user, "重置密码")
    if user.id == current.id:
        raise HTTPException(status_code=400, detail="不能在这里重置自己的密码（请用右上角「修改密码」）")

    password = feishu_notify.default_password()      # 与同步建号同源，通知里发的才是真的
    user.password_hash = hash_password(password)
    user.must_change_password = True                 # 重置后同样强制首登改密
    db.commit()
    db.refresh(user)

    # 登录链接的基地址：与漏洞通知**同一口径**（PUBLIC_BASE_URL 优先 → 请求上下文 →
    # CORS_ORIGINS 第一条），收敛在 utils/public_url.py，不再各写一份
    base = public_base_url(request)

    notified, error = False, None
    open_id = (user.feishu_open_id or "").strip()
    if not open_id:
        error = "该账号没有飞书 open_id（手工账号），初始口令需线下告知本人"
    elif not feishu_notify.notify_enabled():
        error = "飞书通知未启用（未配 FEISHU_APP_ID/SECRET，或 FEISHU_NOTIFY=0）"
    else:
        try:
            feishu_notify.send_and_wait(
                open_id,
                "interactive",
                feishu_notify.credentials_card(
                    user.username, password, base,
                    reason=f"{current.full_name or current.username} 为你重置了密码，"
                           f"请用下面的凭据登录",
                ),
            )
            notified = True
        except Exception as exc:  # noqa: BLE001 —— 通知失败不影响"已重置"这个事实
            error = str(getattr(exc, "detail", None) or exc)

    write_operation_log(
        db, current, "reset_password", "admin",
        f"重置用户 {user.username} 密码为初始口令（飞书通知："
        f"{'已发送' if notified else '未发送 - ' + str(error)}）",
    )
    return {
        "message": "已重置为初始密码" + ("，并已通过飞书私信通知本人" if notified else ""),
        "notified": notified,
        "error": error,
        "password": password,     # 通知失败时管理员可直接线下告知
    }


# ============ 系统资产 ============
@router.post("/systems", response_model=AssetSystemOut)
def create_system(data: AssetSystemCreate, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    if current.role is None or current.role.code not in ("admin", "secops"):
        raise HTTPException(status_code=403, detail="仅管理员/安全专家可维护资产")
    if db.query(AssetSystem).filter(AssetSystem.name == data.name).first():
        raise HTTPException(status_code=400, detail="系统名已存在")
    system = AssetSystem(**data.model_dump())
    db.add(system)
    db.commit()
    db.refresh(system)
    write_operation_log(db, current, "create_system", "asset", f"创建系统 {system.name}")
    return system


@router.get("/systems", response_model=list[AssetSystemOut])
def list_systems(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    systems = db.query(AssetSystem).all()
    result = []
    for s in systems:
        out = AssetSystemOut.model_validate(s)
        owner = db.query(User).filter(User.id == s.owner_id).first() if s.owner_id else None
        out.owner_name = owner.full_name if owner else None
        result.append(out)
    return result


@router.put("/systems/{system_id}", response_model=AssetSystemOut)
def update_system(system_id: int, data: AssetSystemUpdate, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    if current.role is None or current.role.code not in ("admin", "secops"):
        raise HTTPException(status_code=403, detail="仅管理员/安全专家可维护资产")
    system = db.query(AssetSystem).filter(AssetSystem.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="系统不存在")
    if data.name and data.name != system.name:
        if db.query(AssetSystem).filter(AssetSystem.name == data.name).first():
            raise HTTPException(status_code=400, detail="系统名已存在")
    for field in ("name", "description", "owner_id", "department_id", "status"):
        val = getattr(data, field, None)
        if val is not None:
            setattr(system, field, val)
    db.commit()
    db.refresh(system)
    write_operation_log(db, current, "update_system", "asset", f"编辑系统 {system.name}")
    out = AssetSystemOut.model_validate(system)
    owner = db.query(User).filter(User.id == system.owner_id).first() if system.owner_id else None
    out.owner_name = owner.full_name if owner else None
    return out


@router.delete("/systems/{system_id}")
def delete_system(
    system_id: int,
    force: bool = False,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    """删除系统资产。

    默认拒绝：若系统下存在漏洞/组件/扫描/基线记录，不允许删除。
    - force=true  会一并删除关联数据（管理员强制清理时使用，会写入审计日志）。
    """
    if current.role is None or current.role.code not in ("admin", "secops"):
        raise HTTPException(status_code=403, detail="仅管理员/安全专家可删除资产")

    system = db.query(AssetSystem).filter(AssetSystem.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="系统不存在")

    # 统计关联数据（展示给用户的简要统计）
    vuln_ids_sub = db.query(Vuln.id).filter(Vuln.system_id == system_id).subquery()
    refs = {
        "漏洞":       db.query(Vuln).filter(Vuln.system_id == system_id).count(),
        "组件":       db.query(SBOMComponent).filter(SBOMComponent.system_id == system_id).count(),
        "扫描发现":   db.query(ScanResult).filter(ScanResult.system_id == system_id).count(),
        "基线结果":   db.query(BaselineResult).filter(BaselineResult.system_id == system_id).count(),
    }
    total_refs = sum(refs.values())

    if total_refs > 0 and not force:
        detail = (
            f"系统「{system.name}」下存在关联数据："
            f"{', '.join(f'{k} {v} 条' for k, v in refs.items() if v)}，"
            f"请先清理后再删除，或在请求中加 force=true 强制级联删除"
        )
        raise HTTPException(status_code=409, detail=detail)

    deleted_counts = {}
    try:
        if total_refs > 0:
            # 按依赖顺序删除：先子表（依赖 Vuln/Component）→ 再主表 → 最后 AssetSystem
            # 1. 漏洞相关子表
            deleted_counts["漏洞流转"]   = db.query(VulnFlow).filter(VulnFlow.vuln_id.in_(vuln_ids_sub)).delete(synchronize_session=False)
            deleted_counts["漏洞附件"]   = db.query(VulnAttachment).filter(VulnAttachment.vuln_id.in_(vuln_ids_sub)).delete(synchronize_session=False)
            deleted_counts["漏洞评论"]   = db.query(VulnComment).filter(VulnComment.vuln_id.in_(vuln_ids_sub)).delete(synchronize_session=False)
            # 2. 扫描发现（依赖 SBOMComponent）
            deleted_counts["扫描发现"]   = db.query(ScanResult).filter(ScanResult.system_id == system_id).delete(synchronize_session=False)
            # 3. 漏洞主表
            deleted_counts["漏洞"]       = db.query(Vuln).filter(Vuln.system_id == system_id).delete(synchronize_session=False)
            # 4. SBOM 组件
            deleted_counts["组件"]       = db.query(SBOMComponent).filter(SBOMComponent.system_id == system_id).delete(synchronize_session=False)
            # 5. 基线结果
            deleted_counts["基线结果"]   = db.query(BaselineResult).filter(BaselineResult.system_id == system_id).delete(synchronize_session=False)
            # 6. 关联的扫描任务本身
            deleted_counts["扫描任务"]   = db.query(ScanTask).filter(ScanTask.system_id == system_id).delete(synchronize_session=False)

        db.query(AssetSystem).filter(AssetSystem.id == system_id).delete()
        db.commit()
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"级联删除失败：{str(e.orig)[:200]}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"级联删除异常：{str(e)[:200]}")

    write_operation_log(
        db, current, "delete_system", "asset",
        f"删除系统 {system.name}" + (f"（强制清理：{deleted_counts}）" if deleted_counts else ""),
    )
    return {"ok": True, "force_cascade": bool(deleted_counts), "deleted": deleted_counts}
