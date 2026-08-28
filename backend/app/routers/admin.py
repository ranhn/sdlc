"""管理路由：用户/角色/部门/系统资产。"""
from fastapi import APIRouter, Depends, HTTPException
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
    ChangePasswordIn,
)
from ..security import get_current_user, hash_password, write_operation_log

router = APIRouter(prefix="/api", tags=["管理"])


def require_admin(user: User):
    if user.role is None or user.role.code not in ("admin",):
        raise HTTPException(status_code=403, detail="仅超级管理员可操作")


# ============ 部门 ============
@router.get("/departments", response_model=list[DepartmentOut])
def list_departments(db: Session = Depends(get_db)):
    return db.query(Department).all()


# ============ 角色 ============
@router.get("/roles", response_model=list[RoleOut])
def list_roles(db: Session = Depends(get_db)):
    return db.query(Role).all()


# ============ 用户 ============
@router.post("/users", response_model=UserOut)
def create_user(data: UserCreate, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    require_admin(current)
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=400, detail="用户名已存在")
    if not db.query(Role).filter(Role.id == data.role_id).first():
        raise HTTPException(status_code=400, detail="角色不存在")
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


@router.get("/users", response_model=list[UserOut])
def list_users(
    q: str | None = None,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    require_admin(current)
    query = db.query(User).filter(User.is_deleted == False)
    if q:
        like = f"%{q.strip()}%"
        query = query.filter(
            (User.username.ilike(like))
            | (User.full_name.ilike(like))
            | (User.email.ilike(like))
        )
    users = query.order_by(User.id.asc()).all()
    result = []
    for u in users:
        out = UserOut.model_validate(u)
        out.role_name = u.role.name if u.role else None
        result.append(out)
    return result


@router.post("/users/{user_id}/toggle", response_model=UserOut)
def toggle_user(user_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    require_admin(current)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
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
    user.password_hash = hash_password(data.new_password)
    db.commit()
    write_operation_log(db, current, "change_password", "admin", f"重置用户 {user.username} 密码")
    return {"message": "密码重置成功"}


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
