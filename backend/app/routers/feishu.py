"""飞书开放平台 - 用户同步路由。

通过飞书自建应用的 App ID / App Secret 获取 tenant_access_token，
拉取企业内成员列表，按 open_id 去重写入本地 User 表。

安全约束：
- 仅 admin 角色可调用
- App Secret 仅在服务端使用，不返回给前端
- 同步产生的用户密码随机生成，首次登录后强制改密
"""
import json
import os
import secrets
from datetime import datetime
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Department, Role, User
from ..security import get_current_user, hash_password, write_operation_log

from app.utils import network_clock as nc
router = APIRouter(prefix="/api/admin/feishu", tags=["飞书同步"])

FEISHU_BASE = "https://open.feishu.cn/open-apis"


# ===================== 配置读取 =====================

def _get_config():
    """读取飞书配置 + 部门映射 + 默认角色。"""
    app_id = os.getenv("FEISHU_APP_ID", "").strip()
    app_secret = os.getenv("FEISHU_APP_SECRET", "").strip()
    default_role_id_raw = os.getenv("FEISHU_DEFAULT_ROLE_ID", "").strip()
    dept_map_raw = os.getenv("FEISHU_DEPT_MAP_JSON", "").strip()
    default_dept_id_raw = os.getenv("FEISHU_DEFAULT_DEPT_ID", "").strip()

    dept_map = {}
    if dept_map_raw:
        try:
            dept_map = json.loads(dept_map_raw)
        except json.JSONDecodeError:
            dept_map = {}

    default_role_id = int(default_role_id_raw) if default_role_id_raw.isdigit() else None
    default_dept_id = int(default_dept_id_raw) if default_dept_id_raw.isdigit() else None

    return {
        "app_id": app_id,
        "app_secret": app_secret,
        "default_role_id": default_role_id,
        "default_dept_id": default_dept_id,
        "dept_map": dept_map,
    }


# ===================== 飞书 API 调用 =====================

async def _get_tenant_token(app_id: str, app_secret: str) -> str:
    """获取 tenant_access_token。"""
    url = f"{FEISHU_BASE}/auth/v3/tenant_access_token/internal"
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(url, json={"app_id": app_id, "app_secret": app_secret})
    data = r.json()
    if data.get("code") != 0:
        raise HTTPException(status_code=502, detail=f"飞书鉴权失败：{data.get('msg', 'unknown')}")
    return data["tenant_access_token"]


async def _list_feishu_dept_users(token: str, department_id: str, page_size: int = 50) -> list:
    """拉取某飞书部门下的所有用户（自动翻页）。"""
    url = f"{FEISHU_BASE}/contact/v3/users"
    headers = {"Authorization": f"Bearer {token}"}
    users = []
    page_token = ""
    while True:
        params = {
            "department_id": department_id,
            "page_size": str(page_size),
            "user_id_type": "open_id",
        }
        if page_token:
            params["page_token"] = page_token
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(url, headers=headers, params=params)
        data = r.json()
        if data.get("code") != 0:
            raise HTTPException(status_code=502, detail=f"拉取飞书用户失败：{data.get('msg')}")
        users.extend(data.get("data", {}).get("items", []) or [])
        if not data.get("data", {}).get("has_more"):
            break
        page_token = data["data"].get("page_token", "")
        if not page_token:
            break
    return users


async def _list_feishu_root_depts(token: str) -> list:
    """拉取根部门列表（用于遍历全公司）。"""
    url = f"{FEISHU_BASE}/contact/v3/departments"
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(url, headers=headers, params={"parent_department_id": "0", "page_size": "50"})
    data = r.json()
    if data.get("code") != 0:
        return []
    return data.get("data", {}).get("items", []) or []


# ===================== 同步逻辑 =====================

def _pick_dept_id(feishu_dept_ids: list, dept_map: dict, default_dept_id: Optional[int]) -> Optional[int]:
    """从飞书部门 ID 列表中匹配本地部门。"""
    for fid in feishu_dept_ids or []:
        key = str(fid)
        if key in dept_map:
            return int(dept_map[key])
    return default_dept_id


def _gen_username(prefix: str, open_id: str) -> str:
    """生成不超过 50 字符的 username。"""
    suffix = open_id[-8:] if open_id else secrets.token_hex(4)
    return f"{prefix}_{suffix}"[:50]


class FeishuConfigOut(BaseModel):
    enabled: bool
    default_role_id: Optional[int]
    default_dept_id: Optional[int]
    dept_map_keys: list


class FeishuSyncResult(BaseModel):
    total: int
    created: int
    updated: int
    skipped: int
    failed: int
    details: list


@router.get("/config", response_model=FeishuConfigOut)
def get_config(current: User = Depends(get_current_user)):
    """查看飞书同步配置状态（不返回敏感字段）。"""
    if current.role is None or current.role.code != "admin":
        raise HTTPException(status_code=403, detail="仅超级管理员可操作")
    cfg = _get_config()
    return FeishuConfigOut(
        enabled=bool(cfg["app_id"] and cfg["app_secret"]),
        default_role_id=cfg["default_role_id"],
        default_dept_id=cfg["default_dept_id"],
        dept_map_keys=list(cfg["dept_map"].keys()),
    )


@router.post("/sync", response_model=FeishuSyncResult)
async def sync_users(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    """从飞书拉取用户并同步到本地。"""
    if current.role is None or current.role.code != "admin":
        raise HTTPException(status_code=403, detail="仅超级管理员可操作")
    cfg = _get_config()
    if not (cfg["app_id"] and cfg["app_secret"]):
        raise HTTPException(status_code=400, detail="飞书配置未启用（FEISHU_APP_ID / FEISHU_APP_SECRET）")

    # 默认角色兜底：取第一个 role 或创建"普通员工"
    default_role_id = cfg["default_role_id"]
    if not default_role_id:
        emp_role = db.query(Role).filter(Role.code == "employee").first()
        if not emp_role:
            emp_role = Role(name="普通员工", code="employee", description="飞书同步默认角色")
            db.add(emp_role)
            db.commit()
            db.refresh(emp_role)
        default_role_id = emp_role.id

    # 默认部门兜底：取第一个
    default_dept_id = cfg["default_dept_id"]
    if not default_dept_id:
        first_dept = db.query(Department).first()
        if first_dept:
            default_dept_id = first_dept.id

    token = await _get_tenant_token(cfg["app_id"], cfg["app_secret"])
    depts = await _list_feishu_root_depts(token)

    result = FeishuSyncResult(total=0, created=0, updated=0, skipped=0, failed=0, details=[])
    seen_open_ids: set = set()

    # 若未配置任何飞书部门，则按"根部门 0"取全员
    target_depts = [d["open_department_id"] for d in depts] if depts else ["0"]

    for fid in target_depts:
        try:
            fs_users = await _list_feishu_dept_users(token, fid)
        except HTTPException as e:
            result.failed += 1
            result.details.append({"dept": fid, "error": e.detail})
            continue
        for fu in fs_users:
            open_id = fu.get("open_id")
            if not open_id or open_id in seen_open_ids:
                continue
            seen_open_ids.add(open_id)
            result.total += 1
            try:
                name = fu.get("name") or "未命名"
                email = fu.get("email") or None
                mobile = fu.get("mobile") or ""
                fs_dept_ids = fu.get("department_ids") or []
                dept_id = _pick_dept_id(fs_dept_ids, cfg["dept_map"], default_dept_id)
                username = _gen_username("fs", open_id)

                existing = db.query(User).filter(User.feishu_open_id == open_id).first()
                now = nc.utcnow()
                if existing:
                    existing.full_name = name
                    existing.email = email or existing.email
                    existing.department_id = dept_id or existing.department_id
                    existing.last_synced_at = now
                    existing.is_active = True
                    result.updated += 1
                else:
                    # 邮箱为空时用 mobile 拼一个占位邮箱，便于登录
                    if not email and mobile:
                        email = f"{mobile}@feishu.local"
                    # 密码随机生成，用户首次登录后必须改密（业务侧实现）
                    pwd = secrets.token_urlsafe(12)
                    user = User(
                        username=username,
                        password_hash=hash_password(pwd),
                        full_name=name,
                        email=email,
                        role_id=default_role_id,
                        department_id=dept_id,
                        is_active=True,
                        feishu_open_id=open_id,
                        last_synced_at=now,
                        must_change_password=True,  # 飞书同步用户首次登录必须改密
                    )
                    db.add(user)
                    result.created += 1
            except Exception as e:
                result.failed += 1
                result.details.append({"open_id": open_id, "error": str(e)})

    db.commit()
    write_operation_log(
        db, current, "feishu_sync", "admin",
        f"飞书同步: 总数 {result.total}, 新建 {result.created}, 更新 {result.updated}, 失败 {result.failed}",
    )
    return result
