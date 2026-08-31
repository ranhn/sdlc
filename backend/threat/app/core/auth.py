"""威胁建模子应用的鉴权：复用 SDLC 主应用的 JWT 凭证。

威胁建模作为独立子应用挂载在 /threat 前缀，原本只使用 X-API-Key 鉴权，
不感知 SDLC 主应用的用户身份。为实现「按角色查看建模结果」的权限控制，
这里读取与 SDLC 同源的 SECRET_KEY，解码 Bearer token，从中解析出
user_id / username / role，供 threat 路由做 owner 校验与角色判断。

无需直接 import SDLC 内部模块 —— 双方通过环境变量 SECRET_KEY 共享签名密钥。
"""
import os
from typing import Optional

from fastapi import Header, HTTPException, status
from jose import JWTError, jwt

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

# 拥有「全量查看 / 删除所有建模结果」权限的角色
ADMIN_ROLES = {"admin", "secops"}


class CurrentUser(dict):
    """轻量级当前用户字典：user_id / username / role。"""


def _decode_sdlc_token(token: str) -> dict:
    if not SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="威胁建模未配置 SECRET_KEY，无法识别用户身份",
        )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证凭据",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    sub = payload.get("sub")
    if sub is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证凭据",
        )
    return {
        "user_id": int(sub) if str(sub).isdigit() else None,
        "username": payload.get("username") or "",
        "role": payload.get("role") or "user",
    }


def get_sdlc_user(authorization: Optional[str] = Header(None)) -> dict:
    """FastAPI 依赖：从 Authorization 头解析 SDLC 当前用户。

    未携带 token 时也允许通过（兼容老的 X-API-Key 鉴权场景），
    返回的 username 留空 —— 路由内部按需判断是否强制登录。
    """
    if not authorization:
        return {"user_id": None, "username": "", "role": "user"}
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        return {"user_id": None, "username": "", "role": "user"}
    return _decode_sdlc_token(parts[1].strip())


def require_login(user: dict = None, authorization: Optional[str] = Header(None)) -> dict:
    """强制要求已登录的 FastAPI 依赖：未登录直接 401。"""
    current = user or get_sdlc_user(authorization)
    if not current.get("user_id") or not current.get("username"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="请先登录 SDLC 平台后再使用威胁建模",
        )
    return current


def can_view_all(user: dict) -> bool:
    """是否拥有查看所有威胁建模结果的权限。"""
    return user.get("role") in ADMIN_ROLES
