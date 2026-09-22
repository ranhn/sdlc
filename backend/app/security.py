"""认证与权限工具：密码哈希、JWT、当前用户依赖。"""
from datetime import datetime, timedelta
import os

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from .database import get_db
from .models import User, OperationLog

# 生产环境必须通过环境变量注入强随机 SECRET_KEY
from app.utils import network_clock as nc
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 720))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


# ============ 密码 ============
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ============ JWT ============
def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    if not SECRET_KEY:
        raise RuntimeError("SECRET_KEY 环境变量未设置，生产环境禁止使用默认密钥")
    to_encode = data.copy()
    expire = nc.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无效的认证凭据",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.id == user_id).first()
    if user is None or not user.is_active:
        raise credentials_exception
    return user


# ============ 操作审计 ============
def write_operation_log(db: Session, user: User | None, action: str,
                        module: str, detail: str | None = None,
                        username: str | None = None):
    """写一条操作审计。

    ``username`` 用于**没有登录用户**的操作（定时任务）：不传时沿用原行为
    （有 user 取 user.username，没有则 "anonymous"）。定时任务若不动它，
    日志里会落成 anonymous —— 事后看不出是"系统自动跑的"还是"某个匿名请求"。
    """
    log = OperationLog(
        user_id=user.id if user else None,
        username=username or (user.username if user else "anonymous"),
        action=action,
        module=module,
        detail=detail,
    )
    db.add(log)
    db.commit()
