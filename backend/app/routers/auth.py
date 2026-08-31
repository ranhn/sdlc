"""认证路由：登录、改密。"""
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User
from ..schemas import ChangePasswordIn, Token
from ..security import create_access_token, get_current_user, hash_password, verify_password

router = APIRouter(prefix="/api/auth", tags=["认证"])


@router.post("/login", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # 用户名匹配：先精确匹配，未命中再回退为不区分大小写匹配
    username = form.username.strip()
    user = db.query(User).filter(User.username == username).first()
    if not user:
        # 不区分大小写匹配时优先取未删除账号，避免命中同名不同大小写的已删除记录
        user = db.query(User).filter(
            func.lower(User.username) == username.lower(),
            User.is_deleted == False,  # noqa: E712
        ).first()
    if not user:
        # 仍未命中则允许匹配已删除账号，以便返回准确的「账号已删除」提示
        user = db.query(User).filter(func.lower(User.username) == username.lower()).first()
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误",
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="账号已禁用")
    if getattr(user, "is_deleted", False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="账号已删除")

    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "username": user.username,
            "role": user.role.code if user.role else "user",
        },
        expires_delta=timedelta(minutes=720),
    )
    return Token(
        access_token=access_token,
        role=user.role.code if user.role else "user",
        full_name=user.full_name,
        username=user.username,
        must_change_password=user.must_change_password,
    )


@router.post("/change-password")
def change_password(
    body: ChangePasswordIn,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    """修改当前登录用户的密码。

    要求传入旧密码以验证身份；新密码长度 8-64 位，且不能与旧密码相同。
    改密成功后自动清除 must_change_password 标记。
    """
    if not verify_password(body.old_password, current.password_hash):
        raise HTTPException(status_code=400, detail="旧密码错误")
    if body.old_password == body.new_password:
        raise HTTPException(status_code=400, detail="新密码不能与旧密码相同")
    current.password_hash = hash_password(body.new_password)
    current.must_change_password = False
    db.commit()
    return {"ok": True}
