"""数据库连接与会话管理。

默认使用 SQLite（本地零配置即可运行），后续可切换 MySQL：
只需将 DATABASE_URL 环境变量设置为 mysql+pymysql://user:pass@host/dbname
"""
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# 默认 SQLite，可通过环境变量覆盖为 MySQL
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./security_platform.db",
)

# SQLite 需要 check_same_thread=False 以支持 FastAPI 多线程
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI 依赖：提供数据库会话。"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
