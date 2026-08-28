"""SDLC安全平台 - 业务子应用入口（非统一入口）。

⚠️ 注意：本文件是业务子应用（FastAPI app），仅包含 SDLC 业务路由（工作台/漏洞/基线/扫描/培训/人员等）。

统一入口请使用项目根目录的 backend/main.py，它会：
  1. 导入本文件的业务 app
  2. 挂载威胁建模子应用（/threat）
  3. 托管 Vue3 前端构建产物（static_new）

开发调试可直接运行本文件：uvicorn app.app_entry:app --reload
但此时不包含威胁建模子应用；如需调试威胁建模，请改用 backend/main.py。
"""
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from .database import Base, SessionLocal, engine
from .models import BaselineCategory, BaselineItem
from .routers import admin, auth, baseline, dashboard, feishu, logs, scan, training, vulns

# 创建数据表
Base.metadata.create_all(bind=engine)


def _run_lightweight_migrations():
    """轻量级迁移：对老库添加新列（SQLite 3.35+ 支持 ADD COLUMN IF NOT EXISTS）。"""
    migrations = [
        ("sys_user", "feishu_open_id", "VARCHAR(100)"),
        ("sys_user", "last_synced_at", "DATETIME"),
        ("sys_user", "must_change_password", "BOOLEAN DEFAULT 0"),
    ]
    with engine.begin() as conn:
        for table, column, col_type in migrations:
            try:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"))
            except Exception:
                # 列已存在或不支持，忽略
                pass
    # 为 sys_user.feishu_open_id 创建索引（已存在则忽略）
    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_sys_user_feishu_open_id ON sys_user (feishu_open_id)"))
    except Exception:
        pass


_run_lightweight_migrations()


def _seed_baseline_defaults():
    """播种内置安全基线检查项（幂等）。"""
    db = SessionLocal()
    try:
        if db.query(BaselineCategory).count() > 0:
            return
        catalog = [
            ("account", "账号安全", "账号启用、权限最小化、定期审查", [
                ("禁用默认/共享账号", "检查系统是否存在默认口令账号或多人共享账号，应禁用或分配唯一账号", "high"),
                ("账号权限最小化", "管理员、运维、开发账号仅授予完成任务所需的最小权限", "high"),
                ("离职/闲置账号清理", "定期清理离职人员与长期未使用账号，并及时回收权限", "medium"),
            ]),
            ("password", "密码策略", "口令复杂度、有效期、防爆破", [
                ("密码复杂度", "密码长度不少于8位，须包含大小写字母、数字和特殊字符", "high"),
                ("密码有效期", "强制密码定期更换（建议90天），过期后要求重置", "medium"),
                ("登录失败锁定", "连续登录失败应触发账号锁定或登录限速，防止暴力破解", "high"),
            ]),
            ("hardening", "系统加固", "服务器/终端安全配置", [
                ("最小化服务", "关闭不必要端口与服务，仅开放业务所需", "medium"),
                ("补丁更新", "操作系统与应用及时安装安全补丁，无已知高危漏洞", "high"),
                ("远程访问管控", "SSH/RDP等远程访问仅限授权IP，并使用强认证", "high"),
            ]),
            ("log", "日志审计", "日志记录、留存与监控", [
                ("日志留存", "关键系统开启日志记录，日志留存不少于180天", "medium"),
                ("访问审计", "记录用户登录、权限变更、敏感操作等审计日志", "medium"),
                ("告警监控", "对异常登录、暴力破解、越权访问等设置监控告警", "medium"),
            ]),
            ("web", "Web安全", "应用层安全配置", [
                ("HTTPS加密", "对外Web服务强制HTTPS，禁用不安全的HTTP明文传输", "high"),
                ("安全响应头", "配置 CSP、X-Frame-Options、X-Content-Type-Options 等安全响应头", "medium"),
                ("输入校验", "对用户输入进行服务端校验与过滤，防范注入与XSS", "high"),
            ]),
            ("data", "数据安全", "数据加密、备份与脱敏", [
                ("敏感数据加密", "对数据库、配置中的敏感信息（口令、密钥、PII）加密存储", "high"),
                ("定期备份", "核心数据定期备份并验证可恢复性，异地留存", "high"),
                ("数据脱敏", "测试环境使用脱敏数据，生产数据不外泄", "medium"),
            ]),
        ]
        for code, name, desc, items in catalog:
            cat = BaselineCategory(code=code, name=name, description=desc)
            db.add(cat)
            db.flush()
            for idx, (iname, idesc, sev) in enumerate(items):
                db.add(BaselineItem(
                    category_id=cat.id, name=iname, description=idesc,
                    severity=sev, sort=idx, check_method="manual",
                ))
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


_seed_baseline_defaults()

app = FastAPI(
    title="SDLC安全平台",
    description="SDLC安全平台后端API",
    version="0.1.0",
)

# CORS：从环境变量读取白名单，生产环境必须配置
cors_origins_env = os.getenv("CORS_ORIGINS", "")
allow_origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()] if cors_origins_env else []
if not allow_origins:
    raise RuntimeError("CORS_ORIGINS 环境变量未设置，生产环境必须配置允许的来源")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(feishu.router)
app.include_router(vulns.router)
app.include_router(dashboard.router)
app.include_router(scan.router)
app.include_router(training.router)
app.include_router(baseline.router)
app.include_router(logs.router)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "security-platform"}
