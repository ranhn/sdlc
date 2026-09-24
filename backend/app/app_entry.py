"""SDLC安全平台 - 业务子应用入口（非统一入口）。

⚠️ 注意：本文件是业务子应用（FastAPI app），仅包含 SDLC 业务路由（工作台/漏洞/基线/扫描/培训/人员等）。

统一入口请使用项目根目录的 backend/main.py，它会：
  1. 导入本文件的业务 app
  2. 挂载威胁建模子应用（/threat）
  3. 托管 Vue3 前端构建产物（static_new）

开发调试可直接运行本文件：uvicorn app.app_entry:app --reload
但此时不包含威胁建模子应用；如需调试威胁建模，请改用 backend/main.py。
"""
import asyncio
import os

# ⚠️ 必须在 `from .database` / `from .routers` **之前**加载 .env：
#   · .database 在 import 时读 DATABASE_URL（决定连哪个 sqlite 文件）；
#   · .routers.auth → security 在 import 时读 SECRET_KEY（漏了它 → 登录 500）。
# 本文件也能单独启动（`uvicorn app.app_entry:app --reload`），所以这里同样兜一层；
# 从 main.py 启动时它已经加载过，load_dotenv 不覆盖已有值，重复调用无副作用。
try:
    from pathlib import Path as _Path

    from dotenv import load_dotenv

    load_dotenv(_Path(__file__).resolve().parents[2] / ".env")
except Exception:  # noqa: BLE001 —— 缺 dotenv 不该影响启动
    pass

# 应用日志：**必须在这里**（任何业务模块 import 之前），否则业务模块的 INFO
# （如「飞书通知已发送/失败」）会被 root logger 的默认级别丢掉，日志里查不到
# "通知到底发出去没有"。幂等，两个入口都会经过（见 logging_setup 说明）。
from .logging_setup import setup_logging

setup_logging()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from .database import Base, SessionLocal, engine
from .models import BaselineCategory, BaselineItem
from .routers import admin, auth, baseline, dashboard, feishu, logs, scan, training, vulns
from . import baseline_reminder, scheduler
from .vuln_taxonomy import TYPE_TO_CATEGORY

# 创建数据表
Base.metadata.create_all(bind=engine)

# 自动初始化种子数据（角色/部门/管理员账号/示例漏洞/培训课程/SBOM/扫描任务等）
# 幂等：seed.init() 内部每个数据项都做了存在性检查，可重复调用
try:
    from seed import init as _seed_init
    _seed_init()
except Exception as _seed_err:
    # seed 失败不阻塞启动（表结构已建好，只是缺演示数据）
    import logging
    logging.getLogger(__name__).warning("种子数据初始化失败: %s", _seed_err)


def _run_lightweight_migrations():
    """轻量级迁移：对老库添加新列（SQLite 3.35+ 支持 ADD COLUMN IF NOT EXISTS）。"""
    migrations = [
        ("sys_user", "feishu_open_id", "VARCHAR(100)"),
        ("sys_user", "last_synced_at", "DATETIME"),
        ("sys_user", "must_change_password", "BOOLEAN DEFAULT 0"),
        ("sys_user", "en_name", "VARCHAR(50)"),
        ("sys_department", "feishu_open_dept_id", "VARCHAR(100)"),
        ("vuln", "is_external", "BOOLEAN DEFAULT 0 NOT NULL"),
        ("vuln", "external_source", "VARCHAR(100)"),
        ("vuln", "api_endpoint", "VARCHAR(500)"),
        ("vuln", "step_screenshots", "TEXT"),
        ("vuln", "fix_suggestion", "TEXT"),
        ("vuln", "vuln_category", "VARCHAR(50)"),
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
    # 为 sys_department.feishu_open_dept_id 创建索引（飞书部门同步按它匹配，已存在则忽略）
    try:
        with engine.begin() as conn:
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_sys_department_feishu_open_dept_id "
                "ON sys_department (feishu_open_dept_id)"
            ))
    except Exception:
        pass


def _backfill_vuln_category():
    """为历史漏洞回填一级大类（vuln_category 为 NULL 的记录）。幂等。"""
    try:
        with engine.begin() as conn:
            for vtype, vcat in TYPE_TO_CATEGORY.items():
                conn.execute(
                    text(
                        "UPDATE vuln SET vuln_category = :cat "
                        "WHERE vuln_category IS NULL AND vuln_type = :t"
                    ),
                    {"cat": vcat, "t": vtype},
                )
            # 无法匹配的兜底为「其他」
            conn.execute(
                text(
                    "UPDATE vuln SET vuln_category = '其他' "
                    "WHERE vuln_category IS NULL AND vuln_type IS NOT NULL AND vuln_type != ''"
                )
            )
    except Exception:
        # 回填失败不阻塞启动
        pass


_run_lightweight_migrations()

# 历史漏洞数据回填一级大类：按二级类型反查所属大类（幂等，仅填 NULL 值）
_backfill_vuln_category()


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


# ============ 定时任务 ============
# 两个：① 每周一 08:00（北京时间）自动同步飞书通讯录（app/scheduler.py）；
#       ② 每天 09:00 后提醒基线需求负责人（app/baseline_reminder.py）。
#
# 为什么挂在 startup 事件里、而不是模块级 asyncio.create_task()：
#   import 阶段还没有事件循环，模块级 create_task 会直接抛 RuntimeError（服务起不来）。
_scheduler_task: "asyncio.Task | None" = None
_due_task: "asyncio.Task | None" = None


@app.on_event("startup")
async def _start_schedulers() -> None:
    """启动后台定时任务（幂等：已启动则不重复起）。"""
    global _scheduler_task, _due_task
    if _scheduler_task is None or _scheduler_task.done():
        # 必须存**强引用**：asyncio 只持弱引用，不存变量的话任务会被 GC 静默回收 ——
        # 表现是"服务正常、但定时任务某天开始一声不响地不跑了"，极难排查。
        _scheduler_task = asyncio.create_task(scheduler.weekly_feishu_sync_loop())
    if _due_task is None or _due_task.done():
        # 基线需求到期提醒：同一个需求每天最多一条（去重靠操作日志）
        _due_task = asyncio.create_task(baseline_reminder.daily_due_loop())
