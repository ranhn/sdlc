# VeSync SDLC 平台 — 架构文档

> 版本：v0.1 · 维护：安全研发团队 · 状态：MVP / 准生产

## 1. 概述

**VeSync SDLC** 是面向研发团队的安全开发生命周期（SDLC）一体化平台，覆盖：

| 模块 | 主要功能 |
|---|---|
| **整体概览** | 风险热力、个人 / 部门 / 项目维度统计 |
| **威胁建模** | AI 驱动的 STRIDE / VAST / PASTA / LINDDUN / AttackTree 自动建模 |
| **漏洞管理** | 漏洞录入、状态机流转、评论、附件截图 |
| **安全基线** | 五大基线（需求 / APP / 前端 / 后端 / 固件）检查项与扫描 |
| **安全培训** | 课程中心、附件在线学习、我的进度、题库练习 |
| **漏洞扫描** | 漏洞扫描任务调度与结果展示 |
| **系统管理** | 用户、角色、部门、菜单、操作日志 |

## 2. 技术栈

### 后端
- **Python 3.11** + **FastAPI 0.115**
- **SQLAlchemy 2.x** ORM + **Pydantic v2** 数据契约
- **SQLite**（开发/小规模）/ **PostgreSQL 14+**（生产推荐）
- **JWT** 鉴权 + 基于角色的访问控制（RBAC）
- **Uvicorn** ASGI 服务器

### 前端
- **Vue 3.4** + **Vite 5**
- **Element Plus 2.7** UI 组件库
- **Pinia 2** 状态管理 + **Vue Router 4** 路由
- **Axios** HTTP 客户端（统一拦截 + 401 自动跳登录）
- **D3.js 7** 数据流图（DFD）可视化
- **Marked** + **DOMPurify** Markdown 渲染与清洗

### 基础设施
- **Docker** + **docker-compose** 一键部署
- **Nginx** 反向代理 + HTTPS
- **SQLite WAL** 模式（开发）/ **PostgreSQL** 主备（生产）

## 3. 部署架构

```
┌─────────────────────────────────────────────────────────────┐
│                       Browser (Vue3 SPA)                     │
│   http://localhost:5173 (dev) / https://sdlc.xxx.com (prod)  │
└──────────────────────────┬──────────────────────────────────┘
                           │ Axios (/api/*, /threat/api/*)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              Nginx (反代 + 静态托管 + HTTPS)                  │
└──────────────────────────┬──────────────────────────────────┘
                           │ 转发 /api/*, /threat/*, /uploads/*
                           ▼
┌─────────────────────────────────────────────────────────────┐
│        Uvicorn :8001  (backend/main.py 统一入口)              │
│  ┌────────────────────────────────────────────────────┐     │
│  │ SDLC 业务子应用 (app.app_entry.app)                 │     │
│  │  ├ /api/auth      登录 / 鉴权                      │     │
│  │  ├ /api/users     用户管理                         │     │
│  │  ├ /api/vulns     漏洞管理 + 状态机                 │     │
│  │  ├ /api/baselines 安全基线                         │     │
│  │  ├ /api/scan      漏洞扫描                         │     │
│  │  ├ /api/training  安全培训                         │     │
│  │  ├ /api/dashboard 数据看板                         │     │
│  │  └ /api/logs      操作日志                         │     │
│  └────────────────────────────────────────────────────┘     │
│  ┌────────────────────────────────────────────────────┐     │
│  │ AI 威胁建模子应用 (threat.app.api.router.app)       │     │
│  │  └ /threat/api/*  挂载到 /threat 前缀                │     │
│  └────────────────────────────────────────────────────┘     │
└──────────────────────────┬──────────────────────────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
   ┌──────────────────┐      ┌──────────────────────┐
   │ SQLite/PostgreSQL │      │ uploads/ (附件目录)   │
   │ security_platform  │      │ 培训附件 / 漏洞截图    │
   │ .db                │      │                       │
   └──────────────────┘      └──────────────────────┘
```

## 4. 目录结构

```
sdlc-platform/
├── backend/                            # FastAPI 后端
│   ├── main.py                         # ★ 统一入口（生产必用）
│   ├── seed.py                         # 初始数据
│   ├── requirements.txt
│   ├── uploads/                        # 运行时附件目录
│   ├── static_new/                     # 前端构建产物（部署时拷贝）
│   └── app/
│       ├── app_entry.py                # SDLC 业务子应用入口
│       ├── database.py                 # SQLAlchemy 引擎 + Session
│       ├── models.py                   # ORM 模型
│       ├── schemas.py                  # Pydantic 数据契约
│       ├── auth.py                     # JWT + RBAC
│       ├── state_machine.py            # 漏洞状态机（核心）
│       ├── scanner.py                  # 基线扫描器
│       ├── routers/                    # 业务路由
│       │   ├── auth.py
│       │   ├── admin.py
│       │   ├── vulns.py
│       │   ├── baselines.py
│       │   ├── scan.py
│       │   ├── training.py
│       │   ├── dashboard.py
│       │   └── logs.py
│       └── threat/                     # 威胁建模子应用
│           ├── app/
│           │   ├── api/router.py       # FastAPI 子应用实例
│           │   ├── services/           # 业务服务（LLM、分析器）
│           │   └── models/             # 数据模型
│           └── tests/
├── frontend/                           # Vue 3 前端
│   ├── package.json
│   ├── vite.config.js                  # 代理 /api -> 8001
│   └── src/
│       ├── main.js / App.vue
│       ├── api/                        # API 封装
│       │   ├── index.js                # 业务 API
│       │   └── threat.js               # 威胁建模 API
│       ├── store/                      # Pinia 状态
│       ├── router/                     # Vue Router
│       ├── layout/                     # 框架布局（侧边栏 / 顶栏）
│       ├── views/                      # 页面（按业务域拆分）
│       ├── components/                 # 通用组件
│       │   └── threat/                 # 威胁建模专属组件
│       ├── styles/                     # 全局样式
│       └── utils/                      # 工具函数
├── docker-compose.yml
├── ARCHITECTURE.md                     # 本文件
└── API.md                              # API 文档
```

## 5. 关键设计

### 5.1 漏洞状态机

`app/state_machine.py` 集中管理 **角色 × 当前状态 → 可执行动作** 的规则：

```python
ACTION_RULES = {
    "confirm":     {"from": ["pending"],                "to": "confirmed",  "roles": ["admin", "secops"]},
    "reject":      {"from": ["pending"],                "to": "rejected",   "roles": ["admin", "secops"]},
    "ignore":      {"from": ["pending", "confirmed"],   "to": "ignored",    "roles": ["admin", "secops"]},
    "start_fix":   {"from": ["confirmed"],              "to": "fixing",     "roles": ["admin", "secops", "dev"]},
    "finish_fix":  {"from": ["fixing"],                 "to": "retest",     "roles": ["admin", "secops", "dev", "tester"]},
    "pass_retest": {"from": ["retest"],                 "to": "fixed",      "roles": ["admin", "secops", "tester"]},
    "close":       {"from": ["fixed"],                  "to": "closed",     "roles": ["admin", "secops"]},
}
```

前端 `can(action)` 同时校验角色 + 状态前置，避免显示不可用按钮。

### 5.2 RBAC

四级角色：
- **admin** 系统管理员
- **secops** 安全专家
- **dev** 开发工程师
- **tester** 测试工程师

权限校验在两层：
1. **路由级**：`router.beforeEach` 检查 `meta.roles`
2. **接口级**：`Depends(require_role("admin"))` 依赖

### 5.3 数据契约

所有 HTTP 接口都通过 `app/schemas.py` 中的 Pydantic 模型定义入参 / 出参，前后端字段名、类型严格一致。OpenAPI 文档自动生成于 `/docs`。

### 5.4 子应用分层

- `app/` 是 SDLC 业务子应用
- `threat/` 是 AI 威胁建模子应用
- `main.py` 是统一入口，**生产必用**；它会 mount 业务子应用 + 威胁建模子应用到 `/threat` 前缀 + 托管前端 SPA

开发调试可只跑 `app.app_entry:app`（不含威胁建模），但**生产部署必须用 `main.py`**。

## 6. 安全设计

| 维度 | 措施 |
|---|---|
| 鉴权 | JWT（HS256），30 分钟过期，可配置 refresh |
| 密码 | bcrypt 哈希（passlib），不存明文 |
| CORS | 开发允许 `*`；生产建议指定前端域名 |
| 文件上传 | 类型白名单（PDF / DOCX / 图片），大小限制 20MB |
| SQL 注入 | 全部走 SQLAlchemy ORM / 参数化查询 |
| XSS | 前端 Vue 模板默认转义；富文本走 DOMPurify |
| CSRF | Bearer Token 不存 cookie，免 CSRF |
| 速率限制 | 登录接口建议部署 Nginx 层限流（生产） |
| HTTPS | 生产强制 HTTPS，Let's Encrypt 或内部 CA |

## 7. 数据流

### 7.1 漏洞提交流程

```
用户提交表单
   ↓
POST /api/vulns  (status: pending)
   ↓
VulnOut 返回前端
   ↓
安全专家列表看到 "待确认"
   ↓
PATCH /api/vulns/{id}/action/confirm  (pending → confirmed)
   ↓
开发领取，开始修复
   ↓
PATCH /api/vulns/{id}/action/start_fix  (confirmed → fixing)
   ↓
finish_fix  → retest  → pass_retest  → close
```

每次状态变更写入 `vuln_flow` 表，保留完整审计轨迹。

### 7.2 威胁建模流程

```
用户填写需求/架构/方法论
   ↓
POST /threat/api/analyze  (异步，返回 task_id)
   ↓
前端轮询 GET /threat/api/tasks/{task_id}
   ↓
任务完成 → 自动建结果记录 (threat_result)
   ↓
GET /threat/api/results/{id}  获取 DFD + 威胁列表
   ↓
PATCH /threat/api/results/{id}/threats/{tid}  更新处置状态
```

LLM 分析支持缓存：相同输入（指纹一致）直接返回历史结果。

## 8. 扩展点

| 想做的事 | 看这里 |
|---|---|
| 加新的漏洞状态动作 | `app/state_machine.py` |
| 加新的角色权限 | `app/auth.py` `require_role()` + 前端 `router/index.js` `meta.roles` |
| 加新的业务路由 | `app/routers/` 新建文件 + `app/app_entry.py` 注册 |
| 加新的页面 | `frontend/src/views/` 新建 + `router/index.js` 注册 |
| 加新的 API 封装 | `frontend/src/api/` 新建模块 |
| 接入新的 LLM | `backend/threat/app/services/` 适配器 |

## 9. 部署清单

### 9.1 最小化部署（Docker Compose）

```bash
git clone <repo>
cd sdlc-platform
# 构建前端
cd frontend && npm install && npm run build && cd ..
# 启动后端
docker compose up -d
# 访问
open http://localhost:8001
```

### 9.2 生产部署（推荐 Rocky Linux 8/9）

- Nginx 反代 + HTTPS
- PostgreSQL 14+ 主备
- Uvicorn + systemd（4 worker 起步）
- 每日 03:00 数据库自动备份 + 异地留存
- 文件上传目录挂载独立磁盘
- 配置日志收集（Filebeat/Loki）
- 配置监控告警（CPU/内存/磁盘/服务存活）

详见 [API.md](./API.md)。
