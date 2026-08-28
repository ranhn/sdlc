# VeSync SDLC 安全平台 v2.0

> 统一 SDLC（软件开发生命周期）安全管理 + AI 威胁建模 一体化平台
>
> `FastAPI + Vue3` 前后端分离，单进程部署，单端口对外。

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Vue](https://img.shields.io/badge/Vue-3.4+-42b883.svg)](https://vuejs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/license-Internal-lightgrey.svg)](#许可证)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED.svg)](docker-compose.yml)

---

## 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [系统架构](#系统架构)
- [功能清单](#功能清单)
- [快速开始](#快速开始)
  - [Docker 一键部署（推荐）](#docker-一键部署推荐)
  - [本地开发模式](#本地开发模式)
- [AI 威胁建模配置](#ai-威胁建模配置)
- [运维与监控](#运维与监控)
- [项目结构](#项目结构)
- [文档索引](#文档索引)
- [常见问题](#常见问题)
- [许可证](#许可证)

---

## 项目简介

本平台将企业 SDLC 安全管理（漏洞、扫描、基线、培训、审计）与 **AI 驱动的威胁建模** 整合为一套系统：

- **业务侧**：漏洞全生命周期管理、SBOM 组件扫描、安全基线检查、安全培训、人员/角色、审计日志
- **AI 侧**：DFD 数据流图绘制、文档解析、AI 威胁识别（STRIDE）、威胁评分、结果导出
- **统一认证**：单点登录（JWT），一套账号打通所有模块

---

## 核心特性

| 特性 | 说明 |
|---|---|
| **一体化部署** | 一条 `docker compose up` 命令，对外仅暴露 8000 端口 |
| **AI 威胁建模** | DFD 可视化 + LLM 智能分析（OpenAI 兼容协议，可对接私有模型） |
| **DFD 评审** | 内置规则引擎，自动识别缺失的信任边界/数据流 |
| **威胁评分** | STRIDE × CVSS × 业务上下文 多维度评分 |
| **结果导出** | 支持 Markdown / JSON / Excel 三种格式导出 |
| **审计完备** | 所有写操作自动记录审计日志（含 IP、UA、操作前后值） |
| **可观测** | 健康检查 + 邮件告警 + 磁盘清理 cron（脚本开箱即用） |
| **可备份** | 一键备份/恢复 SQLite 数据库（详见 `BACKUP.md`） |

---

## 系统架构

```
┌─────────────────────────────────────────────────────────┐
│                    浏览器（Vue3 SPA）                    │
└──────────────────────────┬──────────────────────────────┘
                           │ HTTPS / HTTP
                           ▼
┌─────────────────────────────────────────────────────────┐
│             FastAPI 统一进程（端口 8000）                │
│  ┌──────────────────────┐  ┌──────────────────────────┐ │
│  │  SDLC 业务子应用     │  │  AI 威胁建模子应用       │ │
│  │  /api/*              │  │  /threat/api/*           │ │
│  │  (auth/vulns/scan/   │  │  (DFD/AI/result)         │ │
│  │   baseline/training/ │  │                          │ │
│  │   admin/logs)        │  │                          │ │
│  └──────────────────────┘  └──────────────────────────┘ │
│  ┌────────────────────────────────────────────────────┐ │
│  │  静态前端托管（构建后由 FastAPI 直接 serve）       │ │
│  └────────────────────────────────────────────────────┘ │
└──────────────────────────┬──────────────────────────────┘
                           │ SQLAlchemy ORM
                           ▼
                  ┌────────────────────┐
                  │  SQLite / PostgreSQL│
                  └────────────────────┘
```

**关键设计**：
- **单进程**：业务与威胁建模共用一个 FastAPI 进程，共享 JWT、CORS、配置
- **静态托管**：前端 `npm run build` 产物由 FastAPI 直接托管，无需 Nginx（生产可加 Nginx 做 HTTPS 卸载）
- **统一认证**：`/api/auth/login` 签发 JWT，前端 axios 自动附带 `Authorization: Bearer <token>`

---

## 功能清单

| 模块 | 路由 | 说明 |
|---|---|---|
| 工作台 | `/dashboard` | 漏洞统计、趋势图、系统风险排行 |
| 漏洞管理 | `/vulns` | 提交（含截图）、状态机流转、指派、评论、复测 |
| 系统资产 | `/systems` | 资产登记、负责人、状态、级联删除 |
| 漏洞扫描 | `/scan` | SBOM 组件、CVE 情报库、扫描任务、结果转单 |
| 安全基线 | `/baseline` | 合规率、检查项评估、分类管理 |
| 安全培训 | `/training` | 课程、学习进度、题库 |
| 人员管理 | `/users` | 用户/角色/部门（仅管理员） |
| 审计日志 | `/audit` | 操作审计（仅管理员） |
| AI 威胁建模 | `/threat-modeling` | DFD 数据流图、威胁识别、AI 分析、结果导出 |

---

## 快速开始

### Docker 一键部署（推荐）

```bash
# 1. 克隆仓库
git clone https://github.com/ranhn/sdlc.git
cd sdlc

# 2. 准备环境变量
cp .env.example .env
vi .env   # 至少修改 SECRET_KEY（openssl rand -hex 32）

# 3. 启动
docker compose up -d --build

# 4. 访问
# 浏览器打开 http://<服务器IP>:8000
# 默认账号：admin / admin123（首次登录后请立即修改）
```

**部署后必做**：
- 修改默认密码（`admin / admin123`、`secops / sec123`）
- 修改 `SECRET_KEY`（生产环境必须）
- 配置 SMTP（用于告警邮件）

### 本地开发模式

需要同时启动后端（端口 8001）和前端开发服务器（端口 5173）。

**后端**：
```bash
cd backend
pip install -r requirements.txt
pip install -r threat/requirements.txt

# Windows
.\start_dev.bat

# Linux/macOS
SECRET_KEY=dev-secret-key-32chars \
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:8001 \
DATABASE_URL=sqlite:///./security_platform.db \
uvicorn app.app_entry:app --host 127.0.0.1 --port 8001 --reload
```

**前端**：
```bash
cd frontend
npm install
npm run dev
# 访问 http://localhost:5173
```

> 前端 Vite 已配置代理：`/api` 和 `/threat` 自动转发到 `http://127.0.0.1:8001`

---

## AI 威胁建模配置

不配置 LLM 时，威胁建模的 **DFD 绘制、文档上传、结果管理** 等功能均可使用，仅 **"AI 威胁分析"** 按钮需要 LLM：

```bash
# .env 中添加
LLM_BASE_URL=https://api.openai.com/v1   # 或私有 LLM 网关
LLM_API_KEY=sk-xxxx
LLM_MODEL=gpt-4o
```

**支持的 LLM**：任何 OpenAI 兼容协议的服务（OpenAI、Azure OpenAI、DeepSeek、月之暗面、Qwen、本地 Ollama 等）。

**降级策略**：LLM 调用失败时自动降级到规则引擎（基于 STRIDE + 资产类型生成基础威胁清单）。

---

## 运维与监控

| 脚本 | 用途 | 部署方式 |
|---|---|---|
| `healthcheck.sh` | 健康检查 + 邮件告警 | cron 每 5 分钟 |
| `cleanup.sh` | 磁盘清理（LLM缓存/附件/结果/日志） | cron 每天凌晨 |
| `backup.sh` | SQLite 数据库备份 | cron 每天凌晨 |
| `restore.sh` | 数据库恢复 | 手动 |
| `scripts/alert.py` | SMTP 邮件告警（独立模块） | 被 healthcheck.sh 调用 |
| `scripts/cleanup_cache.py` | LLM 缓存过期清理 + VACUUM | 被 cleanup.sh 调用 |

**配置监控告警**：
```bash
cp .env.monitor.example .env.monitor
chmod 600 .env.monitor
vi .env.monitor   # 填入 SMTP 信息
```

详见 `DEPLOY.md`。

---

## 项目结构

```
sdlc-platform/
├── backend/                    # 统一 FastAPI 后端（单进程）
│   ├── app/                    # SDLC 业务（auth/vulns/scan/training/baseline/admin/logs）
│   ├── threat/app/             # AI 威胁建模子应用（挂载到 /threat）
│   ├── scripts/                # 运维脚本（baseline 导入等）
│   ├── main.py                 # 统一入口
│   ├── app_entry.py            # ASGI 应用工厂
│   ├── requirements.txt
│   ├── threat/requirements.txt
│   ├── Dockerfile
│   └── start_dev.bat           # 本地开发启动脚本（Windows）
├── frontend/                   # 统一 Vue3 前端
│   ├── src/
│   │   ├── layout/             # 主框架
│   │   ├── views/              # 业务页面
│   │   ├── components/threat/  # 威胁建模 X6 图等组件
│   │   ├── api/                # axios 封装
│   │   ├── store/ router/      # Pinia / Vue Router
│   │   └── main.js
│   ├── package.json
│   └── vite.config.js
├── nginx/                      # 可选：Nginx 反向代理（HTTPS 卸载）
├── scripts/                    # 运维脚本（告警/清理）
├── docker-compose.yml          # 一键部署
├── healthcheck.sh              # 健康检查
├── cleanup.sh                  # 磁盘清理
├── backup.sh                   # 数据库备份
├── restore.sh                  # 数据库恢复
├── .env.example                # 环境变量模板
├── .env.monitor.example        # 监控告警配置模板
├── .gitignore
├── README.md                   # 本文件
├── API.md                      # API 接口文档
├── ARCHITECTURE.md             # 架构设计文档
├── DEPLOY.md                   # 部署指南
└── BACKUP.md                   # 备份恢复指南
```

---

## 文档索引

| 文档 | 内容 |
|---|---|
| [API.md](API.md) | REST API 接口文档（路径、参数、响应、错误码） |
| [ARCHITECTURE.md](ARCHITECTURE.md) | 架构设计、模块划分、数据模型 |
| [DEPLOY.md](DEPLOY.md) | 详细部署指南（Docker / 裸机 / Nginx HTTPS） |
| [BACKUP.md](BACKUP.md) | 数据库备份与恢复 |

---

## 常见问题

<details>
<summary><b>Q1: 默认账号密码是什么？</b></summary>

- `admin / admin123`（超级管理员）
- `secops / sec123`（安全专家）

**生产部署后请立即修改！**
</details>

<details>
<summary><b>Q2: SQLite 还是 PostgreSQL？</b></summary>

- **50 用户以内 / 内部使用**：SQLite 完全够用，单文件备份简单
- **>50 用户 / 高并发**：建议 PostgreSQL，修改 `DATABASE_URL` 即可，代码无需改动（SQLAlchemy ORM 透明切换）
</details>

<details>
<summary><b>Q3: AI 威胁建模必须配置 LLM 吗？</b></summary>

不是。DFD 绘制、文档上传、规则引擎生成的基础威胁清单均可离线使用。仅"AI 智能分析"按钮需要 LLM。
</details>

<details>
<summary><b>Q4: 怎么对接公司私有 LLM？</b></summary>

任何 OpenAI 兼容协议的服务都可以。修改 `.env`：
```
LLM_BASE_URL=https://your-llm-gateway.company.com/v1
LLM_API_KEY=your-key
LLM_MODEL=your-model-name
```
</details>

<details>
<summary><b>Q5: 端口冲突怎么办？</b></summary>

修改 `docker-compose.yml` 中的 `ports: "8000:8000"` 为 `"8888:8000"` 即可（只改左边）。
</details>

<details>
<summary><b>Q6: 怎么升级？</b></summary>

```bash
git pull
docker compose up -d --build
# 数据库会自动迁移（SQLAlchemy create_all）
```
</details>

---

## 许可证

本项目为公司内部使用项目，未经授权不得用于商业用途或对外分发。

---

## 贡献

内部开发流程：
1. 从 `master` 切功能分支：`git checkout -b feat/xxx`
2. 提交：`git commit -m "feat: xxx"`
3. 推送并创建 Merge Request
4. Code Review + 合并

**Commit 规范**：`<type>(<scope>): <subject>`
- `feat`：新功能
- `fix`：Bug 修复
- `docs`：文档变更
- `refactor`：重构
- `chore`：杂项（构建/依赖）
