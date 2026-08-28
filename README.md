# VeSync SDLC 安全平台 v2.0

统一 SDLC 安全平台，将**软件开发生命周期安全管理**与 **AI 威胁建模** 整合为一套
`FastAPI + Vue3` 前后端分离系统。

## 架构

```
sdlc-platform/
├── backend/                    # 统一 FastAPI 后端（单进程）
│   ├── main.py                 # 统一入口：SDLC 业务 + 威胁建模子应用 + 前端静态托管
│   ├── app/                    # SDLC 业务（auth/vulns/scan/training/baseline/admin/logs）
│   ├── threat/app/             # AI 威胁建模子应用（挂载到 /threat）
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/                   # 统一 Vue3 前端（Vite + Element Plus + ECharts + X6）
│   ├── src/
│   │   ├── layout/             # 主框架（侧边栏 + 顶栏）
│   │   ├── views/              # 各业务页面 + 威胁建模全屏页
│   │   ├── components/threat/  # 威胁建模 X6 图等组件
│   │   ├── api/                # axios 封装（自动附带 JWT）
│   │   ├── store/ router/      # Pinia 状态、Vue Router
│   │   └── main.js
│   └── package.json
├── docker-compose.yml          # 一键部署
└── README.md
```

### 路由设计
- **业务 API**：`/api/*`（工作台、漏洞、扫描、基线、培训、人员、审计）
- **威胁建模**：`/threat/api/*`（DFD 分析、AI 威胁生成、结果管理）
- **前端页面**：`/` 下各路由（SPA）

### 统一认证
- 登录接口 `/api/auth/login` 签发 JWT
- 前端 axios 自动附带 `Authorization: Bearer <token>`
- 威胁建模子应用同样处于统一后端内，复用同一端口、同一 CORS

## 本地开发

```bash
# 1. 启动后端（端口 8001）
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8001

# 2. 启动前端开发服务器（端口 5173，自动代理 /api 与 /threat 到 8001）
cd frontend
npm install
npm run dev
# 访问 http://localhost:5173
```

默认账号：`admin / admin123`（超级管理员）、`secops / sec123`（安全专家）

## 生产部署（Docker，推荐）

```bash
cd sdlc-platform
docker compose up -d --build
# 访问 http://<服务器IP>:8000
```

一条命令完成前端构建 + 后端启动，对外**仅暴露一个端口 8000**，无需配置反向代理与 CORS。

## AI 威胁建模配置

不配置 LLM 时，威胁建模的 DFD 绘制、文档上传、结果管理等功能均可使用，
仅"AI 威胁分析"需要配置 LLM：

```yaml
# docker-compose.yml 中
environment:
  - LLM_BASE_URL=https://api.openai.com/v1
  - LLM_API_KEY=sk-xxxx
  - LLM_MODEL=gpt-4o
```

## 功能清单

| 模块 | 说明 |
|------|------|
| 工作台 | 漏洞统计、趋势图、系统风险排行 |
| 漏洞管理 | 提交（含截图）、状态机流转、指派、评论、复测 |
| 系统资产 | 资产登记、负责人、状态 |
| 漏洞扫描 | SBOM 组件、CVE 情报库、扫描任务、结果转单 |
| 安全基线 | 合规率、检查项评估、分类管理 |
| 安全培训 | 课程、学习进度、题库 |
| 人员管理 | 用户/角色/部门（仅管理员） |
| 审计日志 | 操作审计（仅管理员） |
| AI 威胁建模 | DFD 数据流图、威胁识别、AI 分析、结果导出 |
