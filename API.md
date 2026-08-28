# VeSync SDLC 平台 — API 文档

> 自动生成于 FastAPI OpenAPI Schema v0.1
>
> 完整 Swagger UI：部署后访问 `http://<host>:8001/docs`
> OpenAPI JSON：`http://<host>:8001/openapi.json`
>
> 所有接口统一前缀：
> - **SDLC 业务 API**：`/api/...`
> - **AI 威胁建模 API**：`/threat/api/...`
> - **静态文件**：`/uploads/...`、`/static/...`
>
> 鉴权：除登录注册外，所有接口需在 Header 带 `Authorization: Bearer <jwt>`

---

## 1. SDLC 业务 API

### 1.1 鉴权 `/api/auth`

| 方法 | 路径 | 说明 | 角色 |
|---|---|---|---|
| POST | `/api/auth/login` | 账号密码登录，返回 JWT | 公开 |
| POST | `/api/auth/register` | 注册新用户（默认 dev 角色） | 公开 |
| GET | `/api/auth/me` | 获取当前登录用户信息 | 已登录 |
| POST | `/api/auth/change-password` | 修改自己的密码 | 已登录 |

**登录请求：**
```json
{ "username": "admin", "password": "admin123" }
```

**登录响应：**
```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "user": { "id": 1, "username": "admin", "name": "系统管理员", "role": "admin" }
}
```

### 1.2 用户管理 `/api/users`

| 方法 | 路径 | 说明 | 角色 |
|---|---|---|---|
| GET | `/api/users` | 用户列表 | admin / secops |
| POST | `/api/users` | 新增用户 | admin |
| PATCH | `/api/users/{id}` | 修改用户（角色/部门/状态） | admin |
| DELETE | `/api/users/{id}` | 删除用户（不能删自己） | admin |
| POST | `/api/users/{id}/reset-password` | 重置密码 | admin |
| GET | `/api/departments` | 部门列表 | 已登录 |

### 1.3 漏洞管理 `/api/vulns`

| 方法 | 路径 | 说明 | 角色 |
|---|---|---|---|
| GET | `/api/vulns` | 漏洞列表（支持分页/筛选） | 已登录 |
| GET | `/api/vulns/{id}` | 漏洞详情 | 已登录 |
| POST | `/api/vulns` | 新增漏洞 | secops+ / dev |
| PATCH | `/api/vulns/{id}` | 修改漏洞 | 提交人 / secops+ |
| DELETE | `/api/vulns/{id}` | 删除漏洞 | admin / secops |
| POST | `/api/vulns/{id}/action/{action}` | 状态机动作 | 视动作 |
| POST | `/api/vulns/{id}/reject` | 驳回（带原因） | admin / secops |
| POST | `/api/vulns/{id}/assign` | 指派处理人 | admin / secops |
| POST | `/api/vulns/{id}/comments` | 添加评论 | 已登录 |
| GET | `/api/vulns/{id}/comments` | 评论列表 | 已登录 |
| POST | `/api/vulns/{id}/attachments` | 上传截图（multipart） | 已登录 |
| GET | `/api/vulns/{id}/attachments` | 附件列表 | 已登录 |
| DELETE | `/api/vulns/{id}/attachments/{aid}` | 删除附件 | 提交人 / secops+ |

**动作 action 枚举：** `confirm | reject | ignore | start_fix | finish_fix | pass_retest | close`

**状态机：**
```
pending → confirmed → fixing → retest → fixed → closed
   ↓          ↓
rejected   ignored
```

每个 action 的角色限制见后端 `app/state_machine.py` 的 `ACTION_RULES`。

**动作请求体（可选）：**
```json
{ "comment": "备注" }
```

### 1.4 安全基线 `/api/baselines`

| 方法 | 路径 | 说明 | 角色 |
|---|---|---|---|
| GET | `/api/baselines/categories` | 基线分类列表 | 已登录 |
| GET | `/api/baselines/items` | 基线检查项列表 | 已登录 |
| POST | `/api/baselines/items` | 新增检查项 | admin / secops |
| PATCH | `/api/baselines/items/{id}` | 修改检查项 | admin / secops |
| DELETE | `/api/baselines/items/{id}` | 删除检查项 | admin |
| POST | `/api/baselines/scan` | 触发扫描 | admin / secops |
| GET | `/api/baselines/scan/results` | 扫描结果列表 | 已登录 |
| GET | `/api/baselines/scopes` | 基线五大类（需求/APP/前端/后端/固件） | 已登录 |

**基线五大类枚举：**
- `requirement` 安全需求基线
- `app` APP 开发安全基线
- `frontend` 前端开发安全基线
- `backend` 后端开发安全基线
- `firmware` 固件开发安全基线

### 1.5 漏洞扫描 `/api/scan`

| 方法 | 路径 | 说明 | 角色 |
|---|---|---|---|
| GET | `/api/scan/tasks` | 扫描任务列表 | 已登录 |
| POST | `/api/scan/tasks` | 创建扫描任务 | admin / secops |
| GET | `/api/scan/tasks/{id}` | 任务详情 + 结果 | 已登录 |
| DELETE | `/api/scan/tasks/{id}` | 删除任务 | admin |

### 1.6 安全培训 `/api/training`

| 方法 | 路径 | 说明 | 角色 |
|---|---|---|---|
| GET | `/api/training/courses` | 课程列表 | 已登录 |
| GET | `/api/training/courses/{id}` | 课程详情 | 已登录 |
| POST | `/api/training/courses` | 新增课程 | admin / secops |
| PATCH | `/api/training/courses/{id}` | 修改课程 | admin / secops |
| DELETE | `/api/training/courses/{id}` | 删除课程 | admin / secops |
| POST | `/api/training/courses/{id}/upload` | 上传课程附件（multipart） | admin / secops |
| GET | `/api/training/download/{id}` | 下载 / 在线查看附件 | 已登录 |
| POST | `/api/training/courses/{id}/start` | 开始学习 | 已登录 |
| POST | `/api/training/courses/{id}/complete` | 完成学习 | 已登录 |
| GET | `/api/training/progress` | 我的进度 | 已登录 |
| GET | `/api/training/questions` | 题库列表 | 已登录 |
| POST | `/api/training/questions` | 新增题目 | admin / secops |
| DELETE | `/api/training/questions/{id}` | 删除题目 | admin / secops |

### 1.7 数据看板 `/api/dashboard`

| 方法 | 路径 | 说明 | 角色 |
|---|---|---|---|
| GET | `/api/dashboard/overview` | 总览（漏洞/风险/培训） | 已登录 |
| GET | `/api/dashboard/trend` | 风险趋势（按天） | 已登录 |
| GET | `/api/dashboard/by-department` | 按部门统计 | 已登录 |
| GET | `/api/dashboard/by-system` | 按系统统计 | 已登录 |
| GET | `/api/dashboard/by-severity` | 按严重等级统计 | 已登录 |

### 1.8 系统资产 `/api/assets`

| 方法 | 路径 | 说明 | 角色 |
|---|---|---|---|
| GET | `/api/assets/systems` | 系统列表 | 已登录 |
| POST | `/api/assets/systems` | 新增系统 | admin / secops |
| PATCH | `/api/assets/systems/{id}` | 修改系统 | admin / secops |
| DELETE | `/api/assets/systems/{id}` | 删除系统 | admin |

### 1.9 操作日志 `/api/logs`

| 方法 | 路径 | 说明 | 角色 |
|---|---|---|---|
| GET | `/api/logs` | 操作日志列表（支持筛选） | admin / secops |

### 1.10 健康检查 `/api/health`

```http
GET /api/health
```

**响应：**
```json
{ "status": "ok", "service": "security-platform" }
```

---

## 2. AI 威胁建模 API `/threat/api`

### 2.1 健康检查

```http
GET /threat/api/health
```

### 2.2 模板与输入

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/threat/api/templates` | 获取示例场景模板 |
| POST | `/threat/api/fingerprint` | 计算输入指纹（用于缓存命中） |
| POST | `/threat/api/upload` | 上传 PDF/DOCX 文档（multipart） |
| GET | `/threat/api/system-prompt` | 查看某方法论下的系统提示词（调试） |
| GET | `/threat/api/llm/config` | 获取 LLM 配置 |
| POST | `/threat/api/llm/config` | 更新 LLM 配置 |

### 2.3 分析任务

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/threat/api/analyze` | 提交分析任务（异步） |
| GET | `/threat/api/tasks/{task_id}` | 查询任务进度 |
| POST | `/threat/api/tasks/{task_id}/cancel` | 取消任务 |
| GET | `/threat/api/tasks` | 任务列表（分页） |

**analyze 请求：**
```json
{
  "title": "电商订单系统",
  "requirements": "用户下单、支付、查询订单...",
  "architecture": "前端 -> API 网关 -> 订单服务 -> 库存服务 -> MySQL",
  "images": ["data:image/png;base64,..."],
  "methodology": "stride",
  "industry": "ecommerce"
}
```

**analyze 响应：**
```json
{
  "task_id": "t_abc123",
  "status": "queued",
  "steps": ["需求解析", "DFD 构建", "威胁识别", "风险评级"]
}
```

**任务状态：**
- `queued` 排队中
- `running` 分析中
- `succeeded` 完成
- `failed` 失败
- `cancelled` 已取消

### 2.4 结果管理

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/threat/api/results` | 结果列表（支持分页/搜索） |
| GET | `/threat/api/results/{id}` | 结果详情（DFD + 威胁） |
| PATCH | `/threat/api/results/{id}` | 重命名结果 |
| DELETE | `/threat/api/results/{id}` | 删除结果 |
| GET | `/threat/api/results/{id}/export?format=md` | 导出结果（md/json/csv） |
| PATCH | `/threat/api/results/{id}/threats/{tid}` | 更新某条威胁状态 |

**威胁处置状态：**
- `open` 待处理
- `mitigated` 已缓解
- `accepted` 已接受
- `false_positive` 误报
- `out_of_scope` 范围外（用 `outOfScope: true` 标记）

---

## 3. 通用约定

### 3.1 错误响应

```json
{ "detail": "无效的认证凭据" }
```

FastAPI 校验错误时 `detail` 为数组：
```json
{
  "detail": [
    { "loc": ["body", "username"], "msg": "field required", "type": "value_error.missing" }
  ]
}
```

### 3.2 分页

```http
GET /api/vulns?page=1&pageSize=20
```

**响应：**
```json
{
  "items": [...],
  "total": 42,
  "page": 1,
  "page_size": 20,
  "pages": 3
}
```

### 3.3 时间格式

所有时间字段为 ISO 8601 字符串（`2026-08-27T10:30:00`），威胁建模任务为 Unix 毫秒时间戳（`1724735400000`）。

---

## 4. 前端调用示例

```js
import http from '@/api'  // 或 '@/api/threat'

// 登录
const { data } = await http.post('/auth/login', {
  username: 'admin',
  password: 'admin123',
})
localStorage.setItem('token', data.access_token)

// 提交漏洞
const { data: vuln } = await http.post('/vulns', {
  title: 'SQL 注入',
  severity: 'high',
  system_id: 1,
  description: '...',
})

// 状态机动作
await http.post(`/vulns/${vuln.id}/action/confirm`, { comment: '已确认' })

// 提交威胁建模
import { analyze, getTask } from '@/api/threat'
const { task_id } = await analyze({ requirements, architecture, methodology: 'stride' })
// 轮询
const task = await getTask(task_id)
if (task.status === 'succeeded') { /* 渲染 task.result */ }
```

---

## 5. 版本变更

| 版本 | 日期 | 变更 |
|---|---|---|
| v0.1 | 2026-08 | MVP 发布，SDLC 业务 + AI 威胁建模 完整闭环 |
