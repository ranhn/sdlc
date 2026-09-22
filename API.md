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
| POST | `/api/vulns/{id}/reject` | 驳回（带原因） | admin / secops / 该漏洞负责人 |
| POST | `/api/vulns/{id}/assign` | 指派 / 转派处理人 | admin / secops / 该漏洞当前负责人 |
| POST | `/api/vulns/{id}/comments` | 添加评论 | 已登录 |
| GET | `/api/vulns/{id}/comments` | 评论列表 | 已登录 |
| POST | `/api/vulns/{id}/attachments` | 上传截图（multipart） | 已登录 |
| GET | `/api/vulns/{id}/attachments` | 附件列表 | 已登录 |
| DELETE | `/api/vulns/{id}/attachments/{aid}` | 删除附件 | 提交人 / secops+ |

**动作 action 枚举：** `confirm | reject | start_fix | finish_fix | pass_retest | fail_retest | close`

> 注：`ignore`（忽略）**已从状态机移除**（页面上从来没有该入口），`ignored` 仅作为历史状态兼容显示。

**状态机：**
```
draft → pending → confirmed → fixing → retest → fixed → closed
                            ↑        │
                            └────────┘ fail_retest（复测不通过，打回重修）
           │
           └─ reject → rejected
```

每个 action 的角色限制见后端 `app/state_machine.py` 的 `ACTION_RULES`。

**动作的飞书通知对象**（`vulns._STATUS_RECIPIENTS`）：

| action | 通知谁 | 备注 |
|---|---|---|
| `confirm` | 提单人 | —— |
| `reject` | 提单人 | 卡片含**驳回原因** |
| `start_fix` | —— | 刻意不发（避免噪音） |
| `finish_fix` | 提单人 | 提示进入待复测 |
| `pass_retest` | 提单人 + 负责人 | —— |
| `fail_retest` | 负责人 + 提单人 | 卡片含**不通过原因**；状态回到 `fixing` |
| `close` | 提单人 + 负责人 | —— |
| `assign`（指派/转派） | 新负责人 | 首次登录账号会附上初始口令 |

> 操作人本人不会被通知；收件人是手工账号（无 `feishu_open_id`）时跳过并在日志记一行。

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
| POST | `/threat/api/upload` | 上传 PDF/DOCX 文档（multipart） |
| GET | `/threat/api/system-prompt` | 查看某方法论下的系统提示词（调试） |
| GET | `/threat/api/llm/config` | 获取 LLM 配置（Key 脱敏，所有登录用户可读） |
| POST | `/threat/api/llm/config` | 更新 LLM 配置（仅 admin / secops） |
| DELETE | `/threat/api/llm/config` | 清空 LLM 配置（仅 admin / secops） |

> 注：输入指纹由前端本地计算（与后端 `_compute_fingerprint` 算法一致），不存在 `POST /threat/api/fingerprint` 端点。

### 2.3 分析任务

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/threat/api/analyze` | 提交分析任务（异步，返回 task_id） |
| GET | `/threat/api/tasks/{task_id}` | 查询任务进度 / 日志 / 结果 |
| POST | `/threat/api/tasks/{task_id}/cancel` | 取消进行中的任务 |

> 注：任务保存在进程内存中，没有 `GET /threat/api/tasks` 列表端点；服务重启后任务状态会丢失。

**analyze 请求：**
```json
{
  "title": "电商订单系统",
  "requirements": "用户下单、支付、查询订单...",
  "architecture": "前端 -> API 网关 -> 订单服务 -> 库存服务 -> MySQL",
  "images": ["data:image/png;base64,..."],
  "pasted_images": ["data:image/png;base64,..."],
  "methodology": "STRIDE",
  "industry": "health"
}
```

- `requirements`：必填，最少 10 字符
- `architecture`：可选，为空时由 `architecture_reasoner` 自动推断
- `methodology`：可选，默认 `STRIDE`；可选值见 §2.5
- `images` / `pasted_images`：可选，支持多模态输入

**analyze 响应：**
```json
{
  "task_id": "t_abc123",
  "status": "pending",
  "steps": ["需求解析", "DFD 构建", "DFD 自校验", "威胁识别"],
  "deduped": false
}
```

当 `deduped=true` 时表示命中幂等窗口，`task_id` 指向已存在的任务。

**任务状态（`task_manager.py`）：**
- `pending` 排队中
- `running` 分析中
- `success` 完成
- `error` 失败
- `cancelled` 已取消

### 2.4 结果管理

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/threat/api/results` | 结果列表（支持分页/方法论筛选/关键词搜索，按 owner 隔离） |
| GET | `/threat/api/results/{id}` | 结果详情（含完整 Threat Dragon v2 model） |
| PATCH | `/threat/api/results/{id}` | 重命名结果（1~60 字符） |
| DELETE | `/threat/api/results/{id}` | 删除结果，并精准失效对应的 LLM 缓存 |
| GET | `/threat/api/results/{id}/export?format=md` | 导出结果（`md` / `json` / `csv` / `docx`） |
| PATCH | `/threat/api/results/{id}/threats/{tid}` | 更新某条威胁的处理状态 / 范围外标记 |

**威胁处置状态：**
- `Open` 待处理
- `In Progress` 处理中
- `Mitigated` 已缓解
- `Accepted` 已接受
- `NotApplicable` 不适用

范围外标记独立于状态，通过请求体 `outOfScope: true` 设置。

### 2.5 支持的威胁建模方法论

| 方法论 | 说明 |
|---|---|
| `STRIDE` | 微软经典六分类（Spoofing / Tampering / Repudiation / Info Disclosure / DoS / Elevation） |
| `STRIDE-AI` | 平台扩展：STRIDE 叠加 AI 元素专属威胁，含 DREAD 五维评分与 OWASP LLM Top10 映射 |
| `CIA` | 机密性 / 完整性 / 可用性 |
| `CIADIE` | CIA + Distributed / Immutable / Ephemeral |
| `LINDDUN` | 隐私威胁七分类 |
| `PLOT4ai` | 隐私威胁八分类 |
| `EOP` | Cornucopia suits（Authentication / Authorization / Cryptography / Data Validation / Session Management） |
| `MAESTRO` | OWASP 多智能体（Agentic AI）分层框架：七层模型 × 十类智能体威胁（目标劫持 / 工具滥用 / 权限扩散 / 记忆投毒 / 智能体间欺骗 / 自主失控 / 编排不安全 / 可观测性缺失 / 供应链投毒 / 数据泄露） |

### 2.6 威胁评审（确认 / 驳回）

AI 识别的威胁必然包含误报，需要人工确认或推翻。评审结论与处置状态（`status`）**正交**：
`review` 回答「这条威胁是否成立」，`status` 回答「打算怎么处理」。

`PATCH /api/results/{result_id}/threats/{threat_id}/review`

```json
{ "state": "Confirmed", "comment": "经复核，该接口确实缺少越权校验" }
```

- `state`：`Pending`（待评审，可用于撤销）/ `Confirmed`（已确认）/ `Rejected`（已驳回）
- 驳回时会同步把 `status` 置为 `NotApplicable`，避免误报继续计入待处理统计
- 权限：`admin` / `secops` 可评审任意结果；其他用户仅限自己建模的结果

`GET /api/results/{result_id}/review-summary` — 返回评审进度（`total` / `pending` /
`confirmed` / `rejected` / `reviewRate` / `reviewers`），用于回答「这份模型的评审做完了吗」。

### 2.7 AI 知识库

| 端点 | 说明 |
|---|---|
| `GET /api/knowledge/atlas` | MITRE ATLAS 技术目录（AI 领域对抗战术与技术），含按战术分组视图 |
| `GET /api/knowledge/prompt` | 预览指定方法论 + 行业模板生成的系统提示词（不发起 LLM 调用） |
| `GET /api/templates` | 示例场景模板库（6 个场景，覆盖 STRIDE / STRIDE-AI / MAESTRO / LINDDUN / EOP） |

单次建模结果的度量指标（`metrics`）中包含 `atlasCovered`（命中的 ATLAS 技术编号）
与 `atlasHits`（各技术命中次数），便于把威胁对齐到业界通用的攻击语言。

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
