"""示例场景模板库。

内置多个可直接一键填充的示例场景（需求 + 架构设计文档），降低新用户
上手成本。模板覆盖平台支持的主要方法论与常见系统形态：

- STRIDE          通用 Web / 微服务 / IoT
- STRIDE-AI       大模型应用（RAG、Agent、多模态）
- MAESTRO         多智能体（Agentic AI）协作系统
- LINDDUN         涉及个人隐私数据的系统
- EOP             面向 OWASP Cornucopia 的 Web 业务系统

模板内容仅是便于起步的"样例文档"，用户可在此基础上编辑后提交分析。
"""

from __future__ import annotations

from typing import Any

SCENARIO_TEMPLATES: list[dict[str, Any]] = [
    {
        "id": "wearable-health-iot",
        "name": "智能可穿戴健康数据平台",
        "description": "健康手环 / 智能穿戴设备：BLE 同步 + 健康云 + 配套 H5 看板。",
        "methodology": "STRIDE",
        "tags": ["IoT", "BLE", "可穿戴", "健康云"],
        "requirements": (
            "系统需求：\n"
            "1. 面向欧美市场的智能健康手环 + 配套移动端 H5 看板，手环 BLE 与手机 App 配对后定时上报体征（心率/步数/睡眠/血氧）。\n"
            "2. App 将体征数据汇聚后上传到健康云（云网关 → 健康数据中心），用户可在 H5 看板查看历史曲线与异常提醒。\n"
            "3. 支持固件 OTA 升级（手环端通过 BLE 经手机中转下载，校验签名后刷写）。\n"
            "4. 健康数据需符合 GDPR / HIPAA（如面向美国市场）：传输加密（TLS 1.2+）、存储加密、用户可一键导出与删除。\n"
            "5. 设备与手机配对需要双向鉴权（设备证书 + 手机端 Token），防止仿冒设备上传脏数据。\n"
            "6. 提供第三方健康 API（如接入 Apple Health / Google Fit）能力，需明确用户授权与数据共享范围。\n"
            "7. 异常体征（心率过速等）触发实时告警链路（含短信/邮件通知），需防告警轰炸与未授权触发。\n"
        ),
        "architecture": (
            "产品架构设计：\n"
            "1. 可穿戴设备（手环/手表）：传感器 + BLE 模块，运行固件；通过 BLE 与手机端 App 通信。\n"
            "2. 手机端 App / H5：接收 BLE 数据，本地缓存（HTTPS 上传至云网关）；同时承载 OTA 中转与设备配对。\n"
            "3. 云网关（API Gateway）：鉴权、限流、HTTPS 终止，路由到健康数据中心。\n"
            "4. 健康数据中心（Health Ingest Service）：体征数据写入时序数据库（InfluxDB / TimescaleDB）+ 对象存储（原始 JSON 备份）。\n"
            "5. 告警服务（Alert Service）：基于规则 + AI 模型识别异常体征，触发短信/邮件通知（通过 Twilio / SES）。\n"
            "6. H5 静态资源（CDN / OSS）：用户看板前端静态文件分发；HTTPS + 防篡改签名。\n"
            "7. OTA 服务（OTA Service）：固件包签名（RSA/ECDSA）分发，App 中转下载，手环端验签后刷写。\n"
            "8. 第三方接入：Apple HealthKit / Google Fit 数据导入/导出（OAuth2，用户授权范围受限）。\n"
            "9. 数据流：手环 ←BLE→ 手机 App ←HTTPS→ 云网关 → 健康数据中心 → 时序 DB + 对象存储；App → OTA → 手环；告警服务 → 短信/邮件。\n"
        ),
    },
    {
        "id": "ecommerce-order-payment",
        "name": "电商订单与支付系统",
        "description": "典型电商：下单 → 库存 → 支付 → 履约，含促销与退款。",
        "methodology": "STRIDE",
        "tags": ["电商", "支付", "订单", "高并发"],
        "requirements": (
            "系统需求：\n"
            "1. 用户在 H5 / App 浏览商品、加入购物车、提交订单并在线支付（支持信用卡与第三方钱包）。\n"
            "2. 下单需扣减库存并锁定优惠券，支付成功后进入履约流程（发货、物流跟踪）。\n"
            "3. 支持退款与售后：用户发起退款申请，运营审核后原路退回。\n"
            "4. 促销系统支持秒杀与限时折扣，需防刷单与超卖。\n"
            "5. 订单金额计算包含商品价、税费、运费、优惠券，计算过程不可被客户端篡改。\n"
            "6. 支付回调需校验签名，防伪造支付成功通知。\n"
            "7. 用户订单与地址属于个人敏感信息，需满足个人信息保护合规要求。\n"
        ),
        "architecture": (
            "系统架构设计：\n"
            "1. 客户端：H5 / 移动 App，通过 HTTPS 调用 API 网关。\n"
            "2. API 网关：统一鉴权（JWT）、限流、防重放，路由到各微服务。\n"
            "3. 订单服务（Order Service）：下单、订单状态机、幂等控制；写入订单库（MySQL）。\n"
            "4. 库存服务（Inventory Service）：库存扣减与回滚，使用 Redis 预扣 + DB 落库。\n"
            "5. 促销服务（Promotion Service）：优惠券校验与核销，Redis 缓存热点券。\n"
            "6. 支付服务（Payment Service）：对接第三方支付网关（Stripe / 微信支付），处理支付与回调验签。\n"
            "7. 履约服务（Fulfillment Service）：发货、物流对接、状态同步。\n"
            "8. 售后/退款服务（Refund Service）：退款申请与审核，调用支付服务原路退回。\n"
            "9. 消息队列（Kafka）：订单创建、支付成功等事件异步分发。\n"
            "10. 数据流：客户端 → 网关 → 订单服务 → 库存/促销服务 → 支付服务 → 第三方支付 → 回调；订单事件 → Kafka → 履约/风控。\n"
        ),
    },
    {
        "id": "llm-rag-knowledge-assistant",
        "name": "企业知识库智能问答（RAG）",
        "description": "基于大模型 + 向量检索的企业内部知识问答助手。",
        "methodology": "STRIDE-AI",
        "tags": ["LLM", "RAG", "知识库", "提示注入"],
        "requirements": (
            "系统需求：\n"
            "1. 员工在内部门户提问，系统基于企业内部文档（制度、技术手册）检索并生成回答。\n"
            "2. 文档来源包括 Confluence、共享盘 PDF/Word，由管理员上传并解析入库。\n"
            "3. 回答必须标注引用来源，不得编造不存在的规定。\n"
            "4. 不同部门文档有访问权限差异：员工只能检索到本部门及公开范围的文档。\n"
            "5. 系统需防止用户通过提示注入诱导模型泄露系统提示词或其他部门的机密文档。\n"
            "6. 支持多轮对话，需要维护会话上下文。\n"
            "7. 所有问答需留痕以便审计，管理员可导出使用记录。\n"
        ),
        "architecture": (
            "系统架构设计：\n"
            "1. 员工端（Web 门户）：提问界面，Bearer Token 鉴权。\n"
            "2. 应用后端（BFF）：会话管理、权限校验、调用编排层。\n"
            "3. 编排层（Orchestrator / Agent）：组装提示词、调用检索与模型、拼接引用；具备工具调用能力。\n"
            "4. 检索服务（Retriever）：按用户权限过滤后查询向量库，返回 Top-K 文档片段。\n"
            "5. 向量库（VectorStore）：存储文档 embedding，随文档更新增量重建。\n"
            "6. 大模型服务（LLM Service）：通过公司统一网关调用外部大模型 API（可能传输内部文档内容）。\n"
            "7. 文档处理流水线：上传 → 解析（PDF/DOCX）→ 分块 → 向量化 → 入库；由管理员触发。\n"
            "8. 审计与日志：记录提问、检索结果、模型回答，写入日志库。\n"
            "9. 数据流：员工 → 门户 → BFF → 编排层 → 检索服务 → 向量库；编排层 → 大模型服务 → 返回；文档流水线 → 向量库。\n"
        ),
    },
    {
        "id": "multi-agent-ops-copilot",
        "name": "多智能体运维 Copilot",
        "description": "多个 Agent 协作完成告警分析、根因定位与自动处置的运维系统。",
        "methodology": "MAESTRO",
        "tags": ["多智能体", "Agentic AI", "自动化运维", "权限扩散"],
        "requirements": (
            "系统需求：\n"
            "1. 监控系统产生告警后，由编排器 Agent 分派给诊断 Agent 与日志分析 Agent 协作定位根因。\n"
            "2. 诊断 Agent 可调用工具查询监控指标、链路追踪、Pod 状态。\n"
            "3. 根因确认后，修复 Agent 可执行受限的自动处置动作（重启 Pod、扩容、回滚版本）。\n"
            "4. 各 Agent 拥有长期记忆，记录历史故障与处置经验，供后续相似告警复用。\n"
            "5. 高危动作（如回滚生产版本）需要人工在 IM 中确认后才执行。\n"
            "6. 所有 Agent 的决策链路与工具调用需完整留痕，支持事后复盘。\n"
            "7. 系统需要防止告警内容或日志中的恶意文本诱导 Agent 执行非预期的高危操作。\n"
            "8. 各 Agent 使用同一套集群凭据访问 K8s API 与监控系统。\n"
        ),
        "architecture": (
            "系统架构设计：\n"
            "1. 告警接入（Alert Ingest）：接收 Prometheus / Zabbix 告警，标准化后投递到编排器。\n"
            "2. 编排器 Agent（Orchestrator）：任务规划、子 Agent 分派、结果汇总；持有集群凭据与任务上下文。\n"
            "3. 诊断 Agent（Diagnosis Agent）：调用监控查询工具分析指标异常。\n"
            "4. 日志分析 Agent（Log Agent）：检索日志系统（ES/Loki）定位错误堆栈。\n"
            "5. 修复 Agent（Remediation Agent）：调用 K8s 工具执行重启/扩容/回滚；高危动作需 IM 人工确认。\n"
            "6. 工具层（Tool Layer）：监控查询、日志检索、K8s API、IM 通知等工具封装。\n"
            "7. 记忆库（Memory / VectorStore）：存储历史故障案例与处置经验，支持语义检索。\n"
            "8. 大模型服务（LLM Service）：为各 Agent 提供推理能力。\n"
            "9. 审批服务（Approval Service）：高危操作人工确认工作流。\n"
            "10. 审计服务（Audit）：记录 Agent 决策链路、工具调用入参出参与执行结果。\n"
            "11. 数据流：告警 → 接入 → 编排器 → 诊断/日志 Agent → 工具层（监控/日志）→ 编排器汇总 → 修复 Agent → 工具层（K8s）→ 集群；全程 → 审计与记忆库 ↔ 各 Agent。\n"
        ),
    },
    {
        "id": "user-profile-analytics",
        "name": "用户画像与行为分析平台",
        "description": "采集用户行为埋点，构建画像标签并对外提供定向能力。",
        "methodology": "LINDDUN",
        "tags": ["隐私", "用户画像", "埋点", "GDPR"],
        "requirements": (
            "系统需求：\n"
            "1. 采集 App/Web 端用户行为埋点（浏览、点击、搜索、位置），用于构建用户画像标签。\n"
            "2. 画像标签包括兴趣偏好、消费能力、活跃度，供推荐与营销系统使用。\n"
            "3. 支持第三方广告平台投放，需按平台要求提供人群包（可能包含设备标识）。\n"
            "4. 用户可查询、导出、删除自己的个人数据，并关闭个性化推荐。\n"
            "5. 需要满足 GDPR / 个人信息保护法对告知同意、最小必要、可撤回的要求。\n"
            "6. 内部运营可查看聚合报表，但不允许直接查看单个用户的完整轨迹。\n"
            "7. 数据需区分不同国家/地区用户，跨境传输需合法依据。\n"
        ),
        "architecture": (
            "系统架构设计：\n"
            "1. 客户端 SDK：App / Web 埋点上报，采集设备标识与行为事件。\n"
            "2. 采集网关（Collection Gateway）：接收埋点事件，写入消息队列（Kafka）。\n"
            "3. 实时计算（Flink）：实时清洗与聚合，产出实时标签写入在线存储（Redis / HBase）。\n"
            "4. 离线计算（Spark）：T+1 全量画像计算，写入画像宽表（Hive / ClickHouse）。\n"
            "5. 标签服务（Profile Service）：对外提供标签查询 API，供推荐与营销调用。\n"
            "6. 人群包服务（Audience Service）：生成人群包并按协议推送给第三方广告平台。\n"
            "7. 用户权利服务（DSAR Service）：处理查询/导出/删除请求，联动各存储执行删除。\n"
            "8. 数据流：SDK → 采集网关 → Kafka → Flink → 在线存储；Kafka → Spark → 画像宽表 → 标签服务 → 推荐/营销；标签服务 → 人群包服务 → 第三方平台；用户 → DSAR 服务 → 各存储。\n"
        ),
    },
    {
        "id": "web-saas-admin-portal",
        "name": "SaaS 管理后台与开放 API",
        "description": "多租户 SaaS 管理后台，含 RBAC 权限与对外开放 API。",
        "methodology": "EOP",
        "tags": ["SaaS", "多租户", "RBAC", "开放API"],
        "requirements": (
            "系统需求：\n"
            "1. 多租户 SaaS 平台，租户管理员可在后台管理本租户用户、角色与权限。\n"
            "2. 支持 RBAC：角色绑定权限点，用户绑定角色；权限校验需在服务端强制执行。\n"
            "3. 对外开放 API：第三方开发者使用 API Key + Secret 签名调用，按租户限流计量。\n"
            "4. 后台提供文件上传（头像、Excel 批量导入）、数据导出（CSV/Excel）能力。\n"
            "5. 登录支持密码 + 短信双因素，会话需支持主动注销与超时失效。\n"
            "6. 运营人员可模拟登录（impersonate）任一租户账号排查问题，操作需留痕。\n"
            "7. 所有写操作需记录审计日志，租户数据严格隔离，禁止跨租户越权访问。\n"
        ),
        "architecture": (
            "系统架构设计：\n"
            "1. 管理后台前端（SPA）：通过 HTTPS 调用后台 API，Token 存于内存 + 刷新令牌。\n"
            "2. API 网关：路由、限流、API Key 校验，区分管理端与开放 API 两类流量。\n"
            "3. 认证服务（Auth Service）：密码登录、短信验证码、双因素校验、令牌签发与注销。\n"
            "4. 权限服务（RBAC Service）：角色/权限点管理，提供鉴权决策接口。\n"
            "5. 租户服务（Tenant Service）：租户与用户管理，模拟登录（impersonate）入口。\n"
            "6. 业务服务（Business Service）：租户的业务数据 CRUD，所有查询强制带上租户上下文。\n"
            "7. 文件服务（File Service）：上传下载，对象存储（OSS/S3），生成签名 URL。\n"
            "8. 开放 API 服务（Open API）：签名校验、计量、限流，调用业务服务。\n"
            "9. 审计服务（Audit）：记录写操作与模拟登录行为，写入审计库。\n"
            "10. 数据流：前端 → 网关 → 认证/权限/租户/业务服务 → 业务库；第三方 → 开放 API → 业务服务；业务服务 → 文件服务 → 对象存储；各服务 → 审计服务。\n"
        ),
    },
]


def list_templates() -> list[dict[str, Any]]:
    """返回模板库（去掉冗余字段，仅返回元数据 + 完整文档）。"""
    return [dict(t) for t in SCENARIO_TEMPLATES]


def get_template(template_id: str) -> dict[str, Any] | None:
    """按 id 查询模板；不存在返回 None。"""
    for t in SCENARIO_TEMPLATES:
        if t["id"] == template_id:
            return dict(t)
    return None
