"""轻量架构推理：仅在用户没给 architecture 时，从 requirements 文本中按
规则化模板推断一份"典型架构"草稿（前端 → API 网关 → 业务服务 → 数据库/缓存）。

设计原则：
- 零 LLM 调用（保证推理稳定且免费），仅按关键词模式匹配
- 推断结果以"建议"形式呈现，不替代用户原始输入（如果用户给了 architecture，永远用它）
- 输出格式与用户原始 architecture 一致：纯文本列表，便于 LLM 在第二轮 prompt 中直接消费
"""
from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


# 关键词 → 架构组件（顺序敏感：前匹配先输出，便于输出稳定）
_KEYWORD_PATTERNS: list[tuple[str, str]] = [
    # 1. 前端
    (r"网页|web\s*应用|网站|h5|浏览器", "前端：浏览器/H5 页面（用户入口）"),
    (r"小程序|微信小程序|支付宝小程序|抖音小程序", "前端：移动端小程序（用户入口）"),
    (r"移动\s*app|移动端|ios|android|原生\s*app", "前端：移动端 App（iOS / Android）"),
    (r"桌面\s*应用|桌面端|客户端\s*应用|pc\s*客户端", "前端：桌面客户端"),
    (r"api\s*网关|网关|反向代理|nginx|ingress", "网关层：API 网关 / 反向代理（Nginx），负责限流、路由与统一鉴权"),
    # 2. 业务后端
    (r"用户\s*服务|用户\s*管理|登录|注册|认证", "业务服务：用户服务（注册 / 登录 / 鉴权）"),
    (r"订单|下单|交易|购物车", "业务服务：订单服务（下单 / 状态机）"),
    (r"支付|收款|微信\s*支付|支付宝", "业务服务：支付服务（对接第三方支付，含回调验签）"),
    (r"商品|库存|sku|类目", "业务服务：商品 / 库存服务"),
    (r"消息|通知|短信|邮件\s*发送|im\s*推送", "业务服务：消息中心（短信 / 邮件 / 推送）"),
    (r"搜索|检索|全文搜索|elastic|opensearch", "业务服务：搜索服务（Elasticsearch / OpenSearch）"),
    (r"推荐|画像|排序算法|feeds?", "业务服务：推荐 / 排序服务"),
    (r"大模型|llm|chatgpt|deepseek|gpt|通义|文心|智能问答|ai\s*助手", "AI 服务：大模型推理服务（含提示词与上下文管理）"),
    (r"rag|知识库|向量\s*检索|embedding", "AI 服务：RAG 知识库服务（向量检索 + 大模型）"),
    (r"agent|智能体|工具\s*调用|function\s*call", "AI 服务：Agent 工具调用框架（含权限沙箱）"),
    (r"iot|物联网|设备\s*接入|传感器|网关\s*接入", "IoT 服务：设备接入网关（MQTT / CoAP）"),
    (r"视频直播|流媒体|音视频|实时音视频", "媒体服务：音视频流媒体服务"),
    # 3. 数据 / 存储
    (r"mysql|postgres|mariadb|关系\s*数据库|主\s*从\s*数据库", "存储：MySQL / PostgreSQL（主从复制，业务核心数据）"),
    (r"redis|缓存|会话\s*缓存|hot\s*cache", "存储：Redis（热点缓存 / 会话 / 分布式锁）"),
    (r"mongo|mongodb|文档\s*数据库", "存储：MongoDB（文档型数据）"),
    (r"es|elasticsearch|全文索引", "存储：Elasticsearch（搜索索引）"),
    (r"kafka|消息队列|rabbitmq|rocketmq", "存储：消息队列（Kafka / RocketMQ，事件总线）"),
    (r"minio|对象存储|oss|cos|s3|文件\s*存储", "存储：对象存储（OSS / MinIO，文件/图片）"),
    (r"数据\s*湖|数据仓库|dwh|clickhouse|bigquery|hive", "存储：数据仓库 / 数据湖（离线分析）"),
    (r"clickhouse|olap|实时\s*分析", "存储：ClickHouse（OLAP 实时分析）"),
    (r"向量\s*库|milvus|qdrant|chroma|pgvector|faiss", "存储：向量数据库（Milvus / pgvector，RAG 检索）"),
    # 4. 部署 / 基础设施
    (r"k8s|kubernetes|容器编排", "部署：Kubernetes 容器编排（多副本 + 自动伸缩）"),
    (r"docker|容器化", "部署：Docker 容器化部署"),
    (r"公有云|阿里云|aws|azure|腾讯云", "部署：部署于公有云（多可用区）"),
    (r"私有云|本地\s*部署|idc|机房", "部署：私有云 / IDC 自有机房"),
    (r"cdn|内容分发|边缘\s*加速", "基础设施：CDN 边缘加速（静态资源 / API 缓存）"),
    (r"waf|web\s*应用\s*防火墙|ddos", "基础设施：WAF / DDoS 防护"),
    # 5. 信任边界
    (r"内网|专有网络|vpc", "信任边界：内网（VPC）"),
    (r"公网|外网|互联网", "信任边界：公网（互联网）"),
]


# 几个常见的"标准架构模板"：如果用户没给 architecture 且 requirements 含某些关键词
# 命中模板，就直接套模板（更稳更快）
_STANDARD_TEMPLATES: list[dict[str, Any]] = [
    {
        "name": "标准 Web + MySQL + Redis",
        "match": [r"用户", r"登录", r"mysql"],
        "arch_text": (
            "- 前端：浏览器 Web 应用（Nginx 静态托管）\n"
            "- 网关：Nginx 反向代理 + API 网关（限流、路由、统一鉴权）\n"
            "- 后端：业务服务（用户/订单/支付等）\n"
            "- 缓存：Redis（会话 / 热点数据）\n"
            "- 存储：MySQL（主从，业务核心数据）\n"
            "- 部署：Docker + K8s，多副本部署"
        ),
    },
    {
        "name": "电商 + 第三方支付",
        "match": [r"商品", r"订单", r"支付"],
        "arch_text": (
            "- 前端：Web/H5 + 小程序\n"
            "- 网关：API 网关（限流、防刷、签名校验）\n"
            "- 业务：商品服务 / 订单服务 / 支付服务\n"
            "- 存储：MySQL（业务数据）+ Redis（库存 / 热点商品缓存）\n"
            "- 第三方：微信支付 / 支付宝（公网回调，含验签）\n"
            "- 消息：Kafka（订单事件流）"
        ),
    },
    {
        "name": "AI / LLM 应用",
        "match": [r"大模型|llm|chatgpt|deepseek|gpt|通义|文心|智能问答|ai\s*助手"],
        "arch_text": (
            "- 前端：对话 UI（Web / 移动端）\n"
            "- 网关：API 网关（限流、token 配额、prompt 注入检测）\n"
            "- AI 服务：大模型推理服务（OpenAI 兼容协议）\n"
            "- 知识库：向量数据库（pgvector / Milvus，RAG 检索）\n"
            "- 工具：Agent 工具调用（白名单 + 权限沙箱）\n"
            "- 审计：推理日志 + 输出护栏"
        ),
    },
    {
        "name": "IoT 设备接入",
        "match": [r"iot|物联网|设备\s*接入|传感器"],
        "arch_text": (
            "- 端：IoT 设备（传感器 / 网关）通过 MQTT / CoAP 接入\n"
            "- 接入层：设备接入网关（认证、协议解析）\n"
            "- 业务层：设备管理 / 数据采集 / 告警服务\n"
            "- 存储：时序数据库（InfluxDB / TDengine） + 业务 MySQL\n"
            "- 上行：消息队列（Kafka，事件分发）"
        ),
    },
]


def infer_architecture(requirements: str) -> dict[str, Any]:
    """从 requirements 文本推断架构（无 LLM 调用，纯规则）。

    Returns:
        {
            "arch_text": str,            # 推断出的架构文本（多行列表）
            "matched_components": [...],  # 命中的组件关键词
            "matched_template": str | None,  # 命中的标准模板名
            "confidence": float,         # 0~1，越高表示越"有把握"
        }
    """
    text = (requirements or "").strip()
    if not text:
        return {
            "arch_text": "",
            "matched_components": [],
            "matched_template": None,
            "confidence": 0.0,
        }

    # 1. 标准模板匹配
    matched_template = None
    template_arch = None
    best_template_hits = 0
    for tmpl in _STANDARD_TEMPLATES:
        hits = sum(1 for p in tmpl["match"] if re.search(p, text, re.IGNORECASE))
        if hits >= len(tmpl["match"]) and hits > best_template_hits:
            matched_template = tmpl["name"]
            template_arch = tmpl["arch_text"]
            best_template_hits = hits

    # 2. 关键词组件匹配
    matched: list[str] = []
    seen_keys: set[str] = set()
    for pat, label in _KEYWORD_PATTERNS:
        if label in seen_keys:
            continue
        if re.search(pat, text, re.IGNORECASE):
            matched.append(label)
            seen_keys.add(label)

    # 3. 拼装
    if template_arch and matched_template:
        # 模板 + 额外匹配（去重）
        extras = [m for m in matched if m not in template_arch]
        arch_text = template_arch
        if extras:
            arch_text = template_arch + "\n# 额外识别：" + "；".join(extras)
    else:
        if matched:
            arch_text = "\n".join(f"- {m}" for m in matched)
        else:
            arch_text = ""

    # 4. 置信度：模板命中 = 0.9；关键词数 ≥ 5 = 0.7；≥ 3 = 0.5；< 3 = 0.3
    if matched_template:
        confidence = 0.9
    elif len(matched) >= 5:
        confidence = 0.7
    elif len(matched) >= 3:
        confidence = 0.5
    elif matched:
        confidence = 0.3
    else:
        confidence = 0.0

    return {
        "arch_text": arch_text,
        "matched_components": matched,
        "matched_template": matched_template,
        "confidence": confidence,
    }
