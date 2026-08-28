"""健康产品线示例场景模板库。

内置多个可直接一键填充的示例场景（需求 + 架构设计文档），降低新用户
上手成本，同时与「跨境健康产品线（美欧市场）」的业务定位保持一致。

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
