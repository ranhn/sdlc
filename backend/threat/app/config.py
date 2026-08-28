"""应用配置模块。

支持通过环境变量或 .env 文件配置 OpenAI 兼容的 LLM 服务。
默认支持任意 OpenAI 兼容 API（如 OpenAI、DeepSeek、通义千问、Moonshot 等）。
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from pydantic import BaseModel

# 加载项目根目录下的 .env 文件
load_dotenv(Path(__file__).resolve().parents[2] / ".env")


class Settings(BaseModel):
    """全局配置，从环境变量读取。"""

    # LLM 配置
    llm_api_key: Optional[str] = os.getenv("LLM_API_KEY", "")
    llm_base_url: str = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1")
    llm_model: str = os.getenv("LLM_MODEL", "gpt-4o")
    llm_temperature: float = float(os.getenv("LLM_TEMPERATURE", "0.2"))
    # LLM 网络请求重试次数（openai SDK 的 max_retries）
    llm_max_retries: int = int(os.getenv("LLM_MAX_RETRIES", "2"))
    # 生成稳定性：固定随机种子（同一模型+seed 下结果可复现）。
    # 设为 0 表示不传 seed（部分国产模型不支持 seed 时置 0 关闭）。
    llm_seed: int = int(os.getenv("LLM_SEED", "42"))
    # 响应缓存开关：同输入（需求文档 hash）在缓存期内直接命中上次结果。
    # 缓存默认开启以提升同输入重复建模的速度；
    # 删除某条建模结果时，会自动失效该结果对应输入的缓存，
    # 保证删除后重新建模不会命中旧结果，而是真实调用 LLM 重新分析。
    llm_cache_enabled: bool = os.getenv("LLM_CACHE_ENABLED", "true").lower() in ("1", "true", "yes")
    llm_cache_ttl_seconds: int = int(os.getenv("LLM_CACHE_TTL_SECONDS", "604800"))  # 默认 7 天

    # DFD AI 自校验开关：构建模型后让 LLM 对生成的 components/flows 做一次
    # 合理性自查并确定性纠偏（见 dfd_reviewer.py）。默认开启；失败会静默降级，
    # 不影响主流程。设为 0 可关闭以节省一次 LLM 调用 / 保证结果完全确定。
    dfd_review_enabled: bool = os.getenv("DFD_REVIEW_ENABLED", "true").lower() in (
        "1",
        "true",
        "yes",
    )
    # DFD 两阶段提取开关：第一轮提取后，若结构自检发现可判定缺陷（缺 process 中转 /
    # 无 process / actor 作中间节点 / 存储生命周期错配等），再让 LLM 基于原文补全。
    # 默认开启；失败静默降级为第一轮结果。设为 0 可关闭以省一次 LLM 调用。
    dfd_refine_enabled: bool = os.getenv("DFD_REFINE_ENABLED", "true").lower() in (
        "1",
        "true",
        "yes",
    )

    # 威胁覆盖补齐模式：
    # - auto（默认）：信任 LLM 识别的威胁，仅当属性规则判定该风险真实存在（严重度 >= High）
    #   时才用骨架补齐遗漏类型。避免"每个元素所有允许类型都被塞满"导致的 100+ 条膨胀。
    # - full：旧行为，强制每个元素覆盖方法论允许的全部威胁类型（可能产生大量低价值骨架威胁）。
    # 两种模式下都不会丢弃 LLM 真正识别出的威胁。
    threat_coverage_mode: str = os.getenv("THREAT_COVERAGE_MODE", "auto").strip().lower()

    # 应用配置
    # 默认 8002：与前端 vite 代理（http://127.0.0.1:8002）和 _verify.ps1
    # 检查脚本保持一致；以前用 8000/8001 时，启动后端口不匹配会导致前端
    # /api/health 全部代理失败，状态栏显示「后端离线」。
    app_host: str = os.getenv("APP_HOST", "127.0.0.1")
    app_port: int = int(os.getenv("APP_PORT", "8002"))
    # 允许的前端来源（CORS）
    # 可通环境变量 CORS_ORIGINS 指定（逗号分隔）；未指定时使用本地开发默认值
    cors_origins: list[str] = [
        o.strip()
        for o in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8080,http://127.0.0.1:8080,http://127.0.0.1:8001",
        ).split(",")
        if o.strip()
    ]

    # 鉴权与防滥用（P1）
    # API Token：为空表示不校验（本地开发默认）；非空时前端需带 X-API-Key
    api_token: str = os.getenv("API_TOKEN", "")
    # 同一 IP 每分钟允许的最大分析请求数（限流）
    rate_limit_per_minute: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "5"))
    # 单次请求允许的最大输入字符数（防烧钱 / 防超大文档导致超时）
    max_input_chars: int = int(os.getenv("MAX_INPUT_CHARS", "40000"))

    @property
    def llm_configured(self) -> bool:
        """LLM 是否真正配置完成（排除占位符 Key）。"""
        k = (self.llm_api_key or "").strip()
        if not k:
            return False
        low = k.lower()
        placeholders = (
            "sk-your-",
            "your-",
            "your_api_key",
            "placeholder",
            "change-me",
            "changeme",
        )
        return not any(p in low for p in placeholders)


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
