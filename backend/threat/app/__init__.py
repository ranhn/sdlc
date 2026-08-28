"""AI Threat Dragon - 自研 AI 威胁建模平台
从需求文档和产品架构文档自动生成数据流图（DFD）并识别 STRIDE 威胁。
数据格式完全兼容 OWASP Threat Dragon v2 模型。
"""

from .config import settings
from .services import (
    ThreatModelBuilder,
    DocumentAnalyzer,
    ThreatAnalyzer,
)
from .api import app

__all__ = [
    "settings",
    "ThreatModelBuilder",
    "DocumentAnalyzer",
    "ThreatAnalyzer",
    "app",
]
