"""LLM 配置运行时存储：管理员可在界面统一配置，全公司用户共享。

设计要点：
- 单实例 LLM 配置：所有用户共用一份（"管理员统一配置一次，其他人员都能用"）。
- 持久化到磁盘 `backend/threat/.llm_runtime.json`，后端进程重启后配置仍在。
- 启动时 load_from_disk() 覆盖 env 提供的默认配置。
- 写入即热生效：`LLMClient` 每次构造都从 `get_config()` 实时取值，
  管理员在 UI 改完配置后，正在进行的下一次分析立即用新配置，
  **不需要重启后端，也不需要用户刷新页面**。
- 启动时如果没有磁盘配置且 env 也没设 → 视为"未配置"。

此模块不应被 import 循环依赖（services 之间互引会启动失败），
因此保持独立、无其他 service 依赖。
"""
from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# 磁盘持久化文件路径：与本模块同目录
_STORE_DIR = Path(__file__).resolve().parent
_STORE_FILE = _STORE_DIR / ".llm_runtime.json"

# 进程内状态：base_url / api_key / model，None 表示"未配置"
_LOCK = threading.RLock()
_RUNTIME: dict[str, Any] = {
    "base_url": None,
    "api_key": None,
    "model": None,
    "updated_at": None,  # ISO 字符串
    "updated_by": None,  # 谁配置的（用户名）
}


def _mask_key(api_key: Optional[str]) -> Optional[str]:
    """给前端展示用的脱敏 Key：保留前 4 后 4，中间用 **** 代替。

    注意：这是**显示用途**，仅供非管理员确认"已配置"状态，
    绝不能用于实际调用 LLM 接口。
    """
    if not api_key:
        return None
    if len(api_key) <= 10:
        return "*" * len(api_key)
    return f"{api_key[:4]}{'*' * (len(api_key) - 8)}{api_key[-4:]}"


def _is_placeholder(api_key: Optional[str]) -> bool:
    """检测 .env 中的占位符 Key（如 sk-your-…）。"""
    if not api_key:
        return True
    low = api_key.lower()
    placeholders = (
        "sk-your-", "your-", "your_api_key",
        "placeholder", "change-me", "changeme",
    )
    return any(p in low for p in placeholders)


def load_from_disk() -> None:
    """从磁盘加载 runtime 配置（如果存在）。

    在后端进程启动时调用一次，进程内其它时刻无需关心。
    启动时从 .env 加载的默认配置（如果有效）会保留；磁盘配置优先级更高。
    """
    # 1) 先用 .env 的默认配置填充
    try:
        from ..config import settings

        if settings.llm_api_key and not _is_placeholder(settings.llm_api_key):
            _RUNTIME["api_key"] = settings.llm_api_key
        if settings.llm_base_url:
            _RUNTIME["base_url"] = settings.llm_base_url
        if settings.llm_model:
            _RUNTIME["model"] = settings.llm_model
    except Exception as exc:  # pragma: no cover
        logger.debug("加载 .env 默认 LLM 配置失败: %s", exc)

    # 2) 磁盘配置覆盖
    if not _STORE_FILE.is_file():
        return
    try:
        raw = json.loads(_STORE_FILE.read_text(encoding="utf-8"))
        with _LOCK:
            if raw.get("base_url"):
                _RUNTIME["base_url"] = raw["base_url"]
            if raw.get("api_key"):
                _RUNTIME["api_key"] = raw["api_key"]
            if raw.get("model"):
                _RUNTIME["model"] = raw["model"]
            _RUNTIME["updated_at"] = raw.get("updated_at")
            _RUNTIME["updated_by"] = raw.get("updated_by")
        logger.info(
            "已从磁盘加载 LLM runtime 配置（updated_by=%s, updated_at=%s）",
            _RUNTIME["updated_by"],
            _RUNTIME["updated_at"],
        )
    except Exception as exc:
        logger.warning("读取 LLM runtime 配置失败（忽略，使用 .env 默认值）: %s", exc)


def get_config() -> dict[str, Any]:
    """返回当前 LLM 配置（进程内实时值，调用方拿到的是快照）。

    返回字段：
      - base_url / model: 字符串或 None
      - api_key: 字符串或 None（**完整 key**，仅供后端构造 LLMClient 使用，
        严禁直接返回给前端非管理员）
      - configured: bool —— 是否真正可用的配置
      - source: "disk" | "env" | "none"
    """
    with _LOCK:
        api_key = _RUNTIME.get("api_key")
        base_url = _RUNTIME.get("base_url")
        model = _RUNTIME.get("model")
        # 是否在 disk 上有显式记录（"管理员在 UI 配置过"）
        has_disk = bool(_RUNTIME.get("updated_at"))
        configured = bool(
            api_key and not _is_placeholder(api_key) and base_url and model
        )
        source = "disk" if has_disk else ("env" if configured else "none")
        return {
            "base_url": base_url or "",
            "model": model or "",
            "configured": configured,
            "source": source,
            # 仅给后端内部使用：完整 key
            "api_key": api_key,
        }


def get_public_config(for_admin: bool = False) -> dict[str, Any]:
    """返回给前端的"公开视图"。

    - 任何登录用户：返回 base_url / model / configured / api_key_masked。
    - 管理员（for_admin=True）：额外返回 is_admin 标记，便于前端决定是否显示编辑入口。
      **完整 api_key 永远不返回给前端**（即使管理员），避免浏览器 localStorage / 网络日志泄露。
    """
    cfg = get_config()
    return {
        "base_url": cfg["base_url"],
        "model": cfg["model"],
        "configured": cfg["configured"],
        "source": cfg["source"],
        "api_key_masked": _mask_key(cfg["api_key"]) if cfg["api_key"] else None,
        "api_key_configured": bool(cfg["api_key"]),
        "is_admin": for_admin,
    }


def set_config(
    *,
    base_url: Optional[str],
    api_key: Optional[str],
    model: Optional[str],
    updated_by: Optional[str] = None,
) -> dict[str, Any]:
    """保存 LLM 配置到磁盘 + 内存。**仅管理员可调用**（路由层做权限校验）。

    行为：
    - 三个字段都被规范化（strip）。
    - 如果新 api_key 为空字符串（前端表单留空）→ **保留旧 key** 不覆盖，
      方便管理员只改 model 时不丢失 key。
    - 立即写入磁盘 + 更新内存，下一次 LLMClient 构造即生效。
    """
    with _LOCK:
        new_base = (base_url or "").strip() or _RUNTIME.get("base_url")
        new_model = (model or "").strip() or _RUNTIME.get("model")
        # api_key 为空时保留旧值（不覆盖为 None）
        if api_key is not None and api_key.strip():
            new_key = api_key.strip()
        else:
            new_key = _RUNTIME.get("api_key")

        # 至少要有 key + base_url + model 之一被显式提供（更新场景允许只改其中一项）
        if not (new_base and new_model):
            raise ValueError("base_url 和 model 是必填项")

        if not new_key or _is_placeholder(new_key):
            raise ValueError("缺少有效的 API Key（不能是 .env 占位符）")

        _RUNTIME["base_url"] = new_base
        _RUNTIME["api_key"] = new_key
        _RUNTIME["model"] = new_model
        _RUNTIME["updated_at"] = _now_iso()
        _RUNTIME["updated_by"] = updated_by or "admin"

        # 持久化（不写 api_key 到日志；磁盘文件权限收紧到 0o600）
        _persist_to_disk()
    logger.info(
        "LLM 配置已更新（updated_by=%s, base_url=%s, model=%s）",
        _RUNTIME["updated_by"],
        _RUNTIME["base_url"],
        _RUNTIME["model"],
    )
    return get_public_config(for_admin=True)


def clear_config() -> None:
    """清空 runtime LLM 配置（仅管理员）。

    注意：清空**不会**恢复 .env 默认值；如果 .env 里也有配置，重启后端后
    会自动 load 回来。运行时清空是"立即停用"。
    """
    with _LOCK:
        _RUNTIME["base_url"] = None
        _RUNTIME["api_key"] = None
        _RUNTIME["model"] = None
        _RUNTIME["updated_at"] = None
        _RUNTIME["updated_by"] = None
        try:
            if _STORE_FILE.is_file():
                _STORE_FILE.unlink()
        except Exception as exc:
            logger.warning("删除 LLM runtime 配置文件失败: %s", exc)


def _persist_to_disk() -> None:
    """把当前 runtime 写入磁盘 JSON（权限 0o600，仅本用户可读）。"""
    payload = {
        "base_url": _RUNTIME.get("base_url"),
        "api_key": _RUNTIME.get("api_key"),
        "model": _RUNTIME.get("model"),
        "updated_at": _RUNTIME.get("updated_at"),
        "updated_by": _RUNTIME.get("updated_by"),
    }
    try:
        _STORE_DIR.mkdir(parents=True, exist_ok=True)
        _STORE_FILE.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        try:
            os.chmod(_STORE_FILE, 0o600)
        except Exception:
            # Windows 不支持 chmod, 忽略
            pass
    except Exception as exc:
        logger.exception("持久化 LLM runtime 配置失败: %s", exc)
        raise


def _now_iso() -> str:
    from datetime import datetime

    return datetime.now().isoformat(timespec="seconds")
