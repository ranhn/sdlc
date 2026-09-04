"""威胁建模结果的持久化存储。

每次 AI 威胁建模成功后，会把完整结果（model/summary/stats/元数据）序列化
为 JSON 文件存放在 ``backend/data/results/`` 目录下，支持历史列表查询、
详情查看、删除与导出。

存储结构（单个结果文件）::

    {
        "id": "20260819-153000-abc123",
        "title": "用户给需求的短标题（自动生成）",
        "methodology": "STRIDE",
        "created_at": 1770...,            # epoch 秒
        "model": {...},                   # 完整 Threat Dragon 模型
        "summary": "...",
        "stats": {...}
    }
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from app.utils import network_clock as nc
logger = logging.getLogger(__name__)

# 结果目录：backend/data/results/
DATA_DIR = Path(__file__).resolve().parents[2] / "data"
RESULTS_DIR = DATA_DIR / "results"

# 历史结果最大保留条数（超出后删除最旧的）
MAX_RESULTS = 200

# result_id 白名单：仅允许「日期-时间-短uuid」格式（如 20260819-153000-abc123），
# 用于防御路径穿越（../ 越权读取/删除磁盘文件）。
_RESULT_ID_RE = re.compile(r"^[0-9A-Za-z-]{16,40}$")


class ResultStore:
    """基于本地 JSON 文件的建模结果存储（线程安全）。"""

    def __init__(self, results_dir: Path | None = None) -> None:
        self._dir = Path(results_dir) if results_dir else RESULTS_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # 内部工具
    # ------------------------------------------------------------------
    def _path(self, result_id: str) -> Path:
        """根据 result_id 生成结果文件路径。

        result_id 须符合白名单格式，否则直接抛 ``ValueError``，
        避免把攻击者构造的 ``../../etc/passwd`` 之类输入拼进路径（路径穿越）。
        """
        if not _RESULT_ID_RE.fullmatch(str(result_id or "")):
            raise ValueError(f"非法的结果 ID：{result_id!r}")
        return self._dir / f"{result_id}.json"

    def _safe_title(self, text: str, max_len: int = 30) -> str:
        """从需求/架构文本中提取一句简短、有意义的标题。

        优先级：
        1. 文本中的 Markdown 一级标题（# 开头）
        2. 以「XX系统/XX平台/XX模块/XX服务」为后缀/前缀的句式
        3. 第一行非空内容
        4. 兜底：截取前若干字
        """
        src = (text or "").strip()
        if not src:
            return "未命名威胁建模"

        lines = [ln.strip() for ln in src.splitlines() if ln.strip()]

        # 1. Markdown 标题（# / ## 行）
        for ln in lines:
            m = re.match(r"^#{1,3}\s+(.+)$", ln)
            if m:
                candidate = m.group(1).strip()
                if candidate:
                    return self._truncate(candidate, max_len)

        # 2. 包含「XX系统/平台/模块/服务/应用」的短句
        pattern = re.compile(r"(.{2,20}?(?:系统|平台|模块|服务|应用|网关|中心))")
        for ln in lines:
            m = pattern.search(ln)
            if m:
                candidate = m.group(1).strip(" ：:，,。；;")
                if candidate:
                    return self._truncate(candidate, max_len)

        # 3. 第一行
        if lines:
            return self._truncate(lines[0], max_len)

        # 4. 兜底
        one_line = re.sub(r"\s+", " ", src)
        return self._truncate(one_line, max_len) or "未命名威胁建模"

    @staticmethod
    def _truncate(text: str, max_len: int) -> str:
        text = re.sub(r"\s+", " ", text).strip()
        if len(text) > max_len:
            return text[: max_len - 1] + "…"
        return text

    # ------------------------------------------------------------------
    # 写入
    # ------------------------------------------------------------------
    def save(
        self,
        model: dict[str, Any],
        summary: str,
        stats: dict[str, Any],
        methodology: str,
        source_text: str,
        cache_keys: list[str] | None = None,
        title: str | None = None,
        owner: dict[str, Any] | None = None,
        fingerprint: str | None = None,
    ) -> dict[str, Any]:
        """保存一次建模结果，返回该结果的元数据字典。

        Args:
            cache_keys: 本次建模过程中写入的 LLM 响应缓存键。
                删除该结果时，会用这些键精准失效对应输入的缓存，
                从而保证删除后重新建模不会命中旧结果。
            title: 用户自定义标题；为空时自动从 source_text 提取。
            owner: 建模人信息 ``{"user_id": int, "username": str,
                "display_name": str}``；None 表示匿名（兼容老数据）。
            fingerprint: 输入指纹（需求+架构+方法论的 sha1 前 16 字节），
                用于在前端双击 / 网络重试 / 用户重复点提交 时做幂等去重。
                同 owner + 同 fingerprint 在窗口期内的重复请求将复用已有 result。
        """
        result_id = f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        owner_payload: dict[str, Any] = {}
        if owner:
            owner_payload = {
                "owner_id": owner.get("user_id"),
                "owner_username": owner.get("username") or "",
                "owner_display_name": owner.get("display_name")
                or owner.get("username")
                or "",
            }
        record = {
            "id": result_id,
            "title": title.strip() if title else self._safe_title(source_text),
            "methodology": methodology,
            "created_at": nc.epoch(),
            "model": model,
            "summary": summary,
            "stats": stats,
            "cache_keys": list(cache_keys or []),
            "input_fingerprint": (fingerprint or "").strip() or None,
            **owner_payload,
        }
        with self._lock:
            self._write(record)
            self._prune()
        logger.info("已保存建模结果 %s (owner=%s)", result_id, owner_payload.get("owner_username") or "-")
        return self._meta(record)

    # ------------------------------------------------------------------
    # 读取
    # ------------------------------------------------------------------
    def find_recent_by_fingerprint(
        self,
        owner_username: str,
        fingerprint: str,
        window_sec: int = 60,
    ) -> dict[str, Any] | None:
        """查找同 owner 在最近 window_sec 秒内使用相同 fingerprint 提交的已有结果。

        用于 P0 持久化幂等：网络重试 / 用户双击 / 浏览器重发 POST 都能命中。
        返回的 dict 已剥离完整 model（仅 meta），无访问权限限制（仅按 owner_username 过滤）。

        Returns:
            找到的元数据字典（含 id / created_at），未命中返回 None。
        """
        if not (owner_username and fingerprint):
            return None
        cutoff = nc.epoch() - max(1, int(window_sec))
        with self._lock:
            for p in self._dir.glob("*.json"):
                if p.name.startswith("."):
                    continue
                rec = self._load(p)
                if not rec:
                    continue
                if (rec.get("owner_username") or "") != owner_username:
                    continue
                if (rec.get("input_fingerprint") or "") != fingerprint:
                    continue
                if rec.get("created_at", 0) < cutoff:
                    continue
                return self._meta(rec)
        return None

    def _write(self, record: dict[str, Any]) -> None:
        tmp = self._dir / f".{record['id']}.tmp"
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(record, f, ensure_ascii=False, indent=2)
        tmp.replace(self._path(record["id"]))

    @staticmethod
    def _meta(record: dict[str, Any]) -> dict[str, Any]:
        """返回不含完整 model 的元数据（用于列表展示）。"""
        return {
            "id": record["id"],
            "title": record["title"],
            "methodology": record["methodology"],
            "created_at": record["created_at"],
            "stats": record.get("stats", {}),
            "owner_id": record.get("owner_id"),
            "owner_username": record.get("owner_username") or "",
            "owner_display_name": record.get("owner_display_name")
            or record.get("owner_username")
            or "",
        }

    @staticmethod
    def _can_view(record: dict[str, Any], user: dict[str, Any] | None) -> bool:
        """判断当前用户是否可访问该结果。

        - 角色 ``admin`` / ``secops``：可访问所有结果（含无 owner 的历史结果）
        - 其他角色：仅当 ``record.owner_username == user.username`` 时可访问
        - 未登录（user 为 None 或 username 为空）：仅 admin/secops 可访问
        """
        if not user:
            return False
        role = user.get("role") or ""
        if role in {"admin", "secops"}:
            return True
        owner_username = record.get("owner_username") or ""
        # 历史无 owner 字段的旧结果：仅 admin/secops 可见（见 _can_view）
        if not owner_username:
            return False
        return owner_username == (user.get("username") or "")

    def list(
        self,
        user: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """按创建时间倒序返回当前用户可见的结果元数据。

        - admin / secops：返回所有结果
        - 其他用户：仅返回 ``owner_username`` 与当前用户匹配的结果
        - 未登录（无 user_id 且无 username）：返回空列表
        """
        with self._lock:
            records = [r for r in self._iter_records()]
        records.sort(key=lambda r: r.get("created_at", 0), reverse=True)
        # admin/secops 不过滤
        is_admin = bool(user) and (user.get("role") in {"admin", "secops"})
        if is_admin:
            return [self._meta(r) for r in records]
        username = (user or {}).get("username") or ""
        if not username:
            # 未登录用户不可见任何结果
            return []
        return [
            self._meta(r)
            for r in records
            if (r.get("owner_username") or "") == username
        ]

    def get(
        self,
        result_id: str,
        user: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """返回单个结果的完整内容；不存在返回 None。

        当 ``user`` 不为空时，会校验访问权限：非 owner 且非 admin/secops 抛
        ``PermissionError``，调用方需将其转译为 403。
        """
        with self._lock:
            path = self._path(result_id)
            if not path.exists():
                return None
            record = self._load(path)
        if record is None:
            return None
        if user is not None and not self._can_view(record, user):
            raise PermissionError("无权访问该威胁建模结果")
        return record

    def delete(self, result_id: str, user: dict[str, Any] | None = None) -> bool:
        """删除指定结果；返回是否存在并删除成功。

        - admin / secops：可直接删除任意结果
        - 其他用户：仅可删除自己建模的结果
        """
        with self._lock:
            path = self._path(result_id)
            if not path.exists():
                return False
            record = self._load(path)
        if record is None:
            return False
        if user is not None and not self._can_view(record, user):
            raise PermissionError("无权删除该威胁建模结果")
        path.unlink()
        logger.info(
            "已删除建模结果 %s (by %s)", result_id, (user or {}).get("username") or "-"
        )
        return True

    def update_threat_status(
        self,
        result_id: str,
        threat_id: str,
        new_status: str | None = None,
        out_of_scope: bool | None = None,
        user: dict[str, Any] | None = None,
    ) -> bool:
        """更新指定结果中某条威胁的处置状态或范围外标记，并持久化回写。

        Args:
            result_id: 结果 id
            threat_id: 威胁 id（cell 的 threat id）
            new_status: 新的处置状态（Open / Mitigated / ...），None 表示不修改
            out_of_scope: 是否标记为范围外，None 表示不修改
            user: 当前操作人；非 owner 且非 admin/secops 时抛 ``PermissionError``

        Returns:
            是否找到并成功更新（找不到威胁返回 False）。
        """
        if new_status is None and out_of_scope is None:
            # 没有要更新的内容，仍按"无更新"处理
            return True
        with self._lock:
            path = self._path(result_id)
            if not path.exists():
                return False
            record = self._load(path)
            if record is None:
                return False
            if user is not None and not self._can_view(record, user):
                raise PermissionError("无权修改该威胁建模结果")
            model = record.get("model") or {}
            diagrams = ((model.get("detail") or {}).get("diagrams")) or []
            found = False
            for diagram in diagrams:
                for cell in diagram.get("cells") or []:
                    for threat in cell.get("threats") or []:
                        # 威胁 ID 可能存于 id 或 threatId 字段
                        cur_id = threat.get("id") or threat.get("threatId")
                        if cur_id == threat_id:
                            if new_status is not None:
                                threat["status"] = new_status
                            if out_of_scope is not None:
                                threat["outOfScope"] = bool(out_of_scope)
                            found = True
            if not found:
                return False
            self._write(record)
            logger.info(
                "已更新结果 %s 威胁 %s (status=%s, oos=%s)",
                result_id,
                threat_id,
                new_status,
                out_of_scope,
            )
            return True

    def rename(
        self,
        result_id: str,
        title: str,
        user: dict[str, Any] | None = None,
    ) -> bool:
        """重命名指定结果的标题，并持久化回写。

        Args:
            user: 当前操作人；非 owner 且非 admin/secops 时抛 ``PermissionError``

        Returns:
            是否找到并成功更新（找不到结果返回 False）。
        """
        title = (title or "").strip()
        if not title:
            return False
        title = self._truncate(title, 60)
        with self._lock:
            path = self._path(result_id)
            if not path.exists():
                return False
            record = self._load(path)
            if record is None:
                return False
            if user is not None and not self._can_view(record, user):
                raise PermissionError("无权重命名该威胁建模结果")
            record["title"] = title
            # 同步更新 meta（部分调用方读取 meta.title）
            meta = record.setdefault("meta", {})
            if isinstance(meta, dict):
                meta["title"] = title
            self._write(record)
            logger.info("已重命名结果 %s 为「%s」", result_id, title)
            return True

    # ------------------------------------------------------------------
    # 内部遍历
    # ------------------------------------------------------------------
    def _iter_records(self) -> Any:
        for p in sorted(self._dir.glob("*.json")):
            if p.name.startswith("."):
                continue
            r = self._load(p)
            if r:
                yield r

    @staticmethod
    def _load(path: Path) -> dict[str, Any] | None:
        try:
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:  # 损坏文件跳过
            logger.warning("读取结果文件 %s 失败: %s", path.name, exc)
            return None

    def _prune(self) -> None:
        """超过最大条数时删除最旧的结果。"""
        files = sorted(
            self._dir.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for old in files[MAX_RESULTS:]:
            try:
                old.unlink()
            except OSError:
                pass


# 全局单例
result_store = ResultStore()
