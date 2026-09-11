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
import os
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
# 归档目录：backend/data/results-archive/
# 超出 MAX_RESULTS 的旧结果会移到这里（而非直接删除），避免用户数据静默丢失。
ARCHIVE_DIR = DATA_DIR / "results-archive"

# 历史结果最大保留条数（超出后归档最旧的）
MAX_RESULTS = int(os.getenv("THREAT_MAX_RESULTS", "200"))

# result_id 白名单：仅允许「日期-时间-短uuid」格式（如 20260819-153000-abc123），
# 用于防御路径穿越（../ 越权读取/删除磁盘文件）。
_RESULT_ID_RE = re.compile(r"^[0-9A-Za-z-]{16,40}$")

# 威胁处置状态白名单。
# 之前 update_threat_status 直接接受任意字符串（见 schemas.ThreatStatusUpdate 的
# 注释里写的 Open/Mitigated/Accepted/In Progress），导致写入脏数据。
# 这里以 Threat Dragon 官方状态机为基础，并保留平台前端已提供的两个扩展态。
THREAT_STATUSES: tuple[str, ...] = (
    "Open",
    "In Progress",
    "Mitigated",
    "Accepted",
    "NotApplicable",
)

# 威胁评审结论白名单。
# 对应 Threat Modeling Manifesto 原则 4「威胁建模是一个持续的过程」：
# AI 识别出的威胁需要有人**确认或推翻**，否则大量误报会淹没真实风险，
# 团队会逐渐不再信任这份模型。评审结论与处置状态（status）是两个正交维度：
#   - status    回答"这条威胁我们打算怎么处理"
#   - review    回答"我们是否认可这条威胁成立"
REVIEW_STATES: tuple[str, ...] = (
    "Pending",     # 待评审（默认）
    "Confirmed",   # 已确认：认可威胁成立，需跟进处置
    "Rejected",    # 已驳回：误报或经评估不成立
)


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
        if new_status is not None and new_status not in THREAT_STATUSES:
            raise ValueError(
                f"非法的威胁状态：{new_status!r}，可选值：{'/'.join(THREAT_STATUSES)}"
            )
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

    # ------------------------------------------------------------------
    # 威胁评审（确认 / 驳回）
    # ------------------------------------------------------------------
    def review_threat(
        self,
        result_id: str,
        threat_id: str,
        state: str,
        comment: str | None = None,
        reviewer: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """给一条威胁写入评审结论（确认 / 驳回）。

        AI 识别的威胁必然包含误报，需要人工确认或推翻：
        - ``Confirmed``：认可威胁成立，推进到整改流程；
        - ``Rejected``：误报或经评估不成立，避免污染后续风险统计。

        评审结论与处置状态（status）正交：承认威胁成立（Confirmed）
        不代表已经缓解（Mitigated）。

        Args:
            state: ``REVIEW_STATES`` 之一。
            comment: 可选评审意见。
            reviewer: 评审人（来自 JWT），记录 username 以便追溯。

        Returns:
            更新后的评审信息字典；找不到返回 None。
        """
        if state not in REVIEW_STATES:
            raise ValueError(
                f"非法的评审结论：{state!r}，可选值：{'/'.join(REVIEW_STATES)}"
            )
        with self._lock:
            path = self._path(result_id)
            if not path.exists():
                return None
            record = self._load(path)
            if record is None:
                return None
            model = record.get("model") or {}
            diagrams = ((model.get("detail") or {}).get("diagrams")) or []
            for diagram in diagrams:
                for cell in diagram.get("cells") or []:
                    for threat in cell.get("threats") or []:
                        cur_id = threat.get("id") or threat.get("threatId")
                        if cur_id != threat_id:
                            continue
                        review = {
                            "state": state,
                            "comment": (comment or "").strip(),
                            "reviewer": (reviewer or {}).get("username") or "",
                            "reviewer_id": (reviewer or {}).get("user_id"),
                            "reviewed_at": int(time.time()),
                        }
                        threat["review"] = review
                        # 驳回的威胁不应继续留在待办里：同步把 status 收敛，
                        # 让下游按 status 统计的报表不会把误报算作待处理。
                        if state == "Rejected":
                            threat["status"] = "NotApplicable"
                        self._write(record)
                        logger.info(
                            "结果 %s 威胁 %s 评审为 %s（%s）",
                            result_id, threat_id, state, review["reviewer"],
                        )
                        return review
        return None

    def review_summary(
        self,
        result_id: str,
        user: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """统计某结果的评审进度，用于回答「评审做完了吗」。"""
        with self._lock:
            path = self._path(result_id)
            if not path.exists():
                return None
            record = self._load(path)
            if record is None:
                return None
            if user is not None and not self._can_view(record, user):
                raise PermissionError("无权访问该威胁建模结果")
            model = record.get("model") or {}
            diagrams = ((model.get("detail") or {}).get("diagrams")) or []
            counts = {s: 0 for s in REVIEW_STATES}
            reviewers: set[str] = set()
            total = 0
            for diagram in diagrams:
                for cell in diagram.get("cells") or []:
                    for threat in cell.get("threats") or []:
                        total += 1
                        # 未评审的威胁没有 review 字段，计入 Pending
                        state = ((threat.get("review") or {}).get("state")) or "Pending"
                        if state not in counts:
                            state = "Pending"
                        counts[state] += 1
                        who = (threat.get("review") or {}).get("reviewer")
                        if who:
                            reviewers.add(who)
            reviewed = counts["Confirmed"] + counts["Rejected"]
            return {
                "total": total,
                "pending": counts["Pending"],
                "confirmed": counts["Confirmed"],
                "rejected": counts["Rejected"],
                "reviewed": reviewed,
                # 评审完成率：0~1，前端用于进度条
                "reviewRate": round(reviewed / total, 3) if total else 0.0,
                "reviewers": sorted(reviewers),
            }

    # ------------------------------------------------------------------
    # 威胁的手工编辑（AI 提取必然有遗漏，需要允许安全工程师补充）
    # ------------------------------------------------------------------
    @staticmethod
    def _find_cell_by_element(model: dict[str, Any], element_id: str) -> dict[str, Any] | None:
        """按 cell.id 或 cell.data.name 定位元素 cell。"""
        diagrams = ((model.get("detail") or {}).get("diagrams")) or []
        wanted = str(element_id or "").strip()
        if not wanted:
            return None
        for diagram in diagrams:
            cells = diagram.get("cells") or []
            # 先按 cell.id 精确匹配
            for cell in cells:
                if str(cell.get("id") or "") == wanted:
                    return cell
            # 再按组件名匹配（前端常用名字而非随机 uuid 定位）
            for cell in cells:
                name = str(((cell.get("data") or {}).get("name")) or "")
                if name and name == wanted:
                    return cell
        return None

    def add_threat(
        self,
        result_id: str,
        element_id: str,
        payload: dict[str, Any],
        user: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """在指定元素下手工新增一条威胁。

        Args:
            element_id: 目标元素的 ``cell.id`` 或组件名。
            payload: 威胁字段（title 必填，其余可选）。
            user: 当前操作人；非 owner 且非 admin/secops 时抛 ``PermissionError``。

        Returns:
            新增的威胁字典（含生成的 threatId），失败返回 None。
        """
        title = str(payload.get("title") or "").strip()
        if not title:
            raise ValueError("威胁标题不能为空")
        with self._lock:
            path = self._path(result_id)
            if not path.exists():
                return None
            record = self._load(path)
            if record is None:
                return None
            if user is not None and not self._can_view(record, user):
                raise PermissionError("无权修改该威胁建模结果")
            model = record.get("model") or {}
            cell = self._find_cell_by_element(model, element_id)
            if cell is None:
                return None

            threats = cell.setdefault("threats", [])
            # number 是全局递增序号，取当前最大值 +1 保持连续
            top = ((model.get("detail") or {}).get("threatTop")) or 0
            new_number = int(top) + 1
            threat = {
                "id": uuid.uuid4().hex,
                "threatId": uuid.uuid4().hex,
                "number": new_number,
                "title": title,
                "type": str(payload.get("type") or "Other"),
                "severity": str(payload.get("severity") or "Medium"),
                "status": str(payload.get("status") or THREAT_STATUSES[0]),
                "description": str(payload.get("description") or ""),
                "mitigation": str(payload.get("mitigation") or ""),
                "cwe": str(payload.get("cwe") or ""),
                "outOfScope": bool(payload.get("outOfScope")),
                # 标记来源，便于与 AI 识别的威胁区分
                "source": "manual",
            }
            if threat["status"] not in THREAT_STATUSES:
                raise ValueError(f"非法的威胁状态：{threat['status']!r}")
            threats.append(threat)
            # 更新全局威胁计数，保持 hasOpenThreats 等派生字段一致
            detail = model.setdefault("detail", {})
            detail["threatTop"] = new_number
            cell.setdefault("data", {})["hasOpenThreats"] = True
            self._write(record)
            logger.info("已在结果 %s 的元素 %s 新增威胁「%s」", result_id, element_id, title)
            return threat

    def update_threat(
        self,
        result_id: str,
        threat_id: str,
        payload: dict[str, Any],
        user: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """编辑一条威胁的可写字段（标题/描述/缓解措施/类型/严重度/状态/CWE）。

        与 ``update_threat_status`` 的区别：那个只改状态与范围外标记（普通用户
        也能用），这个允许改写内容，属于"安全工程师补充完善"的场景。
        """
        editable = {
            "title", "description", "mitigation", "type",
            "severity", "status", "cwe", "outOfScope",
        }
        with self._lock:
            path = self._path(result_id)
            if not path.exists():
                return None
            record = self._load(path)
            if record is None:
                return None
            if user is not None and not self._can_view(record, user):
                raise PermissionError("无权修改该威胁建模结果")
            if payload.get("status") is not None and payload["status"] not in THREAT_STATUSES:
                raise ValueError(f"非法的威胁状态：{payload['status']!r}")
            model = record.get("model") or {}
            diagrams = ((model.get("detail") or {}).get("diagrams")) or []
            for diagram in diagrams:
                for cell in diagram.get("cells") or []:
                    for threat in cell.get("threats") or []:
                        cur_id = threat.get("id") or threat.get("threatId")
                        if cur_id != threat_id:
                            continue
                        for field in editable:
                            if field in payload and payload[field] is not None:
                                if field == "outOfScope":
                                    threat[field] = bool(payload[field])
                                elif field == "title":
                                    text = str(payload[field]).strip()
                                    if not text:
                                        raise ValueError("威胁标题不能为空")
                                    threat[field] = text
                                else:
                                    threat[field] = payload[field]
                        self._write(record)
                        logger.info("已编辑结果 %s 的威胁 %s", result_id, threat_id)
                        return threat
        return None

    def update_layout(
        self,
        result_id: str,
        positions: dict[str, dict[str, float]],
        user: dict[str, Any] | None = None,
    ) -> int:
        """批量更新 DFD 元素的坐标（用户拖动微调布局后持久化）。

        Args:
            positions: ``{cell_id: {"x": float, "y": float}}``。
            user: 当前操作人；非 owner 且非 admin/secops 时抛 ``PermissionError``。

        Returns:
            实际更新的元素数量。
        """
        if not positions:
            return 0
        with self._lock:
            path = self._path(result_id)
            if not path.exists():
                return 0
            record = self._load(path)
            if record is None:
                return 0
            if user is not None and not self._can_view(record, user):
                raise PermissionError("无权修改该威胁建模结果")
            model = record.get("model") or {}
            diagrams = ((model.get("detail") or {}).get("diagrams")) or []
            updated = 0
            for diagram in diagrams:
                for cell in diagram.get("cells") or []:
                    pos = positions.get(str(cell.get("id") or ""))
                    if not pos:
                        continue
                    try:
                        cell["position"] = {"x": float(pos["x"]), "y": float(pos["y"])}
                        updated += 1
                    except (KeyError, TypeError, ValueError):
                        continue
            if updated:
                self._write(record)
                logger.info("已更新结果 %s 的 %d 个元素坐标", result_id, updated)
            return updated

    def rename_element(
        self,
        result_id: str,
        element_id: str,
        name: str,
        user: dict[str, Any] | None = None,
    ) -> bool:
        """重命名一个 DFD 元素（组件/数据流）。

        AI 提取的组件名常有偏差（如把"用户认证服务"写成"认证模块"），
        允许用户直接改写名称，无需重新建模。
        """
        new_name = str(name or "").strip()
        if not new_name:
            raise ValueError("元素名称不能为空")
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
            cell = self._find_cell_by_element(model, element_id)
            if cell is None:
                return False
            cell.setdefault("data", {})["name"] = new_name
            self._write(record)
            logger.info("已重命名结果 %s 的元素 %s 为「%s」", result_id, element_id, new_name)
            return True

    def delete_threat(
        self,
        result_id: str,
        threat_id: str,
        user: dict[str, Any] | None = None,
    ) -> bool:
        """删除一条威胁（例如 AI 误报、经评估不适用）。"""
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
            for diagram in diagrams:
                for cell in diagram.get("cells") or []:
                    threats = cell.get("threats") or []
                    for i, threat in enumerate(threats):
                        cur_id = threat.get("id") or threat.get("threatId")
                        if cur_id == threat_id:
                            threats.pop(i)
                            self._write(record)
                            logger.info("已删除结果 %s 的威胁 %s", result_id, threat_id)
                            return True
        return False

    def get_threat(
        self,
        result_id: str,
        threat_id: str,
        user: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """读取指定结果中的某条威胁，并补上所在组件信息。

        Args:
            user: 当前操作人；非 owner 且非 admin/secops 时抛 ``PermissionError``

        Returns:
            威胁字典（附 ``componentId`` / ``componentName`` / ``componentType``），
            找不到返回 None。
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
            model = record.get("model") or {}
            diagrams = ((model.get("detail") or {}).get("diagrams")) or []
            for diagram in diagrams:
                for cell in diagram.get("cells") or []:
                    for threat in cell.get("threats") or []:
                        cur_id = threat.get("id") or threat.get("threatId")
                        if cur_id != threat_id:
                            continue
                        enriched = dict(threat)
                        data = cell.get("data") or {}
                        enriched.setdefault("componentId", cell.get("id"))
                        enriched.setdefault("componentName", data.get("name"))
                        enriched.setdefault("componentType", data.get("type"))
                        return enriched
        return None

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
        """超过最大条数时把最旧的结果**归档**（移入 results-archive/）。

        历史行为是直接 unlink 删除，用户不会收到任何提示，存在数据静默丢失风险。
        现在改为移动到归档目录：主列表不再显示，但数据仍在磁盘上可追溯。
        """
        files = sorted(
            self._dir.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        overflow = files[MAX_RESULTS:]
        if not overflow:
            return
        try:
            self._archive_dir().mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.warning("创建归档目录失败，跳过本次归档：%s", exc)
            return
        for old in overflow:
            try:
                # 目标同名文件已存在时加时间戳后缀，避免覆盖既有归档
                dest = self._archive_dir() / old.name
                if dest.exists():
                    dest = self._archive_dir() / f"{old.stem}-{int(old.stat().st_mtime)}{old.suffix}"
                old.replace(dest)
                logger.info("结果 %s 超出保留上限(%d)，已归档至 %s", old.stem, MAX_RESULTS, dest.name)
            except OSError as exc:
                logger.warning("归档结果文件 %s 失败：%s", old.name, exc)

    # ------------------------------------------------------------------
    # 归档
    # ------------------------------------------------------------------
    def _archive_dir(self) -> Path:
        """归档目录（与结果目录同级，便于整体备份）。"""
        if self._dir == RESULTS_DIR:
            return ARCHIVE_DIR
        # 自定义目录场景（测试）下，归档到同级 results-archive/
        return self._dir.parent / f"{self._dir.name}-archive"

    def list_archived(self) -> list[dict[str, Any]]:
        """列出已归档的结果元数据，按创建时间倒序。"""
        rows: list[dict[str, Any]] = []
        adir = self._archive_dir()
        if not adir.exists():
            return rows
        for p in adir.glob("*.json"):
            if p.name.startswith("."):
                continue
            rec = self._load(p)
            if rec:
                meta = self._meta(rec)
                meta["archived"] = True
                rows.append(meta)
        rows.sort(key=lambda r: r.get("created_at", 0), reverse=True)
        return rows

    def restore_archived(self, result_id: str) -> bool:
        """把某条归档结果恢复到主结果目录。成功返回 True。"""
        if not _RESULT_ID_RE.fullmatch(str(result_id or "")):
            return False
        with self._lock:
            adir = self._archive_dir()
            if not adir.exists():
                return False
            # 归档文件名可能带时间戳后缀，需要模糊匹配前缀
            candidates = [
                p for p in adir.glob(f"{result_id}*.json") if not p.name.startswith(".")
            ]
            if not candidates:
                return False
            src = candidates[0]
            dest = self._dir / f"{result_id}.json"
            try:
                src.replace(dest)
                logger.info("已从归档恢复结果 %s", result_id)
                return True
            except OSError as exc:
                logger.warning("恢复归档结果 %s 失败：%s", result_id, exc)
                return False


# 全局单例
result_store = ResultStore()
