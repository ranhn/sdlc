"""任务管理器：跟踪 AI 威胁建模异步任务的进度与结果。

设计说明：
- 任务状态保存在进程内字典（读取快、无锁竞争），适合单机单 worker 场景
  （本项目的默认部署形态）。
- **同时落盘一份 JSON**：后端重启（部署、崩溃、容器重建）后，进行中的任务
  原本会「凭空消失」，前端只能拿到 404 并提示用户重做，体验很差。
  落盘后重启可恢复任务历史，并把重启前处于 pending/running 的任务标记为
  中断（interrupted），前端据此给出明确提示而非「找不到任务」���
- 任务生命周期：pending -> running -> success | error | cancelled | interrupted。
- 结果在任务完成后保留一段时间（TTL），到期自动清理，避免内存膨胀。
- 若未来需要多 worker / 多机，可替换为 Redis + Celery，但 API 契约保持不变。
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from app.utils import network_clock as nc
logger = logging.getLogger(__name__)

# 任务完成后结果保留时长（秒）
RESULT_TTL = 60 * 30
# 清理未完成任务 / 过期结果的间隔（秒）
_CLEANUP_INTERVAL = 60

# 任务快照落盘目录（可用环境变量覆盖，便于容器挂载持久卷）。
# 基准与 result_store 保持一致（backend/threat/data/），避免受当前工作目录影响 ——
# uvicorn / 容器启动时 cwd 不一定是 backend/。
TASKS_DIR = Path(
    os.getenv(
        "THREAT_TASKS_DIR",
        str(Path(__file__).resolve().parents[2] / "data" / "threat_tasks"),
    )
)
# 落盘间隔节流：避免每次 add_log / update 都写盘（高频写会拖慢分析主流程）
_PERSIST_MIN_INTERVAL = 1.0


class TaskStatus:
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    ERROR = "error"
    CANCELLED = "cancelled"
    # 后端重启导致中断：与业务失败（error）区分开，
    # 前端可据此给出「服务重启，请重新发起」的精准提示。
    INTERRUPTED = "interrupted"


class TaskNotFoundError(Exception):
    """任务不存在或已过期。"""


# 日志分级白名单：前端按 level 做降噪/折叠，非法值统一归为 milestone。
_LOG_LEVELS = ("milestone", "detail", "warn", "error")


def _norm_level(level: str | None) -> str:
    """把日志级别归一化到白名单，未知值退化为 milestone。"""
    lv = (level or "").strip().lower()
    return lv if lv in _LOG_LEVELS else "milestone"


class TaskManager:
    """异步任务注册表（内存 + JSON 落盘）。"""

    def __init__(self, tasks_dir: Path | None = None) -> None:
        self._tasks: dict[str, dict[str, Any]] = {}
        self._cleanup_task: Optional[asyncio.Task] = None
        self._dir = Path(tasks_dir) if tasks_dir else TASKS_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        # task_id -> 上次落盘时间（节流用）
        self._persisted_at: dict[str, float] = {}
        self._restore()

    # ------------------------------------------------------------------
    # 落盘 / 恢复
    # ------------------------------------------------------------------
    def _persist(self, task_id: str, force: bool = False) -> None:
        """把任务快照写入磁盘（原子替换，避免读到半截 JSON）。

        节流：默认 1 秒内最多落盘一次，状态终态时 ``force=True`` 强制写，
        保证任务结束时磁盘一定是最终状态。
        """
        record = self._tasks.get(task_id)
        if record is None:
            return
        now = time.time()
        if not force and (now - self._persisted_at.get(task_id, 0)) < _PERSIST_MIN_INTERVAL:
            return
        target = self._dir / f"{task_id}.json"
        try:
            fd, tmp_name = tempfile.mkstemp(dir=str(self._dir), suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(record, f, ensure_ascii=False)
            os.replace(tmp_name, target)
            self._persisted_at[task_id] = now
        except Exception as exc:  # noqa: BLE001 - 落盘失败不应影响主流程
            logger.warning("任务 %s 落盘失败：%s", task_id, exc)

    def _restore(self) -> None:
        """启动时从磁盘恢复任务，并把中断的任务标记为 interrupted。

        重启前处于 pending/running 的任务，其执行协程已随进程消失，
        永远不可能再推进；若原样恢复，前端会一直看到「进行中」而卡死。
        因此这里统一标记为 interrupted 并写明原因。
        """
        restored = 0
        interrupted = 0
        for path in sorted(self._dir.glob("*.json")):
            try:
                with path.open("r", encoding="utf-8") as f:
                    record = json.load(f)
            except Exception as exc:  # noqa: BLE001
                logger.warning("恢复任务 %s 失败（跳过）：%s", path.name, exc)
                continue
            task_id = record.get("id")
            if not task_id:
                continue
            if record.get("status") in (TaskStatus.PENDING, TaskStatus.RUNNING):
                record["status"] = TaskStatus.INTERRUPTED
                record["error"] = "服务重启导致任务中断，请重新发起建模"
                record["finished_at"] = record.get("finished_at") or nc.epoch()
                interrupted += 1
            # 兼容老快照：metrics/stage_timings/started_at 字段是后加的，
            # 缺失时补默认值，避免前端读到 undefined
            record.setdefault("metrics", {})
            record.setdefault("stage_timings", [])
            record.setdefault("started_at", None)
            self._tasks[task_id] = record
            restored += 1
        if restored:
            logger.info(
                "已恢复 %d 个任务快照（其中 %d 个标记为中断）", restored, interrupted
            )

    def create(self, steps: list[str]) -> str:
        """创建任务，返回 task_id。

        Args:
            steps: 进度阶段名列表（与前端展示对应）。
        """
        task_id = uuid.uuid4().hex
        self._tasks[task_id] = {
            "id": task_id,
            "status": TaskStatus.PENDING,
            "steps": steps,
            "step_index": 0,
            "progress": 0,  # 0~100
            "log": [],
            # 实时指标：建模过程中不断覆盖更新（组件数/流数/自检修复数…），
            # 供前端「建模中」右栏仪表盘展示，无需等最终 result。
            "metrics": {},
            # 阶段计时（P1）：与 steps 对齐的数组，每项 {start, end}（epoch 秒）。
            # end 为 None 表示该阶段仍在进行中；未开始的阶段为 None 占位。
            # 权威数据源在后端——前端本地估算跨刷新/恢复会失真。
            "stage_timings": [],
            "started_at": None,  # 首次进入 running 的时间（总耗时计算基准）
            "result": None,
            "error": None,
            "cancelled": False,  # 取消标志，供长任务在各步骤间检查
            "created_at": nc.epoch(),
            "finished_at": None,
        }
        self._ensure_cleanup()
        # 创建即落盘：否则刚提交任务就重启，前端拿到的将是 404 而非「已中断」
        self._persist(task_id, force=True)
        return task_id

    def cancel(self, task_id: str) -> bool:
        """请求取消一个进行中的任务。

        返回任务是否处于可取消状态（pending/running）。任务实际的协程会在
        各阶段边界通过 ``is_cancelled`` 检查后退出。
        """
        task = self._tasks.get(task_id)
        if not task:
            raise TaskNotFoundError(f"任务 {task_id} 不存在或已过期")
        if task["status"] in (TaskStatus.SUCCESS, TaskStatus.ERROR, TaskStatus.CANCELLED):
            return False
        task["cancelled"] = True
        task["log"].append({"time": nc.epoch(), "message": "收到取消请求"})
        # 若任务尚未真正运行（pending），直接置为 cancelled
        if task["status"] == TaskStatus.PENDING:
            task["status"] = TaskStatus.CANCELLED
            task["finished_at"] = nc.epoch()
            task["error"] = "任务已取消"
        self._persist(task_id, force=True)
        return True

    def is_cancelled(self, task_id: str) -> bool:
        """供任务协程在各阶段边界检查是否需要提前退出。"""
        task = self._tasks.get(task_id)
        return bool(task and task["cancelled"])

    def mark_running(self, task_id: str) -> None:
        task = self._tasks.get(task_id)
        if not task:
            return
        # 总耗时基准：只记首次（重试/重复调用不重置）
        if not task.get("started_at"):
            task["started_at"] = nc.epoch()
        task["status"] = TaskStatus.RUNNING
        self._persist(task_id)

    @staticmethod
    def _close_running_stages(task: dict[str, Any]) -> None:
        """把所有「已开启但未结束」的阶段计时关闭（用于阶段切换与任务收尾）。"""
        now = nc.epoch()
        for tm in task.get("stage_timings") or []:
            if isinstance(tm, dict) and tm.get("start") and not tm.get("end"):
                tm["end"] = now

    def mark_step(
        self,
        task_id: str,
        index: int,
        message: str | None = None,
        sub_progress: float | None = None,
        level: str = "milestone",
    ) -> None:
        """标记当前进度阶段。index 为 0 基的阶段下标。

        P1-7：新增 ``sub_progress`` 参数（0~1），表示"当前阶段内"的细粒度进度。
        最终 progress = (index + sub_progress) / steps_count * 100，
        让长 LLM 调用的阶段不再"卡在固定 25%/50% 上很久"。
        例如：DFD 提取阶段（index=0, steps=4）下，sub_progress=0.6
        会显示 progress = 15% 而非 0%。

        ``level`` 为日志分级（milestone/detail/warn/error），供前端降噪过滤。
        """
        task = self._tasks.get(task_id)
        if not task:
            return
        old_index = task.get("step_index", 0)
        new_index = max(0, min(index, max(0, len(task["steps"]) - 1)))
        task["step_index"] = new_index
        # 阶段计时：进入新阶段时关闭旧阶段、开启新阶段；同一阶段内的
        # sub_progress 推进（重复调用）不重置 start。
        timings = task.setdefault("stage_timings", [])
        while len(timings) < len(task["steps"]):
            timings.append(None)
        now = nc.epoch()
        if new_index != old_index:
            self._close_running_stages(task)  # 跳阶段也能把中间阶段关干净
        slot = timings[new_index]
        if slot is None:
            timings[new_index] = {"start": now, "end": None}
        elif not slot.get("start"):
            slot["start"] = now
        steps_n = max(1, len(task["steps"]))
        sub = 0.0 if sub_progress is None else max(0.0, min(1.0, float(sub_progress)))
        # 阶段完成（sub=1.0）才把进度推到下一阶段起点；阶段内推进时按 (i+sub) 算
        task["progress"] = int(
            (task["step_index"] + sub) / steps_n * 100
        )
        if message:
            task["log"].append(
                {"time": nc.epoch(), "message": message, "level": _norm_level(level)}
            )
        self._persist(task_id)

    def add_log(self, task_id: str, message: str, level: str = "milestone") -> None:
        """追加一条任务日志。

        ``level`` 供前端分级降噪：
          - milestone：阶段里程碑（默认展示）
          - detail   ：阶段内细节（前端默认折叠）
          - warn     ：非阻塞告警
          - error    ：真实失败
        """
        task = self._tasks.get(task_id)
        if task:
            task["log"].append(
                {"time": nc.epoch(), "message": message, "level": _norm_level(level)}
            )
            self._persist(task_id)

    def set_metrics(self, task_id: str, **metrics: Any) -> None:
        """更新任务实时指标（供前端「建模中」右栏仪表盘展示）。

        与 log 不同，这里是**就地覆盖**的键值（componentCount/flowCount/
        selfcheckCount 等），前端拿到的是"当前已知的完整快照"而非增量。
        值传 None 表示删除该键（例如某指标已失效）。
        """
        task = self._tasks.get(task_id)
        if not task:
            return
        bucket = task.setdefault("metrics", {})
        for k, v in metrics.items():
            if v is None:
                bucket.pop(k, None)
            else:
                bucket[k] = v
        self._persist(task_id)

    def complete(self, task_id: str, result: Any) -> None:
        task = self._tasks.get(task_id)
        if not task:
            return
        self._close_running_stages(task)
        task["status"] = TaskStatus.SUCCESS
        task["result"] = result
        task["progress"] = 100
        task["finished_at"] = nc.epoch()
        self._persist(task_id, force=True)

    def mark_cancelled(self, task_id: str) -> None:
        """供任务协程在各步骤边界调用，正式标记为已取消。"""
        task = self._tasks.get(task_id)
        if not task:
            return
        self._close_running_stages(task)
        task["status"] = TaskStatus.CANCELLED
        task["cancelled"] = True
        task["finished_at"] = nc.epoch()
        task["error"] = "任务已取消"
        self._persist(task_id, force=True)

    def fail(self, task_id: str, error: str, status_code: int = 500) -> None:
        task = self._tasks.get(task_id)
        if not task:
            return
        self._close_running_stages(task)
        task["status"] = TaskStatus.ERROR
        task["error"] = error
        task["status_code"] = status_code
        task["finished_at"] = nc.epoch()
        self._persist(task_id, force=True)

    def get(self, task_id: str) -> dict[str, Any]:
        """获取任务快照。不存在则抛 TaskNotFoundError。"""
        task = self._tasks.get(task_id)
        if not task:
            raise TaskNotFoundError(f"任务 {task_id} 不存在或已过期")
        return dict(task)

    def _update(self, task_id: str, **fields: Any) -> None:
        task = self._tasks.get(task_id)
        if task:
            task.update(fields)
            self._persist(task_id)

    # ------------------------------------------------------------------
    # 自动清理
    # ------------------------------------------------------------------
    def _ensure_cleanup(self) -> None:
        if self._cleanup_task and not self._cleanup_task.done():
            return
        loop = asyncio.get_event_loop()
        self._cleanup_task = loop.create_task(self._cleanup_loop())

    async def _cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(_CLEANUP_INTERVAL)
            try:
                self._sweep()
            except Exception:  # 清理失败不应影响主流程
                logger.exception("task cleanup failed")

    def _sweep(self) -> None:
        now = nc.epoch()
        expired = []
        for tid, task in self._tasks.items():
            finished = task.get("finished_at")
            # 已完成且超 TTL 的，或创建超时（保护性兜底）的
            if finished and now - finished > RESULT_TTL:
                expired.append(tid)
            elif not finished and now - task["created_at"] > RESULT_TTL:
                expired.append(tid)
        for tid in expired:
            self._tasks.pop(tid, None)
            self._persisted_at.pop(tid, None)
            # 同步删除磁盘快照，避免重启后已过期任务被"复活"
            try:
                (self._dir / f"{tid}.json").unlink(missing_ok=True)
            except Exception as exc:  # noqa: BLE001
                logger.warning("删除任务快照 %s 失败：%s", tid, exc)
            logger.info("清理过期任务 %s", tid)


task_manager = TaskManager()
