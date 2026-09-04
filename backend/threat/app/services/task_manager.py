"""内存任务管理器：跟踪 AI 威胁建模异步任务的进度与结果。

设计说明：
- 使用进程内字典保存任务，适合单机单 worker 场景（本项目的默认部署形态）。
- 任务生命周期：pending -> running -> success | error。
- 结果在任务完成后保留一段时间（TTL），到期自动清理，避免内存膨胀。
- 若未来需要多 worker / 多机，可替换为 Redis + Celery，但 API 契约保持不变。
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any, Optional

from app.utils import network_clock as nc
logger = logging.getLogger(__name__)

# 任务完成后结果保留时长（秒）
RESULT_TTL = 60 * 30
# 清理未完成任务 / 过期结果的间隔（秒）
_CLEANUP_INTERVAL = 60


class TaskStatus:
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    ERROR = "error"
    CANCELLED = "cancelled"


class TaskNotFoundError(Exception):
    """任务不存在或已过期。"""


class TaskManager:
    """进程内异步任务注册表。"""

    def __init__(self) -> None:
        self._tasks: dict[str, dict[str, Any]] = {}
        self._cleanup_task: Optional[asyncio.Task] = None

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
            "result": None,
            "error": None,
            "cancelled": False,  # 取消标志，供长任务在各步骤间检查
            "created_at": nc.epoch(),
            "finished_at": None,
        }
        self._ensure_cleanup()
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
        return True

    def is_cancelled(self, task_id: str) -> bool:
        """供任务协程在各阶段边界检查是否需要提前退出。"""
        task = self._tasks.get(task_id)
        return bool(task and task["cancelled"])

    def mark_running(self, task_id: str) -> None:
        self._update(task_id, status=TaskStatus.RUNNING)

    def mark_step(
        self,
        task_id: str,
        index: int,
        message: str | None = None,
        sub_progress: float | None = None,
    ) -> None:
        """标记当前进度阶段。index 为 0 基的阶段下标。

        P1-7：新增 ``sub_progress`` 参数（0~1），表示"当前阶段内"的细粒度进度。
        最终 progress = (index + sub_progress) / steps_count * 100，
        让长 LLM 调用的阶段不再"卡在固定 25%/50% 上很久"。
        例如：DFD 提取阶段（index=0, steps=4）下，sub_progress=0.6
        会显示 progress = 15% 而非 0%。
        """
        task = self._tasks.get(task_id)
        if not task:
            return
        task["step_index"] = max(0, min(index, max(0, len(task["steps"]) - 1)))
        steps_n = max(1, len(task["steps"]))
        sub = 0.0 if sub_progress is None else max(0.0, min(1.0, float(sub_progress)))
        # 阶段完成（sub=1.0）才把进度推到下一阶段起点；阶段内推进时按 (i+sub) 算
        task["progress"] = int(
            (task["step_index"] + sub) / steps_n * 100
        )
        if message:
            task["log"].append({"time": nc.epoch(), "message": message})

    def add_log(self, task_id: str, message: str) -> None:
        task = self._tasks.get(task_id)
        if task:
            task["log"].append({"time": nc.epoch(), "message": message})

    def complete(self, task_id: str, result: Any) -> None:
        task = self._tasks.get(task_id)
        if not task:
            return
        task["status"] = TaskStatus.SUCCESS
        task["result"] = result
        task["progress"] = 100
        task["finished_at"] = nc.epoch()

    def mark_cancelled(self, task_id: str) -> None:
        """供任务协程在各步骤边界调用，正式标记为已取消。"""
        task = self._tasks.get(task_id)
        if not task:
            return
        task["status"] = TaskStatus.CANCELLED
        task["cancelled"] = True
        task["finished_at"] = nc.epoch()
        task["error"] = "任务已取消"

    def fail(self, task_id: str, error: str, status_code: int = 500) -> None:
        task = self._tasks.get(task_id)
        if not task:
            return
        task["status"] = TaskStatus.ERROR
        task["error"] = error
        task["status_code"] = status_code
        task["finished_at"] = nc.epoch()

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
            logger.info("清理过期任务 %s", tid)


task_manager = TaskManager()
