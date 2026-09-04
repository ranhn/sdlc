"""FastAPI 路由：健康检查、AI 威胁建模（异步任务）与任务进度查询。"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import logging
import time
from datetime import datetime
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse
from openai import APIStatusError, AuthenticationError, BadRequestError

from ..config import settings
from ..core.auth import get_sdlc_user, can_view_all, ADMIN_ROLES
from ..models.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    HealthResponse,
    LLMConfigPublic,
    LLMConfigUpdate,
    RenameResultBody,
    ResultDetailResponse,
    ResultListResponse,
    ResultMeta,
    TaskResponse,
    TaskStepLog,
    TemplateItem,
    TemplateListResponse,
    ThreatStatusUpdate,
)
from ..services.llm_client import LLMClient
from ..services import llm_config_store
from ..services.dfd_reviewer import DFDReviewer
from ..services.document_extractor import extract_assets, extract_text, UnsupportedFileTypeError
from ..services.attachment_store import save_attachment
from ..services.document_analyzer import DocumentAnalyzer
from ..services.threat_analyzer import ThreatAnalyzer
from ..services.model_builder import ThreatModelBuilder
from ..services.task_manager import task_manager, TaskStatus, TaskNotFoundError
from ..services.rate_limiter import rate_limiter
from ..services.result_store import result_store
from ..services.result_exporter import (
    render_result_markdown,
    render_result_json,
    render_result_csv,
    render_result_docx,
)

logger = logging.getLogger(__name__)
router = APIRouter()

# ----------------------------------------------------------------------
# P0-1：In-flight 任务去重（5 秒窗口）
# ----------------------------------------------------------------------
# 同一 owner 在 5 秒内对相同 fingerprint 提交分析请求，视为重复提交：
# 直接复用已注册的 task_id（前端轮询同一任务），不再开新的 LLM 任务。
# 任务结束（success / fail / cancel）必须 _unregister_inflight 释放，
# 否则用户在 5 秒内不能再次重提（用户感知：按钮无效）。
_INFLIGHT: dict[tuple[str, str], tuple[float, str]] = {}
_INFLIGHT_TTL_SEC = 5.0


def _compute_fingerprint(req: AnalyzeRequest) -> str:
    """基于 (title, requirements, architecture, methodology, images) 计算输入指纹。

    客户端传来的 input_fingerprint 仅作交叉验证用，**不**直接信任——
    后端再算一遍以防止客户端伪造绕过幂等。
    P0-3：把 pasted_images 也纳入指纹（同一粘贴图 + 同一文档应复用缓存）。
    """
    payload = {
        "title": (req.title or "").strip(),
        "requirements": (req.requirements or "").strip(),
        "architecture": (req.architecture or "").strip(),
        "methodology": (req.methodology or "STRIDE").strip(),
        # 图片仅按"张数 + 总哈希"纳入指纹（避免巨大 data URI 把指纹算得很慢）
        "image_count": (
            len(req.attachments or []) + len(req.pasted_images or [])
        ),
        "image_hash": hashlib.sha1(
            "".join(
                list(req.attachments or []) + list(req.pasted_images or [])
            ).encode("utf-8", "ignore")
        ).hexdigest(),
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha1(raw).hexdigest()[:16]


def _register_inflight(owner: str, fp: str, task_id: str) -> None:
    """登记一个正在跑的任务，TTL 内同 owner+fp 的请求会复用。"""
    now = nc.epoch()
    # 顺手清理过期键，避免长时间运行后 dict 膨胀
    for k, (ts, _) in list(_INFLIGHT.items()):
        if now - ts > _INFLIGHT_TTL_SEC:
            _INFLIGHT.pop(k, None)
    _INFLIGHT[(owner, fp)] = (now, task_id)


def _unregister_inflight(owner: str, fp: str, task_id: str) -> None:
    """任务结束（无论 success/fail/cancel）时释放 in-flight 槽位。"""
    cur = _INFLIGHT.get((owner, fp))
    if cur and cur[1] == task_id:
        _INFLIGHT.pop((owner, fp), None)

# 根据配置初始化限流参数
rate_limiter.set_config(settings.rate_limit_per_minute)

# 启动时加载磁盘上的 LLM 运行时配置（覆盖 .env 默认值）
llm_config_store.load_from_disk()

# 方法论 -> 威胁分析阶段展示文案（与前端进度面板一一对应）
# 第 2 步针对所选方法论动态渲染，避免出现「选了 CIA 却显示 STRIDE」的情况
_METHODOLOGY_DESCRIPTIONS: dict[str, dict[str, str]] = {
    "STRIDE":   {"analyze": "对组件进行 STRIDE 威胁分析",   "report": "生成 STRIDE 风险评估报告"},
    "STRIDE-AI":{"analyze": "对 AI 组件进行 STRIDE-AI 威胁分析（含提示注入/RAG/Agent/模型）", "report": "生成 STRIDE-AI AI 威胁风险评估报告"},
    "CIA":      {"analyze": "对组件进行 CIA 威胁分析",       "report": "生成 CIA 风险评估报告"},
    "CIADIE":   {"analyze": "对组件进行 CIA+DIE 威胁分析",   "report": "生成 CIA+DIE 风险评估报告"},
    "LINDDUN":  {"analyze": "对组件进行 LINDDUN 威胁分析",   "report": "生成 LINDDUN 风险评估报告"},
    "PLOT4ai":  {"analyze": "对组件进行 PLOT4ai 威胁分析",   "report": "生成 PLOT4ai 风险评估报告"},
    "EOP":      {"analyze": "对组件进行 EOP 威胁分析",       "report": "生成 EOP 风险评估报告"},
}


def _build_analyze_steps(methodology: str | None) -> list[str]:
    """按所选方法论生成分析阶段文案。"""
    from ..services.methodology import normalize_methodology

    method = normalize_methodology(methodology or "STRIDE")
    desc = _METHODOLOGY_DESCRIPTIONS.get(
        method,
        {"analyze": f"对组件进行 {method} 威胁分析", "report": f"生成 {method} 风险评估报告"},
    )
    return [
        "解析需求与架构文档，提取 DFD 元素",
        desc["analyze"],
        "构建 Threat Dragon 威胁模型",
        desc["report"],
    ]


# ----------------------------------------------------------------------
# 鉴权与防滥用依赖
# ----------------------------------------------------------------------
def _client_ip(request: Request) -> str:
    """获取客户端 IP（优先取 X-Forwarded-For，其次 remote）。"""
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def verify_api_key(x_api_key: str | None = Header(None)) -> None:
    """校验 X-API-Key（当配置了 API_TOKEN 时强制校验）。"""
    if settings.api_token and x_api_key != settings.api_token:
        raise HTTPException(status_code=401, detail="无效或缺失 API Token（X-API-Key）")


def enforce_rate_limit(request: Request) -> None:
    """基于客户端 IP 的滑动窗口限流。"""
    ip = _client_ip(request)
    if not rate_limiter.allow(ip):
        raise HTTPException(
            status_code=429,
            detail=f"请求过于频繁，每分钟最多 {settings.rate_limit_per_minute} 次分析。请稍后再试。",
        )


def validate_input_chars(request: AnalyzeRequest) -> None:
    """校验输入长度，防止超大文档导致 LLM 超时或烧钱。

    P1-8：补充校验多模态图片总字节数（data URI 长度累加），
    避免图片超限后被 LLM 网关直接 5xx 拒掉。
    """
    total = len(request.requirements or "") + len(request.architecture or "")
    if total > settings.max_input_chars:
        raise HTTPException(
            status_code=413,
            detail=(
                f"输入内容过长（{total} 字符），超过上限 {settings.max_input_chars} 字符。"
                "请精简文档后重试，或在 backend/.env 中调大 MAX_INPUT_CHARS。"
            ),
        )
    # P1-8：图片总字节校验（attachments + pasted_images）
    from ..services.image_pipeline import validate_image_byte_budget
    all_images = list(request.attachments or []) + list(request.pasted_images or [])
    validate_image_byte_budget(all_images)


# ----------------------------------------------------------------------
# 健康检查
# ----------------------------------------------------------------------
@router.get("/api/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """健康检查。

    LLM 状态从 llm_config_store 读取（admin 在 UI 配置后立即生效），
    不再读 settings.llm_configured（那是启动时的快照，无法热更新）。
    """
    cfg = llm_config_store.get_config()
    return HealthResponse(
        status="ok",
        llm_configured=cfg["configured"],
        base_url=cfg["base_url"] if cfg["configured"] else "",
        model=cfg["model"] if cfg["configured"] else "",
    )


# ----------------------------------------------------------------------
# LLM 统一配置（管理员在 UI 一次性配置，全公司用户共享）
# ----------------------------------------------------------------------
def _is_admin(user: dict) -> bool:
    """当前用户是否为管理员（可改 LLM 配置）。"""
    return (user or {}).get("role") in {"admin", "secops"}


@router.get("/api/llm/config", response_model=LLMConfigPublic)
async def get_llm_config(
    current_user: dict = Depends(get_sdlc_user),
) -> LLMConfigPublic:
    """读取公司统一的 LLM 配置（**所有登录用户可读**）。

    - 非管理员：返回 base_url / model / configured / api_key_masked（脱敏），
      用于前端展示"已为公司配置 X 模型"等状态。
    - 管理员（admin / secops）：额外返回 is_admin=true 标记，
      前端据此显示"编辑配置"入口。

    **完整 api_key 永远不返回给前端**（仅在内存中给 LLMClient 构造使用）。
    """
    admin = _is_admin(current_user)
    cfg = llm_config_store.get_public_config(for_admin=admin)
    return LLMConfigPublic(**cfg)


@router.post("/api/llm/config", response_model=LLMConfigPublic)
async def update_llm_config(
    body: LLMConfigUpdate,
    current_user: dict = Depends(get_sdlc_user),
) -> LLMConfigPublic:
    """保存公司统一的 LLM 配置（**仅 admin / secops**）。

    - api_key 留空 → 保留旧值（不覆盖），便于只改 model。
    - 立即写入磁盘 + 内存，下一次 LLMClient 构造生效，
      **用户无需刷新页面、无需重启后端**。
    """
    if not _is_admin(current_user):
        raise HTTPException(
            status_code=403,
            detail="仅管理员可修改 LLM 统一配置，请联系管理员",
        )
    try:
        cfg = llm_config_store.set_config(
            base_url=body.base_url,
            api_key=body.api_key,
            model=body.model,
            updated_by=(current_user or {}).get("username") or "admin",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return LLMConfigPublic(**cfg)


@router.delete("/api/llm/config")
async def delete_llm_config(
    current_user: dict = Depends(get_sdlc_user),
) -> dict[str, Any]:
    """清空公司统一的 LLM 配置（**仅 admin / secops**）。

    清空后所有用户立即无法调用 LLM。重启后端会从 .env 自动 load 回来（如果 .env 里有）。
    """
    if not _is_admin(current_user):
        raise HTTPException(
            status_code=403,
            detail="仅管理员可清空 LLM 统一配置",
        )
    llm_config_store.clear_config()
    return {"cleared": True}


# ----------------------------------------------------------------------
# 异步 AI 威胁建模
# ----------------------------------------------------------------------
@router.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(
    request: AnalyzeRequest,
    req: Request,
    _auth: None = Depends(verify_api_key),
    _rl: None = Depends(enforce_rate_limit),
    current_user: dict = Depends(get_sdlc_user),
) -> AnalyzeResponse:
    """异步提交 AI 威胁建模任务，立即返回 task_id。

    真实的分析流程在后台执行，前端通过 ``GET /api/tasks/{task_id}``
    轮询进度与结果。流程：文档 -> DFD 数据流图 -> STRIDE 威胁 -> 威胁模型。

    P0-1 in-flight 去重：同 owner + 同 fingerprint 在 5 秒内视为重复提交，
    直接复用已注册的 task_id（前端轮询同一任务），不再开新的 LLM 任务。
    """
    # 输入长度校验
    validate_input_chars(request)

    # 按所选方法论动态生成进度阶段
    analyze_steps = _build_analyze_steps(request.methodology)

    owner_username = (current_user or {}).get("username") or ""
    fingerprint = _compute_fingerprint(request)

    # P0-1 in-flight 去重：同 owner + 同 fp 在 TTL 内复用 task_id
    if owner_username:
        existing = _INFLIGHT.get((owner_username, fingerprint))
        if existing:
            ts, existing_tid = existing
            if nc.epoch() - ts <= _INFLIGHT_TTL_SEC:
                logger.info(
                    "P0-1 in-flight 去重：复用 task_id=%s（owner=%s, fp=%s, age=%.2fs）",
                    existing_tid, owner_username, fingerprint, nc.epoch() - ts,
                )
                return AnalyzeResponse(
                    task_id=existing_tid,
                    status=TaskStatus.RUNNING,
                    steps=analyze_steps,
                    deduped=True,
                )

    # 创建任务并立即返回
    task_id = task_manager.create(analyze_steps)
    task_manager.mark_running(task_id)
    if owner_username:
        _register_inflight(owner_username, fingerprint, task_id)

    # 后台执行完整分析
    asyncio.get_running_loop().create_task(
        _run_analysis_task(
            task_id,
            request.requirements,
            request.architecture or "",
            request.images,
            llm_overrides=(
                {
                    "base_url": request.llm.base_url,
                    "api_key": request.llm.api_key,
                    "model": request.llm.model,
                }
                if request.llm
                else None
            ),
            methodology=request.methodology,
            industry=request.industry,
            attachments=request.attachments,
            pasted_images=request.pasted_images,
            title=request.title,
            owner=current_user if current_user.get("user_id") else None,
            fingerprint=fingerprint,
        )
    )
    logger.info(
        "已提交分析任务 %s（IP=%s, user=%s, fp=%s）",
        task_id,
        _client_ip(req),
        owner_username or "-",
        fingerprint,
    )
    return AnalyzeResponse(task_id=task_id, status=TaskStatus.RUNNING, steps=analyze_steps)


@router.get("/api/tasks/{task_id}", response_model=TaskResponse)
async def get_task(
    task_id: str,
    _auth: None = Depends(verify_api_key),
) -> TaskResponse:
    """查询异步分析任务的进度与结果。"""
    try:
        task = task_manager.get(task_id)
    except TaskNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return TaskResponse(
        id=task["id"],
        status=task["status"],
        progress=task["progress"],
        steps=task["steps"],
        step_index=task["step_index"],
        log=[TaskStepLog(time=entry["time"], message=entry["message"]) for entry in task["log"]],
        result=task["result"],
        error=task["error"],
        status_code=task.get("status_code"),
    )


# ----------------------------------------------------------------------
# 后台任务执行
# ----------------------------------------------------------------------
def _build_llm(llm_overrides: dict[str, Any] | None) -> LLMClient:
    """构建 LLM 客户端（界面传入配置优先，否则用 .env 默认值）。"""
    return LLMClient(
        base_url=(llm_overrides or {}).get("base_url"),
        api_key=(llm_overrides or {}).get("api_key"),
        model=(llm_overrides or {}).get("model"),
    )


def _map_llm_error(exc: Exception) -> HTTPException:
    """把 LLM 相关异常映射为带合适状态码的 HTTPException。"""
    if isinstance(exc, AuthenticationError):
        return HTTPException(
            status_code=401,
            detail=f"LLM 鉴权失败：{exc}。请检查 API Key 是否正确。",
        )
    if isinstance(exc, BadRequestError):
        return HTTPException(
            status_code=502,
            detail=f"LLM 请求被拒绝：{exc}。请检查 base_url 与 model 名是否匹配该服务。",
        )
    if isinstance(exc, APIStatusError):
        return HTTPException(
            status_code=502,
            detail=f"LLM 服务返回 {exc.status_code}：{exc}。",
        )
    if isinstance(exc, (ValueError, RuntimeError)):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail=f"AI 分析失败: {exc}")


def _finish_cancelled(task_id: str) -> None:
    """标记任务为已取消（供协程在步骤边界检查后调用）。"""
    task_manager.mark_cancelled(task_id)


async def _run_analysis_task(
    task_id: str,
    requirements: str,
    architecture: str,
    images: list[str] | None,
    llm_overrides: dict[str, Any] | None,
    methodology: str = "STRIDE",
    industry: str | None = None,
    attachments: list[str] | None = None,
    pasted_images: list[str] | None = None,    # P0-3：用户在前端粘贴的图（多模态进 LLM）
    title: str | None = None,
    owner: dict[str, Any] | None = None,
    fingerprint: str | None = None,
) -> None:
    """后台执行完整的 AI 威胁建模流程，并逐步上报进度。"""
    owner_username = (owner or {}).get("username") or ""
    # 开始收集本次建模产生的 LLM 响应缓存键（供删除结果时精准失效）
    from ..services.llm_cache import begin_cache_run, end_cache_run
    begin_cache_run()
    try:
        # 归一化方法论
        from ..services.methodology import normalize_methodology
        from ..services.ai_knowledge import get_industry_template

        method = normalize_methodology(methodology)
        task_manager.add_log(task_id, f"采用威胁建模方法论：{method}")

        # P2-12：轻量架构推理——用户没给 architecture 时，从 requirements 推断
        inferred_arch_meta: dict[str, Any] | None = None
        if not (architecture or "").strip():
            try:
                from ..services.architecture_reasoner import infer_architecture
                inferred = infer_architecture(requirements)
                if inferred.get("arch_text"):
                    architecture = "（自动推断，置信度 {:.0%}）\n{}".format(
                        inferred["confidence"], inferred["arch_text"]
                    )
                    inferred_arch_meta = inferred
                    if inferred.get("matched_template"):
                        task_manager.add_log(
                            task_id,
                            f"未提供架构文档，已按标准模板「{inferred['matched_template']}」"
                            f"（置信度 {inferred['confidence']:.0%}）自动补全",
                        )
                    else:
                        task_manager.add_log(
                            task_id,
                            f"未提供架构文档，已按关键词命中自动补全"
                            f"（{len(inferred['matched_components'])} 个组件，置信度 {inferred['confidence']:.0%}）",
                        )
                else:
                    task_manager.add_log(
                        task_id, "未提供架构文档，且无法从需求中推断（继续使用空架构）"
                    )
            except Exception as exc:  # noqa: BLE001
                logger.warning("架构推理失败：%s", exc)

        # 行业场景模板（STRIDE-AI 下可选）
        industry_hint = None
        if industry:
            tmpl = get_industry_template(industry)
            if tmpl:
                industry_hint = tmpl["prompt_hint"]
                task_manager.add_log(
                    task_id,
                    f"应用行业场景模板：{tmpl['label']}（重点关注 "
                    f"{'、'.join(tmpl['priority_threats'])}）",
                )
            else:
                task_manager.add_log(task_id, f"行业场景 {industry} 未命中模板，使用通用分析")

        # 构建 LLM 客户端
        try:
            llm = _build_llm(llm_overrides)
        except ValueError as exc:
            task_manager.fail(task_id, str(exc), status_code=400)
            return
        task_manager.add_log(task_id, "LLM 连接就绪")

        # P0-3：合并多模态图片（附件 + 粘贴图），按总上限截断并去重
        from ..services.image_pipeline import merge_image_data_uris
        merged_images, img_truncated, img_deduped = merge_image_data_uris(
            attachments or [], pasted_images or []
        )
        if pasted_images:
            task_manager.add_log(
                task_id,
                f"已合并 {len(attachments or [])} 张附件图 + {len(pasted_images or [])} 张粘贴图 → "
                f"{len(merged_images)} 张多模态图（{img_truncated} 张被截断，{img_deduped} 张去重）",
            )

        # P1-8：阶段内细粒度进度回调。
        # - progress(msg, sub_progress) 任意调用点都可推 sub（sub 0~1）
        # - 长 LLM 期间是黑盒（一个 await 30~90s），无法内推；用 _heartbeat
        #   后台协程每 2s 自动从 start_sub 线性推到 end_sub（保留 end-1 给
        #   LLM 完成后的真实 sub 推送），让进度条"动起来"而不是卡 30s
        def _progress_factory(step_index: int, log: bool = True):
            def _cb(msg: str, sub_progress: float | None = None) -> None:
                if log and msg:
                    task_manager.add_log(task_id, msg)
                if sub_progress is not None:
                    task_manager.mark_step(
                        task_id, step_index, sub_progress=sub_progress
                    )
            return _cb

        def _heartbeat(
            step_index: int,
            start_sub: float,
            end_sub: float,
            interval: float = 2.0,
        ):
            """在 LLM 黑盒调用期间的后台心跳：每 interval 秒把 sub 从
            start_sub 线性推到 end_sub - 0.05（保留少量余量给 LLM 完成
            后的真实 sub 推送），让前端进度条持续可见推进。

            返回 ``(task, stop_event)``：调用方 await asyncio.create_task(task) 启动，
            LLM 完成后调用 stop_event.set() 让心跳协程在下一次循环优雅退出。
            """
            stop_event = asyncio.Event()

            async def _run() -> None:
                # 留 5% 余量给真实 sub（避免心跳推太满导致 mark_step 后续被
                # 较小的真实 sub 覆盖时进度条"回退"）。
                cap = max(start_sub, end_sub - 0.05)
                i = 0
                while not stop_event.is_set():
                    # 线性插值（最多 60 步 ≈ 2 分钟），公式：
                    #   sub = start + (cap - start) * (i / 60)
                    frac = min(1.0, i / 60.0)
                    sub = start_sub + (cap - start_sub) * frac
                    try:
                        task_manager.mark_step(
                            task_id, step_index, sub_progress=sub
                        )
                    except Exception:  # noqa: BLE001 - 心跳不影响主流程
                        pass
                    i += 1
                    try:
                        await asyncio.wait_for(stop_event.wait(), timeout=interval)
                    except asyncio.TimeoutError:
                        continue
                    else:
                        return

            task = asyncio.create_task(_run())
            return task, stop_event

        # 1. 文档分析 -> DFD 元素
        task_manager.mark_step(task_id, 0, sub_progress=0.05)
        analyzer = DocumentAnalyzer(llm)
        # P1-8: LLM 期间 0.10→0.40 心跳；真实 sub 由 analyzer.analyze 内部进度回调推送
        hb_task, hb_stop = _heartbeat(0, start_sub=0.10, end_sub=0.45)
        try:
            dfd = await analyzer.analyze(
                requirements,
                architecture,
                images,
                progress=_progress_factory(0),
                methodology=method,
                image_data_uris=merged_images,
            )
        finally:
            hb_stop.set()
            try:
                await asyncio.wait_for(hb_task, timeout=1.0)
            except (asyncio.TimeoutError, Exception):
                hb_task.cancel()
        if task_manager.is_cancelled(task_id):
            _finish_cancelled(task_id)
            return
        components = dfd["components"]
        flows = dfd["flows"]
        # P1-8: 阶段收尾 - refine 路径 analyzer 内部已推 0.85；非 refine 路径这里补推。
        # 同值幂等，不影响已有 sub 进度。
        task_manager.mark_step(task_id, 0, sub_progress=0.85)
        task_manager.mark_step(task_id, 1)
        task_manager.add_log(
            task_id,
            f"识别出 {len(components)} 个组件、{len(flows)} 条数据流",
        )

        # 1.5 DFD AI 自校验：让 LLM 对生成的 components/flows 做一次合理性自查
        #    并确定性纠偏（类型/生命周期合法化、去自环/悬空/重复）。可配置关闭，
        #    失败静默降级为原结果，不影响主流程。
        if getattr(settings, "dfd_review_enabled", True):
            task_manager.mark_step(task_id, 1, sub_progress=0.55, message="DFD AI 自校验中…")
            # P1-8: 0.60→0.90 心跳
            hb_task, hb_stop = _heartbeat(1, start_sub=0.60, end_sub=0.95)
            try:
                review_result = await DFDReviewer(llm).review(components, flows)
            finally:
                hb_stop.set()
                try:
                    await asyncio.wait_for(hb_task, timeout=1.0)
                except (asyncio.TimeoutError, Exception):
                    hb_task.cancel()
            components = review_result["components"]
            flows = review_result["flows"]
            for log_line in review_result["log"]:
                task_manager.add_log(task_id, log_line)
        task_manager.mark_step(task_id, 1, sub_progress=0.95)

        # 2. 威胁识别（组件 + 数据流都纳入方法论分析）
        #    行业模板：为 STRIDE-AI 组件注入行业相关的 AI 属性默认值
        if method == "STRIDE-AI" and industry:
            tmpl = get_industry_template(industry)
            if tmpl:
                ai_props = tmpl["ai_props"]
                for c in components:
                    if c.get("type") in (
                        "model", "process", "vectorstore", "tool",
                        "prompt", "agentconfig", "trainingdata",
                    ):
                        for k, v in ai_props.items():
                            c.setdefault(k, v)
        threat_analyzer = ThreatAnalyzer(llm)
        # P1-8: 0.10→0.55 心跳（LLM 主体调用 30~90s）；后处理由 analyze_components 内部
        # 通过 progress(msg, sub) 推 0.55→0.95；最后 mark_step(2) 走 1.0
        hb_task, hb_stop = _heartbeat(2, start_sub=0.10, end_sub=0.55)
        try:
            threats = await threat_analyzer.analyze_components(
                components,
                flows=flows,
                progress=_progress_factory(2),
                methodology=method,
                industry_hint=industry_hint,
            )
        finally:
            hb_stop.set()
            try:
                await asyncio.wait_for(hb_task, timeout=1.0)
            except (asyncio.TimeoutError, Exception):
                hb_task.cancel()
        if task_manager.is_cancelled(task_id):
            _finish_cancelled(task_id)
            return
        task_manager.mark_step(task_id, 2)

        # 3. 构建模型
        builder = ThreatModelBuilder()
        model = builder.build(
            summary=dfd["summary"],
            diagram=dfd["diagram"],
            components=components,
            flows=flows,
            threats=threats,
            methodology=method,
        )
        task_manager.mark_step(task_id, 3)
        task_manager.add_log(task_id, f"威胁模型构建完成，共 {len(threats)} 条威胁")

        stats = {
            "componentCount": len(components),
            "flowCount": len(flows),
            "threatCount": len(threats),
            "threatCountBySeverity": _count_by_severity(threats),
            "threatCountByType": _count_by_type(threats),
            "industry": industry,
            "metrics": _build_metrics(method, components, flows, threats),
        }

        # 完成：存储最终结果（并持久化到历史库，供结果页查看/导出）
        source_text = (requirements or "")[:4000]
        # 结束缓存键收集：本次建模产生的缓存键随结果一起落盘，
        # 删除该结果时会据此失效对应输入的缓存。
        cache_keys = end_cache_run()
        try:
            meta = result_store.save(
                model=model,
                summary=dfd["summary"],
                stats=stats,
                methodology=method,
                source_text=source_text,
                cache_keys=cache_keys,
                title=title,
                owner=owner,
                fingerprint=fingerprint,
            )
        except Exception:
            logger.exception("持久化建模结果失败（不影响本次任务）")
            meta = None
        result_id = meta["id"] if meta else None

        # 缓存可观测：本次任务的 LLM 调用是否命中响应缓存。
        # 命中 → 结果与历史某次完全一致（确定性复现）；未命中 → 全新分析。
        from ..services.llm_client import last_cache_hit

        cache_meta = {"hit": last_cache_hit()}

        task_manager.complete(
            task_id,
            {
                "model": model,
                "summary": dfd["summary"],
                "stats": stats,
                "result_id": result_id,
                "cache_meta": cache_meta,
                # DFD 自动纠错日志（如「组件 X 类型 process → datastore」），供前端透出
                "dfd_autofix": list(dfd.get("diagram", {}).get("autofixLog") or []),
            },
        )
        logger.info("分析任务 %s 完成（%d 威胁，result_id=%s）", task_id, len(threats), result_id)
    except HTTPException as exc:
        task_manager.fail(task_id, exc.detail, status_code=exc.status_code)
    except Exception as exc:  # 统一兜底
        logger.exception("分析任务 %s 失败", task_id)
        http_exc = _map_llm_error(exc)
        task_manager.fail(task_id, http_exc.detail, status_code=http_exc.status_code)
    finally:
        # P0-1：任务结束（无论成功/失败/取消）必须释放 in-flight 槽位，
        # 否则用户在 5 秒窗口内无法再次提交相同输入。
        if owner_username and fingerprint:
            _unregister_inflight(owner_username, fingerprint, task_id)


def _count_by_severity(threats: list[dict]) -> dict[str, int]:
    from collections import Counter

    return dict(Counter(t.get("severity", "Unknown") for t in threats))


def _count_by_type(threats: list[dict]) -> dict[str, int]:
    from collections import Counter

    return dict(Counter(t.get("type", "Unknown") for t in threats))


def _build_metrics(
    methodology: str,
    components: list[dict],
    flows: list[dict],
    threats: list[dict],
) -> dict[str, Any]:
    """构建度量指标：覆盖度 / 风险收敛率 / DREAD 均值 / OWASP LLM 覆盖 / 合规映射。"""
    metrics: dict[str, Any] = {}
    from ..services.ai_knowledge import get_compliance_mapping

    # 覆盖度：已建模元素（组件 + 数据流）中有威胁的元素占比。
    # 威胁既可挂在组件上也可挂在数据流上，分母必须包含两者，否则会虚高甚至 >100%。
    total_elems = len(components) + len(flows or [])
    modeled = set(t.get("componentId") for t in threats)
    metrics["coverageRate"] = round(len(modeled) / total_elems, 3) if total_elems else 0
    metrics["modeledElements"] = len(modeled)
    metrics["totalElements"] = total_elems

    # 风险收敛率：已缓解/不适用/范围外的高危威胁占比
    high_critical = [
        t for t in threats if t.get("severity") in ("High", "Critical")
    ]
    if high_critical:
        closed = [
            t for t in high_critical
            if t.get("status") in ("Mitigated", "NotApplicable")
        ]
        metrics["riskConvergence"] = round(len(closed) / len(high_critical), 3)
    else:
        metrics["riskConvergence"] = 0.0

    # DREAD 评级均值（STRIDE-AI）
    if methodology == "STRIDE-AI":
        dread_keys = ["damage", "reproducibility", "exploitability", "affectedUsers", "discoverability"]
        averages: dict[str, float] = {}
        for k in dread_keys:
            vals = [
                t["dread"].get(k, 0) for t in threats
                if isinstance(t.get("dread"), dict)
            ]
            averages[k] = round(sum(vals) / len(vals), 2) if vals else 0.0
        scores = [
            t.get("dreadScore", 0) for t in threats
            if isinstance(t.get("dread"), dict)
        ]
        metrics["dreadAverage"] = {
            **averages,
            "total": round(sum(scores) / len(scores), 2) if scores else 0.0,
        }

    # OWASP Top 10 for LLM 覆盖：以威胁类型/标题映射到 LLM 条目
    if methodology == "STRIDE-AI":
        from ..services.ai_knowledge import get_owasp_llm_list

        llm_items = get_owasp_llm_list()
        covered: list[str] = []
        text_blob = " ".join(
            f"{t.get('title','')} {t.get('description','')} {t.get('cwe','')}"
            for t in threats
        ).lower()
        for it in llm_items:
            code = it["code"].lower()
            title_kw = it["title"].lower().replace(" ", "")
            # 以条目英文标题关键词是否命中威胁描述为覆盖判断
            if code in text_blob or title_kw.replace(" ", "") in text_blob.replace(" ", ""):
                covered.append(it["code"])
        metrics["owaspLlmCovered"] = covered
        metrics["owaspLlmCoverRate"] = round(len(covered) / len(llm_items), 3) if llm_items else 0

    # 合规映射
    comp = get_compliance_mapping()
    threat_types = set(t.get("type", "") for t in threats)
    mapped = [
        {
            "code": c["code"],
            "label": c["label"],
            "covered": bool(set(c["threat_types"]) & threat_types),
        }
        for c in comp
    ]
    metrics["compliance"] = mapped
    return metrics


# ----------------------------------------------------------------------
# 历史建模结果管理
# ----------------------------------------------------------------------
@router.get("/api/results", response_model=ResultListResponse)
async def list_results(
    _auth: None = Depends(verify_api_key),
    page: int = Query(1, ge=1, description="页码（从 1 开始）"),
    page_size: int = Query(20, ge=1, le=100, description="每页条数"),
    methodology: str | None = Query(None, description="按方法论筛选"),
    keyword: str | None = Query(None, description="按标题关键词搜索"),
    current_user: dict = Depends(get_sdlc_user),
) -> ResultListResponse:
    """返回已保存的建模结果元数据（按时间倒序，支持分页 / 筛选 / 搜索）。

    权限规则：
    - 系统管理员 (admin) / 安全专家 (secops)：可看到所有结果
    - 其他角色：仅看到自己建模的结果
    """
    items = result_store.list(user=current_user)
    # 筛选
    if methodology:
        items = [i for i in items if i.get("methodology") == methodology]
    if keyword:
        kw = keyword.strip().lower()
        items = [i for i in items if kw in (i.get("title") or "").lower()]
    # 分页
    total = len(items)
    pages = max(1, -(-total // page_size)) if total else 1
    page = min(page, pages)
    start = (page - 1) * page_size
    paged = items[start : start + page_size]
    return ResultListResponse(
        items=[ResultMeta(**item) for item in paged],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/api/results/{result_id}", response_model=ResultDetailResponse)
async def get_result(
    result_id: str,
    _auth: None = Depends(verify_api_key),
    current_user: dict = Depends(get_sdlc_user),
) -> ResultDetailResponse:
    """返回单个建模结果的完整详情。"""
    try:
        record = result_store.get(result_id, user=current_user)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if not record:
        raise HTTPException(status_code=404, detail=f"结果不存在：{result_id}")
    return ResultDetailResponse(
        id=record["id"],
        title=record["title"],
        methodology=record["methodology"],
        created_at=record["created_at"],
        model=record["model"],
        summary=record.get("summary", ""),
        stats=record.get("stats", {}),
    )


@router.delete("/api/results/{result_id}")
async def delete_result(
    result_id: str,
    _auth: None = Depends(verify_api_key),
    current_user: dict = Depends(get_sdlc_user),
) -> dict[str, Any]:
    """删除一条历史建模结果。

    权限：
    - admin / secops：可删除任意结果
    - 其他用户：仅可删除自己建模的结果

    删除时会一并失效该结果对应输入的 LLM 响应缓存，
    保证删除后重新建模不会命中旧结果，而是真实调用 LLM 重新分析。
    """
    # 删除前先取出该结果记录，用于获取对应输入的缓存键与 owner 校验
    try:
        record = result_store.get(result_id, user=current_user)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if not record:
        raise HTTPException(status_code=404, detail=f"结果不存在：{result_id}")
    try:
        deleted = result_store.delete(result_id, user=current_user)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if not deleted:
        raise HTTPException(status_code=404, detail=f"结果不存在：{result_id}")
    # 失效该结果对应的缓存键。
    #
    # 规则：
    # 1) 结果记录带 cache_keys（新格式）→ 精准失效这些键，不误伤其它结果复用缓存；
    # 2) 结果记录没有 cache_keys 字段（cache_keys 落盘功能上线前保存的旧格式，
    #    无法反查它复用了哪些缓存键）→ 清空整个 LLM 缓存兜底，
    #    确保删除后重新建模（相同输入）不会命中旧结果，而是真实重新分析。
    from ..services.llm_cache import get_llm_cache
    record_keys = (record or {}).get("cache_keys")
    if isinstance(record_keys, list) and record_keys:
        removed = get_llm_cache().remove_keys(record_keys)
        logger.info(
            "删除结果 %s 后已精准失效 %d 条 LLM 响应缓存", result_id, removed
        )
    elif "cache_keys" not in (record or {}):
        # 旧格式结果：无 cache_keys 信息，清空缓存保证删除后必重新分析
        cleared = get_llm_cache().clear()
        logger.info(
            "删除旧格式结果 %s 后已清空 %d 条 LLM 响应缓存（无 cache_keys 可精准失效）",
            result_id, cleared,
        )
    return {"deleted": True, "id": result_id}


@router.patch("/api/results/{result_id}")
async def rename_result(
    result_id: str,
    body: RenameResultBody,
    _auth: None = Depends(verify_api_key),
    current_user: dict = Depends(get_sdlc_user),
) -> dict[str, Any]:
    """重命名一条历史建模结果的标题，便于检索。

    权限：admin / secops 可重命名任意结果；其他用户仅可重命名自己建模的结果。
    """
    try:
        renamed = result_store.rename(result_id, body.title, user=current_user)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if not renamed:
        raise HTTPException(status_code=404, detail=f"结果不存在：{result_id}")
    return {"renamed": True, "id": result_id, "title": body.title.strip()}


@router.get("/api/results/{result_id}/export")
async def export_result(
    result_id: str,
    _auth: None = Depends(verify_api_key),
    current_user: dict = Depends(get_sdlc_user),
    format: str = Query("md", description="导出格式：md | json | csv | docx"),
):
    """导出指定建模结果（Markdown / Threat Dragon JSON / CSV 威胁清单 / Word 报告）。

    权限：admin / secops 可导出任意结果；其他用户仅可导出自己建模的结果。
    """
    try:
        record = result_store.get(result_id, user=current_user)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if not record:
        raise HTTPException(status_code=404, detail=f"结果不存在：{result_id}")

    # 统一文件名：威胁建模标题 + 时间戳
    title = (record.get("title") or "threat-model").strip() or "threat-model"
    # ASCII-only safe title for HTTP header (Python 3 str.isalnum() 接受 Unicode，需要 .isascii() 限制)
    ascii_title = "".join(c if c.isascii() and c.isalnum() else "_" for c in title)
    ascii_title = "".join(c for c in ascii_title if c.isalnum() or c in "_-").strip("_-_") or "export"
    ts = nc.now().strftime("%Y%m%d_%H%M%S")
    ascii_filename = f"{ascii_title}_{ts}.{format}"
    # RFC 5987: 中文/Unicode 文件名用 filename* (UTF-8''percent-encoded) + ASCII fallback
    content_disp = (
        f'attachment; filename="{ascii_filename}"; '
        f"filename*=UTF-8''{quote(f'{title}_{ts}.{format}')}"
    )
    filename = ascii_filename

    if format == "json":
        content = render_result_json(record)
        media_type = "application/json; charset=utf-8"
    elif format == "csv":
        content = render_result_csv(record)
        media_type = "text/csv; charset=utf-8"
    elif format == "docx":
        try:
            payload = render_result_docx(record)
        except Exception as e:  # python-docx 未安装等
            raise HTTPException(status_code=500, detail=f"Word 导出失败：{e}") from e
        return StreamingResponse(
            io.BytesIO(payload),
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": content_disp},
        )
    else:  # 默认 md
        content = render_result_markdown(record)
        media_type = "text/markdown; charset=utf-8"
    return PlainTextResponse(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": content_disp},
    )


@router.patch("/api/results/{result_id}/threats/{threat_id}")
async def update_threat_status(
    result_id: str,
    threat_id: str,
    body: ThreatStatusUpdate,
    _auth: None = Depends(verify_api_key),
    current_user: dict = Depends(get_sdlc_user),
) -> dict[str, Any]:
    """更新指定结果中某条威胁的处置状态（Open → Mitigated 等）并持久化。

    权限：admin / secops 可修改任意结果；其他用户仅可修改自己建模的结果。
    """
    try:
        updated = result_store.update_threat_status(
            result_id,
            threat_id,
            new_status=body.status,
            out_of_scope=body.outOfScope,
            user=current_user,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if not updated:
        raise HTTPException(
            status_code=404, detail="结果或威胁不存在，无法更新状态"
        )
    return {
        "updated": True,
        "result_id": result_id,
        "threat_id": threat_id,
        "status": body.status,
        "outOfScope": body.outOfScope,
    }


# ----------------------------------------------------------------------
# 场景模板库
# ----------------------------------------------------------------------
@router.get("/api/system-prompt")
async def get_system_prompt(
    methodology: str = Query("STRIDE", description="方法论名（STRIDE/STRIDE-AI/...）"),
    industry: str | None = Query(None, description="可选的行业场景，注入到提示词中"),
    _auth: None = Depends(verify_api_key),
) -> dict[str, Any]:
    """返回某个方法论下真实构建出的系统提示词——便于前端调试与透明度展示。

    注意：此处只依赖 ``ThreatAnalyzer._build_system_prompt`` 的字符串拼接逻辑，
    不调用任何外部 LLM 接口，是纯函数。
    """
    from ..services.llm_client import LLMClient as _DummyClient

    # 构造一个最小可用的实例，仅用于构造系统提示词（不发起任何调用）
    dummy = ThreatAnalyzer(_DummyClient(api_key="dummy", base_url="http://localhost"))
    prompt = dummy._build_system_prompt(methodology, industry)
    return {
        "methodology": methodology,
        "industry": industry,
        "system_prompt": prompt,
        "length": len(prompt),
    }


@router.get("/api/templates", response_model=TemplateListResponse)
async def list_templates(
    _auth: None = Depends(verify_api_key),
) -> TemplateListResponse:
    """返回示例场景模板库（健康产品线相关场景，可直接一键填充）。"""
    from ..services.scenario_templates import list_templates as _list_templates

    return TemplateListResponse(
        items=[TemplateItem(**t) for t in _list_templates()]
    )


# ----------------------------------------------------------------------
# 任务取消
# ----------------------------------------------------------------------
@router.post("/api/tasks/{task_id}/cancel")
async def cancel_task(
    task_id: str,
    _auth: None = Depends(verify_api_key),
) -> dict[str, Any]:
    """取消一个进行中的分析任务。"""
    try:
        ok = task_manager.cancel(task_id)
    except TaskNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if not ok:
        raise HTTPException(status_code=400, detail="任务已完成或正在结束，无法取消")
    return {"cancelled": True, "id": task_id}


# ----------------------------------------------------------------------
# 文档上传与解析
# ----------------------------------------------------------------------
@router.post("/api/upload")
async def upload_document(
    file: UploadFile = File(...),
    _auth: None = Depends(verify_api_key),
) -> dict[str, Any]:
    """上传需求/架构文档。

    支持 .txt / .md / .pdf / .docx。除抽取纯文本外，还会：
    1. 把原始文档保存为附件（attachment_id），后续建模时作为整体读取；
    2. 从 PDF/DOCX 中抽取内嵌图片（架构图/数据流图等）为 data URI，
       供多模态 LLM 直接分析，避免转成纯文本丢失图表信息。

    返回 ``extracted``（可回填到输入框，纯文本降级用）与 ``images``
    （图片 data URI，随建模请求一并提交给 AI）。
    """
    data = await file.read()
    # 文档解析（PDF/DOCX 抽取 + 图片压缩）与附件落盘都是 CPU/IO 阻塞操作。
    # 必须放到线程池里执行，否则会阻塞整个事件循环，导致大文档上传期间
    # 页面其它请求（健康检查/任务轮询/模板）全部卡死、看起来像"页面卡死"。
    loop = asyncio.get_running_loop()
    try:
        assets = await loop.run_in_executor(
            None,
            lambda: extract_assets(file.filename or "", data),
        )
    except UnsupportedFileTypeError as exc:
        raise HTTPException(status_code=415, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    text = assets.get("text", "")
    images = assets.get("images", []) or []
    if not text.strip() and not images:
        raise HTTPException(
            status_code=422,
            detail="未能从文档中提取到任何文本或图片，请检查文件内容",
        )

    # 保存原始文档为附件（含抽取图片），供后续 AI 建模按整体读取
    meta = await loop.run_in_executor(
        None,
        lambda: save_attachment(
            file.filename or "",
            data,
            extracted_text=text,
            images=images,
        ),
    )

    return {
        "attachment_id": meta["attachment_id"],
        "filename": meta["filename"],
        "filetype": meta["filetype"],
        "chars": len(text),
        "image_count": meta.get("image_count", len(images)),
        "image_original_count": meta.get("image_original_count", len(images)),
        "image_truncated": meta.get("image_truncated", False),
        "image_oversized": meta.get("image_oversized", 0),
        "warnings": assets.get("warnings", []),   # P1-5：抽取过程告警
        "extracted": text,
        "images": images,
    }


# ----------------------------------------------------------------------
# FastAPI 应用装配
# ----------------------------------------------------------------------
from fastapi import FastAPI

from app.utils import network_clock as nc
app = FastAPI(
    title="AI Threat Dragon",
    description="从需求文档和产品架构文档自动生成 DFD 数据流图并识别 STRIDE 威胁",
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(ValueError)
async def _value_error_handler(request: Request, exc: ValueError):
    """把 store 层的参数校验错误（如非法的 result_id/attachment_id 路径穿越尝试）
    统一映射为 400 Bad Request，而不是默认的 500。"""
    return PlainTextResponse(str(exc), status_code=400)


app.include_router(router)
