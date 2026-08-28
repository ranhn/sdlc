"""FastAPI 路由：健康检查、AI 威胁建模（异步任务）与任务进度查询。"""

from __future__ import annotations

import asyncio
import io
import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse
from openai import APIStatusError, AuthenticationError, BadRequestError

from ..config import settings
from ..models.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    HealthResponse,
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

# 根据配置初始化限流参数
rate_limiter.set_config(settings.rate_limit_per_minute)

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
    """校验输入长度，防止超大文档导致 LLM 超时或烧钱。"""
    total = len(request.requirements or "") + len(request.architecture or "")
    if total > settings.max_input_chars:
        raise HTTPException(
            status_code=413,
            detail=(
                f"输入内容过长（{total} 字符），超过上限 {settings.max_input_chars} 字符。"
                "请精简文档后重试，或在 backend/.env 中调大 MAX_INPUT_CHARS。"
            ),
        )


# ----------------------------------------------------------------------
# 健康检查
# ----------------------------------------------------------------------
@router.get("/api/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """健康检查。"""
    return HealthResponse(
        status="ok",
        llm_configured=settings.llm_configured,
        base_url=settings.llm_base_url if settings.llm_configured else "",
        model=settings.llm_model if settings.llm_configured else "",
    )


# ----------------------------------------------------------------------
# 异步 AI 威胁建模
# ----------------------------------------------------------------------
@router.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(
    request: AnalyzeRequest,
    req: Request,
    _auth: None = Depends(verify_api_key),
    _rl: None = Depends(enforce_rate_limit),
) -> AnalyzeResponse:
    """异步提交 AI 威胁建模任务，立即返回 task_id。

    真实的分析流程在后台执行，前端通过 ``GET /api/tasks/{task_id}``
    轮询进度与结果。流程：文档 -> DFD 数据流图 -> STRIDE 威胁 -> 威胁模型。
    """
    # 输入长度校验
    validate_input_chars(request)

    # 按所选方法论动态生成进度阶段
    analyze_steps = _build_analyze_steps(request.methodology)

    # 创建任务并立即返回
    task_id = task_manager.create(analyze_steps)
    task_manager.mark_running(task_id)

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
            title=request.title,
        )
    )
    logger.info("已提交分析任务 %s（IP=%s）", task_id, _client_ip(req))
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
    title: str | None = None,
) -> None:
    """后台执行完整的 AI 威胁建模流程，并逐步上报进度。"""
    # 开始收集本次建模产生的 LLM 响应缓存键（供删除结果时精准失效）
    from ..services.llm_cache import begin_cache_run, end_cache_run
    begin_cache_run()
    try:
        # 归一化方法论
        from ..services.methodology import normalize_methodology
        from ..services.ai_knowledge import get_industry_template

        method = normalize_methodology(methodology)
        task_manager.add_log(task_id, f"采用威胁建模方法论：{method}")

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

        # 1. 文档分析 -> DFD 元素
        task_manager.mark_step(task_id, 0)
        analyzer = DocumentAnalyzer(llm)
        dfd = await analyzer.analyze(
            requirements,
            architecture,
            images,
            progress=lambda msg: task_manager.add_log(task_id, msg),
            methodology=method,
            image_data_uris=attachments,
        )
        if task_manager.is_cancelled(task_id):
            _finish_cancelled(task_id)
            return
        components = dfd["components"]
        flows = dfd["flows"]
        task_manager.mark_step(task_id, 1)
        task_manager.add_log(
            task_id,
            f"识别出 {len(components)} 个组件、{len(flows)} 条数据流",
        )

        # 1.5 DFD AI 自校验：让 LLM 对生成的 components/flows 做一次合理性自查
        #    并确定性纠偏（类型/生命周期合法化、去自环/悬空/重复）。可配置关闭，
        #    失败静默降级为原结果，不影响主流程。
        if getattr(settings, "dfd_review_enabled", True):
            review_result = await DFDReviewer(llm).review(components, flows)
            components = review_result["components"]
            flows = review_result["flows"]
            for log_line in review_result["log"]:
                task_manager.add_log(task_id, log_line)

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
        threats = await threat_analyzer.analyze_components(
            components,
            flows=flows,
            progress=lambda msg: task_manager.add_log(task_id, msg),
            methodology=method,
            industry_hint=industry_hint,
        )
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
) -> ResultListResponse:
    """返回已保存的建模结果元数据（按时间倒序，支持分页 / 筛选 / 搜索）。"""
    items = result_store.list()
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
) -> ResultDetailResponse:
    """返回单个建模结果的完整详情。"""
    record = result_store.get(result_id)
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
) -> dict[str, Any]:
    """删除一条历史建模结果。

    删除时会一并失效该结果对应输入的 LLM 响应缓存，
    保证删除后重新建模不会命中旧结果，而是真实调用 LLM 重新分析。
    """
    # 删除前先取出该结果记录，用于获取对应输入的缓存键
    record = result_store.get(result_id)
    deleted = result_store.delete(result_id)
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
) -> dict[str, Any]:
    """重命名一条历史建模结果的标题，便于检索。"""
    renamed = result_store.rename(result_id, body.title)
    if not renamed:
        raise HTTPException(status_code=404, detail=f"结果不存在：{result_id}")
    return {"renamed": True, "id": result_id, "title": body.title.strip()}


@router.get("/api/results/{result_id}/export")
async def export_result(
    result_id: str,
    _auth: None = Depends(verify_api_key),
    format: str = Query("md", description="导出格式：md | json | csv | docx"),
):
    """导出指定建模结果（Markdown / Threat Dragon JSON / CSV 威胁清单 / Word 报告）。"""
    record = result_store.get(result_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"结果不存在：{result_id}")

    # 统一文件名：威胁建模标题 + 时间戳
    title = (record.get("title") or "threat-model").strip() or "threat-model"
    safe_title = "".join(c for c in title if c.isalnum() or c in "_- ").replace(" ", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{safe_title}_{ts}.{format}"

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
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{filename}"'
                )
            },
        )
    else:  # 默认 md
        content = render_result_markdown(record)
        media_type = "text/markdown; charset=utf-8"
    return PlainTextResponse(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.patch("/api/results/{result_id}/threats/{threat_id}")
async def update_threat_status(
    result_id: str,
    threat_id: str,
    body: ThreatStatusUpdate,
    _auth: None = Depends(verify_api_key),
) -> dict[str, Any]:
    """更新指定结果中某条威胁的处置状态（Open → Mitigated 等）并持久化。"""
    updated = result_store.update_threat_status(
        result_id,
        threat_id,
        new_status=body.status,
        out_of_scope=body.outOfScope,
    )
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
        "image_count": len(images),
        "extracted": text,
        "images": images,
    }


# ----------------------------------------------------------------------
# FastAPI 应用装配
# ----------------------------------------------------------------------
from fastapi import FastAPI

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
