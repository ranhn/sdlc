"""API 数据模型定义。"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class LLMConfig(BaseModel):
    """前端界面传入的 LLM 模型配置（地址 + API Key）。"""

    base_url: Optional[str] = Field(
        None, description="OpenAI 兼容 API 地址，如 https://api.deepseek.com/v1"
    )
    api_key: Optional[str] = Field(
        None, description="API Key"
    )
    model: Optional[str] = Field(
        None, description="模型名称，如 deepseek-chat"
    )


class AnalyzeRequest(BaseModel):
    """AI 威胁建模分析请求。"""

    title: Optional[str] = Field(
        "", description="威胁建模标题（用户自定义，为空时后端自动提取）"
    )
    requirements: str = Field(
        ..., description="系统需求文档文本内容", min_length=10
    )
    architecture: Optional[str] = Field(
        "", description="产品架构设计文档文本内容"
    )
    images: Optional[list[str]] = Field(
        None, description="架构图/流程图的可选描述文本"
    )
    attachments: Optional[list[str]] = Field(
        None,
        description=(
            "上传文档内嵌图片的 data URI 列表（架构图/数据流图等），"
            "以多模态方式交给 LLM 分析。模型不支持图片时后端自动降级为纯文本。"
        ),
    )
    llm: Optional[LLMConfig] = Field(
        None, description="界面传入的模型配置，优先于 .env 中的配置"
    )
    methodology: Optional[str] = Field(
        "STRIDE",
        description=(
            "威胁建模方法论：STRIDE / STRIDE-AI / CIA / CIADIE / LINDDUN / "
            "PLOT4ai / EOP。默认 STRIDE；STRIDE-AI 用于大模型/Agent/RAG 等 "
            "AI 系统的威胁建模。"
        ),
    )
    industry: Optional[str] = Field(
        None,
        description=(
            "可选行业场景模板：health（跨境健康产品线，美欧市场）。"
            "用于 STRIDE-AI 分析时注入行业相关 AI 威胁与属性。"
        ),
    )


class AnalyzeResponse(BaseModel):
    """AI 威胁建模分析的异步提交响应。

    分析在后台异步执行，前端通过 ``task_id`` 轮询任务状态。
    """

    task_id: str = Field(
        ..., description="异步任务 ID，用于轮询任务进度与结果"
    )
    status: str = Field(
        ..., description="任务初始状态，通常为 pending"
    )
    steps: list[str] = Field(
        default_factory=list, description="分析阶段名列表（用于展示真实进度）"
    )


class TaskStepLog(BaseModel):
    """任务日志条目。"""

    time: float
    message: str


class TaskResponse(BaseModel):
    """异步任务状态与结果查询响应。"""

    id: str
    status: str = Field(..., description="pending | running | success | error")
    progress: int = Field(..., description="0~100 的真实进度百分比")
    steps: list[str] = Field(default_factory=list)
    step_index: int = Field(0, description="当前进度阶段下标（0 基）")
    log: list[TaskStepLog] = Field(default_factory=list)
    result: Optional[dict[str, Any]] = Field(
        None, description="任务成功后的结果（含 model/summary/stats）"
    )
    error: Optional[str] = Field(None, description="任务失败时的错误信息")
    status_code: Optional[int] = Field(None, description="失败时的 HTTP 状态码建议")


class ResultMeta(BaseModel):
    """一条已保存的建模结果元数据（列表展示用）。"""

    id: str = Field(..., description="结果 ID")
    title: str = Field(..., description="结果标题（自动从输入提取）")
    methodology: str = Field(..., description="威胁建模方法论")
    created_at: float = Field(..., description="创建时间（epoch 秒）")
    stats: dict[str, Any] = Field(
        default_factory=dict, description="统计信息（组件数/威胁数等）"
    )
    owner_id: Optional[int] = Field(
        None, description="建模人用户 ID；历史无 owner 的旧结果为 None"
    )
    owner_username: str = Field(
        "", description="建模人用户名（SDLC 平台 username）"
    )
    owner_display_name: str = Field(
        "", description="建模人显示名（中文姓名 / 昵称）"
    )


class ResultListResponse(BaseModel):
    """历史建模结果列表响应（支持分页）。"""

    items: list[ResultMeta] = Field(
        default_factory=list, description="结果元数据列表（按时间倒序）"
    )
    total: int = Field(0, description="结果总数（过滤后）")
    page: int = Field(1, description="当前页")
    page_size: int = Field(20, description="每页条数")
    pages: int = Field(0, description="总页数")


class ThreatStatusUpdate(BaseModel):
    """更新单条威胁处置状态/范围外标记请求。"""

    status: str | None = Field(
        default=None, description="新处置状态：Open / Mitigated / Accepted / In Progress"
    )
    outOfScope: bool | None = Field(
        default=None, description="是否将该威胁标记为不在范围内"
    )


class RenameResultBody(BaseModel):
    """重命名一条建模结果标题请求。"""

    title: str = Field(
        ..., min_length=1, max_length=60, description="新的结果标题"
    )


class TemplateItem(BaseModel):
    """场景模板库条目。"""

    id: str = Field(..., description="模板 ID")
    name: str = Field(..., description="模板名称")
    description: str = Field(..., description="模板简介")
    methodology: str = Field("STRIDE", description="推荐的威胁建模方法论")
    requirements: str = Field(..., description="预填的需求文档")
    architecture: str = Field(..., description="预填的架构设计文档")
    tags: list[str] = Field(default_factory=list, description="标签")


class TemplateListResponse(BaseModel):
    """场景模板库响应。"""

    items: list[TemplateItem] = Field(default_factory=list, description="模板列表")


class ResultDetailResponse(BaseModel):
    """单个建模结果完整详情响应。"""

    id: str
    title: str
    methodology: str
    created_at: float
    model: dict[str, Any] = Field(
        ..., description="完整 Threat Dragon 模型"
    )
    summary: dict[str, Any] = Field(
        default_factory=dict,
        description="威胁模型摘要（{title, description, owner}）",
    )
    stats: dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    """健康检查响应。"""

    status: str = "ok"
    llm_configured: bool = Field(
        ..., description="是否已配置 LLM API Key"
    )
    base_url: str = Field(
        "", description="当前生效的 LLM API 地址（仅供前端展示；不会返回 API Key）"
    )
    model: str = Field(
        "", description="当前生效的 LLM 模型名"
    )


class LLMConfigUpdate(BaseModel):
    """管理员更新 LLM 统一配置的请求体（仅 admin 可写）。"""

    base_url: str = Field(..., description="OpenAI 兼容 API 地址")
    model: str = Field(..., description="模型名称")
    api_key: Optional[str] = Field(
        None,
        description=(
            "API Key。**留空表示不更新**（管理员只改 model 时不丢 key）；"
            "传值则覆盖。完整 key 永不会通过接口返回给前端。"
        ),
    )


class LLMConfigPublic(BaseModel):
    """LLM 运行时配置的"公开视图"（所有登录用户可读）。"""

    base_url: str = ""
    model: str = ""
    configured: bool = False
    source: str = "none"  # "disk" | "env" | "none"
    api_key_masked: Optional[str] = None
    api_key_configured: bool = False
    is_admin: bool = False
