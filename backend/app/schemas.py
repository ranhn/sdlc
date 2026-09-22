"""Pydantic 请求/响应模型。"""
from datetime import datetime, timezone
from typing import Annotated, Optional

from pydantic import BaseModel, Field, PlainSerializer


def _ensure_utc_iso(dt: datetime) -> str:
    """把时间统一按 UTC 语义序列化为带时区后缀的 ISO 字符串。

    本项目数据库以 naive UTC 存储（datetime.utcnow），此前响应不标注时区，
    前端误把 UTC 时刻当成浏览器本地时间显示，导致国内(东八区)看到的时间
    比实际少 8 小时。这里统一补上 UTC 偏移(+00:00)，前端按用户本地时区换算。
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat()


# 仅影响 JSON 序列化输出；模型校验/比较仍用原始 datetime，不影响既有逻辑。
AwareDT = Annotated[datetime, PlainSerializer(_ensure_utc_iso, return_type=str, when_used="json")]


# ============ 认证 ============
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    full_name: str
    username: str
    must_change_password: bool = False
    # 用户 id：前端要用它判断"这条记录是不是我的"（如修复人能否看到确认/驳回、
    # 提交人能否编辑自己提交的漏洞）。此前不返回，那些判断在前端永远是"否"
    #（表现为修复人看不到按钮），只能靠从 JWT 的 sub 解 —— 这里显式给出来。
    id: Optional[int] = None


# ============ 用户 ============
class UserCreate(BaseModel):
    username: str
    password: str
    full_name: str
    email: Optional[str] = None
    role_id: int
    department_id: Optional[int] = None
    must_change_password: bool = False


class UserUpdate(BaseModel):
    """编辑用户：只开放姓名 / 邮箱 / 角色 / 部门。

    刻意不开放两个字段：
      · username —— 改掉会让人无法用原账号登录（而且飞书同步的用户名就是英文名，
        再手工改名会被下次同步覆盖）；
      · password —— 有独立的"改密"入口，重置密码应当在明确操作下进行。
    """
    full_name: Optional[str] = None
    email: Optional[str] = None
    role_id: Optional[int] = None
    department_id: Optional[int] = None


class ChangePasswordIn(BaseModel):
    old_password: Optional[str] = None
    new_password: str = Field(min_length=8, max_length=64)


class UserOut(BaseModel):
    id: int
    username: str
    full_name: str
    en_name: Optional[str] = None  # 英文名（飞书 name 里拆出来的，与中文名分列展示）
    email: Optional[str] = None
    role_id: int
    role_name: Optional[str] = None
    role_code: Optional[str] = None  # 用于前端判断是否对目标用户开放写操作（如 secops 不可操作 admin 行）
    department_id: Optional[int] = None
    department_name: Optional[str] = None  # 人员列表直接显示部门名，避免前端再查一次
    is_active: bool
    is_deleted: bool = False
    # 下面两个字段前端列表要用：飞书标签（feishu_open_id）与"最近同步"列。
    # 之前 UserOut 里没有它们，接口不返回 → 列表里"最近同步"永远显示"—"、飞书标签也不出现。
    feishu_open_id: Optional[str] = None
    last_synced_at: Optional[AwareDT] = None

    class Config:
        from_attributes = True


class UserPickOut(BaseModel):
    """人员下拉（选择负责人 / 指派）专用：只要 3 个字段。

    为什么不复用 UserOut：飞书通讯录同步后公司有 1600+ 人，UserOut 带邮箱/角色/
    部门/飞书 id 等十几个字段（其中大半是 null），一次序列化约 580KB；下拉只需要
    "英文名 + 中文名"，其余全是白下载 + 白解析。这个模型一次约 60KB。
    """

    id: int
    username: str
    full_name: str

    class Config:
        from_attributes = True


class DepartmentOut(BaseModel):
    id: int
    name: str
    parent_id: Optional[int] = None
    feishu_open_dept_id: Optional[str] = None

    class Config:
        from_attributes = True


class RoleOut(BaseModel):
    id: int
    name: str
    code: str

    class Config:
        from_attributes = True


# ============ 漏洞 ============
class VulnCreate(BaseModel):
    title: str = Field(..., min_length=2, max_length=200)
    description: Optional[str] = None
    reproduce_steps: Optional[str] = None
    impact: Optional[str] = None
    screenshots: Optional[list[str]] = None
    step_screenshots: Optional[list[dict]] = None  # [{"step_no": 1, "data_url": "data:image/png;base64,..."}]
    system_id: Optional[int] = None
    severity: str = "medium"
    vuln_category: Optional[str] = None   # 一级大类：注入类 / 访问控制 / 信息泄露 等
    vuln_type: Optional[str] = None       # 二级子类：SQL注入 / 水平越权(IDOR) 等
    cvss: Optional[str] = None
    assignee_id: Optional[int] = None
    # 漏洞来源：False=内部提交（默认），True=外部报告
    is_external: bool = False
    external_source: Optional[str] = None
    # 接口地址：受漏洞影响的 API 路径（开发人员直接定位修复）
    api_endpoint: str = Field(..., min_length=1, max_length=500)
    # 修复建议：方向/改造方案/参考链接等，可空
    fix_suggestion: Optional[str] = None


class VulnAssign(BaseModel):
    assignee_id: int


class VulnUpdate(BaseModel):
    """编辑漏洞字段。提交人/管理员/安全专家可在「非 closed」状态下补充修改。

    所有字段可选——前端按用户实际改动提交，避免覆盖空值。
    """
    title: Optional[str] = Field(default=None, min_length=2, max_length=200)
    description: Optional[str] = None
    reproduce_steps: Optional[str] = None
    impact: Optional[str] = None
    screenshots: Optional[list[str]] = None
    step_screenshots: Optional[list[dict]] = None
    system_id: Optional[int] = None
    severity: Optional[str] = None
    vuln_category: Optional[str] = None   # 一级大类
    vuln_type: Optional[str] = None       # 二级子类
    cvss: Optional[str] = None
    assignee_id: Optional[int] = None
    is_external: Optional[bool] = None
    external_source: Optional[str] = None
    api_endpoint: Optional[str] = Field(default=None, min_length=1, max_length=500)
    fix_suggestion: Optional[str] = None


class VulnStatusAction(BaseModel):
    comment: Optional[str] = None


class VulnReject(BaseModel):
    reason: str


class VulnOut(BaseModel):
    id: int
    title: str
    description: Optional[str] = None
    reproduce_steps: Optional[str] = None
    impact: Optional[str] = None
    screenshots: Optional[list[str]] = None
    step_screenshots: Optional[list[dict]] = None
    system_id: Optional[int] = None
    system_name: Optional[str] = None
    severity: str
    status: str
    reporter_id: int
    reporter_name: Optional[str] = None
    assignee_id: Optional[int] = None
    assignee_name: Optional[str] = None
    reviewer_id: Optional[int] = None
    reviewer_name: Optional[str] = None
    cvss: Optional[str] = None
    vuln_category: Optional[str] = None   # 一级大类
    vuln_type: Optional[str] = None       # 二级子类
    source: str
    is_external: bool = False
    external_source: Optional[str] = None
    api_endpoint: Optional[str] = None
    fix_suggestion: Optional[str] = None
    rejection_reason: Optional[str] = None
    sla_deadline: Optional[AwareDT] = None
    created_at: AwareDT
    updated_at: Optional[AwareDT] = None

    class Config:
        from_attributes = True


class VulnListItem(VulnOut):
    """漏洞**列表/看板**用的清单级模型 = VulnOut 去掉详情级大字段。

    为什么必须瘦：`screenshots` / `step_screenshots` 存的是 base64 图片，单条可达几十 KB；
    `description` / `reproduce_steps` / `impact` / `fix_suggestion` 是长文本。
    实测 15 条漏洞的列表响应 **416KB**，而列表页只用得到清单字段（标题/系统/等级/
    类型/状态/负责人/时间）—— 每次刷新页面都要下载 + 解析这一坨，是"刷新很慢"的主因。
    详情展示、编辑回填、Word 导出走全量的 `GET /api/vulns/{id}`（VulnOut），功能不受影响。

    ⚠️ 为什么不用路由上的 `response_model_exclude`：实测 FastAPI 0.115 对
    `response_model=list[...]` 这种"列表根"**不生效**（字段照样返回，最小复现已验证）。
    用子模型 + `Field(exclude=True)` 是在 pydantic 序列化阶段真正丢掉，
    OpenAPI 文档里也只出现轻字段，前端一看就知道列表能拿到什么。
    """

    description: Optional[str] = Field(default=None, exclude=True)
    reproduce_steps: Optional[str] = Field(default=None, exclude=True)
    impact: Optional[str] = Field(default=None, exclude=True)
    fix_suggestion: Optional[str] = Field(default=None, exclude=True)
    screenshots: Optional[list[str]] = Field(default=None, exclude=True)
    step_screenshots: Optional[list[dict]] = Field(default=None, exclude=True)


class VulnPage(BaseModel):
    """漏洞列表的**分页**响应。

    为什么要分页：以前 `GET /api/vulns` 一次返回全量，前端只做"视图切片" —— 漏洞一多，
    每次进页面/翻页都要把全部行传下来再解析（筛选、排序也都在前端假装完成）。
    现在由服务端按页取（筛选与排序仍在库里做），`total` 是**满足筛选条件的总数**，
    前端分页组件靠它算页数 —— 注意 total 不受分页参数影响，两个页面的页码才稳定。
    """

    items: list[VulnListItem]
    total: int          # 筛选命中的总条数（不是当前页条数）
    page: int
    page_size: int


class VulnFlowOut(BaseModel):
    id: int
    from_status: Optional[str] = None
    to_status: str
    operator_name: Optional[str] = None
    comment: Optional[str] = None
    created_at: AwareDT

    class Config:
        from_attributes = True


class VulnCommentOut(BaseModel):
    id: int
    username: str
    content: str
    created_at: AwareDT

    class Config:
        from_attributes = True


# ============ 系统资产 ============
class AssetSystemCreate(BaseModel):
    name: str
    description: Optional[str] = None
    owner_id: Optional[int] = None
    department_id: Optional[int] = None
    status: str = "running"


class AssetSystemUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    owner_id: Optional[int] = None
    department_id: Optional[int] = None
    status: Optional[str] = None


class AssetSystemOut(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    owner_id: Optional[int] = None
    owner_name: Optional[str] = None
    status: str
    created_at: AwareDT

    class Config:
        from_attributes = True


# ============ 组件扫描 ============
class ComponentCreate(BaseModel):
    system_id: int
    name: str
    version: str
    license: Optional[str] = None


class ComponentOut(BaseModel):
    id: int
    system_id: int
    system_name: Optional[str] = None
    name: str
    version: str
    license: Optional[str] = None
    created_at: AwareDT

    class Config:
        from_attributes = True


class CveCreate(BaseModel):
    cve_id: str
    component: str
    fixed_versions: Optional[str] = None
    severity: str = "medium"
    cvss: Optional[str] = None
    description: Optional[str] = None


class CveOut(BaseModel):
    id: int
    cve_id: str
    component: str
    fixed_versions: Optional[str] = None
    severity: str
    cvss: Optional[str] = None
    description: Optional[str] = None

    class Config:
        from_attributes = True


class ScanTaskOut(BaseModel):
    id: int
    system_id: int
    system_name: Optional[str] = None
    engine: str
    status: str
    trigger: str
    component_count: int
    vuln_count: int
    created_at: AwareDT
    finished_at: Optional[AwareDT] = None

    class Config:
        from_attributes = True


class ScanResultOut(BaseModel):
    id: int
    task_id: int
    system_id: int
    system_name: Optional[str] = None
    component: str
    current_version: str
    cve_id: str
    severity: str
    cvss: Optional[str] = None
    fixed_version: Optional[str] = None
    description: Optional[str] = None
    is_false_positive: bool
    linked_vuln_id: Optional[int] = None

    class Config:
        from_attributes = True


# ============ 安全培训 ============
class TrainingCourseCreate(BaseModel):
    title: str = Field(..., min_length=2, max_length=200)
    category: str = "通用"
    description: Optional[str] = None
    content: Optional[str] = None
    attachment_path: Optional[str] = None
    attachment_name: Optional[str] = None
    instructor_id: Optional[int] = None
    duration_min: int = 30
    is_required: bool = False
    is_published: bool = True


class TrainingCourseOut(BaseModel):
    id: int
    title: str
    category: str
    description: Optional[str] = None
    content: Optional[str] = None
    attachment_path: Optional[str] = None
    attachment_name: Optional[str] = None
    instructor_id: Optional[int] = None
    instructor_name: Optional[str] = None
    duration_min: int
    is_required: bool
    is_published: bool
    created_at: AwareDT
    # 扩展字段：当前用户完成状态/参与人数
    completed: Optional[bool] = None
    enroll_count: Optional[int] = None

    class Config:
        from_attributes = True


class CourseProgressOut(BaseModel):
    id: int
    course_id: int
    course_title: Optional[str] = None
    category: Optional[str] = None
    user_id: int
    started_at: AwareDT
    completed_at: Optional[AwareDT] = None
    score: Optional[int] = None
    is_completed: Optional[bool] = None

    class Config:
        from_attributes = True


class CourseComplete(BaseModel):
    score: Optional[int] = None   # 可选关联测验得分


class QuizQuestionCreate(BaseModel):
    course_id: Optional[int] = None
    type: str = "single"
    question: str = Field(..., min_length=1)
    options: Optional[str] = None
    answer: str = Field(..., max_length=10)
    analysis: Optional[str] = None


class QuizQuestionOut(BaseModel):
    id: int
    course_id: Optional[int] = None
    type: str
    question: str
    options: Optional[str] = None
    answer: Optional[str] = None     # 仅对出题人/阅卷可见，答题时脱敏
    analysis: Optional[str] = None
    created_at: AwareDT

    class Config:
        from_attributes = True


class QuizQuestionOutSecure(BaseModel):
    """答题用：不返回答案/解析。"""
    id: int
    course_id: Optional[int] = None
    type: str
    question: str
    options: Optional[str] = None

    class Config:
        from_attributes = True


class QuizSubmit(BaseModel):
    answers: dict[int, str]   # {question_id: answer}


class QuizExamOut(BaseModel):
    id: int
    course_id: Optional[int] = None
    course_title: Optional[str] = None
    user_id: int
    user_name: Optional[str] = None
    title: str
    total_score: Optional[int] = None
    pass_score: Optional[int] = None
    started_at: AwareDT
    submitted_at: Optional[AwareDT] = None
    status: str

    class Config:
        from_attributes = True


# ============ 安全基线 ============
class BaselineCategoryCreate(BaseModel):
    name: str
    code: str
    description: Optional[str] = None
    sort: int = 0
    baseline_type: str = "security_requirement"


class BaselineCategoryOut(BaseModel):
    id: int
    name: str
    code: str
    description: Optional[str] = None
    sort: int = 0
    baseline_type: str = "security_requirement"

    class Config:
        from_attributes = True


class BaselineItemCreate(BaseModel):
    category_id: int
    name: str = Field(..., min_length=2, max_length=200)
    description: Optional[str] = None
    check_method: str = "manual"
    severity: str = "medium"
    is_required: bool = True
    sort: int = 0


class BaselineItemOut(BaseModel):
    id: int
    category_id: int
    category_name: Optional[str] = None
    name: str
    description: Optional[str] = None
    check_method: str
    severity: str
    is_required: bool
    sort: int
    created_at: AwareDT

    class Config:
        from_attributes = True


class BaselineResultUpdate(BaseModel):
    status: str = "pass"   # pass / fail / na
    evidence: Optional[str] = None


class BaselineResultOut(BaseModel):
    id: int
    system_id: int
    item_id: int
    status: str
    evidence: Optional[str] = None
    checked_at: Optional[AwareDT] = None
    system_name: Optional[str] = None
    item_name: Optional[str] = None
    category_id: Optional[int] = None
    category_name: Optional[str] = None
    severity: Optional[str] = None
    check_method: Optional[str] = None
    item_description: Optional[str] = None

    class Config:
        from_attributes = True


# ---------- 基线需求（某系统绑定了哪几个基线）----------
class BaselineTypeOut(BaseModel):
    """基线类型目录项（"新增需求"弹窗的勾选列表）。

    item_count/category_count 是给用户**当场看到工作量**的：固件开发基线 50 项、
    APP 开发基线 15 项，勾下去之前就该知道差别。0 项的类型照样返回（前端置灰），
    它就是"这批 Excel 还没导入"的信号。
    """
    key: str
    label: str
    item_count: int = 0
    category_count: int = 0


class BaselineRequirementCreate(BaseModel):
    system_id: int
    name: Optional[str] = None                  # 留空 → 后端生成「<系统名>-基线评估」
    baseline_types: list[str] = Field(default_factory=list)
    owner_id: Optional[int] = None
    due_date: Optional[datetime] = None


class BaselineRequirementUpdate(BaseModel):
    """编辑需求：只改传了的字段（前端不传 = 不动）。

    `due_date` 显式传 null 表示**清除**截止日期（exclude_unset 会把显式 null 视为"已设置"）。
    """
    name: Optional[str] = None
    baseline_types: Optional[list[str]] = None
    owner_id: Optional[int] = None
    due_date: Optional[datetime] = None
    status: Optional[str] = None                # in_progress / done


class BaselineRequirementBaselineOut(BaseModel):
    """需求里单个基线的完成情况（列表卡上一条 chip 的进度与计数）。

    单独拿出来是因为"只有总数"看不出问题在哪：75 项里做了 8 项，可能是后端基线的
    36 项全做了、安全需求基线的 39 项没动，也可能是反的 —— 展示粒度不同，结论完全不同。
    """
    type: str
    label: str
    total: int = 0
    pass_count: int = 0
    fail_count: int = 0
    na_count: int = 0
    pending_count: int = 0
    compliance: float = 0.0
    progress: float = 0.0


class BaselineRequirementOut(BaseModel):
    id: int
    system_id: int
    system_name: Optional[str] = None
    name: str
    baseline_types: list[str] = Field(default_factory=list)    # 已解析的 key（库里是 JSON 文本）
    baseline_labels: list[str] = Field(default_factory=list)   # 展示名，前端不必再维护一份映射
    owner_id: Optional[int] = None
    owner_name: Optional[str] = None
    due_date: Optional[AwareDT] = None
    status: str = "in_progress"
    created_at: Optional[AwareDT] = None
    baselines: list[BaselineRequirementBaselineOut] = Field(default_factory=list)
    # ---- 统计：分母只算**本需求绑定范围**内的条目 ----
    bound_items: int = 0        # 应评条目数（= 绑定基线下的全部条目）
    pass_count: int = 0
    fail_count: int = 0
    na_count: int = 0
    pending_count: int = 0
    compliance: float = 0.0     # 合规率 = 通过 ÷ (应评 − 不适用)
    progress: float = 0.0       # 进度 = 已评估 ÷ 应评


class BaselineRequirementItemOut(BaselineResultOut):
    """需求详情里的条目：在结果字段上补"属于哪个基线"，供详情按基线分组展示。"""
    baseline_type: Optional[str] = None
    baseline_label: Optional[str] = None
