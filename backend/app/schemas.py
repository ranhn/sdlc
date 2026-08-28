"""Pydantic 请求/响应模型。"""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ============ 认证 ============
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    full_name: str
    username: str
    must_change_password: bool = False


# ============ 用户 ============
class UserCreate(BaseModel):
    username: str
    password: str
    full_name: str
    email: Optional[str] = None
    role_id: int
    department_id: Optional[int] = None
    must_change_password: bool = False


class ChangePasswordIn(BaseModel):
    old_password: Optional[str] = None
    new_password: str = Field(min_length=8, max_length=64)


class UserOut(BaseModel):
    id: int
    username: str
    full_name: str
    email: Optional[str] = None
    role_id: int
    role_name: Optional[str] = None
    department_id: Optional[int] = None
    is_active: bool
    is_deleted: bool = False

    class Config:
        from_attributes = True


class DepartmentOut(BaseModel):
    id: int
    name: str

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
    system_id: Optional[int] = None
    severity: str = "medium"
    vuln_type: Optional[str] = None
    cvss: Optional[str] = None


class VulnAssign(BaseModel):
    assignee_id: int


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
    vuln_type: Optional[str] = None
    source: str
    rejection_reason: Optional[str] = None
    sla_deadline: Optional[datetime] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class VulnFlowOut(BaseModel):
    id: int
    from_status: Optional[str] = None
    to_status: str
    operator_name: Optional[str] = None
    comment: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class VulnCommentOut(BaseModel):
    id: int
    username: str
    content: str
    created_at: datetime

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
    created_at: datetime

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
    created_at: datetime

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
    created_at: datetime
    finished_at: Optional[datetime] = None

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
    created_at: datetime
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
    started_at: datetime
    completed_at: Optional[datetime] = None
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
    created_at: datetime

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
    started_at: datetime
    submitted_at: Optional[datetime] = None
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
    created_at: datetime

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
    checked_at: Optional[datetime] = None
    system_name: Optional[str] = None
    item_name: Optional[str] = None
    category_id: Optional[int] = None
    category_name: Optional[str] = None
    severity: Optional[str] = None
    check_method: Optional[str] = None
    item_description: Optional[str] = None

    class Config:
        from_attributes = True
