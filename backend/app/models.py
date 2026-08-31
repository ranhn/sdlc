"""数据模型定义（精简版，面向中小公司）。

表数量控制在 20 张以内，此处为核心业务模型：
用户/角色/部门/权限 / 漏洞 / 漏洞流转 / 漏洞附件 / 漏洞评论 / 系统资产 / 组件
"""
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from .database import Base


# ============ 用户权限域 ============

class Department(Base):
    """部门/组织架构。"""
    __tablename__ = "sys_department"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    parent_id = Column(Integer, nullable=True)


class Role(Base):
    """角色。内置：超管/安全专家/研发人员/测试人员/普通员工。"""
    __tablename__ = "sys_role"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False)
    code = Column(String(50), unique=True, nullable=False)
    description = Column(String(255), nullable=True)


class User(Base):
    """用户。"""
    __tablename__ = "sys_user"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(50), nullable=False)
    email = Column(String(100), nullable=True)
    role_id = Column(Integer, ForeignKey("sys_role.id"), nullable=False)
    department_id = Column(Integer, ForeignKey("sys_department.id"), nullable=True)
    is_active = Column(Boolean, default=True)
    is_deleted = Column(Boolean, default=False)  # 软删除标记
    feishu_open_id = Column(String(100), nullable=True, index=True)  # 飞书 open_id，用于同步去重
    last_synced_at = Column(DateTime, nullable=True)                 # 最近一次飞书同步时间
    must_change_password = Column(Boolean, default=False)            # 强制改密标记（飞书同步用户首次登录）
    created_at = Column(DateTime, default=datetime.utcnow)

    role = relationship("Role")


class OperationLog(Base):
    """操作审计日志。"""
    __tablename__ = "sys_operation_log"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)
    username = Column(String(50), nullable=True)
    action = Column(String(100), nullable=False)      # 如 create_vuln / confirm_vuln
    module = Column(String(50), nullable=True)         # 如 vuln / auth
    detail = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


# ============ 漏洞域 ============

class AssetSystem(Base):
    """应用系统台账（轻量版）。"""
    __tablename__ = "asset_system"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    owner_id = Column(Integer, ForeignKey("sys_user.id"), nullable=True)  # 系统负责人
    department_id = Column(Integer, ForeignKey("sys_department.id"), nullable=True)
    status = Column(String(20), default="running")  # running/dev/offline
    created_at = Column(DateTime, default=datetime.utcnow)


class Vuln(Base):
    """漏洞。状态机：
    draft(草稿) -> pending(待确认) -> confirmed(已确认) -> fixing(修复中)
    -> retest(待复测) -> fixed(已修复) -> closed(已关闭)
    分支：rejected(已驳回) / ignored(已忽略)
    """
    __tablename__ = "vuln"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    reproduce_steps = Column(Text, nullable=True)     # 漏洞复现步骤（拼接文本，兼容老数据）
    impact = Column(Text, nullable=True)              # 影响范围/危害
    screenshots = Column(Text, nullable=True)         # JSON 数组：base64 截图（所有图，兼容老数据）
    step_screenshots = Column(Text, nullable=True)    # JSON 数组：[{"step_no": 1, "data_url": "data:image/png;base64,..."}]
    system_id = Column(Integer, ForeignKey("asset_system.id"), nullable=True)
    severity = Column(String(20), default="medium")  # critical/high/medium/low
    status = Column(String(20), default="pending", index=True)
    reporter_id = Column(Integer, ForeignKey("sys_user.id"), nullable=False)  # 提交人
    assignee_id = Column(Integer, ForeignKey("sys_user.id"), nullable=True)   # 修复负责人
    reviewer_id = Column(Integer, ForeignKey("sys_user.id"), nullable=True)   # 复测人
    cvss = Column(String(10), nullable=True)
    vuln_type = Column(String(50), nullable=True)     # 如 SQL注入 / XSS / 越权
    source = Column(String(20), default="manual")     # manual/manual_scan/ci_scan
    rejection_reason = Column(Text, nullable=True)
    sla_deadline = Column(DateTime, nullable=True)
    fixed_at = Column(DateTime, nullable=True)
    closed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    system = relationship("AssetSystem")


class VulnFlow(Base):
    """漏洞状态流转记录（时间线）。"""
    __tablename__ = "vuln_flow"

    id = Column(Integer, primary_key=True, index=True)
    vuln_id = Column(Integer, ForeignKey("vuln.id"), nullable=False, index=True)
    from_status = Column(String(20), nullable=True)
    to_status = Column(String(20), nullable=False)
    operator_id = Column(Integer, nullable=True)
    operator_name = Column(String(50), nullable=True)
    comment = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class VulnAttachment(Base):
    """漏洞附件。"""
    __tablename__ = "vuln_attachment"

    id = Column(Integer, primary_key=True, index=True)
    vuln_id = Column(Integer, ForeignKey("vuln.id"), nullable=False)
    filename = Column(String(255), nullable=False)
    filepath = Column(String(500), nullable=False)
    uploader_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class VulnComment(Base):
    """漏洞评论/协作。"""
    __tablename__ = "vuln_comment"

    id = Column(Integer, primary_key=True, index=True)
    vuln_id = Column(Integer, ForeignKey("vuln.id"), nullable=False)
    user_id = Column(Integer, nullable=False)
    username = Column(String(50), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


# ============ 组件扫描域（预留，P1 实现） ============

class SBOMComponent(Base):
    """组件清单（SBOM 轻量版）。"""
    __tablename__ = "sbom_component"

    id = Column(Integer, primary_key=True, index=True)
    system_id = Column(Integer, ForeignKey("asset_system.id"), nullable=False)
    name = Column(String(100), nullable=False)
    version = Column(String(50), nullable=False)
    license = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    __table_args__ = (UniqueConstraint("system_id", "name", "version", name="uq_component"),)

    system = relationship("AssetSystem")


class CVEInfo(Base):
    """漏洞情报库（内置轻量版，P1 实现，可后续对接 NVD/CNVD 同步）。"""
    __tablename__ = "cve_info"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(30), unique=True, nullable=False, index=True)  # 如 CVE-2021-44228
    component = Column(String(100), nullable=False, index=True)           # 受影响组件名
    fixed_versions = Column(String(255), nullable=True)                   # 修复版本，逗号分隔
    severity = Column(String(20), default="medium")                       # critical/high/medium/low
    cvss = Column(String(10), nullable=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ScanTask(Base):
    """扫描任务。"""
    __tablename__ = "scan_task"

    id = Column(Integer, primary_key=True, index=True)
    system_id = Column(Integer, ForeignKey("asset_system.id"), nullable=False)
    engine = Column(String(20), default="builtin")   # builtin/trivy
    status = Column(String(20), default="running")   # running/success/failed
    trigger = Column(String(20), default="manual")   # manual/schedule/ci
    component_count = Column(Integer, default=0)
    vuln_count = Column(Integer, default=0)
    log = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    finished_at = Column(DateTime, nullable=True)

    system = relationship("AssetSystem")


class ScanResult(Base):
    """单条扫描结果（组件命中漏洞）。"""
    __tablename__ = "scan_result"

    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(Integer, ForeignKey("scan_task.id"), nullable=False, index=True)
    system_id = Column(Integer, ForeignKey("asset_system.id"), nullable=False)
    component_id = Column(Integer, ForeignKey("sbom_component.id"), nullable=True)
    component = Column(String(100), nullable=False)
    current_version = Column(String(50), nullable=False)
    cve_id = Column(String(30), nullable=False, index=True)
    severity = Column(String(20), default="medium")
    cvss = Column(String(10), nullable=True)
    fixed_version = Column(String(50), nullable=True)
    description = Column(Text, nullable=True)
    is_false_positive = Column(Boolean, default=False)
    linked_vuln_id = Column(Integer, nullable=True)   # 关联到漏洞管理模块的漏洞单
    created_at = Column(DateTime, default=datetime.utcnow)


# ============ 安全培训域（P2 实现） ============

class TrainingCourse(Base):
    """安全培训课程。"""
    __tablename__ = "training_course"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    category = Column(String(50), default="通用")     # 如 安全意识 / 开发安全 / 应急响应 / 合规
    description = Column(Text, nullable=True)
    content = Column(Text, nullable=True)              # 课程正文/讲义
    attachment_path = Column(String(500), nullable=True)
    attachment_name = Column(String(200), nullable=True)
    instructor_id = Column(Integer, ForeignKey("sys_user.id"), nullable=True)  # 讲师
    duration_min = Column(Integer, default=30)         # 预计时长(分钟)
    is_required = Column(Boolean, default=False)       # 是否必修
    is_published = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    instructor = relationship("User", foreign_keys=[instructor_id])


class CourseProgress(Base):
    """学员学习进度/完成记录。"""
    __tablename__ = "training_progress"

    id = Column(Integer, primary_key=True, index=True)
    course_id = Column(Integer, ForeignKey("training_course.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("sys_user.id"), nullable=False, index=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)     # 非空即视为已完成
    score = Column(Integer, nullable=True)             # 关联测验得分(0-100)
    __table_args__ = (UniqueConstraint("course_id", "user_id", name="uq_progress"),)

    course = relationship("TrainingCourse")
    user = relationship("User")


class QuizQuestion(Base):
    """考试题库：单选题/判断题。答案存 answer 字段（单题答案，如 A 或 T/F）。"""
    __tablename__ = "quiz_question"

    id = Column(Integer, primary_key=True, index=True)
    course_id = Column(Integer, ForeignKey("training_course.id"), nullable=True)  # 可挂到课程
    type = Column(String(10), default="single")        # single(单选) / judge(判断)
    question = Column(Text, nullable=False)
    options = Column(Text, nullable=True)              # 选项，| 分隔，如 A.xxx|B.xxx
    answer = Column(String(10), nullable=False)        # 标准答案
    analysis = Column(Text, nullable=True)             # 答案解析
    created_at = Column(DateTime, default=datetime.utcnow)

    course = relationship("TrainingCourse")


class QuizExam(Base):
    """考试/测验记录。answers 以 JSON 存答题明细。"""
    __tablename__ = "quiz_exam"

    id = Column(Integer, primary_key=True, index=True)
    course_id = Column(Integer, ForeignKey("training_course.id"), nullable=True)
    user_id = Column(Integer, ForeignKey("sys_user.id"), nullable=False, index=True)
    title = Column(String(200), nullable=False)
    questions = Column(Text, nullable=True)            # 试卷题目 id 列表(JSON)
    answers = Column(Text, nullable=True)              # 用户答案(JSON {qid: answer})
    total_score = Column(Integer, default=0)
    pass_score = Column(Integer, default=60)
    started_at = Column(DateTime, default=datetime.utcnow)
    submitted_at = Column(DateTime, nullable=True)
    status = Column(String(20), default="in_progress") # in_progress / submitted / passed / failed

    user = relationship("User")
    course = relationship("TrainingCourse")


# ============ 安全基线域 ============

class BaselineCategory(Base):
    """安全基线分类，如 账号安全 / 密码策略 / 系统加固 / 日志审计 / Web安全 / 数据安全。"""
    __tablename__ = "baseline_category"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), nullable=False)
    code = Column(String(50), nullable=False)
    description = Column(String(255), nullable=True)
    sort = Column(Integer, default=0)
    baseline_type = Column(String(50), default="security_requirement")  # security_requirement / app_dev / frontend_dev / backend_dev / firmware_dev
    __table_args__ = (
        UniqueConstraint("baseline_type", "name", name="uq_baseline_category_type_name"),
        UniqueConstraint("baseline_type", "code", name="uq_baseline_category_type_code"),
    )

    items = relationship("BaselineItem", back_populates="category")


class BaselineItem(Base):
    """基线检查项（模板）。"""
    __tablename__ = "baseline_item"

    id = Column(Integer, primary_key=True, index=True)
    category_id = Column(Integer, ForeignKey("baseline_category.id"), nullable=False, index=True)
    name = Column(String(200), nullable=False)         # 检查项名称
    description = Column(Text, nullable=True)          # 检查说明/整改建议
    check_method = Column(String(50), default="manual")  # manual/automated
    severity = Column(String(20), default="medium")    # critical/high/medium/low
    is_required = Column(Boolean, default=True)        # 是否强制要求
    sort = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    category = relationship("BaselineCategory", back_populates="items")


class BaselineResult(Base):
    """某系统对某检查项的合规结果。"""
    __tablename__ = "baseline_result"

    id = Column(Integer, primary_key=True, index=True)
    system_id = Column(Integer, ForeignKey("asset_system.id"), nullable=False, index=True)
    item_id = Column(Integer, ForeignKey("baseline_item.id"), nullable=False, index=True)
    status = Column(String(20), default="pending")     # pass/fail/na/pending
    evidence = Column(Text, nullable=True)             # 合规证据/备注
    checker_id = Column(Integer, ForeignKey("sys_user.id"), nullable=True)
    checked_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    __table_args__ = (UniqueConstraint("system_id", "item_id", name="uq_baseline_result"),)

    system = relationship("AssetSystem")
    item = relationship("BaselineItem")
