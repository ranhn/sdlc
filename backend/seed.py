"""初始化种子数据：角色、部门、管理员账号、演示账号、示例系统与漏洞。

运行：python -m seed
"""
from datetime import datetime, timedelta

from app.database import Base, SessionLocal, engine
from app.models import (
    AssetSystem, CourseProgress, CVEInfo, Department, QuizQuestion, Role,
    SBOMComponent, ScanResult, ScanTask, TrainingCourse, User, Vuln, VulnFlow,
)
from app.security import hash_password

ROLES = [
    ("超级管理员", "admin", "平台全部权限"),
    ("安全运营", "secops", "漏洞审核/流转/复测、资产维护"),
    ("研发人员", "dev", "提交漏洞、认领修复、学习培训"),
    ("测试人员", "tester", "提交漏洞、复测验证"),
    ("培训讲师", "trainer", "课程/题库/考试管理"),
    ("普通员工", "user", "个人工作台、学习、提交漏洞"),
]

DEPARTMENTS = ["研发部", "安全部", "测试部", "产品部"]


def init():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    # 角色（已存在则更新名称/描述，保证幂等）
    role_map = {}
    for name, code, desc in ROLES:
        role = db.query(Role).filter(Role.code == code).first()
        if not role:
            role = Role(name=name, code=code, description=desc)
            db.add(role)
        else:
            role.name = name
            role.description = desc
        role_map[code] = role
    db.commit()

    # 部门
    dept_map = {}
    for name in DEPARTMENTS:
        dept = db.query(Department).filter(Department.name == name).first()
        if not dept:
            dept = Department(name=name)
            db.add(dept)
            dept_map[name] = dept
        else:
            dept_map[name] = dept
    db.commit()

    # 管理员与演示账号（密码均为 admin123 / sec123 / dev123 ...）
    admin_user = db.query(User).filter(User.username == "admin").first()
    if not admin_user:
        admin_user = User(
            username="admin", password_hash=hash_password("admin123"),
            full_name="系统管理员", role_id=role_map["admin"].id,
            department_id=dept_map["安全部"].id,
        )
        db.add(admin_user)
    sec_user = db.query(User).filter(User.username == "secops").first()
    if not sec_user:
        sec_user = User(
            username="secops", password_hash=hash_password("sec123"),
            full_name="安全运营小李", role_id=role_map["secops"].id,
            department_id=dept_map["安全部"].id,
        )
        db.add(sec_user)
    dev_user = db.query(User).filter(User.username == "dev").first()
    if not dev_user:
        dev_user = User(
            username="dev", password_hash=hash_password("dev123"),
            full_name="研发小王", role_id=role_map["dev"].id,
            department_id=dept_map["研发部"].id,
        )
        db.add(dev_user)
    trainer_user = db.query(User).filter(User.username == "trainer").first()
    if not trainer_user:
        trainer_user = User(
            username="trainer", password_hash=hash_password("train123"),
            full_name="安全培训讲师", role_id=role_map["trainer"].id,
            department_id=dept_map["安全部"].id,
        )
        db.add(trainer_user)
    db.commit()

    # 示例系统
    sys_map = {}
    for name in ["官网门户", "订单系统", "用户中心", "管理后台"]:
        if not db.query(AssetSystem).filter(AssetSystem.name == name).first():
            s = AssetSystem(name=name, description=f"{name}（示例）", owner_id=dev_user.id)
            db.add(s)
            sys_map[name] = s
    db.commit()
    for name in sys_map:
        sys_map[name] = db.query(AssetSystem).filter(AssetSystem.name == name).first()

    # 示例漏洞（仅当漏洞表为空时）
    if db.query(Vuln).count() == 0:
        now = datetime.utcnow()
        samples = [
            ("官网门户SQL注入漏洞", "登录接口存在SQL注入，可绕过认证", "官网门户",
             "critical", "SQL注入", "9.8", "confirmed", dev_user, sec_user),
            ("订单系统越权访问", "订单详情接口未做鉴权，可越权查看他人订单", "订单系统",
             "high", "越权", "8.1", "fixing", dev_user, sec_user),
            ("用户中心XSS漏洞", "个人资料昵称字段未过滤导致存储型XSS", "用户中心",
             "medium", "XSS", "6.3", "pending", sec_user, sec_user),
            ("管理后台弱口令", "后台存在弱口令账号且无锁定策略", "管理后台",
             "high", "弱口令", "7.5", "retest", dev_user, dev_user),
            ("官网门户信息泄露", "错误页面泄露数据库类型与路径信息", "官网门户",
             "low", "信息泄露", "3.7", "fixed", dev_user, sec_user),
            ("订单系统组件漏洞", "log4j 组件版本存在已知 CVE（示例）", "订单系统",
             "critical", "组件漏洞", "10.0", "pending", sec_user, sec_user),
        ]
        for title, desc, sysname, sev, vtype, cvss, status, reporter, assignee in samples:
            v = Vuln(
                title=title, description=desc,
                system_id=sys_map[sysname].id if sysname in sys_map else None,
                severity=sev, vuln_type=vtype, cvss=cvss, status=status,
                reporter_id=reporter.id, assignee_id=assignee.id,
                created_at=now - timedelta(days=3),
            )
            db.add(v)
            db.flush()
            db.add(VulnFlow(vuln_id=v.id, from_status="draft", to_status=status,
                            operator_id=reporter.id, operator_name=reporter.full_name,
                            comment="种子数据导入", created_at=now - timedelta(days=3)))
        db.commit()

    # ---------- P1 组件扫描种子数据 ----------
    # CVE 情报库（内置轻量版）
    cve_samples = [
        # CVE-2021-44228 log4j 修复版本 2.17.1
        ("CVE-2021-44228", "log4j-core", "2.17.1", "critical", "10.0",
         "Apache Log4j2 存在远程代码执行漏洞"),
        ("CVE-2021-45046", "log4j-core", "2.17.1", "high", "9.0",
         "Log4j2 二次DoS漏洞"),
        ("CVE-2017-1000353", "jackson-databind", "2.9.10", "high", "8.1",
         "Jackson 反序列化远程代码执行漏洞"),
        ("CVE-2021-42550", "logback-core", "1.2.9", "critical", "9.8",
         "Logback 序列化远程代码执行漏洞"),
        ("CVE-2023-44487", "netty-codec-http", "4.1.100", "high", "7.5",
         "HTTP/2 快速重置攻击，可导致服务拒绝"),
        ("CVE-2020-13935", "tomcat", "9.0.40", "medium", "7.5",
         "Apache Tomcat WebSocket DoS 漏洞"),
    ]
    for cve_id, comp, fixed, sev, cvss, desc in cve_samples:
        if not db.query(CVEInfo).filter(CVEInfo.cve_id == cve_id).first():
            db.add(CVEInfo(cve_id=cve_id, component=comp, fixed_versions=fixed,
                           severity=sev, cvss=cvss, description=desc))

    # 系统组件清单（SBOM）
    sys_orders = db.query(AssetSystem).filter(AssetSystem.name == "订单系统").first()
    sys_portal = db.query(AssetSystem).filter(AssetSystem.name == "官网门户").first()
    comp_samples = [
        (sys_orders, "log4j-core", "2.14.1", "Apache-2.0"),      # 命中 CVE-2021-44228
        (sys_orders, "jackson-databind", "2.9.8", "Apache-2.0"),  # 命中 CVE-2017-1000353
        (sys_orders, "tomcat", "9.0.30", "Apache-2.0"),           # 命中 CVE-2020-13935
        (sys_orders, "spring-core", "5.3.9", "Apache-2.0"),       # 无漏洞
        (sys_portal, "logback-core", "1.2.3", "EPL-1.0"),         # 命中 CVE-2021-42550
        (sys_portal, "netty-codec-http", "4.1.60", "Apache-2.0"), # 命中 CVE-2023-44487
    ]
    for system, name, version, lic in comp_samples:
        if system and not db.query(SBOMComponent).filter(
                SBOMComponent.system_id == system.id,
                SBOMComponent.name == name).first():
            db.add(SBOMComponent(system_id=system.id, name=name, version=version, license=lic))
    db.commit()

    # 模拟一次已完成的扫描（订单系统）
    if sys_orders and db.query(ScanTask).count() == 0:
        task = ScanTask(
            system_id=sys_orders.id, engine="builtin", status="success",
            trigger="manual", component_count=4, vuln_count=3,
            created_at=now - timedelta(days=1), finished_at=now - timedelta(days=1),
        )
        db.add(task)
        db.flush()
        # 三个命中组件生成扫描结果
        hit_comps = [
            ("log4j-core", "2.14.1", "CVE-2021-44228", "critical", "10.0", "2.17.1"),
            ("jackson-databind", "2.9.8", "CVE-2017-1000353", "high", "8.1", "2.9.10"),
            ("tomcat", "9.0.30", "CVE-2020-13935", "medium", "7.5", "9.0.40"),
        ]
        for name, ver, cve, sev, cvss, fixed in hit_comps:
            comp = db.query(SBOMComponent).filter(
                SBOMComponent.system_id == sys_orders.id, SBOMComponent.name == name).first()
            db.add(ScanResult(
                task_id=task.id, system_id=sys_orders.id,
                component_id=comp.id if comp else None,
                component=name, current_version=ver, cve_id=cve,
                severity=sev, cvss=cvss, fixed_version=fixed,
                description=f"{name} 存在 {cve} 漏洞",
            ))
        db.commit()

    # ---------- P2 安全培训种子数据 ----------
    if db.query(TrainingCourse).count() == 0:
        courses = [
            ("应用安全开发规范", "开发安全", "研发同学必学的基础应用安全规范",
             "一、输入校验：所有外部输入必须校验长度、类型、取值范围。\n"
             "二、SQL 注入防护：必须使用参数化查询，禁止字符串拼接 SQL。\n"
             "三、输出编码：前端渲染动态内容时统一做 HTML 编码防 XSS。\n"
             "四、鉴权：所有接口必须校验登录态与权限，禁止越权访问。\n"
             "五、敏感信息：日志中禁止输出明文密码、Token、手机号等。",
             True, 30),
            ("安全意识与钓鱼邮件防范", "安全意识", "全员安全基础培训",
             "一、识别钓鱼邮件：检查发件人域名、链接真实地址、紧急语气与附件。\n"
             "二、密码安全：使用高强度密码并开启多因素认证。\n"
             "三、社工防范：任何索要密码/验证码的行为都要高度警惕。\n"
             "四、办公安全：离开工位锁屏，不插来历不明的 U 盘。",
             False, 20),
            ("应急响应与漏洞处置流程", "应急响应", "安全运营与研发的漏洞处置标准流程",
             "一、发现：通过扫描或人工报告收集漏洞。\n"
             "二、评估：确认漏洞真实性、危害等级、影响范围。\n"
             "三、处置：高危漏洞应 24 小时内启动修复，按风险优先级排序。\n"
             "四、复测：修复后由测试/安全运营复测验证。\n"
             "五、关闭：复测通过后闭环归档。",
             True, 40),
        ]
        for title, cat, desc, content, required, dur in courses:
            db.add(TrainingCourse(
                title=title, category=cat, description=desc, content=content,
                instructor_id=trainer_user.id, duration_min=dur,
                is_required=required, is_published=True,
            ))
        db.commit()

        # 题库（关联开发安全课程）
        dev_course = db.query(TrainingCourse).filter(
            TrainingCourse.title == "应用安全开发规范").first()
        questions = [
            ("single", "防范 SQL 注入最推荐的做法是？",
             "A.过滤特殊字符|B.使用参数化查询/预编译语句|C.关闭数据库错误提示|D.使用存储过程",
             "B", "参数化查询是防止 SQL 注入的根本手段。", dev_course),
            ("single", "以下哪种日志信息属于敏感信息，不应明文记录？",
             "A.请求方法|B.响应状态码|C.用户密码|D.接口耗时", "C",
             "密码、Token、手机号等属于敏感信息。", dev_course),
            ("single", "存储型 XSS 与反射型 XSS 的关键区别是？",
             "A.是否弹窗|B.恶意脚本是否被持久化存储并影响其他用户|C.是否需要用户点击|D.是否发生在服务端",
             "B", "存储型 XSS 将脚本持久化存储，影响面更大。", dev_course),
            ("single", "关于越权漏洞，正确的说法是？",
             "A.只有管理员会越权|B.是未校验对象级/功能级权限导致的访问|C.仅存在于接口层|D.无法被修复",
             "B", "越权是缺失对象级/功能级访问控制导致的。", dev_course),
            ("judge", "只要对外部输入做了长度限制，就能完全防止注入攻击。",
             None, "F", "长度限制无法防止注入，必须进行语义校验与参数化。", dev_course),
            ("judge", "生产环境关闭错误详细提示信息可以降低信息泄露风险。",
             None, "T", "关闭详细报错可减少敏感信息泄露。", dev_course),
            ("single", "检测依赖组件已知漏洞（如 log4j）通常使用什么方法？",
             "A.代码审计|B.SBOM 组件清单比对 CVE 情报库|C.流量分析|D.蜜罐",
             "B", "通过 SBOM 清单与 CVE 情报比对可发现组件漏洞。", None),
        ]
        for qtype, qtext, opts, ans, analysis, cobj in questions:
            db.add(QuizQuestion(
                type=qtype, question=qtext, options=opts, answer=ans,
                analysis=analysis, course_id=cobj.id if cobj else None,
            ))
        db.commit()

    # 学习进度示例（研发小王学完开发安全规范并得分）
    course_dev = db.query(TrainingCourse).filter(
        TrainingCourse.title == "应用安全开发规范").first()
    if course_dev and not db.query(CourseProgress).filter(
            CourseProgress.course_id == course_dev.id,
            CourseProgress.user_id == dev_user.id).first():
        db.add(CourseProgress(
            course_id=course_dev.id, user_id=dev_user.id,
            started_at=now - timedelta(days=2),
            completed_at=now - timedelta(days=1), score=90,
        ))
        db.commit()

    print("✅ 种子数据初始化完成")
    print("   管理员: admin / （请通过平台修改初始密码）")
    print("   安全运营: secops / （请通过平台修改初始密码）")
    print("   研发人员: dev / （请通过平台修改初始密码）")
    print("   培训讲师: trainer / （请通过平台修改初始密码）")
    db.close()


if __name__ == "__main__":
    init()
