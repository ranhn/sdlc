"""扫描引擎。

内置轻量比对引擎（builtin）：根据 CVE 情报库中的修复版本，判断组件版本是否受漏洞影响。
同时预留 Trivy 对接接口（engine="trivy"），后续可接入真实扫描器。
"""
from datetime import datetime
import re

from sqlalchemy.orm import Session

from .models import CVEInfo, SBOMComponent, ScanResult, ScanTask


def _parse_version(version: str):
    """将版本字符串解析为可比较的数值元组，如 "1.2.3" -> (1, 2, 3)。"""
    parts = re.findall(r"\d+", version)
    return tuple(int(p) for p in parts)


def _version_less(current: str, fixed: str) -> bool:
    """当前版本 < 修复版本（即存在漏洞）。"""
    cur = _parse_version(current)
    fix = _parse_version(fixed)
    if not cur or not fix:
        # 解析失败时按字符串前缀比较兜底
        return current != fixed and fixed.startswith("".join(str(x) for x in cur))
    return cur < fix


def run_scan(db: Session, system_id: int, engine: str = "builtin", trigger: str = "manual"):
    """执行一次组件扫描，返回 ScanTask。"""
    components = db.query(SBOMComponent).filter(SBOMComponent.system_id == system_id).all()

    task = ScanTask(
        system_id=system_id,
        engine=engine,
        status="running",
        trigger=trigger,
        component_count=len(components),
    )
    db.add(task)
    db.commit()
    db.refresh(task)

    try:
        if engine == "builtin":
            results = _builtin_scan(db, system_id, components)
        elif engine == "trivy":
            results = _trivy_scan(db, system_id, components)
        else:
            raise ValueError(f"未知扫描引擎: {engine}")

        # 写入结果
        for r in results:
            r.task_id = task.id
            db.add(r)
        task.status = "success"
        task.vuln_count = len(results)
        task.log = f"扫描完成，发现 {len(results)} 个组件漏洞"
    except Exception as e:
        task.status = "failed"
        task.log = f"扫描失败: {str(e)}"

    task.finished_at = datetime.utcnow()
    db.commit()
    db.refresh(task)
    return task


def _builtin_scan(db: Session, system_id: int, components: list[SBOMComponent]):
    """内置引擎：用 CVE 情报库比对组件版本。"""
    results = []
    for comp in components:
        # 查找该组件的所有 CVE 情报
        cves = db.query(CVEInfo).filter(CVEInfo.component == comp.name).all()
        for cve in cves:
            fixed_versions = [v.strip() for v in (cve.fixed_versions or "").split(",") if v.strip()]
            # 如果组件当前版本小于某个修复版本，则命中漏洞
            hit = any(_version_less(comp.version, fv) for fv in fixed_versions) if fixed_versions else True
            if hit:
                results.append(ScanResult(
                    task_id=0,  # 稍后补 task_id
                    system_id=system_id,
                    component_id=comp.id,
                    component=comp.name,
                    current_version=comp.version,
                    cve_id=cve.cve_id,
                    severity=cve.severity,
                    cvss=cve.cvss,
                    fixed_version=fixed_versions[0] if fixed_versions else None,
                    description=cve.description,
                ))
    return results


def _trivy_scan(db: Session, system_id: int, components: list[SBOMComponent]):
    """预留 Trivy 对接：当前返回空（后续接入真实 Trivy 命令/API）。"""
    # TODO: 对接 Trivy，解析 JSON 输出生成结果
    return []


def link_vulns(db: Session, task: ScanTask):
    """将扫描结果自动生成漏洞单（联动漏洞管理模块）。"""
    from .models import Vuln, User

    results = db.query(ScanResult).filter(
        ScanResult.task_id == task.id,
        ScanResult.is_false_positive == False,  # noqa: E712
        ScanResult.linked_vuln_id.is_(None),
    ).all()

    linked = 0
    # 找到默认安全运营用户作为 reporter
    from .models import Role
    secops_role = db.query(Role).filter(Role.code == "secops").first()
    reporter = db.query(User).filter(User.role_id == secops_role.id).first() if secops_role else None

    for r in results:
        # 避免重复生成：同一系统+组件+CVE 已存在且未关闭，则不重复建单
        dup = db.query(Vuln).filter(
            Vuln.system_id == r.system_id,
            Vuln.title.like(f"%{r.cve_id}%"),
            Vuln.status.in_(["pending", "confirmed", "fixing", "retest"]),
        ).first()
        if dup:
            r.linked_vuln_id = dup.id
            continue

        v = Vuln(
            title=f"组件漏洞 {r.component} ({r.cve_id})",
            description=f"组件 {r.component} 当前版本 {r.current_version} 存在 {r.cve_id} 漏洞。\n"
                        f"建议升级至修复版本 {r.fixed_version or '最新版'}。\n\n{r.description or ''}",
            system_id=r.system_id,
            severity=r.severity,
            vuln_type="组件漏洞",
            cvss=r.cvss,
            reporter_id=reporter.id if reporter else 1,
            status="pending",
            source="ci_scan" if task.trigger == "ci" else "manual_scan",
        )
        db.add(v)
        db.flush()
        r.linked_vuln_id = v.id
        linked += 1

    db.commit()
    return linked
