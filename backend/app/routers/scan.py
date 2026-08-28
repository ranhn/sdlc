"""组件扫描路由：SBOM组件管理、CVE情报库、扫描任务、扫描结果。"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import (
    CVEInfo, Role, SBOMComponent, ScanResult, ScanTask, User,
)
from ..schemas import (
    ComponentCreate, ComponentOut, CveCreate, CveOut,
    ScanResultOut, ScanTaskOut,
)
from ..scanner import link_vulns, run_scan
from ..security import get_current_user, write_operation_log

router = APIRouter(prefix="/api/scan", tags=["组件扫描"])


def _require_secops(user: User):
    if user.role is None or user.role.code not in ("admin", "secops"):
        raise HTTPException(status_code=403, detail="仅管理员/安全专家可操作")


def _to_task(t: ScanTask, db: Session) -> ScanTaskOut:
    out = ScanTaskOut.model_validate(t)
    out.system_name = t.system.name if t.system else None
    return out


def _to_result(r: ScanResult, db: Session) -> ScanResultOut:
    out = ScanResultOut.model_validate(r)
    from ..models import AssetSystem
    sys = db.query(AssetSystem).filter(AssetSystem.id == r.system_id).first()
    out.system_name = sys.name if sys else None
    return out


# ============ 组件清单(SBOM) ============
@router.get("/components", response_model=list[ComponentOut])
def list_components(system_id: int | None = None, db: Session = Depends(get_db),
                    current: User = Depends(get_current_user)):
    query = db.query(SBOMComponent)
    if system_id:
        query = query.filter(SBOMComponent.system_id == system_id)
    comps = query.all()
    result = []
    for c in comps:
        out = ComponentOut.model_validate(c)
        out.system_name = c.system.name if c.system else None
        result.append(out)
    return result


@router.post("/components", response_model=ComponentOut, status_code=201)
def create_component(data: ComponentCreate, db: Session = Depends(get_db),
                     current: User = Depends(get_current_user)):
    _require_secops(current)
    dup = db.query(SBOMComponent).filter(
        SBOMComponent.system_id == data.system_id,
        SBOMComponent.name == data.name,
        SBOMComponent.version == data.version,
    ).first()
    if dup:
        raise HTTPException(status_code=400, detail="该组件已存在于系统中")
    comp = SBOMComponent(**data.model_dump())
    db.add(comp)
    db.commit()
    db.refresh(comp)
    write_operation_log(db, current, "create_component", "scan", f"添加组件 {comp.name}@{comp.version}")
    comp_out = ComponentOut.model_validate(comp)
    comp_out.system_name = comp.system.name if comp.system else None
    return comp_out


@router.delete("/components/{component_id}")
def delete_component(component_id: int, db: Session = Depends(get_db),
                     current: User = Depends(get_current_user)):
    _require_secops(current)
    comp = db.query(SBOMComponent).filter(SBOMComponent.id == component_id).first()
    if not comp:
        raise HTTPException(status_code=404, detail="组件不存在")
    db.delete(comp)
    db.commit()
    write_operation_log(db, current, "delete_component", "scan", f"删除组件 {comp.name}")
    return {"ok": True}


# ============ CVE 情报库 ============
@router.get("/cves", response_model=list[CveOut])
def list_cves(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    return db.query(CVEInfo).order_by(CVEInfo.cve_id).all()


@router.post("/cves", response_model=CveOut, status_code=201)
def create_cve(data: CveCreate, db: Session = Depends(get_db),
               current: User = Depends(get_current_user)):
    _require_secops(current)
    if db.query(CVEInfo).filter(CVEInfo.cve_id == data.cve_id).first():
        raise HTTPException(status_code=400, detail="该CVE已存在")
    cve = CVEInfo(**data.model_dump())
    db.add(cve)
    db.commit()
    db.refresh(cve)
    write_operation_log(db, current, "create_cve", "scan", f"录入情报 {cve.cve_id}")
    return cve


@router.delete("/cves/{cve_id}")
def delete_cve(cve_id: int, db: Session = Depends(get_db),
               current: User = Depends(get_current_user)):
    _require_secops(current)
    cve = db.query(CVEInfo).filter(CVEInfo.id == cve_id).first()
    if not cve:
        raise HTTPException(status_code=404, detail="情报不存在")
    db.delete(cve)
    db.commit()
    write_operation_log(db, current, "delete_cve", "scan", f"删除情报 {cve.cve_id}")
    return {"ok": True}


# ============ 扫描任务 ============
@router.post("/systems/{system_id}/scan", response_model=ScanTaskOut)
def start_scan(system_id: int, engine: str = "builtin", db: Session = Depends(get_db),
               current: User = Depends(get_current_user)):
    _require_secops(current)
    from ..models import AssetSystem
    if not db.query(AssetSystem).filter(AssetSystem.id == system_id).first():
        raise HTTPException(status_code=404, detail="系统不存在")
    task = run_scan(db, system_id, engine=engine, trigger="manual")
    write_operation_log(db, current, "start_scan", "scan", f"触发系统{system_id}扫描")
    return _to_task(task, db)


@router.get("/tasks", response_model=list[ScanTaskOut])
def list_tasks(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    tasks = db.query(ScanTask).order_by(ScanTask.created_at.desc()).all()
    return [_to_task(t, db) for t in tasks]


@router.get("/tasks/{task_id}/results", response_model=list[ScanResultOut])
def task_results(task_id: int, db: Session = Depends(get_db),
                 current: User = Depends(get_current_user)):
    results = db.query(ScanResult).filter(ScanResult.task_id == task_id).all()
    return [_to_result(r, db) for r in results]


# ============ 扫描结果处理 ============
@router.post("/results/{result_id}/link", response_model=ScanResultOut)
def link_result_to_vuln(result_id: int, db: Session = Depends(get_db),
                        current: User = Depends(get_current_user)):
    """将单条扫描结果转为漏洞单。"""
    _require_secops(current)
    r = db.query(ScanResult).filter(ScanResult.id == result_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="扫描结果不存在")
    from ..models import Vuln
    from ..models import AssetSystem
    sys = db.query(AssetSystem).filter(AssetSystem.id == r.system_id).first()
    v = Vuln(
        title=f"组件漏洞 {r.component} ({r.cve_id})",
        description=f"组件 {r.component} 当前版本 {r.current_version} 存在 {r.cve_id} 漏洞。\n"
                    f"建议升级至修复版本 {r.fixed_version or '最新版'}。\n\n{r.description or ''}",
        system_id=r.system_id,
        severity=r.severity,
        vuln_type="组件漏洞",
        cvss=r.cvss,
        reporter_id=current.id,
        status="pending",
        source="manual_scan",
    )
    db.add(v)
    db.flush()
    r.linked_vuln_id = v.id
    db.commit()
    write_operation_log(db, current, "link_result", "scan", f"扫描结果#{r.id}转漏洞单#{v.id}")
    return _to_result(r, db)


@router.post("/results/{result_id}/false_positive")
def mark_false_positive(result_id: int, db: Session = Depends(get_db),
                        current: User = Depends(get_current_user)):
    """标记误报。"""
    _require_secops(current)
    r = db.query(ScanResult).filter(ScanResult.id == result_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="扫描结果不存在")
    r.is_false_positive = not r.is_false_positive
    db.commit()
    db.refresh(r)
    write_operation_log(db, current, "mark_false_positive", "scan", f"扫描结果#{r.id}误报标记")
    return _to_result(r, db)


@router.post("/tasks/{task_id}/link-all")
def link_all_results(task_id: int, db: Session = Depends(get_db),
                     current: User = Depends(get_current_user)):
    """批量将某任务的扫描结果转为漏洞单。"""
    _require_secops(current)
    task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="扫描任务不存在")
    linked = link_vulns(db, task)
    write_operation_log(db, current, "link_all", "scan", f"任务#{task_id}批量转漏洞单 {linked} 条")
    return {"linked": linked}
