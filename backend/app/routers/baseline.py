"""安全基线路由：基线分类、检查项、系统合规检查、合规率统计。"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import (
    AssetSystem,
    BaselineCategory,
    BaselineItem,
    BaselineResult,
    User,
)
from ..schemas import (
    BaselineCategoryCreate,
    BaselineCategoryOut,
    BaselineItemCreate,
    BaselineItemOut,
    BaselineResultOut,
    BaselineResultUpdate,
)
from ..security import get_current_user, write_operation_log

from app.utils import network_clock as nc
router = APIRouter(prefix="/api/baseline", tags=["安全基线"])


def _require_secops(user: User):
    if user.role is None or user.role.code not in ("admin", "secops"):
        raise HTTPException(status_code=403, detail="仅管理员/安全专家可操作")


# ============ 基线分类 ============
@router.get("/categories", response_model=list[BaselineCategoryOut])
def list_categories(baseline_type: str = None, db: Session = Depends(get_db),
                    current: User = Depends(get_current_user)):
    q = db.query(BaselineCategory)
    if baseline_type:
        q = q.filter(BaselineCategory.baseline_type == baseline_type)
    return q.order_by(BaselineCategory.sort).all()


@router.post("/categories", response_model=BaselineCategoryOut, status_code=201)
def create_category(data: BaselineCategoryCreate, db: Session = Depends(get_db),
                    current: User = Depends(get_current_user)):
    _require_secops(current)
    if db.query(BaselineCategory).filter(BaselineCategory.name == data.name).first():
        raise HTTPException(status_code=400, detail="分类名称已存在")
    cat = BaselineCategory(**data.model_dump())
    db.add(cat)
    db.commit()
    db.refresh(cat)
    write_operation_log(db, current, "create_baseline_category", "baseline", f"新增基线分类: {cat.name}")
    return cat


# ============ 基线检查项 ============
@router.get("/items", response_model=list[BaselineItemOut])
def list_items(category_id: int | None = None, db: Session = Depends(get_db),
               current: User = Depends(get_current_user)):
    query = db.query(BaselineItem)
    if category_id:
        query = query.filter(BaselineItem.category_id == category_id)
    items = query.order_by(BaselineItem.category_id, BaselineItem.sort).all()
    result = []
    for it in items:
        out = BaselineItemOut.model_validate(it)
        out.category_name = it.category.name if it.category else None
        result.append(out)
    return result


@router.post("/items", response_model=BaselineItemOut, status_code=201)
def create_item(data: BaselineItemCreate, db: Session = Depends(get_db),
                current: User = Depends(get_current_user)):
    _require_secops(current)
    if not db.query(BaselineCategory).filter(BaselineCategory.id == data.category_id).first():
        raise HTTPException(status_code=400, detail="分类不存在")
    item = BaselineItem(**data.model_dump())
    db.add(item)
    db.commit()
    db.refresh(item)
    out = BaselineItemOut.model_validate(item)
    out.category_name = item.category.name if item.category else None
    write_operation_log(db, current, "create_baseline_item", "baseline", f"新增检查项: {item.name}")
    return out


@router.delete("/items/{item_id}", status_code=204)
def delete_item(item_id: int, db: Session = Depends(get_db),
                current: User = Depends(get_current_user)):
    _require_secops(current)
    item = db.query(BaselineItem).filter(BaselineItem.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="检查项不存在")
    db.query(BaselineResult).filter(BaselineResult.item_id == item_id).delete()
    db.delete(item)
    db.commit()
    return None


# ============ 系统合规检查 ============
@router.get("/systems/{system_id}/items", response_model=list[BaselineResultOut])
def list_system_items(system_id: int, baseline_type: str = None,
                      db: Session = Depends(get_db),
                      current: User = Depends(get_current_user)):
    """返回某系统的所有检查项及其合规状态（未检查的为 pending）。可过滤基线类型。"""
    if not db.query(AssetSystem).filter(AssetSystem.id == system_id).first():
        raise HTTPException(status_code=404, detail="系统不存在")

    query = db.query(BaselineItem)
    if baseline_type:
        query = query.join(BaselineCategory).filter(BaselineCategory.baseline_type == baseline_type)
    items = query.order_by(BaselineItem.category_id, BaselineItem.sort).all()
    results = db.query(BaselineResult).filter(BaselineResult.system_id == system_id).all()
    result_map = {r.item_id: r for r in results}

    out_list = []
    for it in items:
        r = result_map.get(it.id)
        out = BaselineResultOut(
            id=r.id if r else 0,
            system_id=system_id,
            item_id=it.id,
            status=r.status if r else "pending",
            evidence=r.evidence if r else None,
            checked_at=r.checked_at if r else None,
            item_name=it.name,
            category_id=it.category_id,
            category_name=it.category.name if it.category else None,
            severity=it.severity,
            check_method=it.check_method,
            item_description=it.description,
        )
        out_list.append(out)
    return out_list


@router.put("/systems/{system_id}/items/{item_id}", response_model=BaselineResultOut)
def update_system_item(system_id: int, item_id: int, data: BaselineResultUpdate,
                       db: Session = Depends(get_db),
                       current: User = Depends(get_current_user)):
    _require_secops(current)
    if data.status not in ("pass", "fail", "na"):
        raise HTTPException(status_code=400, detail="状态必须为 pass/fail/na")
    if not db.query(BaselineItem).filter(BaselineItem.id == item_id).first():
        raise HTTPException(status_code=404, detail="检查项不存在")

    result = db.query(BaselineResult).filter(
        BaselineResult.system_id == system_id,
        BaselineResult.item_id == item_id,
    ).first()
    if not result:
        result = BaselineResult(system_id=system_id, item_id=item_id)
        db.add(result)
    result.status = data.status
    result.evidence = data.evidence
    result.checker_id = current.id
    result.checked_at = nc.utcnow()
    db.commit()
    db.refresh(result)

    out = BaselineResultOut.model_validate(result)
    out.item_name = result.item.name if result.item else None
    out.category_name = result.item.category.name if result.item and result.item.category else None
    out.severity = result.item.severity if result.item else None
    out.check_method = result.item.check_method if result.item else None
    out.item_description = result.item.description if result.item else None
    write_operation_log(db, current, "check_baseline", "baseline",
                        f"系统#{system_id} 检查项#{item_id} -> {data.status}")
    return out


# ============ 合规率统计 ============
@router.get("/stats")
def baseline_stats(baseline_type: str = None,
                   db: Session = Depends(get_db),
                   current: User = Depends(get_current_user)):
    """各系统合规率统计，用于大盘。可过滤基线类型。"""
    systems = db.query(AssetSystem).order_by(AssetSystem.id).all()

    item_query = db.query(BaselineItem)
    if baseline_type:
        item_query = item_query.join(BaselineCategory).filter(BaselineCategory.baseline_type == baseline_type)
    items_all = item_query.count()
    if items_all == 0:
        return {"systems": [], "overall": 0, "item_count": 0}

    # 限制结果只关联到当前 baseline_type 的检查项
    item_ids = {it.id for it in item_query.all()}

    rows = []
    for s in systems:
        results = db.query(BaselineResult).filter(
            BaselineResult.system_id == s.id,
            BaselineResult.item_id.in_(item_ids) if item_ids else True
        ).all()
        if not results:
            rows.append({"system_id": s.id, "system_name": s.name, "checked": 0,
                         "pass": 0, "fail": 0, "na": 0, "pending": items_all,
                         "compliance": 0.0})
            continue
        pass_n = sum(1 for r in results if r.status == "pass")
        fail_n = sum(1 for r in results if r.status == "fail")
        na_n = sum(1 for r in results if r.status == "na")
        checked = pass_n + fail_n + na_n
        pending = max(0, items_all - checked)
        rate = round(pass_n / items_all * 100, 1) if items_all else 0
        rows.append({"system_id": s.id, "system_name": s.name, "checked": checked,
                     "pass": pass_n, "fail": fail_n, "na": na_n, "pending": pending,
                     "compliance": rate})

    # 整体合规率 = 所有系统通过数 / (系统数 * 检查项数)
    total_pass = sum(r["pass"] for r in rows)
    total_items = items_all * max(len(rows), 1)
    overall = round(total_pass / total_items * 100, 1) if total_items else 0
    return {"systems": rows, "overall": overall, "item_count": items_all}
