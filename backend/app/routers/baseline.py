"""安全基线路由：基线目录、检查项、**基线需求（范围绑定）**、系统合规检查、合规率统计。

## 为什么要有"需求"这一层

此前"系统需要满足哪些基线"没有数据载体：页面把某个基线类型的**全部条目**都当成每个
系统的应评范围，统计口径是 `overall = 所有系统通过数 ÷ (系统数 × 全部条目数)`。后果：

  · 从没做过基线的系统也在拉低整体合规率（实测 6 个系统里只有 1 个做过 → 整体 15.7%，
    而那个做了的系统自己是 94.4%）；分母越大数字越小，且这个数字无法回答"到底谁欠账"；
  · 实际只做 APP + 后端的系统，被要求补前端/固件的条目；没绑定的基线显示 0% 还容易被
    读成"没达标"。

现在「需求」= 某系统这一轮要落地的基线范围（勾选 5 个基线里的哪几个），合规率只按**绑定
范围**计算。老的 /stats 与 /systems/{id}/items 保留不动（兼容既有调用），新页面走
/requirements。

## 统计口径（两处容易搞错，都在测试里钉住了）

1. **分母 = 绑定范围内的条目**，不是全库条目；
2. **「不适用」也计入合规率分母**：`合规率 = 通过 ÷ 应评`（需求方口径）。
   中间有一版曾把"不适用"从分母剔除（担心标了 na 反而拉低数字、逼人虚报通过），
   现按业务要求改回"应评即分母" —— 标了"不适用"的条目同样没通过，不该从分母里消失。
   另给 `进度 = 已评估 ÷ 应评`，把"合规率"与"完成度"分开（不然未评估会被算进合规率）。
"""
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..baseline_catalog import (
    BASELINE_TYPES,
    TYPE_KEYS,
    dump_types,
    label_of,
    normalize_types,
    parse_types,
)
from ..database import get_db
from ..models import (
    AssetSystem,
    BaselineCategory,
    BaselineItem,
    BaselineRequirement,
    BaselineResult,
    User,
)
from ..schemas import (
    BaselineBulkResultIn,
    BaselineCategoryCreate,
    BaselineCategoryOut,
    BaselineCategoryUpdate,
    BaselineItemCreate,
    BaselineItemOut,
    BaselineItemUpdate,
    BaselineRequirementBaselineOut,
    BaselineRequirementCreate,
    BaselineRequirementItemOut,
    BaselineRequirementOut,
    BaselineRequirementUpdate,
    BaselineResultOut,
    BaselineResultUpdate,
    BaselineTypeOut,
)
from ..security import get_current_user, write_operation_log

from app.utils import network_clock as nc
from app.utils.baseline_csv import render_baseline_csv


router = APIRouter(prefix="/api/baseline", tags=["安全基线"])

# 可写基线评估的角色（与模板维护同一口径）
_WRITE_ROLES = ("admin", "secops")


def _require_secops(user: User):
    if user.role is None or user.role.code not in _WRITE_ROLES:
        raise HTTPException(status_code=403, detail="仅管理员/安全专家可操作")


def _role_code(user: User) -> str | None:
    return user.role.code if user.role else None


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
    """新增控制模块。

    重名只在**同一基线内**算冲突（DB 的唯一约束就是 (baseline_type, name)）。
    旧代码查的是全局重名，于是"后端开发基线里能叫『日志审计』，安全需求基线里就不能叫"——
    两个不同基线的模块名本来就该允许重名。
    """
    _require_secops(current)
    dup = (db.query(BaselineCategory)
           .filter(BaselineCategory.baseline_type == data.baseline_type,
                   BaselineCategory.name == data.name).first())
    if dup:
        raise HTTPException(status_code=400, detail=f"「{data.name}」在该基线里已存在")
    payload = data.model_dump()
    if not (payload.get("code") or "").strip():
        payload["code"] = f"cat_{uuid4().hex[:8]}"      # 内部编码，页面不展示
    cat = BaselineCategory(**payload)
    db.add(cat)
    db.commit()
    db.refresh(cat)
    write_operation_log(db, current, "create_baseline_category", "baseline", f"新增基线分类: {cat.name}")
    return cat


@router.put("/categories/{category_id}", response_model=BaselineCategoryOut)
def update_category(category_id: int, data: BaselineCategoryUpdate,
                    db: Session = Depends(get_db),
                    current: User = Depends(get_current_user)):
    """编辑控制模块（改名 / 改描述 / 调顺序），只改传了的字段。"""
    _require_secops(current)
    cat = _get_category(db, category_id)
    if data.name is not None and data.name != cat.name:
        dup = (db.query(BaselineCategory)
               .filter(BaselineCategory.baseline_type == cat.baseline_type,
                       BaselineCategory.name == data.name,
                       BaselineCategory.id != cat.id).first())
        if dup:
            raise HTTPException(status_code=400, detail=f"该基线里已有「{data.name}」")
    for field in ("name", "description", "sort"):
        val = getattr(data, field, None)
        if val is not None:
            setattr(cat, field, val)
    db.commit()
    db.refresh(cat)
    write_operation_log(db, current, "update_baseline_category", "baseline",
                        f"编辑控制模块#{cat.id} {cat.name}")
    return cat


@router.delete("/categories/{category_id}", status_code=204)
def delete_category(category_id: int, db: Session = Depends(get_db),
                    current: User = Depends(get_current_user)):
    """删除控制模块。

    **下面还有检查项时一律拒绝**：删条目会连带删掉各系统在这些条目上的评估结论
    （结论挂在 item_id 上），那是不可逆的取证数据；该由使用者自己决定这些条目
    去哪（删掉还是挪到别的模块），而不是替他一起抹掉。
    """
    _require_secops(current)
    cat = _get_category(db, category_id)
    left = db.query(BaselineItem).filter(BaselineItem.category_id == category_id).count()
    if left:
        raise HTTPException(status_code=400,
                            detail=f"「{cat.name}」下还有 {left} 个检查项：请先把它们删除或移到其它控制模块")
    name = cat.name
    db.delete(cat)
    db.commit()
    write_operation_log(db, current, "delete_baseline_category", "baseline",
                        f"删除控制模块: {name}")
    return None


# ============ 基线类型目录 ============
@router.get("/types", response_model=list[BaselineTypeOut])
def list_baseline_types(db: Session = Depends(get_db),
                        current: User = Depends(get_current_user)):
    """5 个基线类型 + 各自的条目/分类数（"新增需求"弹窗的勾选列表）。

    条目数是给用户**当场判断工作量**的（固件 50 项 vs APP 15 项，勾之前就该知道）；
    0 项的类型也返回 —— 它说明这批 Excel 还没导入（`scripts/import_baseline.py`），
    前端会置灰不可勾选。藏起来的话，用户只会以为"平台里没有这个基线"。
    """
    counts: dict[str, tuple[int, int]] = {}
    rows = (
        db.query(
            BaselineCategory.baseline_type,
            func.count(func.distinct(BaselineCategory.id)),
            func.count(BaselineItem.id),
        )
        .outerjoin(BaselineItem, BaselineItem.category_id == BaselineCategory.id)
        .group_by(BaselineCategory.baseline_type)
        .all()
    )
    for btype, cats, items in rows:
        counts[btype] = (cats or 0, items or 0)

    out = []
    for key, label in BASELINE_TYPES.items():
        cats, items = counts.get(key, (0, 0))
        out.append(BaselineTypeOut(key=key, label=label,
                                   category_count=cats, item_count=items))
    return out


# ============ 基线检查项 ============
@router.get("/items", response_model=list[BaselineItemOut])
def list_items(category_id: int | None = None, baseline_type: str | None = None,
               db: Session = Depends(get_db),
               current: User = Depends(get_current_user)):
    """检查项清单。可按分类或**基线类型**过滤（模板库抽屉要一次拿到某类型全部条目）。"""
    query = db.query(BaselineItem)
    if baseline_type:
        query = query.join(BaselineCategory).filter(BaselineCategory.baseline_type == baseline_type)
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
    _check_method_ok(data.check_method)
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


@router.put("/items/{item_id}", response_model=BaselineItemOut)
def update_item(item_id: int, data: BaselineItemUpdate, db: Session = Depends(get_db),
                current: User = Depends(get_current_user)):
    """编辑检查项（模板维护，权限与新增/删除同一道闸）。

    为什么要有它：此前只有"新增 + 删除"，**改个错别字只能删了重建** —— 而删除会连带删掉
    所有系统在该检查项上的评估结论（前端确认弹窗里就是这么写的）。改名/改要求/挪模块都是
    零风险操作，不该逼用户走那条路。

    改动不影响已有结论：`baseline_result` 挂的是 `item_id`，与名称/描述无关。
    """
    _require_secops(current)
    _check_method_ok(data.check_method)
    item = db.query(BaselineItem).filter(BaselineItem.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="检查项不存在")
    if data.category_id is not None and not db.query(BaselineCategory).filter(
            BaselineCategory.id == data.category_id).first():
        raise HTTPException(status_code=400, detail="控制模块不存在")
    for field in ("category_id", "name", "description", "check_method", "severity",
                  "is_required", "sort"):
        val = getattr(data, field, None)
        if val is not None:
            setattr(item, field, val)
    db.commit()
    db.refresh(item)
    write_operation_log(db, current, "update_baseline_item", "baseline",
                        f"编辑检查项#{item.id} {item.name}")
    out = BaselineItemOut.model_validate(item)
    out.category_name = item.category.name if item.category else None
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


# ============ 结果读写（老接口与新接口共用，避免两套口径）============
def _result_out(result: BaselineResult) -> BaselineResultOut:
    """把结果行补上条目/分类信息 —— 前端表格直接展示，不用再查一次条目。"""
    out = BaselineResultOut.model_validate(result)
    item = result.item
    out.item_name = item.name if item else None
    out.category_id = item.category_id if item else None
    out.category_name = item.category.name if item and item.category else None
    out.severity = item.severity if item else None
    out.check_method = item.check_method if item else None
    out.item_description = item.description if item else None
    return out


def _save_result(db: Session, system_id: int, item: BaselineItem,
                 data: BaselineResultUpdate, current: User) -> BaselineResult:
    """写入/更新某系统对某检查项的结论（upsert，(system_id, item_id) 唯一）。"""
    result = db.query(BaselineResult).filter(
        BaselineResult.system_id == system_id,
        BaselineResult.item_id == item.id,
    ).first()
    if not result:
        result = BaselineResult(system_id=system_id, item_id=item.id)
        db.add(result)
    result.status = data.status
    if data.status == "pending":
        # 「重置为未评估」：说明、评估人、评估时间一并清空。留着一个 status=pending
        # 却挂着上次结论说明与评估人的行，读起来像"评过但没填"，而不是"还没评"。
        result.evidence = None
        result.checker_id = None
        result.checked_at = None
    else:
        result.evidence = data.evidence
        result.checker_id = current.id
        result.checked_at = nc.utcnow()
    db.commit()
    db.refresh(result)
    return result


def _validate_result_in(data: BaselineResultUpdate) -> None:
    """结论校验（单条评估的两个入口共用，口径只能有一份）。

    两条规则，都是"合规"这个场景的实质要求：
    1. 状态合法：pass / fail / na / **pending**（pending = 重置为未评估）；
    2. **「不通过」必须留说明**：整改要求、判定依据或证据链接。一条"不通过"没有依据，
       研发不知道要改什么，审计也问不出所以然 —— 结论可以下，但必须带着理由下。
    """
    if data.status not in ("pass", "fail", "na", "pending"):
        raise HTTPException(status_code=400, detail="状态必须为 pass/fail/na/pending")
    if data.status == "fail" and not (data.evidence or "").strip():
        raise HTTPException(status_code=400,
                            detail="「不通过」必须填写说明：整改要求、判定依据或证据链接")


def _check_method_ok(value: str | None) -> None:
    """检查方式只支持「人工」。

    库里曾有「自动」选项，但**没有任何代码在读 check_method** —— 挂了"自动"的检查项
    照样要人工点结论（模板库那列也因此常年只有"人工"一个值）。与其留一个名不副实的
    选项，不如显式拒绝：等真接上扫描器再开。
    """
    if value not in (None, "manual"):
        raise HTTPException(status_code=400,
                            detail="检查方式目前只支持「人工」（自动扫描尚未接入）")


def _owner_name(db: Session, owner_id: int | None) -> str | None:
    if not owner_id:
        return None
    u = db.query(User).filter(User.id == owner_id).first()
    return (u.full_name or u.username) if u else None


# ============ 需求：范围绑定 ============
def _bound_by_type(db: Session, type_keys: list[str], cache: dict) -> dict[str, set[int]]:
    """绑定类型 → `{baseline_type: 条目 id 集合}`。

    为什么按基线分开存：页面要"每个基线各自做了多少"（列表卡与详情面板都展示），
    只给一个总数的话前端得自己再拉一次条目。
    `cache` 按"类型组合"缓存：列表页 N 条需求、概览按系统聚合时都要用，
    不缓存会重复查库（单类型条目数可达 50）。
    """
    ck = tuple(type_keys)
    if ck not in cache:
        buckets: dict[str, set[int]] = {k: set() for k in type_keys}
        if type_keys:
            rows = (
                db.query(BaselineItem.id, BaselineCategory.baseline_type)
                .join(BaselineCategory, BaselineItem.category_id == BaselineCategory.id)
                .filter(BaselineCategory.baseline_type.in_(list(type_keys)))
                .all()
            )
            for item_id, btype in rows:
                buckets.setdefault(btype, set()).add(item_id)
        cache[ck] = buckets
    return cache[ck]


def _bound_items(db: Session, type_keys: list[str], cache: dict) -> set[int]:
    """绑定范围里**所有**条目的并集（= 合规率的分母范围）。"""
    return {i for ids in _bound_by_type(db, type_keys, cache).values() for i in ids}


def _system_status(db: Session, system_id: int, cache: dict) -> dict[int, str]:
    """某系统已有结论 `{item_id: status}`（按系统缓存：一条需求要按基线分别计数）。"""
    if system_id not in cache:
        cache[system_id] = {
            r.item_id: r.status
            for r in db.query(BaselineResult.item_id, BaselineResult.status)
            .filter(BaselineResult.system_id == system_id).all()
        }
    return cache[system_id]


def _counts(item_ids, status_map: dict[int, str]) -> dict:
    """给定条目集合 + 结论表 → 各状态计数（没有结论行 = 未评估）。

    未知状态（历史脏值）按"未评估"算：宁可显示"没做"，也不要算成"通过"。
    """
    cnt = {"pass": 0, "fail": 0, "na": 0, "pending": 0}
    for i in item_ids:
        st = status_map.get(i, "pending")
        cnt[st if st in cnt else "pending"] += 1
    return cnt


def _rates(bound: int, cnt: dict) -> dict:
    """合规率 / 进度 / 未评估数（口径见模块 docstring）。"""
    assessed = cnt["pass"] + cnt["fail"] + cnt["na"]
    return {
        "bound_items": bound,
        "pass_count": cnt["pass"],
        "fail_count": cnt["fail"],
        "na_count": cnt["na"],
        "pending_count": max(0, bound - assessed),
        # 分母 = 应评，**含"不适用"**：标了不适用的条目同样没通过，不该从分母里消失。
        # （旧口径是 通过 ÷ (应评 − 不适用)；按需求方要求改成"应评即分母"。）
        "compliance": round(cnt["pass"] / bound * 100, 1) if bound else 0.0,
        "progress": round(assessed / bound * 100, 1) if bound else 0.0,
    }


def _requirement_out(req: BaselineRequirement, system_name: str | None,
                     owner_name: str | None, by_type: dict[str, set[int]],
                     status_map: dict[int, str]) -> BaselineRequirementOut:
    """组装需求输出：整体口径 + **每个绑定基线各自**的进度与计数。"""
    keys = req.type_keys
    rows: list[BaselineRequirementBaselineOut] = []
    bound = 0
    total = {"pass": 0, "fail": 0, "na": 0, "pending": 0}
    for key in keys:
        ids = by_type.get(key, set())
        cnt = _counts(ids, status_map)
        bound += len(ids)
        for st in total:
            total[st] += cnt[st]
        per = _rates(len(ids), cnt)
        rows.append(BaselineRequirementBaselineOut(
            type=key, label=label_of(key), total=len(ids),
            pass_count=cnt["pass"], fail_count=cnt["fail"], na_count=cnt["na"],
            pending_count=per["pending_count"],
            compliance=per["compliance"], progress=per["progress"],
        ))
    return BaselineRequirementOut(
        id=req.id,
        system_id=req.system_id,
        system_name=system_name,
        name=req.name,
        baseline_types=keys,
        baseline_labels=[label_of(k) for k in keys],
        owner_id=req.owner_id,
        owner_name=owner_name,
        due_date=req.due_date,
        status=req.status or "in_progress",
        created_at=req.created_at,
        baselines=rows,
        **_rates(bound, total),
    )


def _autoclose_if_done(db: Session, req: BaselineRequirement,
                       current: User | None) -> bool:
    """评估写完后收口：**绑定范围内全部条目都有结论** → 需求自动置为「已完成」。

    为什么自动：进度 100% 却还挂着"进行中"，看的人根本不知道这条到底算不算完。此前是
    在行上再加一个「已评完 · 标记完成」的提示 —— 那是**第二个入口**，和操作区里本来就有的
    「标记完成」重复（页面上于是出现两个标记完成）。现在由系统收口，行上只留一个状态词。

    三条边界：
      · **只单向收口**：不回退、不自动重开 —— 「重新开启」是人的决定，系统不抢；
      · 一条基线都没绑（应评 0）不算做完，免得建完需求就自封完成；
      · 幂等：已经是 done 直接返回，不重复写日志。
    """
    if (req.status or "in_progress") == "done":
        return False
    bound = _bound_items(db, req.type_keys, {})
    if not bound:
        return False
    if _counts(bound, _system_status(db, req.system_id, {}))["pending"] > 0:
        return False
    req.status = "done"
    db.commit()
    write_operation_log(db, current, "baseline_requirement_autodone", "baseline",
                        f"需求#{req.id}「{req.name}」全部评估完成，自动标记为已完成")
    return True


def _get_category(db: Session, category_id: int) -> BaselineCategory:
    cat = db.query(BaselineCategory).filter(BaselineCategory.id == category_id).first()
    if not cat:
        raise HTTPException(status_code=404, detail="控制模块不存在")
    return cat


def _get_requirement(db: Session, requirement_id: int) -> BaselineRequirement:
    req = db.query(BaselineRequirement).filter(BaselineRequirement.id == requirement_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="需求不存在")
    return req


@router.get("/requirements/overview")
def requirements_overview(db: Session = Depends(get_db),
                          current: User = Depends(get_current_user)):
    """需求概览（页面顶部几张卡）。

    按 (系统, 条目) **去重**统计：同一系统上有两条需求都绑了「后端开发安全基线」时，
    同一检查项只算一次 —— 否则需求越多数字越低，越做越难看。
    """
    reqs = db.query(BaselineRequirement).all()
    if not reqs:
        return {"requirement_count": 0, "system_count": 0, "done_count": 0,
                "bound_items": 0, "compliance": 0.0, "progress": 0.0,
                "pass_count": 0, "fail_count": 0, "na_count": 0, "pending_count": 0,
                "systems": []}

    cache: dict = {}
    per_system: dict[int, set[int]] = {}
    for r in reqs:
        per_system.setdefault(r.system_id, set()).update(_bound_items(db, r.type_keys, cache))

    bound_total = 0
    total = {"pass": 0, "fail": 0, "na": 0, "pending": 0}
    sys_cache: dict = {}
    sys_names = {
        s.id: s.name
        for s in db.query(AssetSystem).filter(AssetSystem.id.in_(list(per_system))).all()
    }
    # 每个系统各自的合规情况：首页那张卡要"按系统"看（谁达标、谁拖后腿），
    # 只给一个整体数字回答不了这个问题。按合规率升序返回，最差的排最前。
    systems_rows = []
    for sid, ids in per_system.items():
        cnt = _counts(ids, _system_status(db, sid, sys_cache))
        bound_total += len(ids)
        for k in total:
            total[k] += cnt[k]
        per = _rates(len(ids), cnt)
        systems_rows.append({
            "system_id": sid,
            "system_name": sys_names.get(sid),
            "bound_items": per["bound_items"],
            "pass_count": per["pass_count"],
            "fail_count": per["fail_count"],
            "pending_count": per["pending_count"],
            "compliance": per["compliance"],
            "progress": per["progress"],
        })
    systems_rows.sort(key=lambda r: (r["compliance"], r["system_id"]))

    cited = _rates(bound_total, total)
    return {
        "requirement_count": len(reqs),
        "system_count": len(per_system),
        "done_count": sum(1 for r in reqs if r.status == "done"),
        "bound_items": cited["bound_items"],
        "compliance": cited["compliance"],
        "progress": cited["progress"],
        "pass_count": cited["pass_count"],
        "fail_count": cited["fail_count"],
        "na_count": cited["na_count"],          # 分解条要显示"不适用"占比
        "pending_count": cited["pending_count"],
        "systems": systems_rows,
    }


@router.get("/requirements", response_model=list[BaselineRequirementOut])
def list_requirements(system_id: int | None = None, db: Session = Depends(get_db),
                      current: User = Depends(get_current_user)):
    """需求列表（带各自的范围合规统计）。"""
    q = db.query(BaselineRequirement)
    if system_id:
        q = q.filter(BaselineRequirement.system_id == system_id)
    reqs = q.order_by(BaselineRequirement.id.desc()).all()
    if not reqs:
        return []

    sys_ids = {r.system_id for r in reqs}
    names = {s.id: s.name for s in db.query(AssetSystem).filter(AssetSystem.id.in_(sys_ids)).all()}
    owner_ids = {r.owner_id for r in reqs if r.owner_id}
    owners = {}
    if owner_ids:
        owners = {u.id: (u.full_name or u.username)
                  for u in db.query(User).filter(User.id.in_(owner_ids)).all()}

    item_cache: dict = {}
    sys_cache: dict = {}
    out = []
    for r in reqs:
        out.append(_requirement_out(
            r, names.get(r.system_id), owners.get(r.owner_id),
            _bound_by_type(db, r.type_keys, item_cache),
            _system_status(db, r.system_id, sys_cache),
        ))
    return out


@router.post("/requirements", response_model=BaselineRequirementOut, status_code=201)
def create_requirement(data: BaselineRequirementCreate, db: Session = Depends(get_db),
                       current: User = Depends(get_current_user)):
    """新增需求 = 选系统 + 勾选要绑定的基线（至少一个）。"""
    _require_secops(current)
    system = db.query(AssetSystem).filter(AssetSystem.id == data.system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="系统不存在")

    keys, unknown = normalize_types(data.baseline_types)
    if unknown:
        raise HTTPException(status_code=400, detail="未知基线类型：" + "、".join(unknown))
    if not keys:
        raise HTTPException(status_code=400, detail="请至少绑定一个基线")
    if data.owner_id is not None and not db.query(User).filter(User.id == data.owner_id).first():
        raise HTTPException(status_code=400, detail="负责人不存在")

    name = (data.name or "").strip() or f"{system.name}-基线评估"
    req = BaselineRequirement(
        system_id=system.id,
        name=name[:120],
        baseline_types=dump_types(keys),
        owner_id=data.owner_id,
        due_date=data.due_date,
        status="in_progress",
    )
    db.add(req)
    db.commit()
    db.refresh(req)

    labels = "、".join(label_of(k) for k in keys)
    write_operation_log(db, current, "create_baseline_requirement", "baseline",
                        f"新增基线需求：{req.name}（系统#{system.id}，绑定 {len(keys)} 个基线：{labels}）")

    item_cache: dict = {}
    sys_cache: dict = {}
    return _requirement_out(req, system.name, _owner_name(db, req.owner_id),
                            _bound_by_type(db, req.type_keys, item_cache),
                            _system_status(db, req.system_id, sys_cache))


@router.put("/requirements/{requirement_id}", response_model=BaselineRequirementOut)
def update_requirement(requirement_id: int, data: BaselineRequirementUpdate,
                       db: Session = Depends(get_db),
                       current: User = Depends(get_current_user)):
    """编辑需求：改绑定范围 / 名称 / 负责人 / 截止时间 / 状态（只改传了的字段）。

    解绑某个基线**不会删除已填的评估结论** —— `baseline_result` 记的是"系统对该检查项的
    当前状况"，不属于某条需求（见 models.BaselineRequirement 的说明）。所以重新绑定回来时，
    原来的结论还在，不用重填。
    """
    _require_secops(current)
    req = _get_requirement(db, requirement_id)
    changes = data.model_dump(exclude_unset=True)

    labels_desc = None
    if "baseline_types" in changes:
        keys, unknown = normalize_types(changes["baseline_types"])
        if unknown:
            raise HTTPException(status_code=400, detail="未知基线类型：" + "、".join(unknown))
        if not keys:
            raise HTTPException(status_code=400, detail="请至少绑定一个基线")
        changes["baseline_types"] = dump_types(keys)
        labels_desc = "、".join(label_of(k) for k in keys)
    if "name" in changes:
        nm = (changes["name"] or "").strip()
        if not nm:
            raise HTTPException(status_code=400, detail="需求名称不能为空")
        changes["name"] = nm[:120]
    if changes.get("owner_id") is not None:
        if not db.query(User).filter(User.id == changes["owner_id"]).first():
            raise HTTPException(status_code=400, detail="负责人不存在")
    if "status" in changes and changes["status"] not in ("in_progress", "done"):
        raise HTTPException(status_code=400, detail="状态必须为 in_progress/done")

    for field, value in changes.items():
        setattr(req, field, value)
    db.commit()
    db.refresh(req)

    if changes:
        desc = "；".join(f"{k}={v}" for k, v in changes.items() if k != "baseline_types")
        if labels_desc:
            desc = (desc + "；" if desc else "") + f"绑定基线={labels_desc}"
        write_operation_log(db, current, "update_baseline_requirement", "baseline",
                            f"编辑基线需求：{req.name}（{desc}）")

    system_name = None
    system = db.query(AssetSystem).filter(AssetSystem.id == req.system_id).first()
    if system:
        system_name = system.name
    item_cache: dict = {}
    sys_cache: dict = {}
    return _requirement_out(req, system_name, _owner_name(db, req.owner_id),
                            _bound_by_type(db, req.type_keys, item_cache),
                            _system_status(db, req.system_id, sys_cache))


@router.delete("/requirements/{requirement_id}", status_code=204)
def delete_requirement(requirement_id: int, db: Session = Depends(get_db),
                       current: User = Depends(get_current_user)):
    """删除需求（只删"范围"，不删评估结论 —— 结论属于系统，不属于某条需求）。"""
    _require_secops(current)
    req = _get_requirement(db, requirement_id)
    name = req.name
    db.delete(req)
    db.commit()
    write_operation_log(db, current, "delete_baseline_requirement", "baseline",
                        f"删除基线需求：{name}")
    return None


@router.get("/requirements/{requirement_id}/items",
            response_model=list[BaselineRequirementItemOut])
def list_requirement_items(requirement_id: int, baseline_type: str = None,
                           db: Session = Depends(get_db),
                           current: User = Depends(get_current_user)):
    """需求详情：只返回**该需求绑定范围内**的条目 + 已有结论。

    未绑定的基线整段不出现（而不是显示 0%）—— 0% 读起来像"没达标"，而事实是"本轮不做
    这项"。返回顺序按基线目录顺序，前端直接按 `baseline_type` 分组即可。
    """
    req = _get_requirement(db, requirement_id)
    keys = req.type_keys
    if baseline_type:
        if baseline_type not in keys:
            return []
        keys = [baseline_type]
    if not keys:
        return []

    items = (
        db.query(BaselineItem)
        .join(BaselineCategory, BaselineItem.category_id == BaselineCategory.id)
        .filter(BaselineCategory.baseline_type.in_(keys))
        .order_by(BaselineItem.category_id, BaselineItem.sort)
        .all()
    )
    results = {
        r.item_id: r
        for r in db.query(BaselineResult).filter(BaselineResult.system_id == req.system_id).all()
    }

    buckets: dict[str, list] = {k: [] for k in keys}
    for it in items:
        btype = it.category.baseline_type if it.category else None
        if btype not in buckets:
            continue
        r = results.get(it.id)
        buckets[btype].append(BaselineRequirementItemOut(
            id=r.id if r else 0,
            system_id=req.system_id,
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
            baseline_type=btype,
            baseline_label=label_of(btype),
        ))
    return [o for k in TYPE_KEYS if k in buckets for o in buckets[k]]


@router.put("/requirements/{requirement_id}/items/{item_id}",
            response_model=BaselineResultOut)
def update_requirement_item(requirement_id: int, item_id: int, data: BaselineResultUpdate,
                            db: Session = Depends(get_db),
                            current: User = Depends(get_current_user)):
    """在需求范围内评估某检查项。

    权限：管理员/安全专家，**或该需求的负责人本人**（基线评估通常要研发自评）。

    为什么不复用 `/systems/{system_id}/items/{item_id}`：那个接口没有"需求"上下文，
    无法校验条目是否落在范围内 —— 只要拿到任意 item_id 就能改（含根本不在本次范围内的
    基线）。这里把放宽的权限**锁在绑定范围内**：负责人只能动自己需求绑定的那些条目。
    """
    req = _get_requirement(db, requirement_id)
    if _role_code(current) not in _WRITE_ROLES and req.owner_id != current.id:
        raise HTTPException(status_code=403, detail="仅管理员/安全专家或该需求负责人可评估")
    _validate_result_in(data)

    item = db.query(BaselineItem).filter(BaselineItem.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="检查项不存在")
    if item.id not in _bound_items(db, req.type_keys, {}):
        raise HTTPException(status_code=400, detail="该检查项不在本需求绑定的基线范围内")

    result = _save_result(db, req.system_id, item, data, current)
    # 全部评完就自动收口（行上不再需要第二个"标记完成"入口）
    _autoclose_if_done(db, req, current)
    write_operation_log(db, current, "check_baseline", "baseline",
                        f"需求#{req.id} 系统#{req.system_id} 检查项#{item_id} -> {data.status}")
    return _result_out(result)


@router.post("/requirements/{requirement_id}/bulk-result")
def bulk_update_requirement_items(requirement_id: int, data: BaselineBulkResultIn,
                                  db: Session = Depends(get_db),
                                  current: User = Depends(get_current_user)):
    """把一个需求下**某条基线**的检查项批量置为同一结果（页面上的「全部通过」）。

    为什么要有它：一条基线动辄几十上百项，而绝大多数结论是"通过" —— 逐条点按钮是这页
    最费时间的操作（实测有需求挂着 215 项待评估）。

    权限与单条评估**完全一致**（管理员/安全专家，或该需求负责人本人），并且和单条接口
    一样把放宽的权限**锁在本需求绑定的范围内**：只处理"本需求绑定的基线 × 传入的基线类型"
    的交集，拿到别人的 item_id 也动不了。

    ⚠️ 默认 only_pending=True：只填"未评估"的。已有结论（尤其"不通过"）是有依据的判断，
    批量操作绝不能顺手覆盖 —— 要整组重刷得显式传 only_pending=False。
    """
    req = _get_requirement(db, requirement_id)
    if _role_code(current) not in _WRITE_ROLES and req.owner_id != current.id:
        raise HTTPException(status_code=403, detail="仅管理员/安全专家或该需求负责人可评估")
    # 批量只允许「通过」/「不适用」：「不通过」必须逐项写依据（见 _validate_result_in）。
    # 一次给一整组塞同一句理由，等于把"依据"变成套话 —— 恰恰是合规检查最怕的东西。
    if data.status not in ("pass", "na"):
        raise HTTPException(status_code=400,
                            detail="批量只能置为 pass/na；「不通过」需逐项填写说明")
    if data.baseline_type not in TYPE_KEYS:
        raise HTTPException(status_code=400, detail="基线类型不存在")
    if data.baseline_type not in parse_types(req.type_keys):
        raise HTTPException(status_code=400, detail="该基线不在本需求绑定范围内")

    bound = set(_bound_items(db, [data.baseline_type], {}))
    items = []
    if bound:
        items = (db.query(BaselineItem)
                 .join(BaselineCategory, BaselineItem.category_id == BaselineCategory.id)
                 .filter(BaselineCategory.baseline_type == data.baseline_type,
                         BaselineItem.id.in_(bound))
                 .order_by(BaselineItem.category_id, BaselineItem.sort).all())

    changed = skipped = 0
    for it in items:
        r = db.query(BaselineResult).filter(BaselineResult.system_id == req.system_id,
                                           BaselineResult.item_id == it.id).first()
        if r is not None and data.only_pending and r.status != "pending":
            skipped += 1      # 已有结论（尤其"不通过"）不是"顺手覆盖"的对象
            continue
        _save_result(db, req.system_id, it, BaselineResultUpdate(status=data.status), current)
        changed += 1
    auto_done = _autoclose_if_done(db, req, current)
    write_operation_log(db, current, "check_baseline_bulk", "baseline",
                        f"需求#{req.id} 基线 {data.baseline_type} 批量置为 {data.status}："
                        f"改 {changed} 项 / 跳过 {skipped} 项")
    return {"changed": changed, "skipped": skipped, "total": len(items),
            "status": data.status, "auto_done": auto_done}


def _export_rows(db: Session, req: BaselineRequirement) -> list[dict]:
    """该需求绑定范围内的**全部条目** + 已有结论（导出 = 全量台账，不跟页面筛选走）。

    为什么按"全部"而不是"当前筛选"：这份文件的用途是留档/送审，缺页的台账没有意义；
    页面上筛来筛去是工作视角，两者目的不同。顺序与需求详情一致（基线目录序 + 分类 + sort）。
    """
    keys = req.type_keys
    if not keys:
        return []
    items = (
        db.query(BaselineItem)
        .join(BaselineCategory, BaselineItem.category_id == BaselineCategory.id)
        .filter(BaselineCategory.baseline_type.in_(keys))
        .order_by(BaselineItem.category_id, BaselineItem.sort)
        .all()
    )
    results = {
        r.item_id: r
        for r in db.query(BaselineResult).filter(BaselineResult.system_id == req.system_id).all()
    }
    checker_ids = {r.checker_id for r in results.values() if r.checker_id}
    names: dict[int, str] = {}
    if checker_ids:
        names = {u.id: (u.full_name or u.username)
                 for u in db.query(User).filter(User.id.in_(checker_ids)).all()}
    rows: list[dict] = []
    for it in items:
        r = results.get(it.id)
        rows.append({
            "baseline": label_of(it.category.baseline_type) if it.category else "",
            "category": it.category.name if it.category else "",
            "item": it.name,
            "description": it.description or "",
            "status": r.status if r else "pending",
            "evidence": (r.evidence if r else "") or "",
            "checker": names.get(r.checker_id, "") if r and r.checker_id else "",
            "checked_at": r.checked_at if r else None,
        })
    return rows


@router.get("/requirements/{requirement_id}/export")
def export_requirement(requirement_id: int, fmt: str = "csv",
                       db: Session = Depends(get_db),
                       current: User = Depends(get_current_user)):
    """导出某需求的评估明细（CSV，留档/送审用）。

    权限与评估**完全一致**（管理员/安全专家，或该需求负责人本人）：文件里逐条带着
    "结论 + 依据"，负责人导出自己的需求天经地义；而无关的人连评估都做不了，
    导出自然也不该放行（否则评估的权限闸就成了摆设）。

    文件名用 ``baseline-req<需求ID>-<时间>.csv``：需求名可能含中文，塞进
    Content-Disposition 需要 RFC 5987 编码、各种客户端支持不一，ID 最稳；
    文件内前两列就是系统名与需求名，打开就知道是哪份。
    """
    if fmt != "csv":
        raise HTTPException(status_code=400, detail="目前仅支持 csv")
    req = _get_requirement(db, requirement_id)
    if _role_code(current) not in _WRITE_ROLES and req.owner_id != current.id:
        raise HTTPException(status_code=403, detail="仅管理员/安全专家或该需求负责人可导出")

    system = db.query(AssetSystem).filter(AssetSystem.id == req.system_id).first()
    data = render_baseline_csv(_export_rows(db, req),
                               system_name=system.name if system else "",
                               requirement_name=req.name or "")
    stamp = nc.now().strftime("%Y%m%d-%H%M")
    write_operation_log(db, current, "export_baseline", "baseline",
                        f"导出需求#{req.id} 评估明细 CSV")
    return StreamingResponse(
        iter([data]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition":
                 f'attachment; filename="baseline-req{req.id}-{stamp}.csv"'},
    )


@router.post("/requirements/notify-due")
def notify_due_requirements(days: int | None = None, dry_run: bool = False,
                            db: Session = Depends(get_db),
                            current: User = Depends(get_current_user)):
    """手动跑一轮「需求到期提醒」（补发 / 验证用）。

    为什么要手动入口：定时任务只在每天固定时刻发一次，而"该发的人没收到""想提前提醒一下"
    是常态需求 —— 有个按钮就能补发，也不用来回重启服务去验证。
    去重是按天记的（操作日志），所以**手动发过的，当天定时任务不会再发一遍**。

    dry_run=True：只列出"会发给谁、为什么跳过"，不发消息也不写日志 —— 上线前自检用。
    """
    _require_secops(current)
    from ..baseline_reminder import tick

    result = tick(db, days=days, dry_run=dry_run)
    if not dry_run:
        write_operation_log(db, current, "baseline_due_manual", "baseline",
                            f"手动触发到期提醒：待发 {result['due']} 条 / 已发 {result['sent']} 条")
    return result


# ============ 系统合规检查（老接口，保留兼容）============
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
    _validate_result_in(data)
    item = db.query(BaselineItem).filter(BaselineItem.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="检查项不存在")

    result = _save_result(db, system_id, item, data, current)
    write_operation_log(db, current, "check_baseline", "baseline",
                        f"系统#{system_id} 检查项#{item_id} -> {data.status}")
    return _result_out(result)


# ============ 合规率统计（老接口，保留兼容）============
@router.get("/stats")
def baseline_stats(baseline_type: str = None,
                   db: Session = Depends(get_db),
                   current: User = Depends(get_current_user)):
    """各系统合规率统计（按基线类型）。**老口径**：分母是"系统数 × 全部条目数" ——
    新页面已改用 /requirements 的**按绑定范围**口径；这里保留是为了不破坏既有调用方。"""
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
