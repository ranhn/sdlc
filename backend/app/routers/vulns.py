"""漏洞管理路由：提交/确认/修复/复测/关闭 + 状态机 + 评论。"""
import csv
import io
import json

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import inspect
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AssetSystem, User, Vuln, VulnComment, VulnFlow
from ..schemas import (
    VulnAssign,
    VulnCommentOut,
    VulnCreate,
    VulnFlowOut,
    VulnOut,
    VulnReject,
    VulnStatusAction,
    VulnUpdate,
)
from ..security import get_current_user, write_operation_log
from ..state_machine import STATUS_NAMES, TRANSITIONS, validate_action
from ..utils import network_clock as nc
from ..utils.vuln_docx import SEV_ZH, render_vulns_docx

# 导出文件与页面展示一致：DB 存 naive UTC，展示统一转东八区(北京时间)
from zoneinfo import ZoneInfo
_LOCAL_TZ = ZoneInfo("Asia/Shanghai")


def _cn_strftime(dt) -> str:
    """naive UTC -> 东八区 -> 'YYYY-MM-DD HH:MM'，供 CSV/DOCX 导出使用。"""
    if dt is None:
        return ""
    return nc.to_utc_aware(dt).astimezone(_LOCAL_TZ).strftime("%Y-%m-%d %H:%M")

router = APIRouter(prefix="/api/vulns", tags=["漏洞管理"])

# STATUS_NAMES 已收敛到 state_machine（单一来源），此处不再本地维护一份副本。


def _to_out(v: Vuln, db: Session) -> VulnOut:
    data = {c.key: getattr(v, c.key) for c in inspect(v).mapper.column_attrs}
    if data.get("screenshots"):
        try:
            data["screenshots"] = json.loads(data["screenshots"])
        except (TypeError, json.JSONDecodeError):
            data["screenshots"] = None
    else:
        data["screenshots"] = None
    if data.get("step_screenshots"):
        try:
            data["step_screenshots"] = json.loads(data["step_screenshots"])
        except (TypeError, json.JSONDecodeError):
            data["step_screenshots"] = None
    else:
        data["step_screenshots"] = None
    out = VulnOut.model_validate(data)
    reporter = db.query(User).filter(User.id == v.reporter_id).first()
    assignee = db.query(User).filter(User.id == v.assignee_id).first() if v.assignee_id is not None else None
    reviewer = db.query(User).filter(User.id == v.reviewer_id).first() if v.reviewer_id is not None else None
    out.reporter_name = reporter.full_name if reporter else None
    out.assignee_name = assignee.full_name if assignee else None
    out.reviewer_name = reviewer.full_name if reviewer else None
    if v.system:
        out.system_name = v.system.name
    return out


def _record_flow(db: Session, vuln_id: int, from_status: str | None, to_status: str,
                 operator: User, comment: str | None):
    db.add(VulnFlow(
        vuln_id=vuln_id,
        from_status=from_status,
        to_status=to_status,
        operator_id=operator.id,
        operator_name=operator.full_name,
        comment=comment,
    ))
    db.commit()


def _apply_status_filter(query, status: str | None):
    """按状态过滤（支持逗号分隔的多状态）。

    背景：rejected（已驳回）与 ignored（已忽略）都是"不修的终态"，前端把两者
    归成一个「已忽略 / 已驳回」选项，传 status=ignored,rejected —— 否则驳回的
    漏洞在状态筛选里根本搜不到（此前下拉里也没有「已驳回」项）。
    单值时行为与原来完全一致（精确匹配），历史调用方不受影响。
    """
    if not status:
        return query
    codes = [s.strip() for s in status.split(",") if s.strip()]
    if not codes:
        return query
    if len(codes) == 1:
        return query.filter(Vuln.status == codes[0])
    return query.filter(Vuln.status.in_(codes))


def _describe_scope(
    db: Session,
    *,
    status: str | None = None,
    severity: str | None = None,
    system_id: int | None = None,
    mine: bool = False,
    assigned_to_me: bool = False,
    ids: str | None = None,
) -> str:
    """把导出筛选条件翻译成报告封面/附录用的自然语言范围描述。

    为什么要有：报告一旦离开系统（打印、外发），读者只能从文档本身判断
    "这份清单是哪一批数据"。不写清范围，几份不同筛选的报告混在一起就分不出来了。
    """
    parts: list[str] = []
    if ids:
        parts.append(f"指定漏洞（{len([x for x in ids.split(',') if x.strip()])} 条）")
    if status:
        names = " / ".join(
            STATUS_NAMES.get(s.strip(), s.strip())
            for s in status.split(",") if s.strip()
        )
        if names:
            parts.append(f"状态：{names}")
    if severity:
        parts.append(f"等级：{SEV_ZH.get(severity, severity)}")
    if system_id:
        row = db.query(AssetSystem).filter(AssetSystem.id == system_id).first()
        parts.append(f"所属系统：{row.name if row else system_id}")
    if assigned_to_me:
        parts.append("指派给我的漏洞")
    elif mine:
        parts.append("与我相关（我提交或我负责）")
    return " · ".join(parts) if parts else "全部漏洞"


@router.get("", response_model=list[VulnOut])
def list_vulns(
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    system_id: int | None = Query(default=None),
    vuln_category: str | None = Query(default=None, description="一级大类过滤,如 注入类 / 访问控制"),
    vuln_type: str | None = Query(default=None, description="二级子类过滤,如 SQL注入"),
    mine: bool = Query(default=False),
    assigned_to_me: bool = Query(default=False),
    is_external: bool | None = Query(default=None, description="漏洞来源过滤：None=全部, True=外部, False=内部"),
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    query = db.query(Vuln)
    query = _apply_status_filter(query, status)
    if severity:
        query = query.filter(Vuln.severity == severity)
    if system_id:
        query = query.filter(Vuln.system_id == system_id)
    if vuln_category:
        query = query.filter(Vuln.vuln_category == vuln_category)
    if vuln_type:
        query = query.filter(Vuln.vuln_type == vuln_type)
    if is_external is not None:
        query = query.filter(Vuln.is_external == is_external)
    if mine:
        query = query.filter((Vuln.reporter_id == current.id) | (Vuln.assignee_id == current.id))
    if assigned_to_me:
        query = query.filter(Vuln.assignee_id == current.id)
    vulns = query.order_by(Vuln.created_at.desc()).all()
    return [_to_out(v, db) for v in vulns]


@router.get("/export")
def export_vulns(
    fmt: str = Query(..., pattern="^(csv|docx)$"),
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    system_id: int | None = Query(default=None),
    mine: bool = Query(default=False),
    assigned_to_me: bool = Query(default=False),
    ids: str | None = Query(default=None, description="可选,逗号分隔的漏洞 ID 列表；传了则只导出这些条(与其它筛选条件取交集)"),
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    """批量导出漏洞（CSV / Word）。仅管理员/安全专家可操作。"""
    if current.role is None or current.role.code not in ("admin", "secops"):
        raise HTTPException(status_code=403, detail="仅管理员/安全专家可导出漏洞")
    query = db.query(Vuln)
    # 与列表同一套状态过滤（含 ignored,rejected 这种"忽略组"），保证导出范围与列表所见一致
    query = _apply_status_filter(query, status)
    if severity:
        query = query.filter(Vuln.severity == severity)
    if system_id:
        query = query.filter(Vuln.system_id == system_id)
    if mine:
        query = query.filter((Vuln.reporter_id == current.id) | (Vuln.assignee_id == current.id))
    if assigned_to_me:
        query = query.filter(Vuln.assignee_id == current.id)
    if ids:
        # 解析逗号分隔的 ID 列表,过滤非法值
        try:
            id_list = [int(x) for x in ids.split(",") if x.strip()]
        except ValueError:
            raise HTTPException(status_code=400, detail="ids 参数格式错误,应为逗号分隔的整数")
        if not id_list:
            raise HTTPException(status_code=400, detail="ids 参数不能为空")
        query = query.filter(Vuln.id.in_(id_list))
    vulns = query.order_by(Vuln.created_at.desc()).all()
    rows = [_to_out(v, db) for v in vulns]

    scope_desc = _describe_scope(
        db, status=status, severity=severity, system_id=system_id,
        mine=mine, assigned_to_me=assigned_to_me, ids=ids,
    )
    if fmt == "csv":
        return _export_csv(rows)
    return _export_docx(rows, exported_by=current.full_name, scope_desc=scope_desc)


def _export_csv(rows: list[VulnOut]):
    headers = ["ID", "标题", "所属系统", "接口地址", "等级", "大类", "类型", "状态", "提交人", "负责人", "复测人", "创建时间"]
    buf = io.StringIO()
    # 写入 BOM 让 Excel 正确识别 UTF-8
    buf.write("\ufeff")
    writer = csv.writer(buf)
    writer.writerow(headers)
    for r in rows:
        writer.writerow([
            r.id, r.title, r.system_name or "", r.api_endpoint or "",
            # 等级中文化统一走 vuln_docx.SEV_ZH（Word 报告同源），避免两处各写一份
            SEV_ZH.get(r.severity, r.severity),
            r.vuln_category or "", r.vuln_type or "", STATUS_NAMES.get(r.status, r.status),
            r.reporter_name or "", r.assignee_name or "未指派", r.reviewer_name or "",
            _cn_strftime(r.created_at),
        ])
    data = buf.getvalue().encode("utf-8")
    return StreamingResponse(
        iter([data]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="vulns-{nc.now().strftime("%Y%m%d-%H%M")}.csv"'},
    )


def _export_docx(rows: list[VulnOut], *, exported_by: str | None = None,
                 scope_desc: str | None = None):
    """生成漏洞清单 Word 报告（商业级排版）。

    排版逻辑集中在 ``utils.vuln_docx``（封面 / 统计概览 / 横向清单表 / 逐条详情 /
    页眉页脚页码 / 附录），路由层只负责"渲染 + 包成下载响应"。

    为什么重写（用户反馈："批量导出的 word 报告格式有点问题"）：
        旧实现 ``doc.add_table(rows=1, cols=10)`` 且**不设列宽** —— A4 纵向版心
        16.4cm 被 10 等分，每列约 1.6cm，长文本被压成一字一行（标题竖排、ID 断成
        两行、接口地址只剩一列竖字）。Word 是固定表格布局，列宽必须显式写进
        tblGrid/tcW（见 ``vuln_docx._set_col_widths``），并且清单章改用**横向**
        版心 25.1cm，10 列才有合理宽度。
    """
    data = render_vulns_docx(rows, exported_by=exported_by, scope_desc=scope_desc)
    stamp = nc.now().strftime("%Y%m%d-%H%M")
    return StreamingResponse(
        iter([data]),
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="vulns-report-{stamp}.docx"'},
    )







@router.get("/{vuln_id}", response_model=VulnOut)
def get_vuln(vuln_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    v = db.query(Vuln).filter(Vuln.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    return _to_out(v, db)


@router.post("", response_model=VulnOut, status_code=201)
def create_vuln(data: VulnCreate, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    v = Vuln(
        title=data.title,
        description=data.description,
        reproduce_steps=data.reproduce_steps,
        impact=data.impact,
        screenshots=json.dumps(data.screenshots, ensure_ascii=False) if data.screenshots else None,
        step_screenshots=json.dumps(data.step_screenshots, ensure_ascii=False) if data.step_screenshots else None,
        system_id=data.system_id,
        severity=data.severity,
        vuln_category=data.vuln_category,
        vuln_type=data.vuln_type,
        cvss=data.cvss,
        reporter_id=current.id,
        assignee_id=data.assignee_id,
        status="pending",
        source="manual",
        is_external=data.is_external,
        external_source=data.external_source,
        api_endpoint=data.api_endpoint,
        fix_suggestion=data.fix_suggestion,
    )
    db.add(v)
    db.commit()
    db.refresh(v)
    _record_flow(db, v.id, "draft", "pending", current, "漏洞提交")
    write_operation_log(db, current, "create_vuln", "vuln", f"提交漏洞 #{v.id} {v.title}")
    return _to_out(v, db)


@router.patch("/{vuln_id}", response_model=VulnOut)
def update_vuln(vuln_id: int, data: VulnUpdate, db: Session = Depends(get_db),
                current: User = Depends(get_current_user)):
    """编辑漏洞字段。权限：提交人本人 / 管理员 / 安全专家。

    closed 状态下不可编辑（避免审计期改记录）；其他状态允许补充修正。
    只覆盖请求里实际携带的字段（schema 已全部 Optional）。
    """
    v = db.query(Vuln).filter(Vuln.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    role_code = current.role.code if current.role else "user"
    is_owner = v.reporter_id == current.id
    is_admin_or_secops = role_code in ("admin", "secops")
    if not (is_owner or is_admin_or_secops):
        raise HTTPException(status_code=403, detail="仅提交人本人或管理员/安全专家可编辑")
    if v.status == "closed":
        raise HTTPException(status_code=400, detail="已关闭的漏洞不可编辑")

    # 仅应用显式提供的字段，避免把未传的字段（如 assignee_id=None）误清空。
    updates = data.model_dump(exclude_unset=True)
    # list/dict 字段单独序列化
    if "screenshots" in updates:
        v.screenshots = json.dumps(updates.pop("screenshots"), ensure_ascii=False) if updates["screenshots"] is not None else None
    if "step_screenshots" in updates:
        v.step_screenshots = json.dumps(updates.pop("step_screenshots"), ensure_ascii=False) if updates["step_screenshots"] is not None else None
    for key, val in updates.items():
        setattr(v, key, val)

    db.commit()
    db.refresh(v)
    write_operation_log(
        db, current, "update_vuln", "vuln",
        f"编辑漏洞 #{v.id}「{v.title}」（{role_code}）",
    )
    return _to_out(v, db)


@router.post("/{vuln_id}/assign", response_model=VulnOut)
def assign_vuln(vuln_id: int, data: VulnAssign, db: Session = Depends(get_db),
                current: User = Depends(get_current_user)):
    v = db.query(Vuln).filter(Vuln.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    if current.role is None or current.role.code not in ("admin", "secops"):
        raise HTTPException(status_code=403, detail="仅安全专家可指派")
    if not db.query(User).filter(User.id == data.assignee_id).first():
        raise HTTPException(status_code=400, detail="负责人不存在")
    assignee = db.query(User).filter(User.id == data.assignee_id).first()
    v.assignee_id = data.assignee_id
    db.commit()
    db.refresh(v)
    # 详情里同时记录「指派给 谁(中文名)[ID]」，便于审计日志辨识接收人
    assignee_desc = (
        f"{assignee.username}({assignee.full_name})[ID={assignee.id}]"
        if assignee
        else f"ID={data.assignee_id}"
    )
    write_operation_log(
        db, current, "assign_vuln", "vuln",
        f"指派漏洞 #{v.id}「{v.title}」给 {assignee_desc}",
    )
    return _to_out(v, db)


@router.post("/{vuln_id}/action/{action}", response_model=VulnOut)
def vuln_action(vuln_id: int, action: str, data: VulnStatusAction,
                db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    v = db.query(Vuln).filter(Vuln.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    role_code = current.role.code if current.role else "user"
    if not validate_action(action, v.status, role_code):
        raise HTTPException(status_code=403, detail=f"当前状态({STATUS_NAMES.get(v.status, v.status)})下，角色无权执行[{action}]操作")

    to_status = TRANSITIONS[action]
    from_status = v.status
    v.status = to_status

    if action == "close":
        v.closed_at = __import__("datetime").nc.utcnow()
    if action == "finish_fix":
        v.fixed_at = __import__("datetime").nc.utcnow()
        v.reviewer_id = current.id
    if action == "pass_retest":
        v.reviewer_id = current.id

    db.commit()
    db.refresh(v)
    _record_flow(db, v.id, from_status, to_status, current, data.comment)
    write_operation_log(db, current, f"vuln_{action}", "vuln", f"漏洞 #{v.id} {from_status}->{to_status}")
    return _to_out(v, db)


@router.post("/{vuln_id}/reject", response_model=VulnOut)
def reject_vuln(vuln_id: int, data: VulnReject, db: Session = Depends(get_db),
                current: User = Depends(get_current_user)):
    v = db.query(Vuln).filter(Vuln.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    role_code = current.role.code if current.role else "user"
    if not validate_action("reject", v.status, role_code):
        raise HTTPException(status_code=403, detail="无权限驳回")
    v.status = "rejected"
    v.rejection_reason = data.reason
    db.commit()
    db.refresh(v)
    _record_flow(db, v.id, "pending", "rejected", current, f"驳回：{data.reason}")
    write_operation_log(db, current, "vuln_reject", "vuln", f"漏洞 #{v.id} 驳回：{data.reason}")
    return _to_out(v, db)


@router.get("/{vuln_id}/flows", response_model=list[VulnFlowOut])
def vuln_flows(vuln_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    return db.query(VulnFlow).filter(VulnFlow.vuln_id == vuln_id).order_by(VulnFlow.created_at.asc()).all()


@router.get("/{vuln_id}/comments", response_model=list[VulnCommentOut])
def vuln_comments(vuln_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    return db.query(VulnComment).filter(VulnComment.vuln_id == vuln_id).order_by(VulnComment.created_at.asc()).all()


@router.post("/{vuln_id}/comments", response_model=VulnCommentOut)
def add_comment(vuln_id: int, content: VulnStatusAction, db: Session = Depends(get_db),
                current: User = Depends(get_current_user)):
    if not db.query(Vuln).filter(Vuln.id == vuln_id).first():
        raise HTTPException(status_code=404, detail="漏洞不存在")
    c = VulnComment(vuln_id=vuln_id, user_id=current.id, username=current.full_name, content=content.comment)
    db.add(c)
    db.commit()
    db.refresh(c)
    return c


@router.delete("/{vuln_id}")
def delete_vuln(vuln_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    """删除漏洞。仅管理员/安全专家可操作。"""
    if current.role is None or current.role.code not in ("admin", "secops"):
        raise HTTPException(status_code=403, detail="仅管理员/安全专家可删除漏洞")
    v = db.query(Vuln).filter(Vuln.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    title = v.title
    # 级联删除关联数据
    db.query(VulnFlow).filter(VulnFlow.vuln_id == vuln_id).delete()
    db.query(VulnComment).filter(VulnComment.vuln_id == vuln_id).delete()
    db.delete(v)
    db.commit()
    write_operation_log(db, current, "delete_vuln", "vuln", f"删除漏洞 #{vuln_id} {title}")
    return {"detail": "已删除"}
