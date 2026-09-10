"""漏洞管理路由：提交/确认/修复/复测/关闭 + 状态机 + 评论。"""
import csv
import io
import json

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import inspect
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, Vuln, VulnComment, VulnFlow
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
from ..state_machine import TRANSITIONS, validate_action
from ..utils import network_clock as nc

# 导出文件与页面展示一致：DB 存 naive UTC，展示统一转东八区(北京时间)
from zoneinfo import ZoneInfo
_LOCAL_TZ = ZoneInfo("Asia/Shanghai")


def _cn_strftime(dt) -> str:
    """naive UTC -> 东八区 -> 'YYYY-MM-DD HH:MM'，供 CSV/DOCX 导出使用。"""
    if dt is None:
        return ""
    return nc.to_utc_aware(dt).astimezone(_LOCAL_TZ).strftime("%Y-%m-%d %H:%M")

router = APIRouter(prefix="/api/vulns", tags=["漏洞管理"])

STATUS_NAMES = {
    "draft": "草稿", "pending": "待确认", "confirmed": "已确认", "fixing": "修复中",
    "retest": "待复测", "fixed": "已修复", "closed": "已关闭", "rejected": "已驳回", "ignored": "已忽略",
}


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
    if status:
        query = query.filter(Vuln.status == status)
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
    if status:
        query = query.filter(Vuln.status == status)
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

    if fmt == "csv":
        return _export_csv(rows)
    return _export_docx(rows)


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
            {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}.get(r.severity, r.severity),
            r.vuln_category or "", r.vuln_type or "", STATUS_NAMES.get(r.status, r.status),
            r.reporter_name or "", r.assignee_name or "未指派", r.reviewer_name or "",
            _cn_strftime(r.created_at),
        ])
    data = buf.getvalue().encode("utf-8")
    return StreamingResponse(
        iter([data]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="vulns.csv"'},
    )


def _export_docx(rows: list[VulnOut]):
    from docx import Document
    from docx.shared import Pt, Inches
    from docx.oxml.ns import qn

    def _set_cn_font(run, font_name="Microsoft YaHei", size=None):
        """同时设置 ascii / hAnsi / eastAsia 三个字体族,避免中文显示为方块。"""
        run.font.name = font_name
        rPr = run._element.get_or_add_rPr()
        rFonts = rPr.find(qn("w:rFonts"))
        if rFonts is None:
            rFonts = rPr.makeelement(qn("w:rFonts"), {})
            rPr.insert(0, rFonts)
        rFonts.set(qn("w:eastAsia"), font_name)
        rFonts.set(qn("w:ascii"), font_name)
        rFonts.set(qn("w:hAnsi"), font_name)
        rFonts.set(qn("w:cs"), font_name)
        if size is not None:
            run.font.size = Pt(size)

    def _add_cn_paragraph(doc, text, size=10, bold=False):
        p = doc.add_paragraph()
        run = p.add_run(text)
        _set_cn_font(run, size=size)
        run.bold = bold
        return p

    def _data_url_to_bytes(data_url: str) -> bytes | None:
        """把 data:image/png;base64,xxx 还原成图片字节。"""
        if not data_url or not isinstance(data_url, str):
            return None
        if data_url.startswith("data:"):
            comma = data_url.find(",")
            if comma < 0:
                return None
            head = data_url[:comma]
            payload = data_url[comma + 1 :]
            if "base64" in head:
                import base64
                try:
                    return base64.b64decode(payload)
                except Exception:
                    return None
            # 非 base64,按 utf-8 解码后当文本
            return payload.encode("utf-8", errors="ignore")
        # 已是裸 url 或本地路径,暂不下载(避免依赖网络)
        return None

    def _add_image(doc, data_url: str, width_inches: float = 4.5):
        img_bytes = _data_url_to_bytes(data_url)
        if not img_bytes:
            return False
        try:
            doc.add_picture(io.BytesIO(img_bytes), width=Inches(width_inches))
            return True
        except Exception:
            return False

    doc = Document()
    # 全局 Normal 样式:把 ascii/hAnsi/eastAsia 都设为中文字体
    style = doc.styles["Normal"]
    style.font.name = "Microsoft YaHei"
    style.font.size = Pt(10)
    rpr = style.element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = rpr.makeelement(qn("w:rFonts"), {})
        rpr.insert(0, rfonts)
    rfonts.set(qn("w:eastAsia"), "Microsoft YaHei")
    rfonts.set(qn("w:ascii"), "Microsoft YaHei")
    rfonts.set(qn("w:hAnsi"), "Microsoft YaHei")
    rfonts.set(qn("w:cs"), "Microsoft YaHei")

    # 标题:用 heading 样式(本身可能用 Calibri),再覆盖中文字体
    title = doc.add_heading("漏洞清单", level=1)
    for run in title.runs:
        _set_cn_font(run, size=20, font_name="Microsoft YaHei")
    _add_cn_paragraph(doc, f"导出时间：{nc.now().strftime('%Y-%m-%d %H:%M')}    共 {len(rows)} 条", size=10)

    table = doc.add_table(rows=1, cols=10)
    table.style = "Light Grid Accent 1"
    hdr = table.rows[0].cells
    for i, h in enumerate(["ID", "标题", "系统", "接口地址", "等级", "大类", "类型", "状态", "负责人", "创建时间"]):
        hdr[i].text = ""  # 先清空,再用 run 写入并设置中文字体
        run = hdr[i].paragraphs[0].add_run(h)
        _set_cn_font(run, size=10)
        run.bold = True
    sev_map = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}
    for r in rows:
        cells = table.add_row().cells
        values = [
            str(r.id),
            r.title or "",
            r.system_name or "",
            r.api_endpoint or "",
            sev_map.get(r.severity, r.severity or ""),
            r.vuln_category or "",
            r.vuln_type or "",
            STATUS_NAMES.get(r.status, r.status or ""),
            r.assignee_name or "未指派",
            _cn_strftime(r.created_at),
        ]
        for i, v in enumerate(values):
            cells[i].text = ""
            run = cells[i].paragraphs[0].add_run(str(v))
            _set_cn_font(run, size=10)

    # 详情段落(含截图嵌入)
    if rows:
        doc.add_paragraph()
        h2 = doc.add_heading("漏洞详情", level=2)
        for run in h2.runs:
            _set_cn_font(run, size=14)
        for r in rows:
            h3 = doc.add_heading(f"#{r.id} {r.title}", level=3)
            for run in h3.runs:
                _set_cn_font(run, size=12)
            _add_cn_paragraph(
                doc,
                f"所属系统：{r.system_name or '—'}    接口地址：{r.api_endpoint or '—'}    等级：{sev_map.get(r.severity, r.severity or '')}    状态：{STATUS_NAMES.get(r.status, r.status or '')}",
                size=10,
            )
            _add_cn_paragraph(
                doc,
                f"漏洞类型：{r.vuln_category or '—'} / {r.vuln_type or '—'}",
                size=10,
            )
            _add_cn_paragraph(
                doc,
                f"提交人：{r.reporter_name or '—'}    负责人：{r.assignee_name or '未指派'}    复测人：{r.reviewer_name or '—'}",
                size=10,
            )
            if r.description:
                _add_cn_paragraph(doc, f"【漏洞描述】{r.description}", size=10)
            if r.reproduce_steps:
                _add_cn_paragraph(doc, f"【复现步骤】{r.reproduce_steps}", size=10)
            if r.impact:
                _add_cn_paragraph(doc, f"【影响范围】{r.impact}", size=10)
            if r.fix_suggestion:
                _add_cn_paragraph(doc, f"【修复建议】{r.fix_suggestion}", size=10)

            # 复现步骤截图(每步配图)
            if r.step_screenshots:
                _add_cn_paragraph(doc, f"【复现步骤截图】共 {len(r.step_screenshots)} 张", size=10, bold=True)
                ok = 0
                for shot in r.step_screenshots:
                    data_url = (shot or {}).get("data_url") if isinstance(shot, dict) else None
                    step_no = (shot or {}).get("step_no") if isinstance(shot, dict) else None
                    if step_no is not None:
                        _add_cn_paragraph(doc, f"步骤 {step_no}:", size=10)
                    if data_url and _add_image(doc, data_url):
                        ok += 1
                    else:
                        _add_cn_paragraph(doc, "  (图片数据无法解析,略)", size=10)
                if ok == 0:
                    _add_cn_paragraph(doc, "  (所有步骤截图均无法解析,需通过系统查看)", size=10)

            # 兼容旧字段:全局截图列表
            if r.screenshots:
                _add_cn_paragraph(doc, f"【截图证据】共 {len(r.screenshots)} 张", size=10, bold=True)
                ok = 0
                for url in r.screenshots:
                    if _add_image(doc, url):
                        ok += 1
                if ok == 0:
                    _add_cn_paragraph(doc, "  (截图数据无法解析,需通过系统查看)", size=10)
            doc.add_paragraph("")

    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": 'attachment; filename="vulns.docx"'},
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
