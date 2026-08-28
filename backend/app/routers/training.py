"""安全培训路由（P2）：课程管理、学习进度、考试题库、在线测验、培训统计。"""
import json
import os
import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import (
    CourseProgress, QuizExam, QuizQuestion, TrainingCourse, User,
)
from ..schemas import (
    CourseComplete, CourseProgressOut, QuizExamOut, QuizQuestionCreate,
    QuizQuestionOut, QuizQuestionOutSecure, QuizSubmit, TrainingCourseCreate,
    TrainingCourseOut,
)
from ..security import get_current_user, write_operation_log

UPLOAD_BASE = Path(__file__).resolve().parent.parent.parent / "uploads" / "training"
UPLOAD_BASE.mkdir(parents=True, exist_ok=True)

router = APIRouter(prefix="/api/training", tags=["安全培训"])


# ============ 权限 ============
def _require_trainer(user: User):
    """安全专家/超管可管理课程与题库。"""
    if user.role is None or user.role.code not in ("admin", "secops"):
        raise HTTPException(status_code=403, detail="仅安全专家/管理员可操作")


def _to_course(c: TrainingCourse, db: Session, current: User) -> TrainingCourseOut:
    out = TrainingCourseOut.model_validate(c)
    out.instructor_name = c.instructor.full_name if c.instructor else None
    # 当前用户是否已学完
    p = db.query(CourseProgress).filter(
        CourseProgress.course_id == c.id,
        CourseProgress.user_id == current.id,
    ).first()
    out.completed = bool(p and p.completed_at)
    out.enroll_count = db.query(CourseProgress).filter(
        CourseProgress.course_id == c.id).count()
    return out


def _to_progress(p: CourseProgress, db: Session) -> CourseProgressOut:
    out = CourseProgressOut.model_validate(p)
    out.course_title = p.course.title if p.course else None
    out.category = p.course.category if p.course else None
    out.is_completed = bool(p.completed_at)
    return out


def _to_exam(e: QuizExam, db: Session) -> QuizExamOut:
    out = QuizExamOut.model_validate(e)
    out.course_title = e.course.title if e.course else None
    out.user_name = e.user.full_name if e.user else None
    return out


# ============ 课程管理 ============
@router.get("/courses", response_model=list[TrainingCourseOut])
def list_courses(category: str | None = None, db: Session = Depends(get_db),
                 current: User = Depends(get_current_user)):
    query = db.query(TrainingCourse).filter(TrainingCourse.is_published == True)
    if category:
        query = query.filter(TrainingCourse.category == category)
    courses = query.order_by(TrainingCourse.created_at.desc()).all()
    return [_to_course(c, db, current) for c in courses]


@router.get("/courses/all", response_model=list[TrainingCourseOut])
def list_all_courses(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    """管理视图：含未发布课程。"""
    _require_trainer(current)
    courses = db.query(TrainingCourse).order_by(TrainingCourse.created_at.desc()).all()
    return [_to_course(c, db, current) for c in courses]


@router.post("/courses", response_model=TrainingCourseOut, status_code=201)
def create_course(data: TrainingCourseCreate, db: Session = Depends(get_db),
                  current: User = Depends(get_current_user)):
    _require_trainer(current)
    course = TrainingCourse(**data.model_dump())
    db.add(course)
    db.commit()
    db.refresh(course)
    write_operation_log(db, current, "create_course", "training", f"创建课程 {course.title}")
    return _to_course(course, db, current)


@router.put("/courses/{course_id}", response_model=TrainingCourseOut)
def update_course(course_id: int, data: TrainingCourseCreate, db: Session = Depends(get_db),
                  current: User = Depends(get_current_user)):
    _require_trainer(current)
    course = db.query(TrainingCourse).filter(TrainingCourse.id == course_id).first()
    if not course:
        raise HTTPException(status_code=404, detail="课程不存在")
    for k, v in data.model_dump().items():
        setattr(course, k, v)
    db.commit()
    db.refresh(course)
    write_operation_log(db, current, "update_course", "training", f"更新课程 {course.title}")
    return _to_course(course, db, current)


@router.delete("/courses/{course_id}")
def delete_course(course_id: int, db: Session = Depends(get_db),
                  current: User = Depends(get_current_user)):
    _require_trainer(current)
    course = db.query(TrainingCourse).filter(TrainingCourse.id == course_id).first()
    if not course:
        raise HTTPException(status_code=404, detail="课程不存在")
    # 清理附件文件
    if course.attachment_path and os.path.isfile(course.attachment_path):
        os.remove(course.attachment_path)
    db.delete(course)
    db.commit()
    write_operation_log(db, current, "delete_course", "training", f"删除课程 {course.title}")
    return {"ok": True}


@router.get("/courses/{course_id}", response_model=TrainingCourseOut)
def get_course(course_id: int, db: Session = Depends(get_db),
               current: User = Depends(get_current_user)):
    course = db.query(TrainingCourse).filter(TrainingCourse.id == course_id).first()
    if not course or not course.is_published:
        raise HTTPException(status_code=404, detail="课程不存在")
    return _to_course(course, db, current)


@router.post("/upload")
def upload_file(
    file: UploadFile = File(...),
    current: User = Depends(get_current_user),
):
    """上传课程附件（PPT/PDF/Word/视频等）。"""
    _require_trainer(current)
    allowed = {".ppt", ".pptx", ".pdf", ".doc", ".docx", ".mp4", ".mov", ".avi", ".mkv", ".zip", ".rar"}
    ext = Path(file.filename or "").suffix.lower()
    if ext not in allowed:
        raise HTTPException(status_code=400, detail=f"不支持的文件类型：{ext}")
    # 限制上传大小（默认 50MB）
    max_size = int(os.getenv("MAX_UPLOAD_SIZE_MB", "50")) * 1024 * 1024
    if hasattr(file, "size") and file.size and file.size > max_size:
        raise HTTPException(status_code=413, detail=f"文件过大，最大允许 {max_size // (1024*1024)}MB")
    safe_name = f"{uuid.uuid4().hex}{ext}"
    dest = UPLOAD_BASE / safe_name
    with dest.open("wb") as f:
        shutil.copyfileobj(file.file, f)
    return {
        "url": f"/uploads/training/{safe_name}",
        "path": str(dest),
        "filename": file.filename,
    }


@router.get("/download/{course_id}")
def download_attachment(course_id: int, db: Session = Depends(get_db),
                        current: User = Depends(get_current_user)):
    """下载课程附件。"""
    course = db.query(TrainingCourse).filter(TrainingCourse.id == course_id).first()
    if not course or not course.attachment_path or not os.path.isfile(course.attachment_path):
        raise HTTPException(status_code=404, detail="附件不存在")
    return FileResponse(
        course.attachment_path,
        filename=course.attachment_name or os.path.basename(course.attachment_path),
    )


# ============ 学习进度 ============
@router.post("/courses/{course_id}/start")
def start_course(course_id: int, db: Session = Depends(get_db),
                 current: User = Depends(get_current_user)):
    """开始学习（记录一条进度）。"""
    course = db.query(TrainingCourse).filter(TrainingCourse.id == course_id).first()
    if not course or not course.is_published:
        raise HTTPException(status_code=404, detail="课程不存在")
    p = db.query(CourseProgress).filter(
        CourseProgress.course_id == course_id,
        CourseProgress.user_id == current.id,
    ).first()
    if not p:
        p = CourseProgress(course_id=course_id, user_id=current.id)
        db.add(p)
        db.commit()
        db.refresh(p)
        write_operation_log(db, current, "start_course", "training", f"开始学习课程 {course.title}")
    return {"ok": True, "progress_id": p.id}


@router.post("/courses/{course_id}/complete", response_model=CourseProgressOut)
def complete_course(course_id: int, data: CourseComplete | None = None,
                    db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    """标记课程完成，可携带测验得分。"""
    course = db.query(TrainingCourse).filter(TrainingCourse.id == course_id).first()
    if not course:
        raise HTTPException(status_code=404, detail="课程不存在")
    p = db.query(CourseProgress).filter(
        CourseProgress.course_id == course_id,
        CourseProgress.user_id == current.id,
    ).first()
    if not p:
        p = CourseProgress(course_id=course_id, user_id=current.id)
        db.add(p)
        db.flush()
    from datetime import datetime
    p.completed_at = datetime.utcnow()
    if data and data.score is not None:
        p.score = data.score
    db.commit()
    db.refresh(p)
    write_operation_log(db, current, "complete_course", "training", f"完成课程 {course.title}")
    return _to_progress(p, db)


@router.get("/progress", response_model=list[CourseProgressOut])
def my_progress(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    """我的学习记录。课程被删除后自动清理对应进度。"""
    rows = db.query(CourseProgress).filter(
        CourseProgress.user_id == current.id).order_by(CourseProgress.started_at.desc()).all()
    # 过滤掉课程已被删除的进度
    valid = [p for p in rows if p.course is not None]
    return [_to_progress(p, db) for p in valid]


@router.get("/courses/{course_id}/progress")
def course_progress(course_id: int, db: Session = Depends(get_db),
                    current: User = Depends(get_current_user)):
    """某课程的完成情况（讲师/管理员可见）。"""
    _require_trainer(current)
    rows = db.query(CourseProgress).filter(CourseProgress.course_id == course_id).all()
    data = []
    for p in rows:
        data.append({
            "user_id": p.user_id,
            "user_name": p.user.full_name if p.user else None,
            "started_at": p.started_at.isoformat() if p.started_at else None,
            "completed_at": p.completed_at.isoformat() if p.completed_at else None,
            "score": p.score,
        })
    return data


# ============ 题库 ============
@router.get("/questions", response_model=list[QuizQuestionOut])
def list_questions(course_id: int | None = None, db: Session = Depends(get_db),
                   current: User = Depends(get_current_user)):
    _require_trainer(current)
    query = db.query(QuizQuestion)
    if course_id:
        query = query.filter(QuizQuestion.course_id == course_id)
    return query.order_by(QuizQuestion.id).all()


@router.post("/questions", response_model=QuizQuestionOut, status_code=201)
def create_question(data: QuizQuestionCreate, db: Session = Depends(get_db),
                    current: User = Depends(get_current_user)):
    _require_trainer(current)
    q = QuizQuestion(**data.model_dump())
    db.add(q)
    db.commit()
    db.refresh(q)
    write_operation_log(db, current, "create_question", "training", f"新增题目 {q.question[:20]}")
    return q


@router.delete("/questions/{question_id}")
def delete_question(question_id: int, db: Session = Depends(get_db),
                    current: User = Depends(get_current_user)):
    _require_trainer(current)
    q = db.query(QuizQuestion).filter(QuizQuestion.id == question_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="题目不存在")
    db.delete(q)
    db.commit()
    write_operation_log(db, current, "delete_question", "training", f"删除题目#{question_id}")
    return {"ok": True}


# ============ 在线测验 ============
@router.post("/exams", response_model=QuizExamOut, status_code=201)
def create_exam(course_id: int | None = None, count: int = 5,
                db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    """生成一份测验：从题库随机抽 count 题。"""
    query = db.query(QuizQuestion)
    if course_id:
        query = query.filter(QuizQuestion.course_id == course_id)
    else:
        query = query.filter(QuizQuestion.course_id.is_(None))
    questions = query.all()
    if len(questions) < count:
        count = len(questions)
    if count == 0:
        raise HTTPException(status_code=400, detail="题库为空，请先录入题目")
    import random
    picked = random.sample(questions, count)
    title = "安全培训测验"
    if course_id:
        course = db.query(TrainingCourse).filter(TrainingCourse.id == course_id).first()
        if course:
            title = f"{course.title} - 随堂测验"
    exam = QuizExam(
        course_id=course_id,
        user_id=current.id,
        title=title,
        questions=json.dumps([q.id for q in picked]),
        pass_score=60,
        status="in_progress",
    )
    db.add(exam)
    db.commit()
    db.refresh(exam)
    write_operation_log(db, current, "create_exam", "training", f"生成测验 {title}")
    return _to_exam(exam, db)


@router.get("/exams/{exam_id}/questions", response_model=list[QuizQuestionOutSecure])
def exam_questions(exam_id: int, db: Session = Depends(get_db),
                   current: User = Depends(get_current_user)):
    """取测验题目（答题时，不含答案/解析）。"""
    exam = db.query(QuizExam).filter(QuizExam.id == exam_id).first()
    if not exam or exam.user_id != current.id:
        raise HTTPException(status_code=404, detail="测验不存在")
    qids = json.loads(exam.questions) if exam.questions else []
    questions = db.query(QuizQuestion).filter(QuizQuestion.id.in_(qids)).all()
    # 保持抽题顺序
    order = {qid: i for i, qid in enumerate(qids)}
    questions.sort(key=lambda q: order.get(q.id, 0))
    return [QuizQuestionOutSecure.model_validate(q) for q in questions]


@router.post("/exams/{exam_id}/submit", response_model=QuizExamOut)
def submit_exam(exam_id: int, data: QuizSubmit, db: Session = Depends(get_db),
                current: User = Depends(get_current_user)):
    """提交测验并自动判分。"""
    exam = db.query(QuizExam).filter(QuizExam.id == exam_id).first()
    if not exam or exam.user_id != current.id:
        raise HTTPException(status_code=404, detail="测验不存在")
    if exam.status != "in_progress":
        raise HTTPException(status_code=400, detail="测验已提交，不可重复作答")
    qids = json.loads(exam.questions) if exam.questions else []
    questions = db.query(QuizQuestion).filter(QuizQuestion.id.in_(qids)).all()
    qmap = {q.id: q for q in questions}
    total = 0
    per = 100.0 / len(qids) if qids else 0
    correct = 0
    for qid in qids:
        q = qmap.get(qid)
        if not q:
            continue
        user_ans = data.answers.get(qid)
        if q.answer and user_ans and user_ans.upper() == q.answer.upper():
            total += per
            correct += 1
    score = round(total)
    exam.answers = json.dumps({str(k): v for k, v in data.answers.items()})
    exam.total_score = score
    from datetime import datetime
    exam.submitted_at = datetime.utcnow()
    exam.status = "passed" if score >= exam.pass_score else "failed"
    db.commit()
    # 同步课程学习进度得分
    if exam.course_id:
        p = db.query(CourseProgress).filter(
            CourseProgress.course_id == exam.course_id,
            CourseProgress.user_id == current.id,
        ).first()
        if not p:
            p = CourseProgress(course_id=exam.course_id, user_id=current.id)
            db.add(p)
        p.score = score
        if not p.completed_at:
            p.completed_at = datetime.utcnow()
        db.commit()
    write_operation_log(db, current, "submit_exam", "training",
                        f"测验#{exam.id} 得分{score}/100")
    db.refresh(exam)
    return _to_exam(exam, db)


@router.get("/exams/mine", response_model=list[QuizExamOut])
def my_exams(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    """我的测验记录。"""
    exams = db.query(QuizExam).filter(QuizExam.user_id == current.id).order_by(
        QuizExam.started_at.desc()).all()
    return [_to_exam(e, db) for e in exams]


@router.get("/exams/all", response_model=list[QuizExamOut])
def all_exams(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    """全部测验记录（讲师/管理员）。"""
    _require_trainer(current)
    exams = db.query(QuizExam).order_by(QuizExam.started_at.desc()).all()
    return [_to_exam(e, db) for e in exams]


# ============ 培训统计 ============
@router.get("/stats")
def training_stats(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    _require_trainer(current)
    total_courses = db.query(TrainingCourse).filter(TrainingCourse.is_published == True).count()
    total_progress = db.query(CourseProgress).count()
    completed = db.query(CourseProgress).filter(CourseProgress.completed_at.isnot(None)).count()
    total_users = db.query(User).filter(User.is_active == True).count()
    avg_score_row = db.query(CourseProgress).filter(CourseProgress.score.isnot(None)).all()
    avg_score = round(sum(p.score for p in avg_score_row) / len(avg_score_row)) if avg_score_row else 0
    return {
        "total_courses": total_courses,
        "total_progress": total_progress,
        "completed": completed,
        "completion_rate": round(completed / total_users * 100, 1) if total_users else 0,
        "avg_score": avg_score,
        "exam_count": db.query(QuizExam).filter(QuizExam.status.in_(["passed", "failed"])).count(),
    }


@router.get("/course-stats")
def course_stats(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    """按课程维度统计学习与考试情况（讲师/管理员）。"""
    _require_trainer(current)
    courses = db.query(TrainingCourse).filter(TrainingCourse.is_published == True).all()
    rows = []
    for c in courses:
        progresses = db.query(CourseProgress).filter(CourseProgress.course_id == c.id).all()
        enroll = len(progresses)
        completed = len([p for p in progresses if p.completed_at])
        scored = [p.score for p in progresses if p.score is not None]
        avg = round(sum(scored) / len(scored)) if scored else 0
        exams = db.query(QuizExam).filter(
            QuizExam.course_id == c.id,
            QuizExam.status.in_(["passed", "failed"]),
        ).all()
        passed = len([e for e in exams if e.status == "passed"])
        rows.append({
            "course_id": c.id,
            "course_title": c.title,
            "category": c.category,
            "enroll_count": enroll,
            "completed_count": completed,
            "completion_rate": round(completed / enroll * 100, 1) if enroll else 0,
            "avg_score": avg,
            "exam_count": len(exams),
            "exam_pass_rate": round(passed / len(exams) * 100, 1) if exams else 0,
        })
    return rows
