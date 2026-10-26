import csv
from collections import Counter, defaultdict
from io import StringIO
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select, func

from app.anomaly import compliance_score
from app.audit import log_action, verify_chain
from app.auth import require_role
from app.database import get_session
from app.models import AnomalyAlert, AuditLog, Institution, Program, Setting, Student, User, ValidationFlag

# Router for AICTE admin portal endpoints
router = APIRouter(prefix="/aicte", tags=["AICTE"])
api_router = APIRouter(prefix="/api/aicte", tags=["AICTE API"])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))

SETTING_DEFAULTS = {
    "intake_warn_threshold": "0.90",
    "intake_block_threshold": "1.00",
    "supernumerary_cap_default": "0.10",
    "nri_outlier_threshold": "0.25",
    "yoy_surge_threshold": "2.00",
}


def _settings(session: Session) -> dict[str, str]:
    settings = session.exec(select(Setting)).all()
    values = dict(SETTING_DEFAULTS)
    values.update({setting.key: setting.value for setting in settings})
    return values

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def _csv_response(filename: str, headers: list[str], rows: list[list[object]]) -> Response:
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    writer.writerows(rows)
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _filtered_data(
    session: Session,
    state: Optional[str],
    institution_type: Optional[str],
    academic_year: Optional[str],
):
    institution_query = select(Institution)
    if state:
        institution_query = institution_query.where(Institution.state == state)
    if institution_type:
        institution_query = institution_query.where(Institution.type == institution_type)
    institutions = session.exec(institution_query).all()
    institution_ids = {institution.id for institution in institutions}

    # Query programs safely
    program_query = select(Program)
    if state or institution_type:
        if len(institution_ids) <= 2000:
            program_query = program_query.where(Program.institution_id.in_(institution_ids or {-1}))
        else:
            program_query = program_query.where(Program.institution_id.in_(list(institution_ids)[:2000]))
    if academic_year:
        program_query = program_query.where(Program.academic_year == academic_year)
    programs = session.exec(program_query).all()

    programs_by_institution: dict[int, list[Program]] = defaultdict(list)
    for program in programs:
        programs_by_institution[program.institution_id].append(program)

    # Query active students safely without huge parameter lists
    student_query = select(Student).where(Student.status == "ACTIVE")
    flag_query = select(ValidationFlag).where(ValidationFlag.status == "OPEN")

    if state or institution_type:
        if len(institution_ids) <= 2000:
            student_query = student_query.where(Student.institution_id.in_(institution_ids or {-1}))
            flag_query = flag_query.where(ValidationFlag.institution_id.in_(institution_ids or {-1}))
        else:
            student_query = student_query.where(Student.institution_id.in_(list(institution_ids)[:2000]))
            flag_query = flag_query.where(ValidationFlag.institution_id.in_(list(institution_ids)[:2000]))

    if academic_year:
        try:
            year_int = int(academic_year.split("-")[0])
            student_query = student_query.where(Student.admission_year == year_int)
        except Exception:
            pass

    students = session.exec(student_query).all()
    flags = session.exec(flag_query).all()
    return institutions, programs_by_institution, students, flags


@router.get("/dashboard", response_class=HTMLResponse)
def admin_dashboard(
    request: Request,
    user: User = Depends(require_role("AICTE_ADMIN")),
):
    """Render the AICTE Central Dashboard HTML template."""
    return templates.TemplateResponse(
        request=request,
        name="aicte_dashboard.html",
        context={"role": user.role, "user": user},
    )


@router.get("/duplicates", response_class=HTMLResponse)
def cross_institution_duplicates_view(
    request: Request,
    user: User = Depends(require_role("AICTE_ADMIN")),
    session: Session = Depends(get_session),
):
    """Render cross-institution duplicate evidence panel."""
    active_students = session.exec(
        select(Student).where(Student.status == "ACTIVE", Student.mode == "FULL_TIME")
    ).all()
    by_apaar: dict[str, list[Student]] = defaultdict(list)
    for s in active_students:
        by_apaar[s.apaar_id].append(s)

    duplicates = []
    dup_id = 1
    for apaar_id, s_list in by_apaar.items():
        distinct_insts = {s.institution_id for s in s_list}
        if len(distinct_insts) > 1:
            first = s_list[0]
            second = s_list[1]
            inst1 = session.get(Institution, first.institution_id)
            inst2 = session.get(Institution, second.institution_id)
            prog1 = session.get(Program, first.program_id) if first.program_id else None
            prog2 = session.get(Program, second.program_id) if second.program_id else None

            duplicates.append({
                "id": dup_id,
                "apaar_id": apaar_id,
                "student_name": first.full_name,
                "status": "OPEN",
                "first": {
                    "institution_name": inst1.name if inst1 else "Unknown",
                    "program_name": prog1.name if prog1 else "Unknown",
                    "student_id": first.student_id,
                    "admission_year": first.admission_year,
                    "mode": first.mode,
                    "status": first.status,
                    "created_at": first.created_at,
                },
                "second": {
                    "institution_name": inst2.name if inst2 else "Unknown",
                    "program_name": prog2.name if prog2 else "Unknown",
                    "student_id": second.student_id,
                    "admission_year": second.admission_year,
                    "mode": second.mode,
                    "status": second.status,
                    "created_at": second.created_at,
                },
            })
            dup_id += 1

    return templates.TemplateResponse(
        request=request,
        name="duplicates.html",
        context={"role": user.role, "user": user, "duplicates": duplicates},
    )


@router.post("/duplicates/{dup_id}/confirm")
def confirm_duplicate(
    dup_id: int,
    user: User = Depends(require_role("AICTE_ADMIN")),
):
    return RedirectResponse(url="/aicte/duplicates", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/duplicates/{dup_id}/resolve")
def resolve_duplicate(
    dup_id: int,
    user: User = Depends(require_role("AICTE_ADMIN")),
):
    return RedirectResponse(url="/aicte/duplicates", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/audit", response_class=HTMLResponse)
def audit_log_view(
    request: Request,
    user: Optional[str] = Query(default=None),
    action: Optional[str] = Query(default=None),
    date_from: Optional[str] = Query(default=None),
    date_to: Optional[str] = Query(default=None),
    admin: User = Depends(require_role("AICTE_ADMIN")),
    session: Session = Depends(get_session),
):
    """Render the tamper-evident hash-chained audit log page."""
    query = select(AuditLog).order_by(AuditLog.id.desc()).limit(200)
    if user:
        query = query.where(AuditLog.username.contains(user))
    if action:
        query = query.where(AuditLog.action.contains(action))

    logs = session.exec(query).all()
    return templates.TemplateResponse(
        request=request,
        name="audit.html",
        context={
            "role": admin.role,
            "user": admin,
            "logs": logs,
            "filters": {"user": user, "action": action, "date_from": date_from, "date_to": date_to},
        },
    )


@router.get("/audit/verify")
def verify_audit_chain(
    admin: User = Depends(require_role("AICTE_ADMIN")),
    session: Session = Depends(get_session),
):
    """Verify hash chain integrity."""
    ok, broken_id = verify_chain(session)
    return {"ok": ok, "broken_id": broken_id}


def _render_compliance_summary(
    request: Request,
    session: Session,
    user: User,
    search: Optional[str] = None,
    state: Optional[str] = None,
    institution_type: Optional[str] = None,
    limit: int = 200,
) -> Response:
    """
    High-performance compliance summary supporting both small local datasets and
    large remote PostgreSQL datasets (13,000+ institutions).
    Uses batch aggregate queries instead of per-institution N+1 query loops.
    """
    clean_search = str(search).strip() if search and isinstance(search, str) and search.strip() else None
    clean_state = str(state).strip() if state and isinstance(state, str) and state.strip() else None
    clean_type = str(institution_type).strip() if institution_type and isinstance(institution_type, str) and institution_type.strip() else None
    try:
        clean_limit = int(limit) if limit and isinstance(limit, (int, str)) and str(limit).isdigit() else 200
    except (ValueError, TypeError):
        clean_limit = 200

    # 1. Detect active institutions (institutions with enrolled students, open flags, or anomaly alerts)
    active_stu_ids = set(session.exec(select(Student.institution_id).distinct()).all())
    active_flag_ids = set(session.exec(
        select(ValidationFlag.institution_id).where(ValidationFlag.status == "OPEN").distinct()
    ).all())
    active_alert_ids = set(session.exec(select(AnomalyAlert.institution_id).distinct()).all())
    all_active_ids = active_stu_ids | active_flag_ids | active_alert_ids

    # 2. Build target institutions list
    has_filter = bool(clean_search or clean_state or clean_type)

    if has_filter:
        query = select(Institution.id, Institution.name, Institution.aicte_id, Institution.state, Institution.type)
        if clean_state:
            query = query.where(Institution.state == clean_state)
        if clean_type:
            query = query.where(Institution.type == clean_type)
        if clean_search:
            s = f"%{clean_search}%"
            query = query.where(
                (Institution.name.ilike(s)) | (Institution.aicte_id.ilike(s)) | (Institution.state.ilike(s))
            )
        target_insts = session.exec(query.order_by(Institution.state, Institution.name).limit(clean_limit)).all()
    else:
        # Default view: prioritize all active institutions with demo data first, then other institutions up to limit
        active_insts = session.exec(
            select(Institution.id, Institution.name, Institution.aicte_id, Institution.state, Institution.type)
            .where(Institution.id.in_(all_active_ids))
            .order_by(Institution.id)
        ).all()
        other_limit = max(0, clean_limit - len(active_insts))
        other_insts = []
        if other_limit > 0:
            other_insts = session.exec(
                select(Institution.id, Institution.name, Institution.aicte_id, Institution.state, Institution.type)
                .where(~Institution.id.in_(all_active_ids))
                .order_by(Institution.state, Institution.name)
                .limit(other_limit)
            ).all()
        target_insts = active_insts + other_insts

    target_ids = [inst[0] for inst in target_insts]

    if not target_ids:
        return templates.TemplateResponse(
            request=request,
            name="compliance_summary.html",
            context={
                "rows": [],
                "role": user.role,
                "user": user,
                "search": clean_search or "",
                "selected_state": clean_state or "",
                "selected_type": clean_type or "",
                "states": [],
                "types": [],
                "total_matched": 0,
            },
        )

    # 3. Batch query approved intake sum for target institutions (1 query)
    intake_counts = dict(session.exec(
        select(Program.institution_id, func.sum(Program.approved_intake))
        .where(Program.institution_id.in_(target_ids))
        .group_by(Program.institution_id)
    ).all())

    # 4. Batch query active student count for target institutions (1 query)
    enrolment_counts = dict(session.exec(
        select(Student.institution_id, func.count(Student.id))
        .where(Student.institution_id.in_(target_ids), Student.status == "ACTIVE")
        .group_by(Student.institution_id)
    ).all())

    # 5. Batch query open validation flags grouped by severity for target institutions (1 query)
    flag_rows = session.exec(
        select(ValidationFlag.institution_id, ValidationFlag.severity, func.count(ValidationFlag.id))
        .where(ValidationFlag.institution_id.in_(target_ids), ValidationFlag.status == "OPEN")
        .group_by(ValidationFlag.institution_id, ValidationFlag.severity)
    ).all()
    flags_by_inst = defaultdict(lambda: {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "TOTAL": 0})
    for i_id, sev, cnt in flag_rows:
        flags_by_inst[i_id][sev] += cnt
        flags_by_inst[i_id]["TOTAL"] += cnt

    # 6. Batch query anomaly alerts count for target institutions (1 query)
    anomaly_counts = dict(session.exec(
        select(AnomalyAlert.institution_id, func.count(AnomalyAlert.id))
        .where(AnomalyAlert.institution_id.in_(target_ids))
        .group_by(AnomalyAlert.institution_id)
    ).all())

    # 7. Assemble rows with O(1) in-memory compliance score calculation
    rows = []
    for inst_id, name, aicte_id, inst_state, inst_type in target_insts:
        enrolment = enrolment_counts.get(inst_id, 0)
        intake = int(intake_counts.get(inst_id, 0) or 0)
        fill_ratio = round(enrolment / intake, 3) if intake > 0 else 0.0
        inst_flags = flags_by_inst[inst_id]
        anomaly_count = anomaly_counts.get(inst_id, 0)

        # In-memory compliance scoring (matches compliance_score logic identically)
        penalty = min(inst_flags["HIGH"] * 5.0 + inst_flags["MEDIUM"] * 2.0 + inst_flags["LOW"] * 0.5, 70.0)
        score = max(0, min(100, int(round(100.0 - penalty - min(anomaly_count * 5.0, 25.0)))))

        rows.append({
            "id": inst_id,
            "name": name,
            "aicte_id": aicte_id,
            "state": inst_state,
            "type": inst_type,
            "enrolment": enrolment,
            "intake": intake,
            "fill_ratio": fill_ratio,
            "open_flags": inst_flags["TOTAL"],
            "compliance_score": score,
        })

    all_states = [
        "Andaman and Nicobar Islands", "Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar",
        "Chandigarh", "Chhattisgarh", "Delhi", "Goa", "Gujarat", "Haryana", "Himachal Pradesh",
        "Jammu and Kashmir", "Jharkhand", "Karnataka", "Kerala", "Madhya Pradesh", "Maharashtra",
        "Manipur", "Meghalaya", "Mizoram", "Nagaland", "Odisha", "Puducherry", "Punjab",
        "Rajasthan", "Sikkim", "Tamil Nadu", "Telangana", "Tripura", "Uttar Pradesh",
        "Uttarakhand", "West Bengal"
    ]
    all_types = ["Government", "Private", "Aided", "University", "Autonomous"]

    return templates.TemplateResponse(
        request=request,
        name="compliance_summary.html",
        context={
            "rows": rows,
            "role": user.role,
            "user": user,
            "search": clean_search or "",
            "selected_state": clean_state or "",
            "selected_type": clean_type or "",
            "states": all_states,
            "types": all_types,
            "total_matched": len(rows),
        },
    )


@router.get("/reports/compliance-summary", response_class=HTMLResponse)
def compliance_summary(
    request: Request,
    search: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
    institution_type: Optional[str] = Query(default=None),
    limit: int = Query(default=200, ge=10, le=2000),
    user: User = Depends(require_role("AICTE_ADMIN")),
    session: Session = Depends(get_session),
):
    return _render_compliance_summary(request, session, user, search, state, institution_type, limit)


@router.get("/reports", response_class=HTMLResponse)
def aicte_reports_view(
    request: Request,
    search: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
    institution_type: Optional[str] = Query(default=None),
    limit: int = Query(default=200, ge=10, le=2000),
    user: User = Depends(require_role("AICTE_ADMIN")),
    session: Session = Depends(get_session),
):
    """Render the AICTE compliance and reports overview."""
    return _render_compliance_summary(request, session, user, search, state, institution_type, limit)


@router.get("/institutions", response_class=HTMLResponse)
def aicte_institutions_view(
    request: Request,
    search: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
    institution_type: Optional[str] = Query(default=None),
    limit: int = Query(default=200, ge=10, le=2000),
    user: User = Depends(require_role("AICTE_ADMIN")),
    session: Session = Depends(get_session),
):
    """Render AICTE institutions directory with compliance metrics and drill-down links."""
    return _render_compliance_summary(request, session, user, search, state, institution_type, limit)


@router.get("/institutions/{institution_id}", response_class=HTMLResponse)
def aicte_institution_drilldown(
    institution_id: int,
    request: Request,
    user: User = Depends(require_role("AICTE_ADMIN")),
    session: Session = Depends(get_session),
):
    """Render institution drill-down dashboard with program breakdowns, flags, and anomalies."""
    institution = session.get(Institution, institution_id)
    if not institution:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Institution not found")

    programs = session.exec(
        select(Program).where(Program.institution_id == institution.id)
    ).all()
    students = session.exec(
        select(Student).where(
            Student.institution_id == institution.id,
            Student.status == "ACTIVE",
        )
    ).all()
    total_students = len(students)
    approved_intake = sum(max(0, int(p.approved_intake or 0)) for p in programs)

    flags = session.exec(
        select(ValidationFlag).where(
            ValidationFlag.institution_id == institution.id,
            ValidationFlag.status == "OPEN",
        ).order_by(ValidationFlag.created_at.desc())
    ).all()
    open_flags_count = len(flags)

    alerts = session.exec(
        select(AnomalyAlert).where(
            AnomalyAlert.institution_id == institution.id,
        ).order_by(AnomalyAlert.created_at.desc())
    ).all()

    c_score = compliance_score(institution.id, session)

    programs_data = []
    for prog in programs:
        prog_students = [s for s in students if s.program_id == prog.id]
        enrolled_regular = len(prog_students)
        intake = prog.approved_intake or 0
        fill_ratio = round(enrolled_regular / intake, 3) if intake else 0.0
        decision = "ALLOW"
        if fill_ratio > 1.0:
            decision = "BLOCK"
        elif fill_ratio >= 0.9:
            decision = "WARN"

        programs_data.append({
            "name": prog.name,
            "academic_year": prog.academic_year or "Current",
            "level": prog.level or "UG",
            "enrolled_regular": enrolled_regular,
            "approved_intake": intake,
            "fill_ratio": fill_ratio,
            "decision": decision,
        })

    return templates.TemplateResponse(
        request=request,
        name="institution_detail.html",
        context={
            "role": user.role,
            "user": user,
            "institution": institution,
            "total_students": total_students,
            "approved_intake": approved_intake,
            "open_flags_count": open_flags_count,
            "compliance_score": c_score,
            "programs_data": programs_data,
            "flags": flags,
            "alerts": alerts,
        },
    )


@router.get("/settings", response_class=HTMLResponse)
def aicte_settings_page(
    request: Request,
    user: User = Depends(require_role("AICTE_ADMIN")),
    session: Session = Depends(get_session),
):
    return templates.TemplateResponse(
        request=request,
        name="aicte_settings.html",
        context={"settings": _settings(session)},
    )


@router.post("/settings", response_class=HTMLResponse)
def update_aicte_settings(
    request: Request,
    intake_warn_threshold: str = Form(...),
    intake_block_threshold: str = Form(...),
    supernumerary_cap_default: str = Form(...),
    nri_outlier_threshold: str = Form(...),
    yoy_surge_threshold: str = Form(...),
    user: User = Depends(require_role("AICTE_ADMIN")),
    session: Session = Depends(get_session),
):
    raw_values = {
        "intake_warn_threshold": intake_warn_threshold,
        "intake_block_threshold": intake_block_threshold,
        "supernumerary_cap_default": supernumerary_cap_default,
        "nri_outlier_threshold": nri_outlier_threshold,
        "yoy_surge_threshold": yoy_surge_threshold,
    }
    bounds = {
        "intake_warn_threshold": (0.0, 1.0),
        "intake_block_threshold": (0.0, 1.0),
        "supernumerary_cap_default": (0.0, 1.0),
        "nri_outlier_threshold": (0.0, 1.0),
        "yoy_surge_threshold": (1.0, 10.0),
    }
    values: dict[str, str] = {}
    for key, raw_value in raw_values.items():
        try:
            value = float(raw_value)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"{key} must be numeric",
            ) from exc
        lower, upper = bounds[key]
        if not lower <= value <= upper:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"{key} must be between {lower} and {upper}",
            )
        values[key] = f"{value:.4f}".rstrip("0").rstrip(".")

    if float(values["intake_warn_threshold"]) >= float(values["intake_block_threshold"]):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Intake warning threshold must be lower than the block threshold",
        )

    old_values = _settings(session)
    for key, value in values.items():
        setting = session.exec(select(Setting).where(Setting.key == key)).first()
        if setting is None:
            session.add(Setting(key=key, value=value))
        else:
            setting.value = value
    session.commit()

    changes = {
        key: {"from": old_values.get(key), "to": value}
        for key, value in values.items()
        if old_values.get(key) != value
    }
    if changes:
        log_action(
            session=session,
            user=user,
            action="SETTINGS_UPDATE",
            entity="SETTING",
            details=changes,
        )

    return templates.TemplateResponse(
        request=request,
        name="aicte_settings.html",
        context={"settings": values, "saved": True},
    )


@router.post("/reset-demo")
def reset_demo(
    user: User = Depends(require_role("AICTE_ADMIN")),
    session: Session = Depends(get_session),
):
    raise HTTPException(
        status_code=400,
        detail=(
            "In-place database reset is disabled to protect canonical database integrity. "
            "To restore the canonical database, stop the server and run: "
            "python scripts/setup_dev_database.py --force"
        ),
    )


@api_router.get("/summary")
def aicte_summary(
    state: Optional[str] = Query(default=None),
    institution_type: Optional[str] = Query(default=None),
    academic_year: Optional[str] = Query(default=None),
    user: User = Depends(require_role("AICTE_ADMIN")),
    session: Session = Depends(get_session),
):
    institutions, programs_by_institution, students, flags = _filtered_data(
        session, state, institution_type, academic_year
    )
    institutions_by_id = {institution.id: institution for institution in institutions}
    enrolment_by_institution: Counter[int] = Counter(
        student.institution_id for student in students
    )
    flags_by_institution: Counter[int] = Counter(flag.institution_id for flag in flags)
    flags_by_rule: Counter[str] = Counter(flag.rule_code for flag in flags)

    anomalies = session.exec(
        select(AnomalyAlert).order_by(AnomalyAlert.created_at.desc()).limit(20)
    ).all()
    anomalies_by_inst: dict[int, list[AnomalyAlert]] = defaultdict(list)
    for a in anomalies:
        anomalies_by_inst[a.institution_id].append(a)

    flags_list_by_inst: dict[int, list[ValidationFlag]] = defaultdict(list)
    for f in flags:
        flags_list_by_inst[f.institution_id].append(f)

    active_inst_ids = set(enrolment_by_institution.keys()) | set(flags_by_institution.keys()) | set(programs_by_institution.keys())
    target_institutions = [i for i in institutions if i.id in active_inst_ids]
    if len(target_institutions) < 25:
        target_institutions += [i for i in institutions if i.id not in active_inst_ids][: (50 - len(target_institutions))]

    institution_rows = []
    for institution in target_institutions:
        intake = sum(
            max(0, int(program.approved_intake or 0))
            for program in programs_by_institution[institution.id]
        )
        enrolment = enrolment_by_institution[institution.id]
        score = 100.0
        penalty = sum(
            5.0 if f.severity == "HIGH" else (2.0 if f.severity == "MEDIUM" else 0.5)
            for f in flags_list_by_inst[institution.id]
        )
        score -= min(penalty, 70.0)
        score -= min(len(anomalies_by_inst[institution.id]) * 5.0, 25.0)
        c_score = max(0, min(100, int(round(score))))

        institution_rows.append({
            "id": institution.id,
            "name": institution.name,
            "aicte_id": institution.aicte_id,
            "state": institution.state,
            "type": institution.type,
            "enrolment": enrolment,
            "approved_intake": intake,
            "fill_ratio": round(enrolment / intake, 3) if intake else 0.0,
            "open_flags": flags_by_institution[institution.id],
            "compliance_score": c_score,
        })

    active_institutions_by_apaar: dict[str, set[int]] = defaultdict(set)
    for student in students:
        if student.mode and student.mode.upper() == "FULL_TIME":
            active_institutions_by_apaar[student.apaar_id].add(student.institution_id)
    cross_duplicate_count = sum(
        len(institution_ids) > 1 for institution_ids in active_institutions_by_apaar.values()
    )

    high_flags = sorted(
        (flag for flag in flags if flag.severity == "HIGH"),
        key=lambda flag: flag.created_at,
        reverse=True,
    )[:10]

    academic_years = sorted(list({
        p.academic_year for progs in programs_by_institution.values() for p in progs if p.academic_year
    }))

    return {
        "totals": {
            "institutions": len(institutions),
            "total_enrolment": sum(enrolment_by_institution.values()),
            "total_intake": sum(int(p.approved_intake or 0) for progs in programs_by_institution.values() for p in progs),
            "flagged_institutions": sum(count > 0 for count in flags_by_institution.values()),
            "cross_institution_duplicates": cross_duplicate_count,
        },
        "institutions": institution_rows,
        "flags_by_rule": dict(sorted(flags_by_rule.items())),
        "latest_high_flags": [
            {
                "institution_name": institutions_by_id[flag.institution_id].name,
                "rule_code": flag.rule_code,
                "message": flag.message,
                "created_at": flag.created_at.isoformat(),
            }
            for flag in high_flags
        ],
        "anomaly_alerts": [
            {
                "institution_name": institutions_by_id[alert.institution_id].name,
                "code": alert.code,
                "score": alert.score,
                "reason": alert.reason,
                "recommended_action": (
                    "Review enrollment and quota records."
                    if alert.code in {"A1", "A2"}
                    else "Review student classifications and supporting records."
                    if alert.code == "A3"
                    else "Review records in the flagged program."
                ),
                "created_at": alert.created_at.isoformat(),
            }
            for alert in anomalies
            if alert.institution_id in institutions_by_id
        ],
        "academic_years": academic_years,
    }


@router.get("/reports/enrolment.csv")
def enrolment_report(
    state: Optional[str] = None,
    institution_type: Optional[str] = None,
    academic_year: Optional[str] = None,
    user: User = Depends(require_role("AICTE_ADMIN")),
    session: Session = Depends(get_session),
):
    institutions, programs_by_institution, students, _ = _filtered_data(
        session, state, institution_type, academic_year
    )
    enrolment_by_institution = Counter(student.institution_id for student in students)
    rows = []
    for institution in institutions:
        intake = sum(p.approved_intake for p in programs_by_institution[institution.id])
        enrolment = enrolment_by_institution[institution.id]
        rows.append([
            institution.aicte_id, institution.name, institution.state, institution.type,
            enrolment, intake, round(enrolment / intake, 3) if intake else 0,
        ])
    return _csv_response(
        "enrolment-intake.csv",
        ["aicte_id", "institution", "state", "type", "enrolment", "approved_intake", "fill_ratio"],
        rows,
    )


@router.get("/reports/flags.csv")
def validation_flags_report(
    state: Optional[str] = None,
    institution_type: Optional[str] = None,
    academic_year: Optional[str] = None,
    user: User = Depends(require_role("AICTE_ADMIN")),
    session: Session = Depends(get_session),
):
    institutions, _, _, flags = _filtered_data(session, state, institution_type, academic_year)
    names = {institution.id: institution.name for institution in institutions}
    rows = [[
        names.get(flag.institution_id, ""),
        flag.rule_code,
        flag.severity,
        flag.status,
        flag.student_id or "",
        flag.message,
        flag.recommended_action,
        flag.created_at.isoformat(),
    ] for flag in flags]
    return _csv_response(
        "validation-flags.csv",
        ["institution", "rule_code", "severity", "status", "student_id", "message", "recommended_action", "created_at"],
        rows,
    )


@router.get("/reports/breakdown.csv")
def category_breakdown_report(
    state: Optional[str] = None,
    institution_type: Optional[str] = None,
    academic_year: Optional[str] = None,
    user: User = Depends(require_role("AICTE_ADMIN")),
    session: Session = Depends(get_session),
):
    institutions, _, students, _ = _filtered_data(session, state, institution_type, academic_year)
    names = {institution.id: institution.name for institution in institutions}
    grouped: Counter[tuple[int, str, str]] = Counter()
    for student in students:
        grouped[(student.institution_id, student.category, "category")] += 1
        if student.is_nri:
            grouped[(student.institution_id, "NRI", "admission_group")] += 1
        if student.oci_status:
            grouped[(student.institution_id, "OCI", "admission_group")] += 1
        if student.is_foreign_national:
            grouped[(student.institution_id, "Foreign National", "admission_group")] += 1
    rows = [[names.get(inst_id, ""), group, kind, count] for (inst_id, group, kind), count in sorted(grouped.items())]
    return _csv_response(
        "student-breakdown.csv",
        ["institution", "group", "group_type", "student_count"],
        rows,
    )


@router.get("/reports/duplicates.csv")
def cross_institution_duplicates_report(
    state: Optional[str] = None,
    institution_type: Optional[str] = None,
    academic_year: Optional[str] = None,
    user: User = Depends(require_role("AICTE_ADMIN")),
    session: Session = Depends(get_session),
):
    institutions, _, students, _ = _filtered_data(session, state, institution_type, academic_year)
    active_by_apaar: dict[str, list[Student]] = defaultdict(list)
    for student in students:
        if student.mode.upper() == "FULL_TIME":
            active_by_apaar[student.apaar_id].append(student)
    names = {institution.id: institution.name for institution in institutions}
    rows = []
    for apaar_id, records in active_by_apaar.items():
        if len({record.institution_id for record in records}) > 1:
            for record in records:
                rows.append([
                    apaar_id, names.get(record.institution_id, ""), record.student_id,
                    record.program_id, record.admission_year, record.status,
                ])
    return _csv_response(
        "cross-institution-duplicates.csv",
        ["apaar_id", "institution", "student_id", "program_id", "admission_year", "status"],
        rows,
    )


@router.get("/reports/states.csv")
def state_summary_report(
    state: Optional[str] = None,
    institution_type: Optional[str] = None,
    academic_year: Optional[str] = None,
    user: User = Depends(require_role("AICTE_ADMIN")),
    session: Session = Depends(get_session),
):
    institutions, programs_by_institution, students, flags = _filtered_data(
        session, state, institution_type, academic_year
    )
    enrolment_by_institution = Counter(student.institution_id for student in students)
    flags_by_institution = Counter(flag.institution_id for flag in flags)
    grouped: dict[str, dict[str, int]] = defaultdict(lambda: {"institutions": 0, "enrolment": 0, "intake": 0, "open_flags": 0})
    for institution in institutions:
        group = grouped[institution.state]
        group["institutions"] += 1
        group["enrolment"] += enrolment_by_institution[institution.id]
        group["intake"] += sum(p.approved_intake for p in programs_by_institution[institution.id])
        group["open_flags"] += flags_by_institution[institution.id]
    rows = [[state_name, values["institutions"], values["enrolment"], values["intake"], values["open_flags"]]
            for state_name, values in sorted(grouped.items())]
    return _csv_response(
        "state-summary.csv",
        ["state", "institutions", "enrolment", "approved_intake", "open_flags"],
        rows,
    )
