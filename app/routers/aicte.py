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
    page: int = 1,
    page_size: int = 50,
) -> Response:
    """
    High-performance compliance summary supporting both small local datasets and
    large remote PostgreSQL datasets (13,000+ institutions).
    Uses SQL-based pagination and batch aggregate queries instead of full-table scans.
    """
    clean_search = str(search).strip() if search and isinstance(search, str) and search.strip() else None
    clean_state = str(state).strip() if state and isinstance(state, str) and state.strip() else None
    clean_type = str(institution_type).strip() if institution_type and isinstance(institution_type, str) and institution_type.strip() else None
    try:
        clean_page_size = min(max(10, int(page_size)), 200)
    except (ValueError, TypeError):
        clean_page_size = 50
    try:
        clean_page = max(1, int(page))
    except (ValueError, TypeError):
        clean_page = 1

    base_query = select(Institution.id, Institution.name, Institution.aicte_id, Institution.state, Institution.type)
    count_query = select(func.count(Institution.id))

    if clean_state:
        base_query = base_query.where(Institution.state == clean_state)
        count_query = count_query.where(Institution.state == clean_state)
    if clean_type:
        base_query = base_query.where(Institution.type == clean_type)
        count_query = count_query.where(Institution.type == clean_type)
    if clean_search:
        s = f"%{clean_search}%"
        cond = (Institution.name.ilike(s)) | (Institution.aicte_id.ilike(s)) | (Institution.state.ilike(s))
        base_query = base_query.where(cond)
        count_query = count_query.where(cond)

    total_matched = session.exec(count_query).one()
    total_pages = max(1, (total_matched + clean_page_size - 1) // clean_page_size)
    clean_page = min(clean_page, total_pages) if total_matched > 0 else 1
    offset = (clean_page - 1) * clean_page_size

    # Fast indexed ordering by (state, name)
    target_insts = session.exec(
        base_query.order_by(Institution.state, Institution.name).offset(offset).limit(clean_page_size)
    ).all()
    target_ids = [inst[0] for inst in target_insts]

    all_states = [
        "Andaman and Nicobar Islands", "Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar",
        "Chandigarh", "Chhattisgarh", "Delhi", "Goa", "Gujarat", "Haryana", "Himachal Pradesh",
        "Jammu and Kashmir", "Jharkhand", "Karnataka", "Kerala", "Madhya Pradesh", "Maharashtra",
        "Manipur", "Meghalaya", "Mizoram", "Nagaland", "Odisha", "Puducherry", "Punjab",
        "Rajasthan", "Sikkim", "Tamil Nadu", "Telangana", "Tripura", "Uttar Pradesh",
        "Uttarakhand", "West Bengal"
    ]
    all_types = ["Government", "Private", "Aided", "University", "Autonomous"]

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
                "states": all_states,
                "types": all_types,
                "total_matched": 0,
                "page": clean_page,
                "page_size": clean_page_size,
                "total_pages": total_pages,
                "has_prev": False,
                "has_next": False,
                "prev_page": 1,
                "next_page": 1,
            },
        )

    # Batch query approved intake sum for target page institutions (1 query)
    intake_counts = dict(session.exec(
        select(Program.institution_id, func.sum(Program.approved_intake))
        .where(Program.institution_id.in_(target_ids))
        .group_by(Program.institution_id)
    ).all())

    # Batch query active student count for target page institutions (1 query)
    enrolment_counts = dict(session.exec(
        select(Student.institution_id, func.count(Student.id))
        .where(Student.institution_id.in_(target_ids), Student.status == "ACTIVE")
        .group_by(Student.institution_id)
    ).all())

    # Batch query open validation flags grouped by severity for target page institutions (1 query)
    flag_rows = session.exec(
        select(ValidationFlag.institution_id, ValidationFlag.severity, func.count(ValidationFlag.id))
        .where(ValidationFlag.institution_id.in_(target_ids), ValidationFlag.status == "OPEN")
        .group_by(ValidationFlag.institution_id, ValidationFlag.severity)
    ).all()
    flags_by_inst = defaultdict(lambda: {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "TOTAL": 0})
    for i_id, sev, cnt in flag_rows:
        flags_by_inst[i_id][sev] += cnt
        flags_by_inst[i_id]["TOTAL"] += cnt

    # Batch query anomaly alerts count for target page institutions (1 query)
    anomaly_counts = dict(session.exec(
        select(AnomalyAlert.institution_id, func.count(AnomalyAlert.id))
        .where(AnomalyAlert.institution_id.in_(target_ids))
        .group_by(AnomalyAlert.institution_id)
    ).all())

    # Assemble rows with O(1) in-memory compliance score calculation
    rows = []
    for inst_id, name, aicte_id, inst_state, inst_type in target_insts:
        enrolment = enrolment_counts.get(inst_id, 0)
        intake = int(intake_counts.get(inst_id, 0) or 0)
        fill_ratio = round(enrolment / intake, 3) if intake > 0 else 0.0
        inst_flags = flags_by_inst[inst_id]
        anomaly_count = anomaly_counts.get(inst_id, 0)

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
            "total_matched": total_matched,
            "page": clean_page,
            "page_size": clean_page_size,
            "total_pages": total_pages,
            "has_prev": clean_page > 1,
            "has_next": clean_page < total_pages,
            "prev_page": clean_page - 1,
            "next_page": clean_page + 1,
        },
    )


@router.get("/reports/compliance-summary", response_class=HTMLResponse)
def compliance_summary(
    request: Request,
    search: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
    institution_type: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=10, le=200),
    limit: Optional[int] = Query(default=None),
    user: User = Depends(require_role("AICTE_ADMIN")),
    session: Session = Depends(get_session),
):
    eff_page_size = min(max(10, limit), 200) if limit is not None else page_size
    return _render_compliance_summary(request, session, user, search, state, institution_type, page, eff_page_size)


@router.get("/reports", response_class=HTMLResponse)
def aicte_reports_view(
    request: Request,
    search: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
    institution_type: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=10, le=200),
    limit: Optional[int] = Query(default=None),
    user: User = Depends(require_role("AICTE_ADMIN")),
    session: Session = Depends(get_session),
):
    """Render the AICTE compliance and reports overview."""
    eff_page_size = min(max(10, limit), 200) if limit is not None else page_size
    return _render_compliance_summary(request, session, user, search, state, institution_type, page, eff_page_size)


@router.get("/institutions", response_class=HTMLResponse)
def aicte_institutions_view(
    request: Request,
    search: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
    institution_type: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=10, le=200),
    limit: Optional[int] = Query(default=None),
    user: User = Depends(require_role("AICTE_ADMIN")),
    session: Session = Depends(get_session),
):
    """Render AICTE institutions directory with compliance metrics and drill-down links."""
    eff_page_size = min(max(10, limit), 200) if limit is not None else page_size
    return _render_compliance_summary(request, session, user, search, state, institution_type, page, eff_page_size)


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

    # Aggregate active student counts per program in 1 SQL query without hydrating full Student rows
    prog_counts = dict(
        session.exec(
            select(Student.program_id, func.count(Student.id))
            .where(
                Student.institution_id == institution.id,
                Student.status == "ACTIVE",
            )
            .group_by(Student.program_id)
        ).all()
    )
    total_students = sum(prog_counts.values())
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

    # Reuse already-fetched flags and alerts to avoid 2 redundant WAN round-trips
    c_score = compliance_score(institution.id, session, flags=flags, alerts=alerts)

    programs_data = []
    for prog in programs:
        enrolled_regular = prog_counts.get(prog.id, 0)
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
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    user: User = Depends(require_role("AICTE_ADMIN")),
    session: Session = Depends(get_session),
):
    clean_state = str(state).strip() if state and isinstance(state, str) and state.strip() else None
    clean_type = str(institution_type).strip() if institution_type and isinstance(institution_type, str) and institution_type.strip() else None
    clean_year = str(academic_year).strip() if academic_year and isinstance(academic_year, str) and academic_year.strip() else None

    # 1. Totals: Institution count
    inst_count_query = select(func.count(Institution.id))
    if clean_state:
        inst_count_query = inst_count_query.where(Institution.state == clean_state)
    if clean_type:
        inst_count_query = inst_count_query.where(Institution.type == clean_type)
    total_institutions = session.exec(inst_count_query).one()

    # 2. Totals: Approved intake sum
    intake_query = select(func.coalesce(func.sum(Program.approved_intake), 0)).select_from(Program)
    if clean_state or clean_type:
        intake_query = intake_query.join(Institution, Program.institution_id == Institution.id)
        if clean_state:
            intake_query = intake_query.where(Institution.state == clean_state)
        if clean_type:
            intake_query = intake_query.where(Institution.type == clean_type)
    if clean_year:
        intake_query = intake_query.where(Program.academic_year == clean_year)
    total_intake = session.exec(intake_query).one()

    # 3. Totals: Active enrolment count
    enrol_query = select(func.count(Student.id)).select_from(Student).where(Student.status == "ACTIVE")
    if clean_state or clean_type:
        enrol_query = enrol_query.join(Institution, Student.institution_id == Institution.id)
        if clean_state:
            enrol_query = enrol_query.where(Institution.state == clean_state)
        if clean_type:
            enrol_query = enrol_query.where(Institution.type == clean_type)
    if clean_year:
        try:
            year_int = int(clean_year.split("-")[0])
            enrol_query = enrol_query.where(Student.admission_year == year_int)
        except Exception:
            pass
    total_enrolment = session.exec(enrol_query).one()

    # 4. Totals: Flagged institutions
    flagged_inst_query = (
        select(func.count(func.distinct(ValidationFlag.institution_id)))
        .select_from(ValidationFlag)
        .where(ValidationFlag.status == "OPEN")
    )
    if clean_state or clean_type:
        flagged_inst_query = flagged_inst_query.join(Institution, ValidationFlag.institution_id == Institution.id)
        if clean_state:
            flagged_inst_query = flagged_inst_query.where(Institution.state == clean_state)
        if clean_type:
            flagged_inst_query = flagged_inst_query.where(Institution.type == clean_type)
    flagged_institutions = session.exec(flagged_inst_query).one()

    # 5. Totals: Cross institution duplicates
    dup_query = (
        select(Student.apaar_id)
        .where(Student.status == "ACTIVE", func.upper(Student.mode) == "FULL_TIME")
        .group_by(Student.apaar_id)
        .having(func.count(func.distinct(Student.institution_id)) > 1)
    )
    cross_duplicate_count = len(session.exec(dup_query).all())

    # 6. Flags by rule
    flags_rule_query = (
        select(ValidationFlag.rule_code, func.count(ValidationFlag.id))
        .where(ValidationFlag.status == "OPEN")
        .group_by(ValidationFlag.rule_code)
    )
    if clean_state or clean_type:
        flags_rule_query = flags_rule_query.join(Institution, ValidationFlag.institution_id == Institution.id)
        if clean_state:
            flags_rule_query = flags_rule_query.where(Institution.state == clean_state)
        if clean_type:
            flags_rule_query = flags_rule_query.where(Institution.type == clean_type)
    flags_by_rule = dict(sorted(session.exec(flags_rule_query).all()))

    # 7. Latest HIGH flags
    high_flags_query = (
        select(ValidationFlag, Institution.name)
        .join(Institution, ValidationFlag.institution_id == Institution.id)
        .where(ValidationFlag.status == "OPEN", ValidationFlag.severity == "HIGH")
        .order_by(ValidationFlag.created_at.desc())
        .limit(10)
    )
    latest_high_flags = [
        {
            "institution_name": inst_name,
            "rule_code": flag.rule_code,
            "message": flag.message,
            "created_at": flag.created_at.isoformat(),
        }
        for flag, inst_name in session.exec(high_flags_query).all()
    ]

    # 8. Anomaly alerts
    anomaly_query = (
        select(AnomalyAlert, Institution.name)
        .join(Institution, AnomalyAlert.institution_id == Institution.id)
        .order_by(AnomalyAlert.created_at.desc())
        .limit(20)
    )
    anomaly_alerts = [
        {
            "institution_name": inst_name,
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
        for alert, inst_name in session.exec(anomaly_query).all()
    ]

    # 9. Academic years
    ay_query = select(Program.academic_year).where(Program.academic_year.is_not(None)).distinct()
    academic_years = sorted([y for y in session.exec(ay_query).all() if y])

    # 10. Paginated Institution rows with projected columns
    clean_page_size = min(max(1, int(page_size)), 200)
    clean_page = max(1, int(page))

    inst_base = select(Institution.id, Institution.name, Institution.aicte_id, Institution.state, Institution.type)
    if clean_state:
        inst_base = inst_base.where(Institution.state == clean_state)
    if clean_type:
        inst_base = inst_base.where(Institution.type == clean_type)

    total_matched = session.exec(select(func.count()).select_from(inst_base.subquery())).one()
    total_pages = max(1, (total_matched + clean_page_size - 1) // clean_page_size)
    clean_page = min(clean_page, total_pages) if total_matched > 0 else 1
    offset = (clean_page - 1) * clean_page_size

    target_insts = session.exec(
        inst_base.order_by(Institution.state, Institution.name).offset(offset).limit(clean_page_size)
    ).all()
    target_ids = [inst[0] for inst in target_insts]

    intake_map = dict(session.exec(
        select(Program.institution_id, func.sum(Program.approved_intake))
        .where(Program.institution_id.in_(target_ids or [-1]))
        .group_by(Program.institution_id)
    ).all())

    enrol_map = dict(session.exec(
        select(Student.institution_id, func.count(Student.id))
        .where(Student.institution_id.in_(target_ids or [-1]), Student.status == "ACTIVE")
        .group_by(Student.institution_id)
    ).all())

    flag_rows = session.exec(
        select(ValidationFlag.institution_id, ValidationFlag.severity, func.count(ValidationFlag.id))
        .where(ValidationFlag.institution_id.in_(target_ids or [-1]), ValidationFlag.status == "OPEN")
        .group_by(ValidationFlag.institution_id, ValidationFlag.severity)
    ).all()
    flags_by_inst = defaultdict(lambda: {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "TOTAL": 0})
    for i_id, sev, cnt in flag_rows:
        flags_by_inst[i_id][sev] += cnt
        flags_by_inst[i_id]["TOTAL"] += cnt

    alert_map = dict(session.exec(
        select(AnomalyAlert.institution_id, func.count(AnomalyAlert.id))
        .where(AnomalyAlert.institution_id.in_(target_ids or [-1]))
        .group_by(AnomalyAlert.institution_id)
    ).all())

    institution_rows = []
    for inst_id, name, aicte_id, inst_state, inst_type in target_insts:
        enrolment = enrol_map.get(inst_id, 0)
        intake = int(intake_map.get(inst_id, 0) or 0)
        fill_ratio = round(enrolment / intake, 3) if intake > 0 else 0.0
        inst_flags = flags_by_inst[inst_id]
        anomaly_count = alert_map.get(inst_id, 0)

        penalty = min(inst_flags["HIGH"] * 5.0 + inst_flags["MEDIUM"] * 2.0 + inst_flags["LOW"] * 0.5, 70.0)
        score = max(0, min(100, int(round(100.0 - penalty - min(anomaly_count * 5.0, 25.0)))))

        institution_rows.append({
            "id": inst_id,
            "name": name,
            "aicte_id": aicte_id,
            "state": inst_state,
            "type": inst_type,
            "enrolment": enrolment,
            "approved_intake": intake,
            "fill_ratio": fill_ratio,
            "open_flags": inst_flags["TOTAL"],
            "compliance_score": score,
        })

    # 11. Chart institutions: institutions with activity (for fill % chart visualization)
    active_stu_ids = set(session.exec(select(Student.institution_id).distinct()).all())
    chart_inst_data = []
    if active_stu_ids:
        active_inst_rows = session.exec(
            select(Institution.id, Institution.name, Institution.aicte_id, Institution.state, Institution.type)
            .where(Institution.id.in_(active_stu_ids))
        ).all()
        act_ids = [r[0] for r in active_inst_rows]
        act_intakes = dict(session.exec(
            select(Program.institution_id, func.sum(Program.approved_intake))
            .where(Program.institution_id.in_(act_ids))
            .group_by(Program.institution_id)
        ).all())
        act_enrols = dict(session.exec(
            select(Student.institution_id, func.count(Student.id))
            .where(Student.institution_id.in_(act_ids), Student.status == "ACTIVE")
            .group_by(Student.institution_id)
        ).all())
        for i_id, nm, a_id, st, tp in active_inst_rows:
            enr = act_enrols.get(i_id, 0)
            itk = int(act_intakes.get(i_id, 0) or 0)
            chart_inst_data.append({
                "id": i_id,
                "name": nm,
                "aicte_id": a_id,
                "state": st,
                "type": tp,
                "enrolment": enr,
                "approved_intake": itk,
                "fill_ratio": round(enr / itk, 3) if itk > 0 else 0.0,
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

    return {
        "totals": {
            "institutions": total_institutions,
            "total_enrolment": total_enrolment,
            "total_intake": total_intake,
            "flagged_institutions": flagged_institutions,
            "cross_institution_duplicates": cross_duplicate_count,
        },
        "institutions": institution_rows,
        "chart_institutions": chart_inst_data,
        "flags_by_rule": flags_by_rule,
        "latest_high_flags": latest_high_flags,
        "anomaly_alerts": anomaly_alerts,
        "academic_years": academic_years,
        "states": all_states,
        "types": all_types,
        "page": clean_page,
        "page_size": clean_page_size,
        "total_matched": total_matched,
        "total_pages": total_pages,
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
