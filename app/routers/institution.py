"""
Institution portal router for APAAR Verify.
Implements Student CRUD, CSV uploads with automated validation, Intake Guard checks, and audit logging.
Strictly scoped to the logged-in institution's own data.
"""

import csv
import io
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile, status
import json
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
import pandas as pd
from sqlmodel import Session, func, or_, select

from app.audit import log_action
from app.auth import get_current_user, require_role
from app.database import get_session
from app.models import Institution, Program, Student, User, ValidationFlag, utc_now
from app.security import sign_record
from app.validation import (
    batch_intake_check,
    build_validation_context,
    intake_check,
    validate_program_intake,
    validate_student_row,
    validate_override_request,
    HARD_REJECT_RULE_CODES,
)

router = APIRouter(prefix="/institution", tags=["Institution"])

# Templates reference
BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# In-memory store for generated rejection error CSVs (keyed by institution_id)

# Master AICTE validation rule metadata for inspection diagnostics
RULE_METADATA: Dict[str, Dict[str, str]] = {
    "R1": {
        "name": "APAAR Checksum & Format",
        "category": "Identity Validation",
        "description": "12-digit numeric APAAR ID must satisfy the Verhoeff checksum algorithm and valid formatting.",
        "field_key": "apaar_id",
        "field_label": "APAAR ID",
    },
    "R2": {
        "name": "National Registry Verification",
        "category": "Registry Lookup",
        "description": "APAAR ID must exist in the central AICTE / National Academic Depository master registry.",
        "field_key": "apaar_id",
        "field_label": "APAAR ID",
    },
    "R3": {
        "name": "Identity Mismatch",
        "category": "Identity Verification",
        "description": "Student full name, date of birth, or gender differs from central registry baseline data.",
        "field_key": "identity",
        "field_label": "Full Name / DOB / Gender",
    },
    "R4": {
        "name": "Internal Duplicate APAAR",
        "category": "Duplicate Detection",
        "description": "Same APAAR ID is assigned to multiple student records within this institution.",
        "field_key": "apaar_id",
        "field_label": "APAAR ID",
    },
    "R5": {
        "name": "Cross-Institution Duplicate",
        "category": "Multi-Enrollment",
        "description": "Student is actively registered in concurrent full-time programs across multiple institutions.",
        "field_key": "apaar_id",
        "field_label": "APAAR ID",
    },
    "R6": {
        "name": "Regular Intake Exceeded",
        "category": "Intake Quota",
        "description": "Active regular admissions exceed the sanctioned AICTE intake ceiling for the academic program.",
        "field_key": "intake",
        "field_label": "Regular Intake Capacity",
    },
    "R7": {
        "name": "Supernumerary Cap Exceeded",
        "category": "Intake Quota",
        "description": "Supernumerary admissions exceed AICTE-permitted quota threshold for the program.",
        "field_key": "supernumerary",
        "field_label": "Supernumerary Quota Cap",
    },
    "R8": {
        "name": "Demographic Inconsistency",
        "category": "Data Quality",
        "description": "Logical contradiction detected in demographic fields (e.g., nationality vs NRI/OCI status).",
        "field_key": "nationality",
        "field_label": "Nationality / NRI / OCI",
    },
    "R9": {
        "name": "Mandatory Fields Missing",
        "category": "Data Completeness",
        "description": "Required student record fields (full name, DOB, roll number, admission type) are missing.",
        "field_key": "mandatory",
        "field_label": "Required Fields",
    },
    "R10": {
        "name": "Student Consent Required",
        "category": "Compliance & Privacy",
        "description": "Mandatory DPDP Act / APAAR digital consent not recorded for student data verification.",
        "field_key": "consent",
        "field_label": "Digital Consent",
    },
    "R11": {
        "name": "Unregistered Program Code",
        "category": "Academic Program",
        "description": "Assigned program is not recognized under current AICTE institution approval.",
        "field_key": "program",
        "field_label": "Academic Program",
    },
    "R12": {
        "name": "Duplicate Institutional Roll No",
        "category": "Duplicate Detection",
        "description": "Institutional roll number / enrollment ID is assigned to more than one student in the institution.",
        "field_key": "student_id",
        "field_label": "Institutional Roll No",
    },
}

ERROR_CSVS: Dict[int, str] = {}


@router.get("", response_class=RedirectResponse)
@router.get("/", response_class=RedirectResponse)
def institution_root(request: Request, session: Session = Depends(get_session)):
    """Redirect /institution and /institution/ to the dashboard or AICTE institutions directory."""
    try:
        from app.auth import get_current_user
        user = get_current_user(request=request, session=session)
        if user and user.role == "AICTE_ADMIN":
            return RedirectResponse(url="/aicte/institutions", status_code=status.HTTP_303_SEE_OTHER)
    except Exception:
        pass
    return RedirectResponse(url="/institution/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/dashboard", response_class=HTMLResponse)
def institution_dashboard(
    request: Request,
    resolved: Optional[str] = None,
    session: Session = Depends(get_session),
    user: User = Depends(require_role("INSTITUTION")),
):
    """
    Render institution dashboard with 5 KPI cards:
    - Total Students
    - Approved Intake
    - Fill %
    - Open Flags
    - Compliance Score
    Includes preloaded validation inspector diagnostics for recent alerts.
    """
    inst_id = user.institution_id
    institution = session.get(Institution, inst_id)
    if not institution:
        raise HTTPException(status_code=404, detail="Institution record not found")

    # Fetch programs
    programs = session.exec(
        select(Program).where(Program.institution_id == inst_id)
    ).all()
    programs_map = {p.id: p for p in programs}

    # KPI 1 & 2: Students & Intake
    total_students = session.exec(
        select(func.count(Student.id)).where(Student.institution_id == inst_id, Student.status == "ACTIVE")
    ).one()
    approved_intake = sum(p.approved_intake for p in programs)

    # KPI 3: Fill %
    fill_ratio = round((total_students / approved_intake * 100), 1) if approved_intake > 0 else 0.0

    # KPI 4: Open Flags
    open_flags = session.exec(
        select(ValidationFlag)
        .where(ValidationFlag.institution_id == inst_id, ValidationFlag.status == "OPEN")
        .order_by(ValidationFlag.id.desc())
    ).all()
    open_flags_count = len(open_flags)

    # KPI 5: Compliance Score (100 minus weighted penalties)
    penalty = sum(5 if f.severity == "HIGH" else (2 if f.severity == "MEDIUM" else 0.5) for f in open_flags)
    compliance_score = max(0, int(round(100 - min(70, penalty))))

    # Program quota monitoring data (batch query eliminates N+1)
    programs_data = batch_intake_check(programs, session)

    # Prepare detailed inspection data for recent alerts (batch queries)
    recent_flags = open_flags[:10]
    flag_student_ids = [f.student_id for f in recent_flags if f.student_id]
    students_map = {}
    if flag_student_ids:
        stus = session.exec(
            select(Student).where(Student.id.in_(flag_student_ids), Student.institution_id == inst_id)
        ).all()
        students_map = {s.id: s for s in stus}

    flags_inspector_data = []
    for f in recent_flags:
        stu = students_map.get(f.student_id) if f.student_id else None
        prog = programs_map.get(f.program_id) or (programs_map.get(stu.program_id) if stu else None)
        rule_meta = RULE_METADATA.get(f.rule_code, {
            "name": f"Rule {f.rule_code}",
            "category": "AICTE Guideline",
            "description": f.message,
            "field_key": "general",
            "field_label": "Record",
        })
        flags_inspector_data.append({
            "flag_id": f.id,
            "rule_code": f.rule_code,
            "rule_name": rule_meta["name"],
            "category": rule_meta["category"],
            "rule_description": rule_meta["description"],
            "field_key": rule_meta.get("field_key", "general"),
            "field_label": rule_meta.get("field_label", "Record"),
            "severity": f.severity,
            "message": f.message,
            "recommended_action": f.recommended_action,
            "created_at_fmt": f.created_at.strftime('%Y-%m-%d %H:%M') if f.created_at else "",
            "has_student": stu is not None,
            "student_id_pk": stu.id if stu else None,
            "student_roll": stu.student_id if stu else "",
            "student_name": stu.full_name if stu else "",
            "student_apaar": stu.apaar_id if stu else "",
            "student_dob": stu.dob if stu else "",
            "student_gender": stu.gender if stu else "",
            "student_category": stu.category if stu else "",
            "student_adm_type": stu.admission_type if stu else "",
            "student_adm_year": stu.admission_year if stu else "",
            "student_status": stu.status if stu else "",
            "student_mode": stu.mode if stu else "",
            "student_is_nri": stu.is_nri if stu else False,
            "student_oci": stu.oci_status if stu else False,
            "student_fn": stu.is_foreign_national if stu else False,
            "student_nationality": stu.nationality if stu else "Indian",
            "has_signature": bool(stu and stu.record_signature),
            "has_program": prog is not None,
            "program_id": prog.id if prog else None,
            "program_name": prog.name if prog else "",
            "program_intake": prog.approved_intake if prog else 0,
        })

    flash_message = "Validation alert marked as resolved successfully." if resolved == "1" else None
    flash_type = "success" if resolved == "1" else None

    return templates.TemplateResponse(
        request=request,
        name="institution_dashboard.html",
        context={
            "institution": institution,
            "total_students": total_students,
            "approved_intake": approved_intake,
            "fill_ratio": fill_ratio,
            "open_flags_count": open_flags_count,
            "compliance_score": compliance_score,
            "programs_data": programs_data,
            "recent_flags": recent_flags,
            "students_map": students_map,
            "programs_map": programs_map,
            "rule_metadata": RULE_METADATA,
            "flags_inspector_data": flags_inspector_data,
            "flags_inspector_json": json.dumps(flags_inspector_data),
            "flash_message": flash_message,
            "flash_type": flash_type,
            "role": user.role,
        },
    )


@router.get("/students", response_class=HTMLResponse)
def list_students(
    request: Request,
    q: Optional[str] = None,
    program_id: Optional[str] = None,
    student_pk: Optional[int] = None,
    page: int = 1,
    per_page: int = 10,
    session: Session = Depends(get_session),
    user: User = Depends(require_role("INSTITUTION")),
):
    """
    List enrolled students for the logged-in institution with robust search, program filters, and server-side pagination.
    Supports deep-linking and record highlighting from validation alert inspections.
    """
    inst_id = user.institution_id
    programs = session.exec(select(Program).where(Program.institution_id == inst_id)).all()
    programs_map = {p.id: p.name for p in programs}

    # Normalize per_page and page
    if per_page not in (10, 20, 50, 100):
        per_page = 10
    page = max(1, page)

    # Safely parse program_id string to integer (avoids 422 Unprocessable Entity when form submits program_id="")
    parsed_program_id: Optional[int] = None
    if program_id and str(program_id).strip():
        try:
            parsed_program_id = int(str(program_id).strip())
        except (ValueError, TypeError):
            parsed_program_id = None

    # Base filter criteria
    filters = [Student.institution_id == inst_id]
    if student_pk:
        filters.append(Student.id == student_pk)
    if parsed_program_id:
        filters.append(Student.program_id == parsed_program_id)

    # Robust search: matches student name, institutional roll no, or APAAR ID (handles formatted/spaced IDs)
    if q and q.strip():
        raw_term = q.strip()
        term = f"%{raw_term}%"
        digits_only = "".join(c for c in raw_term if c.isdigit())

        search_clauses = [
            Student.full_name.ilike(term),
            Student.student_id.ilike(term),
            Student.apaar_id.ilike(term),
        ]
        if digits_only:
            digit_term = f"%{digits_only}%"
            search_clauses.append(Student.apaar_id.ilike(digit_term))
            search_clauses.append(Student.student_id.ilike(digit_term))
            if raw_term.isdigit():
                try:
                    search_clauses.append(Student.id == int(raw_term))
                except (ValueError, TypeError):
                    pass

        filters.append(or_(*search_clauses))

    # Total count calculation
    count_statement = select(func.count(Student.id)).where(*filters)
    total_students = session.exec(count_statement).one()

    # Pagination bounds
    total_pages = max(1, (total_students + per_page - 1) // per_page)
    current_page = max(1, min(page, total_pages)) if total_students > 0 else 1
    offset = (current_page - 1) * per_page

    # Query paginated student records
    statement = select(Student).where(*filters).order_by(Student.id.desc()).offset(offset).limit(per_page)
    students = session.exec(statement).all()

    # Pre-calculate open flags count per student for UI badges
    flags = session.exec(
        select(ValidationFlag.student_id, func.count(ValidationFlag.id))
        .where(ValidationFlag.institution_id == inst_id, ValidationFlag.status == "OPEN")
        .group_by(ValidationFlag.student_id)
    ).all()
    flags_by_student = {f[0]: f[1] for f in flags if f[0] is not None}

    start_idx = offset + 1 if total_students > 0 else 0
    end_idx = min(offset + per_page, total_students)

    return templates.TemplateResponse(
        request=request,
        name="institution_students.html",
        context={
            "students": students,
            "programs": programs,
            "programs_map": programs_map,
            "flags_by_student": flags_by_student,
            "search_query": q,
            "selected_program_id": parsed_program_id,
            "highlight_id": student_pk,
            "role": user.role,
            "current_page": current_page,
            "per_page": per_page,
            "total_students": total_students,
            "total_pages": total_pages,
            "start_idx": start_idx,
            "end_idx": end_idx,
            "has_prev": current_page > 1,
            "has_next": current_page < total_pages,
            "prev_page": current_page - 1,
            "next_page": current_page + 1,
        },
    )


@router.get("/alerts/export", response_class=StreamingResponse)
def export_validation_alerts(
    session: Session = Depends(get_session),
    user: User = Depends(require_role("INSTITUTION")),
):
    """
    Download a CSV report of validation flags for the logged-in institution.
    """
    inst_id = user.institution_id
    institution = session.get(Institution, inst_id)
    flags = session.exec(
        select(ValidationFlag)
        .where(ValidationFlag.institution_id == inst_id)
        .order_by(ValidationFlag.id.desc())
    ).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Flag ID",
        "Institution ID",
        "Institution Name",
        "Rule Code",
        "Severity",
        "Student ID",
        "Program ID",
        "Message",
        "Recommended Action",
        "Status",
        "Created At",
    ])
    for f in flags:
        writer.writerow([
            f.id,
            inst_id,
            institution.name if institution else "",
            f.rule_code,
            f.severity,
            f.student_id or "",
            f.program_id or "",
            f.message,
            f.recommended_action,
            f.status,
            f.created_at.strftime("%Y-%m-%d %H:%M:%S") if f.created_at else "",
        ])

    output.seek(0)
    filename = f"institution_validation_alerts_{inst_id}.csv"
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@router.get("/alerts/{flag_id}/inspect", response_class=HTMLResponse)
def inspect_validation_alert(
    flag_id: int,
    request: Request,
    json_mode: Optional[int] = None,
    session: Session = Depends(get_session),
    user: User = Depends(require_role("INSTITUTION")),
):
    """
    Dedicated inspection view for an individual validation alert.
    Displays comprehensive student/program context, exact rule violations, AICTE guidance, and quick actions.
    """
    inst_id = user.institution_id
    flag = session.get(ValidationFlag, flag_id)
    if not flag or flag.institution_id != inst_id:
        raise HTTPException(status_code=404, detail="Validation alert not found or access denied")

    institution = session.get(Institution, inst_id)
    student = session.get(Student, flag.student_id) if flag.student_id else None
    program = session.get(Program, flag.program_id) if flag.program_id else (
        session.get(Program, student.program_id) if student else None
    )

    other_flags = []
    if student:
        other_flags = session.exec(
            select(ValidationFlag)
            .where(
                ValidationFlag.institution_id == inst_id,
                ValidationFlag.student_id == student.id,
                ValidationFlag.status == "OPEN",
                ValidationFlag.id != flag.id,
            )
        ).all()
    elif program:
        other_flags = session.exec(
            select(ValidationFlag)
            .where(
                ValidationFlag.institution_id == inst_id,
                ValidationFlag.program_id == program.id,
                ValidationFlag.status == "OPEN",
                ValidationFlag.id != flag.id,
            )
        ).all()

    rule_meta = RULE_METADATA.get(flag.rule_code, {
        "name": f"Rule {flag.rule_code}",
        "category": "AICTE Guideline",
        "description": flag.message,
        "field_key": "general",
        "field_label": "Record",
    })

    intake_data = None
    if program:
        intake_data = intake_check(program.id, session)

    if json_mode == 1 or request.headers.get("accept", "").startswith("application/json"):
        return JSONResponse({
            "flag_id": flag.id,
            "rule_code": flag.rule_code,
            "rule_name": rule_meta["name"],
            "category": rule_meta["category"],
            "rule_description": rule_meta["description"],
            "severity": flag.severity,
            "message": flag.message,
            "recommended_action": flag.recommended_action,
            "status": flag.status,
            "created_at": flag.created_at.strftime('%Y-%m-%d %H:%M') if flag.created_at else "",
            "student": {
                "id": student.id,
                "student_id": student.student_id,
                "full_name": student.full_name,
                "apaar_id": student.apaar_id,
                "dob": student.dob,
                "gender": student.gender,
                "category": student.category,
                "admission_type": student.admission_type,
                "status": student.status,
            } if student else None,
            "program": {
                "id": program.id,
                "name": program.name,
                "approved_intake": program.approved_intake,
            } if program else None,
        })

    return templates.TemplateResponse(
        request=request,
        name="institution_alert_inspect.html",
        context={
            "institution": institution,
            "flag": flag,
            "student": student,
            "program": program,
            "other_flags": other_flags,
            "rule_meta": rule_meta,
            "intake_data": intake_data,
            "role": user.role,
        },
    )


@router.post("/alerts/{flag_id}/resolve")
def resolve_validation_alert(
    flag_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(require_role("INSTITUTION")),
):
    """
    Mark an open validation alert as RESOLVED and log an immutable audit trail entry.
    """
    inst_id = user.institution_id
    flag = session.get(ValidationFlag, flag_id)
    if not flag or flag.institution_id != inst_id:
        raise HTTPException(status_code=404, detail="Alert record not found or access denied")

    flag.status = "RESOLVED"
    session.add(flag)

    student = session.get(Student, flag.student_id) if flag.student_id else None
    audit_details = (
        f"Institution user {user.username} resolved alert {flag.rule_code} (Flag #{flag.id}) "
        f"for student {student.student_id if student else 'N/A'}"
    )
    log_action(
        session=session,
        user=user,
        action="RESOLVE_FLAG",
        entity="VALIDATION_FLAG",
        entity_id=str(flag.id),
        details=audit_details,
    )
    session.commit()

    accept = request.headers.get("accept", "")
    content_type = request.headers.get("content-type", "")
    if "application/json" in accept or "application/json" in content_type:
        return JSONResponse({"ok": True, "message": f"Alert {flag.rule_code} marked as resolved."})

    return RedirectResponse(
        url="/institution/dashboard?resolved=1",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/flags/{flag_id}/resolve")
def resolve_flag_legacy(
    flag_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(require_role("INSTITUTION")),
):
    """Backward compatibility alias for resolving flags."""
    return resolve_validation_alert(flag_id=flag_id, request=request, session=session, user=user)



@router.get("/students/new", response_class=HTMLResponse)
def new_student_form(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(require_role("INSTITUTION")),
):
    """Render empty student creation form with live seat meter."""
    programs = session.exec(
        select(Program).where(Program.institution_id == user.institution_id)
    ).all()
    return templates.TemplateResponse(
        request=request,
        name="student_form.html",
        context={
            "student": None,
            "programs": programs,
            "role": user.role,
        },
    )


@router.post("/students/new")
def create_student(
    request: Request,
    apaar_id: str = Form(...),
    student_id: str = Form(...),
    full_name: str = Form(...),
    dob: str = Form(...),
    gender: str = Form(...),
    category: str = Form("GENERAL"),
    program_id: int = Form(...),
    admission_year: int = Form(2024),
    admission_type: str = Form("REGULAR"),
    is_nri: bool = Form(False),
    is_foreign_national: bool = Form(False),
    nationality: str = Form("Indian"),
    consent_level: int = Form(1),
    override_justification: Optional[str] = Form(None),
    session: Session = Depends(get_session),
    user: User = Depends(require_role("INSTITUTION")),
):
    """
    Create a single student record with automated compliance validation and Intake Guard enforcement.
    """
    inst_id = user.institution_id
    if consent_level not in (0, 1, 2):
        raise HTTPException(status_code=422, detail="Invalid consent tier. Allowed tiers are 0, 1, or 2.")
    programs = session.exec(select(Program).where(Program.institution_id == inst_id)).all()
    program = session.get(Program, program_id)

    # Ensure program belongs to this institution
    if not program or program.institution_id != inst_id:
        return templates.TemplateResponse(
            request=request,
            name="student_form.html",
            context={"student": None, "programs": programs, "error": "Selected program is invalid for this institution.", "role": user.role},
            status_code=400,
        )

    # Intake Guard check with proposed admission type
    intake = intake_check(program_id, session, target_admission_type=admission_type)
    if intake["decision"] == "BLOCK":
        is_valid_override, override_err = validate_override_request(
            program=program,
            admission_type=admission_type,
            justification=override_justification,
            current_intake_data=intake,
        )
        if not is_valid_override:
            quota_label = "Regular intake" if admission_type == "REGULAR" else "Supernumerary quota"
            err_detail = override_err or f"{quota_label} is FULL (BLOCK). A formal over-admission justification (min 20 characters) is required to proceed."
            return templates.TemplateResponse(
                request=request,
                name="student_form.html",
                context={
                    "student": None,
                    "programs": programs,
                    "error": err_detail,
                    "role": user.role,
                },
                status_code=400,
            )

    # Build validation context and run rules
    ctx = build_validation_context(inst_id, session)
    row_data = {
        "apaar_id": apaar_id.strip(),
        "student_id": student_id.strip(),
        "full_name": full_name.strip(),
        "dob": dob.strip(),
        "gender": gender,
        "category": category,
        "program_name": program.name,
        "program_id": program.id,
        "admission_year": admission_year,
        "admission_type": admission_type,
        "is_nri": is_nri,
        "is_foreign_national": is_foreign_national,
        "nationality": nationality.strip(),
        "mode": "FULL_TIME",
        "consent_given": consent_level > 0,
    }

    flags = validate_student_row(row_data, ctx)
    is_rejected = any(f["rule_code"] in HARD_REJECT_RULE_CODES for f in flags)

    if is_rejected:
        reject_reasons = "; ".join(f["message"] for f in flags if f["rule_code"] in HARD_REJECT_RULE_CODES)
        return templates.TemplateResponse(
            request=request,
            name="student_form.html",
            context={"student": None, "programs": programs, "error": f"Rejected by AICTE Rule: {reject_reasons}", "role": user.role},
            status_code=400,
        )

    # Save Student record
    new_student = Student(
        apaar_id=apaar_id.strip(),
        institution_id=inst_id,
        program_id=program.id,
        student_id=student_id.strip(),
        full_name=full_name.strip(),
        dob=dob.strip(),
        gender=gender,
        category=category,
        admission_type=admission_type,
        is_nri=is_nri,
        oci_status=False,
        is_foreign_national=is_foreign_national,
        nationality=nationality.strip(),
        admission_year=admission_year,
        mode="FULL_TIME",
        status="ACTIVE",
        consent_level=consent_level,
        consent_timestamp=utc_now() if consent_level > 0 else None,
        created_at=utc_now(),
    )
    session.add(new_student)
    session.commit()
    session.refresh(new_student)

    # Sign record with Ed25519 root private key
    new_student.record_signature = sign_record(new_student, session)
    session.add(new_student)
    session.commit()

    # Save non-reject validation flags (e.g. R3, R4, R5, R8, R10, R12)
    for f in flags:
        flag_record = ValidationFlag(
            institution_id=inst_id,
            program_id=program.id,
            student_id=new_student.id,
            rule_code=f["rule_code"],
            severity=f["severity"],
            message=f["message"],
            recommended_action=f["recommended_action"],
            status="OPEN",
            created_at=utc_now(),
        )
        session.add(flag_record)
    session.commit()

    # Re-evaluate program intake
    validate_program_intake(program.id, session)

    # Hash-chained audit logging
    audit_details = f"Created student {new_student.full_name} (Roll: {new_student.student_id}, APAAR: {new_student.apaar_id})"
    if override_justification and override_justification.strip():
        audit_details += f" | Intake BLOCK Override Justification: {override_justification.strip()}"

    log_action(
        session=session,
        user=user,
        action="STUDENT_CREATE",
        entity="STUDENT",
        entity_id=str(new_student.id),
        details=audit_details,
    )

    return RedirectResponse(url="/institution/students", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/students/{id}/edit", response_class=HTMLResponse)
def edit_student_form(
    id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(require_role("INSTITUTION")),
):
    """Render edit form for a student belonging to this institution."""
    student = session.get(Student, id)
    if not student or student.institution_id != user.institution_id:
        raise HTTPException(status_code=404, detail="Student not found or access denied")

    programs = session.exec(
        select(Program).where(Program.institution_id == user.institution_id)
    ).all()

    return templates.TemplateResponse(
        request=request,
        name="student_form.html",
        context={"student": student, "programs": programs, "role": user.role},
    )


@router.post("/students/{id}/edit")
def update_student(
    id: int,
    request: Request,
    full_name: str = Form(...),
    dob: str = Form(...),
    gender: str = Form(...),
    category: str = Form("GENERAL"),
    program_id: int = Form(...),
    admission_year: int = Form(2024),
    admission_type: str = Form("REGULAR"),
    is_nri: bool = Form(False),
    is_foreign_national: bool = Form(False),
    nationality: str = Form("Indian"),
    consent_level: int = Form(1),
    status_field: str = Form("ACTIVE"),
    override_justification: Optional[str] = Form(None),
    session: Session = Depends(get_session),
    user: User = Depends(require_role("INSTITUTION")),
):
    """Update student profile fields with audit trail."""
    if consent_level not in (0, 1, 2):
        raise HTTPException(status_code=422, detail="Invalid consent tier. Allowed tiers are 0, 1, or 2.")
    student = session.get(Student, id)
    if not student or student.institution_id != user.institution_id:
        raise HTTPException(status_code=404, detail="Student not found or access denied")

    # Evaluate seat quota if program changed, admission type changed, or student reactivated
    seat_claim_changed = (
        student.program_id != program_id
        or student.admission_type != admission_type
        or (student.status != "ACTIVE" and status_field == "ACTIVE")
    )
    if seat_claim_changed:
        target_program = session.get(Program, program_id)
        if not target_program or target_program.institution_id != user.institution_id:
            raise HTTPException(status_code=400, detail="Target program is invalid for this institution.")

        intake = intake_check(program_id, session, target_admission_type=admission_type)
        if intake["decision"] == "BLOCK":
            is_valid_override, override_err = validate_override_request(
                program=target_program,
                admission_type=admission_type,
                justification=override_justification,
                current_intake_data=intake,
            )
            if not is_valid_override:
                programs = session.exec(select(Program).where(Program.institution_id == user.institution_id)).all()
                quota_label = "Regular intake" if admission_type == "REGULAR" else "Supernumerary quota"
                err_detail = override_err or f"Target program {quota_label} is FULL (BLOCK). A formal over-admission justification (min 20 characters) is required to proceed."
                return templates.TemplateResponse(
                    request=request,
                    name="student_form.html",
                    context={
                        "student": student,
                        "programs": programs,
                        "error": err_detail,
                        "role": user.role,
                    },
                    status_code=400,
                )

    old_program_id = student.program_id
    old_admission_type = student.admission_type
    old_status = student.status

    student.full_name = full_name.strip()
    student.dob = dob.strip()
    student.gender = gender
    student.category = category
    student.program_id = program_id
    student.admission_year = admission_year
    student.admission_type = admission_type
    student.is_nri = is_nri
    student.is_foreign_national = is_foreign_national
    student.nationality = nationality.strip()
    student.consent_level = consent_level
    student.status = status_field
    student.updated_at = utc_now()
    # Re-sign record on update
    student.record_signature = sign_record(student, session)

    session.add(student)
    session.commit()

    # Re-evaluate intake if program, admission type, or status changed
    if old_program_id != program_id or old_admission_type != admission_type or old_status != status_field:
        if old_program_id:
            validate_program_intake(old_program_id, session)
        validate_program_intake(program_id, session)

    # Audit logging
    audit_details = f"Updated details for student {student.full_name} (Roll: {student.student_id})"
    if override_justification and override_justification.strip():
        audit_details += f" | Intake BLOCK Override Justification: {override_justification.strip()}"

    log_action(
        session=session,
        user=user,
        action="STUDENT_EDIT",
        entity="STUDENT",
        entity_id=str(student.id),
        details=audit_details,
    )

    return RedirectResponse(url="/institution/students", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/upload", response_class=HTMLResponse)
def upload_page(
    request: Request,
    user: User = Depends(require_role("INSTITUTION")),
):
    """Render CSV batch upload interface."""
    return templates.TemplateResponse(
        request=request,
        name="institution_upload.html",
        context={"role": user.role},
    )


@router.get("/upload/template")
def download_template(user: User = Depends(require_role("INSTITUTION"))):
    """Generate and download clean 15-column CSV template."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "apaar_id", "student_id", "full_name", "dob", "gender",
        "category", "program_name", "admission_year", "admission_type",
        "is_nri", "oci_status", "is_foreign_national", "nationality",
        "mode", "consent_given"
    ])
    writer.writerow([
        "100000000001", "DTI-2024-001", "Aarav Sharma", "2004-05-12", "M",
        "GENERAL", "B.Tech Computer Science and Engineering", "2024", "REGULAR",
        "False", "False", "False", "Indian",
        "FULL_TIME", "True"
    ])
    output.seek(0)
    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=student_upload_template.csv"},
    )


@router.post("/upload", response_class=HTMLResponse)
async def process_csv_upload(
    request: Request,
    file: UploadFile = File(...),
    session: Session = Depends(get_session),
    user: User = Depends(require_role("INSTITUTION")),
):
    """
    Process CSV batch upload:
    - Preloads validation context in one query batch.
    - Validates each row against R1 to R12.
    - Rejects rows with R1, R2, R9, R11 and compiles an error CSV.
    - Saves accepted rows as Student records and logs ValidationFlag rows.
    - Re-evaluates affected program quotas (R6, R7).
    - Logs audit record.
    """
    inst_id = user.institution_id

    # Validate file extension
    if not file.filename.lower().endswith(".csv"):
        return templates.TemplateResponse(
            request=request,
            name="institution_upload.html",
            context={"error": "Invalid file format. Please upload a comma-separated .csv file.", "role": user.role},
            status_code=400,
        )

    contents = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(contents), dtype=str).fillna("")
    except Exception as e:
        return templates.TemplateResponse(
            request=request,
            name="institution_upload.html",
            context={"error": f"Failed to parse CSV file: {str(e)}", "role": user.role},
            status_code=400,
        )

    # Preload validation context once
    ctx = build_validation_context(inst_id, session)

    # Pre-fetch intake quotas for institution programs to reject new admissions over capacity
    inst_programs = session.exec(select(Program).where(Program.institution_id == inst_id)).all()
    batch_intake_map: Dict[int, Dict[str, Any]] = {p.id: intake_check(p.id, session, program=p) for p in inst_programs}
    batch_allocated: Dict[int, Dict[str, int]] = defaultdict(lambda: {"REGULAR": 0, "SUPERNUMERARY": 0})

    accepted_clean: List[Student] = []
    accepted_with_warnings: List[Student] = []
    rejected_rows: List[Dict[str, Any]] = []
    affected_program_ids = set()

    for _, row in df.iterrows():
        row_dict = row.to_dict()
        flags = validate_student_row(row_dict, ctx)
        is_rejected = any(f["rule_code"] in HARD_REJECT_RULE_CODES for f in flags)

        if is_rejected:
            reasons = "; ".join(f["message"] for f in flags if f["rule_code"] in HARD_REJECT_RULE_CODES)
            rejected_rows.append({**row_dict, "rejection_reason": reasons})
        else:
            prog_name_key = str(row_dict.get("program_name") or row_dict.get("program_id") or "").strip().lower()
            try:
                adm_yr = int(row_dict.get("admission_year") or 2024)
            except (ValueError, TypeError):
                adm_yr = 2024
            program = (
                ctx["program_map"].get((prog_name_key, adm_yr))
                or ctx["program_map"].get(prog_name_key)
                or ctx["program_map"].get((prog_name_key.replace(" engineering", ""), adm_yr))
                or ctx["program_map"].get(prog_name_key.replace(" engineering", ""))
                or ctx["program_map"].get((f"{prog_name_key} engineering", adm_yr))
                or ctx["program_map"].get(f"{prog_name_key} engineering")
            )
            prog_id = program.id if program else None

            # Capacity Guard for new admissions: do not silently accept invalid new admissions
            adm_type = str(row_dict.get("admission_type") or "REGULAR").strip().upper() or "REGULAR"
            if prog_id and prog_id in batch_intake_map:
                p_info = batch_intake_map[prog_id]
                curr_reg = p_info["enrolled_regular"] + batch_allocated[prog_id]["REGULAR"]
                curr_super = p_info["enrolled_supernumerary"] + batch_allocated[prog_id]["SUPERNUMERARY"]
                curr_total = curr_reg + curr_super
                approved_lim = p_info["approved_intake"]
                super_lim = p_info["permitted_supernumerary"]
                total_lim = p_info["total_capacity"]

                is_quota_rejected = False
                quota_reason = ""
                if adm_type == "REGULAR":
                    if curr_reg >= approved_lim:
                        is_quota_rejected = True
                        quota_reason = f"Regular intake capacity exceeded for program '{program.name}' ({approved_lim} sanctioned). New admissions over approved capacity are rejected."
                    elif curr_total >= total_lim:
                        is_quota_rejected = True
                        quota_reason = f"Total program capacity exceeded for program '{program.name}' ({total_lim} total capacity). New admissions over capacity are rejected."
                elif adm_type == "SUPERNUMERARY":
                    if curr_super >= super_lim:
                        is_quota_rejected = True
                        quota_reason = f"Supernumerary quota capacity exceeded for program '{program.name}' ({super_lim} permitted). New admissions over permitted quota are rejected."
                    elif curr_total >= total_lim:
                        is_quota_rejected = True
                        quota_reason = f"Total program capacity exceeded for program '{program.name}' ({total_lim} total capacity). New admissions over capacity are rejected."

                if is_quota_rejected:
                    rejected_rows.append({**row_dict, "rejection_reason": quota_reason})
                    continue

                batch_allocated[prog_id][adm_type] += 1

            stu = Student(
                apaar_id=str(row_dict.get("apaar_id")).strip(),
                institution_id=inst_id,
                program_id=prog_id,
                student_id=str(row_dict.get("student_id")).strip(),
                full_name=str(row_dict.get("full_name")).strip(),
                dob=str(row_dict.get("dob")).strip(),
                gender=str(row_dict.get("gender") or "Other").strip() or "Other",
                category=str(row_dict.get("category") or "GENERAL").strip() or "GENERAL",
                admission_type=str(row_dict.get("admission_type") or "REGULAR").strip() or "REGULAR",
                is_nri=str(row_dict.get("is_nri", "")).lower() in ["true", "1", "yes"],
                oci_status=str(row_dict.get("oci_status", "")).lower() in ["true", "1", "yes"],
                is_foreign_national=str(row_dict.get("is_foreign_national", "")).lower() in ["true", "1", "yes"],
                nationality=str(row_dict.get("nationality") or "Indian").strip() or "Indian",
                admission_year=int(row_dict.get("admission_year") or 2024),
                mode=str(row_dict.get("mode") or "FULL_TIME").strip() or "FULL_TIME",
                status="ACTIVE",
                consent_level=2 if str(row_dict.get("consent_given", "")).lower() in ["true", "1", "yes", "2"] else 0,
                consent_timestamp=utc_now() if str(row_dict.get("consent_given", "")).lower() in ["true", "1", "yes", "2"] else None,
                created_at=utc_now(),
            )
            session.add(stu)
            session.commit()
            session.refresh(stu)

            # Generate Ed25519 record signature
            stu.record_signature = sign_record(stu, session)
            session.add(stu)
            session.commit()

            if prog_id:
                affected_program_ids.add(prog_id)

            if flags:
                for f in flags:
                    flag_record = ValidationFlag(
                        institution_id=inst_id,
                        program_id=prog_id,
                        student_id=stu.id,
                        rule_code=f["rule_code"],
                        severity=f["severity"],
                        message=f["message"],
                        recommended_action=f["recommended_action"],
                        status="OPEN",
                        created_at=utc_now(),
                    )
                    session.add(flag_record)
                session.commit()
                accepted_with_warnings.append(stu)
            else:
                accepted_clean.append(stu)

    # Re-evaluate intake for affected programs
    for pid in affected_program_ids:
        validate_program_intake(pid, session)

    # Compile downloadable error CSV if any rows were rejected
    if rejected_rows:
        err_buffer = io.StringIO()
        fieldnames = list(rejected_rows[0].keys())
        err_writer = csv.DictWriter(err_buffer, fieldnames=fieldnames)
        err_writer.writeheader()
        err_writer.writerows(rejected_rows)
        ERROR_CSVS[inst_id] = err_buffer.getvalue()
    else:
        ERROR_CSVS.pop(inst_id, None)

    # Log action to audit chain
    log_action(
        session=session,
        user=user,
        action="CSV_UPLOAD",
        entity="INSTITUTION",
        entity_id=str(inst_id),
        details=f"Processed CSV upload ({file.filename}): {len(accepted_clean)} clean, {len(accepted_with_warnings)} with warnings, {len(rejected_rows)} rejected",
    )

    return templates.TemplateResponse(
        request=request,
        name="upload_result.html",
        context={
            "total_rows": len(df),
            "accepted_clean_count": len(accepted_clean),
            "accepted_warning_count": len(accepted_with_warnings),
            "rejected_count": len(rejected_rows),
            "rejected_rows": rejected_rows[:50],
            "has_error_csv": bool(rejected_rows),
            "role": user.role,
        },
    )


@router.get("/upload/error-csv")
def download_error_csv(user: User = Depends(require_role("INSTITUTION"))):
    """Download the rejection report CSV generated by the last batch upload."""
    inst_id = user.institution_id
    csv_data = ERROR_CSVS.get(inst_id)
    if not csv_data:
        raise HTTPException(status_code=404, detail="No error report available for this session.")

    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=rejected_students_report.csv"},
    )


@router.get("/programs/{program_id}/intake-check")
def program_intake_check(
    program_id: int,
    admission_type: Optional[str] = Query(default=None),
    session: Session = Depends(get_session),
    user: User = Depends(require_role("INSTITUTION")),
):
    """AJAX endpoint for live seat meter in student forms."""
    return intake_check(program_id, session, target_admission_type=admission_type)
