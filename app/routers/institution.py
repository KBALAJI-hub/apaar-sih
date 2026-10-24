"""
Institution portal router for APAAR Verify.
Implements Student CRUD, CSV uploads with automated validation, Intake Guard checks, and audit logging.
Strictly scoped to the logged-in institution's own data.
"""

import csv
import io
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
import pandas as pd
from sqlmodel import Session, func, or_, select

from app.audit import log_action
from app.auth import get_current_user, require_role
from app.database import get_session
from app.models import Institution, Program, Student, User, ValidationFlag, utc_now
from app.security import sign_record
from app.validation import (
    build_validation_context,
    intake_check,
    validate_program_intake,
    validate_student_row,
)

router = APIRouter(prefix="/institution", tags=["Institution"])

# Templates reference
BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# In-memory store for generated rejection error CSVs (keyed by institution_id)
ERROR_CSVS: Dict[int, str] = {}


@router.get("/dashboard", response_class=HTMLResponse)
def institution_dashboard(
    request: Request,
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
    """
    inst_id = user.institution_id
    institution = session.get(Institution, inst_id)
    if not institution:
        raise HTTPException(status_code=404, detail="Institution record not found")

    # Fetch programs
    programs = session.exec(
        select(Program).where(Program.institution_id == inst_id)
    ).all()

    # KPI 1 & 2: Students & Intake
    total_students = len(
        session.exec(
            select(Student.id).where(Student.institution_id == inst_id, Student.status == "ACTIVE")
        ).all()
    )
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

    # Program quota monitoring data
    programs_data = [intake_check(p.id, session) for p in programs]

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
            "recent_flags": open_flags[:10],
            "role": user.role,
        },
    )


@router.get("/students", response_class=HTMLResponse)
def list_students(
    request: Request,
    q: Optional[str] = None,
    program_id: Optional[int] = None,
    session: Session = Depends(get_session),
    user: User = Depends(require_role("INSTITUTION")),
):
    """
    List enrolled students for the logged-in institution with search and program filters.
    """
    inst_id = user.institution_id
    programs = session.exec(select(Program).where(Program.institution_id == inst_id)).all()
    programs_map = {p.id: p.name for p in programs}

    # Base query restricted to this institution
    statement = select(Student).where(Student.institution_id == inst_id)

    # Program filter
    if program_id:
        statement = statement.where(Student.program_id == program_id)

    # Search filter (name, roll no, or APAAR ID)
    if q and q.strip():
        term = f"%{q.strip()}%"
        statement = statement.where(
            or_(
                Student.full_name.ilike(term),
                Student.student_id.ilike(term),
                Student.apaar_id.ilike(term),
            )
        )

    statement = statement.order_by(Student.id.desc()).limit(150)
    students = session.exec(statement).all()

    # Pre-calculate open flags count per student for UI badges
    flags = session.exec(
        select(ValidationFlag.student_id, func.count(ValidationFlag.id))
        .where(ValidationFlag.institution_id == inst_id, ValidationFlag.status == "OPEN")
        .group_by(ValidationFlag.student_id)
    ).all()
    flags_by_student = {f[0]: f[1] for f in flags if f[0] is not None}

    return templates.TemplateResponse(
        request=request,
        name="institution_students.html",
        context={
            "students": students,
            "programs": programs,
            "programs_map": programs_map,
            "flags_by_student": flags_by_student,
            "search_query": q,
            "selected_program_id": program_id,
            "role": user.role,
        },
    )


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

    # Intake Guard check
    intake = intake_check(program_id, session)
    if intake["decision"] == "BLOCK" and not (override_justification and override_justification.strip()):
        return templates.TemplateResponse(
            request=request,
            name="student_form.html",
            context={
                "student": None,
                "programs": programs,
                "error": "Intake quota is FULL (BLOCK). An over-admission justification is strictly required to proceed.",
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
    is_rejected = any(f["rule_code"] in ["R1", "R2", "R9", "R11"] for f in flags)

    if is_rejected:
        reject_reasons = "; ".join(f["message"] for f in flags if f["rule_code"] in ["R1", "R2", "R9", "R11"])
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
    student = session.get(Student, id)
    if not student or student.institution_id != user.institution_id:
        raise HTTPException(status_code=404, detail="Student not found or access denied")

    # If program is changed, check target program intake
    if student.program_id != program_id:
        intake = intake_check(program_id, session)
        if intake["decision"] == "BLOCK" and not (override_justification and override_justification.strip()):
            programs = session.exec(select(Program).where(Program.institution_id == user.institution_id)).all()
            return templates.TemplateResponse(
                request=request,
                name="student_form.html",
                context={
                    "student": student,
                    "programs": programs,
                    "error": "Target program intake is FULL (BLOCK). An over-admission justification is strictly required to proceed.",
                    "role": user.role,
                },
                status_code=400,
            )

    old_program_id = student.program_id
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

    # Re-evaluate intake if program changed
    if old_program_id != program_id:
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

    accepted_clean: List[Student] = []
    accepted_with_warnings: List[Student] = []
    rejected_rows: List[Dict[str, Any]] = []
    affected_program_ids = set()

    for _, row in df.iterrows():
        row_dict = row.to_dict()
        flags = validate_student_row(row_dict, ctx)
        is_rejected = any(f["rule_code"] in ["R1", "R2", "R9", "R11"] for f in flags)

        if is_rejected:
            reasons = "; ".join(f["message"] for f in flags if f["rule_code"] in ["R1", "R2", "R9", "R11"])
            rejected_rows.append({**row_dict, "rejection_reason": reasons})
        else:
            prog_name_key = str(row_dict.get("program_name") or row_dict.get("program_id") or "").strip().lower()
            program = ctx["program_map"].get(prog_name_key)
            prog_id = program.id if program else None

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
    session: Session = Depends(get_session),
    user: User = Depends(require_role("INSTITUTION")),
):
    """AJAX endpoint for live seat meter in student forms."""
    return intake_check(program_id, session)
