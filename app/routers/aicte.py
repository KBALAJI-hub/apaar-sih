import csv
from collections import Counter, defaultdict
from io import StringIO
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlmodel import Session, select

from app.anomaly import compliance_score
from app.auth import require_role
from app.database import get_session
from app.models import AnomalyAlert, Institution, Program, Student, User, ValidationFlag

# Router for AICTE admin portal endpoints
router = APIRouter(prefix="/aicte", tags=["AICTE"])
api_router = APIRouter(prefix="/api/aicte", tags=["AICTE API"])


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

    program_query = select(Program).where(Program.institution_id.in_(institution_ids or {-1}))
    if academic_year:
        program_query = program_query.where(Program.academic_year == academic_year)
    programs = session.exec(program_query).all()
    programs_by_institution: dict[int, list[Program]] = defaultdict(list)
    for program in programs:
        programs_by_institution[program.institution_id].append(program)

    program_ids = {program.id for program in programs}
    students = session.exec(
        select(Student).where(
            Student.institution_id.in_(institution_ids or {-1}),
            Student.program_id.in_(program_ids or {-1}),
            Student.status == "ACTIVE",
        )
    ).all()
    flags = session.exec(
        select(ValidationFlag).where(
            ValidationFlag.institution_id.in_(institution_ids or {-1}),
            ValidationFlag.status == "OPEN",
        )
    ).all()
    return institutions, programs_by_institution, students, flags


@router.get("/dashboard", response_model=None)
def admin_dashboard_redirect(
    user: User = Depends(require_role("AICTE_ADMIN")),
):
    from fastapi.responses import RedirectResponse

    return RedirectResponse(url="/api/aicte/summary", status_code=303)


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

    institution_rows = []
    for institution in institutions:
        intake = sum(
            max(0, int(program.approved_intake or 0))
            for program in programs_by_institution[institution.id]
        )
        enrolment = enrolment_by_institution[institution.id]
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
            "compliance_score": compliance_score(institution.id, session),
        })

    active_institutions_by_apaar: dict[str, set[int]] = defaultdict(set)
    for student in students:
        if student.mode.upper() == "FULL_TIME":
            active_institutions_by_apaar[student.apaar_id].add(student.institution_id)
    cross_duplicate_count = sum(
        len(institution_ids) > 1 for institution_ids in active_institutions_by_apaar.values()
    )

    high_flags = sorted(
        (flag for flag in flags if flag.severity == "HIGH"),
        key=lambda flag: flag.created_at,
        reverse=True,
    )[:10]
    anomaly_query = select(AnomalyAlert).where(
        AnomalyAlert.institution_id.in_(institutions_by_id.keys() or {-1})
    ).order_by(AnomalyAlert.created_at.desc()).limit(10)
    anomalies = session.exec(anomaly_query).all()
    academic_year_query = select(Program.academic_year).where(
        Program.institution_id.in_(institutions_by_id.keys() or {-1})
    ).distinct().order_by(Program.academic_year)
    academic_years = session.exec(academic_year_query).all()

    return {
        "totals": {
            "institutions": len(institutions),
            "total_enrolment": sum(enrolment_by_institution.values()),
            "total_intake": sum(row["approved_intake"] for row in institution_rows),
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
