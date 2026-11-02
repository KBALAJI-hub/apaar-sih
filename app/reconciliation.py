"""
Historical Seat Allocation Reconciliation Engine (Phase 6).
SIH PS 26263 - APAAR Verify

Provides comprehensive historical capacity reconciliation:
1. Evaluates existing enrolments against applicable approved regulatory allocations.
2. Distinctly separates:
   - Regular intake violations (admissions > approved sanctioned intake)
   - Supernumerary allocation violations (supernumerary admissions > verified authorized supernumerary seats)
   - Scheme-specific allocation violations (e.g. NRI, FN, OCI, SC, ST, OBC exceeding specific quotas)
   - Missing or unverified approvals (supernumerary or override admissions without verified regulatory approval)
   - Academic-year mismatches (student admission_year conflicting with program academic year)
   - Unclassified admissions (missing/invalid admission_type, missing admission_year, or missing category)
3. Non-destructive: Does NOT automatically reject, delete, or deactivate existing historical student records.
4. Idempotent: Repeated reconciliation runs update records in place without duplicating reports or flags.
5. Report Generation: Generates structured institution and AICTE administrator reports and CSV exports.
6. Preserves immutable audit history with hash-chained AuditLog entries.
7. Truthful Reporting: Does not invent missing historical approval information.
"""

import csv
import io
import json
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from sqlmodel import Session, select, func

from app.audit import log_action
from app.allocation import get_active_allocations_summary, get_program_allocations
from app.models import (
    Institution,
    Program,
    Student,
    SeatAllocation,
    RegulatoryOverride,
    ValidationFlag,
    HistoricalReconciliation,
    User,
    utc_now,
)
from app.validation import parse_academic_year

# Canonical Reconciliation Violation Types
VIOLATION_TYPE_REGULAR = "REGULAR_INTAKE_VIOLATION"
VIOLATION_TYPE_SUPERNUMERARY = "SUPERNUMERARY_VIOLATION"
VIOLATION_TYPE_SCHEME = "SCHEME_SPECIFIC_VIOLATION"
VIOLATION_TYPE_UNVERIFIED_APPROVAL = "MISSING_OR_UNVERIFIED_APPROVAL"
VIOLATION_TYPE_YEAR_MISMATCH = "ACADEMIC_YEAR_MISMATCH"
VIOLATION_TYPE_UNCLASSIFIED = "UNCLASSIFIED_ADMISSION"
VIOLATION_TYPE_NONE = "NONE"


def _upsert_reconciliation_record(
    session: Session,
    institution_id: int,
    program_id: int,
    academic_year: str,
    allocation_type: str,
    category_or_scheme: str,
    approved_capacity: int,
    actual_enrolment: int,
    excess_count: int,
    violation_type: str,
    status: str,
    approval_status: str,
    approval_ref: Optional[str] = None,
    details: Optional[str] = None,
    affected_student_ids: Optional[List[int]] = None,
    user_id: Optional[int] = None,
) -> HistoricalReconciliation:
    """
    Idempotently insert or update a HistoricalReconciliation record.
    Prevents duplicates on repeated reconciliation runs.
    """
    existing = session.exec(
        select(HistoricalReconciliation).where(
            HistoricalReconciliation.program_id == program_id,
            HistoricalReconciliation.academic_year == academic_year,
            HistoricalReconciliation.allocation_type == allocation_type,
            HistoricalReconciliation.category_or_scheme == category_or_scheme,
        )
    ).first()

    student_ids_str = json.dumps(affected_student_ids or [])
    affected_count = len(affected_student_ids or [])

    if existing:
        existing.approved_capacity = approved_capacity
        existing.actual_enrolment = actual_enrolment
        existing.excess_count = excess_count
        existing.violation_type = violation_type
        existing.status = status
        existing.approval_status = approval_status
        existing.approval_ref = approval_ref
        existing.details = details
        existing.affected_student_count = affected_count
        existing.affected_student_ids = student_ids_str
        existing.reconciled_at = utc_now()
        if user_id:
            existing.reconciled_by_user_id = user_id
        session.add(existing)
        return existing
    else:
        new_record = HistoricalReconciliation(
            institution_id=institution_id,
            program_id=program_id,
            academic_year=academic_year,
            allocation_type=allocation_type,
            category_or_scheme=category_or_scheme,
            approved_capacity=approved_capacity,
            actual_enrolment=actual_enrolment,
            excess_count=excess_count,
            violation_type=violation_type,
            status=status,
            approval_status=approval_status,
            approval_ref=approval_ref,
            details=details,
            affected_student_count=affected_count,
            affected_student_ids=student_ids_str,
            reconciled_at=utc_now(),
            reconciled_by_user_id=user_id,
        )
        session.add(new_record)
        return new_record


def _sync_validation_flag(
    session: Session,
    institution_id: int,
    program_id: int,
    rule_code: str,
    severity: str,
    message: str,
    recommended_action: str,
    is_violation: bool,
) -> None:
    """
    Idempotently sync program-level historical validation flags.
    If violation exists: ensures flag is OPEN.
    If violation is resolved: updates status to RESOLVED.
    """
    existing_flag = session.exec(
        select(ValidationFlag).where(
            ValidationFlag.institution_id == institution_id,
            ValidationFlag.program_id == program_id,
            ValidationFlag.rule_code == rule_code,
            ValidationFlag.student_id == None,
        )
    ).first()

    if is_violation:
        if existing_flag:
            existing_flag.severity = severity
            existing_flag.message = message
            existing_flag.recommended_action = recommended_action
            existing_flag.status = "OPEN"
            session.add(existing_flag)
        else:
            flag = ValidationFlag(
                institution_id=institution_id,
                program_id=program_id,
                student_id=None,
                rule_code=rule_code,
                severity=severity,
                message=message,
                recommended_action=recommended_action,
                status="OPEN",
                created_at=utc_now(),
            )
            session.add(flag)
    else:
        if existing_flag and existing_flag.status == "OPEN":
            existing_flag.status = "RESOLVED"
            session.add(existing_flag)


def reconcile_program(
    session: Session,
    program_id: int,
    academic_year: Optional[str] = None,
    user: Optional[User] = None,
    commit: bool = True,
) -> List[HistoricalReconciliation]:
    """
    Reconcile historical enrolments for an academic program against regulatory allocations.
    Evaluates:
    1. Regular Sanctioned Intake vs Active Regular Enrolments.
    2. Supernumerary Authorized Seats vs Active Supernumerary Enrolments.
    3. Within-intake and supernumerary scheme sub-allocations.
    4. Missing or unverified approval evidence.
    5. Academic-year mismatches across student cohorts.
    6. Unclassified student records.

    Idempotent: updates existing records in place.
    Non-destructive: preserves all student records intact.
    """
    program = session.get(Program, program_id)
    if not program:
        return []

    inst_id = program.institution_id
    user_id = user.id if user else None

    # Discover academic years to evaluate for this program
    cohort_years: Set[int] = set()
    prog_year_parsed = parse_academic_year(program.academic_year)
    if prog_year_parsed:
        cohort_years.add(prog_year_parsed)

    # Add academic years present in SeatAllocations
    alloc_years = session.exec(
        select(SeatAllocation.academic_year).where(SeatAllocation.program_id == program_id)
    ).all()
    for ay in alloc_years:
        py = parse_academic_year(ay)
        if py:
            cohort_years.add(py)

    # Add academic years present in Student records
    student_years = session.exec(
        select(Student.admission_year).where(Student.program_id == program_id)
    ).all()
    for sy in student_years:
        if sy and sy > 0:
            cohort_years.add(sy)

    if academic_year:
        target_py = parse_academic_year(academic_year)
        if target_py:
            cohort_years = {target_py}

    # Fetch all students for this program
    all_students = session.exec(
        select(Student).where(Student.program_id == program_id)
    ).all()

    results: List[HistoricalReconciliation] = []

    for cohort_yr in sorted(cohort_years):
        cohort_label = f"{cohort_yr}-{str(cohort_yr + 1)[-2:]}"

        # Partition students for this cohort year
        cohort_students = [s for s in all_students if s.admission_year == cohort_yr]
        active_students = [s for s in cohort_students if str(s.status).upper() == "ACTIVE"]

        active_regular = [
            s for s in active_students
            if str(s.admission_type or "").upper() == "REGULAR"
        ]
        active_super = [
            s for s in active_students
            if str(s.admission_type or "").upper() == "SUPERNUMERARY"
        ]

        # -------------------------------------------------------------------
        # 1. Fetch Approved Regulatory Allocations for (program, cohort_yr)
        # -------------------------------------------------------------------
        alloc_summary = get_active_allocations_summary(
            session=session,
            program_id=program_id,
            academic_year=cohort_label,
            program=program,
        )

        has_verified_allocations = alloc_summary["has_allocations"]
        sanctioned_alloc = alloc_summary["sanctioned_allocation"]
        within_map = alloc_summary["within_intake_allocations"]
        super_map = alloc_summary["supernumerary_allocations"]

        # Determine approved regular sanctioned capacity
        if sanctioned_alloc is not None:
            approved_regular = sanctioned_alloc.approved_seats
            reg_approval_status = "VERIFIED"
            reg_approval_ref = sanctioned_alloc.approval_ref
        elif prog_year_parsed == cohort_yr:
            approved_regular = program.approved_intake
            reg_approval_status = "PROGRAM_BASELINE"
            reg_approval_ref = None
        else:
            # Different cohort with no verified allocation record
            approved_regular = program.approved_intake
            reg_approval_status = "PROGRAM_BASELINE"
            reg_approval_ref = None

        # -------------------------------------------------------------------
        # 2. Reconcile Regular Sanctioned Intake
        # -------------------------------------------------------------------
        reg_enrolled = len(active_regular)
        reg_excess = max(0, reg_enrolled - approved_regular)
        reg_violation = VIOLATION_TYPE_REGULAR if reg_excess > 0 else VIOLATION_TYPE_NONE
        reg_status = "VIOLATION" if reg_excess > 0 else "COMPLIANT"

        reg_details = (
            f"Regular active enrolment ({reg_enrolled}) exceeds sanctioned intake ({approved_regular}) by {reg_excess} seat(s)."
            if reg_excess > 0
            else f"Regular enrolment ({reg_enrolled}/{approved_regular}) compliant with sanctioned intake."
        )

        reg_affected = [s.id for s in active_regular[approved_regular:]] if reg_excess > 0 else []

        rec_reg = _upsert_reconciliation_record(
            session=session,
            institution_id=inst_id,
            program_id=program_id,
            academic_year=cohort_label,
            allocation_type="SANCTIONED",
            category_or_scheme="ALL",
            approved_capacity=approved_regular,
            actual_enrolment=reg_enrolled,
            excess_count=reg_excess,
            violation_type=reg_violation,
            status=reg_status,
            approval_status=reg_approval_status,
            approval_ref=reg_approval_ref,
            details=reg_details,
            affected_student_ids=reg_affected,
            user_id=user_id,
        )
        results.append(rec_reg)

        _sync_validation_flag(
            session=session,
            institution_id=inst_id,
            program_id=program_id,
            rule_code="R6",
            severity="HIGH",
            message=reg_details,
            recommended_action="Submit formal regulatory override or review regular intake limits.",
            is_violation=(reg_excess > 0),
        )

        # -------------------------------------------------------------------
        # 3. Reconcile Supernumerary Allocation
        # -------------------------------------------------------------------
        super_enrolled = len(active_super)

        if super_map:
            approved_super = sum(a.approved_seats for a in super_map.values())
            super_approval_status = "VERIFIED"
            super_approval_ref = ", ".join(a.approval_ref for a in super_map.values() if a.approval_ref)
            super_excess = max(0, super_enrolled - approved_super)
            super_violation = VIOLATION_TYPE_SUPERNUMERARY if super_excess > 0 else VIOLATION_TYPE_NONE
            super_status = "VIOLATION" if super_excess > 0 else "COMPLIANT"
            super_details = (
                f"Supernumerary active enrolment ({super_enrolled}) exceeds authorized quota ({approved_super}) by {super_excess} seat(s)."
                if super_excess > 0
                else f"Supernumerary enrolment ({super_enrolled}/{approved_super}) compliant with authorized allocations."
            )
            super_affected = [s.id for s in active_super[approved_super:]] if super_excess > 0 else []
        elif super_enrolled > 0:
            # Enrolled supernumerary students but NO verified regulatory allocation exists
            # Requirement 9: Do not invent approval information. Report as missing approval.
            approved_super = 0
            super_approval_status = "MISSING"
            super_approval_ref = None
            super_excess = super_enrolled
            super_violation = VIOLATION_TYPE_UNVERIFIED_APPROVAL
            super_status = "VIOLATION"
            super_details = (
                f"Supernumerary enrolment of {super_enrolled} student(s) has NO verified AICTE or regulatory "
                f"seat allocation approval for academic year {cohort_label}. Formal approval is required."
            )
            super_affected = [s.id for s in active_super]
        else:
            approved_super = 0
            super_approval_status = "NONE"
            super_approval_ref = None
            super_excess = 0
            super_violation = VIOLATION_TYPE_NONE
            super_status = "COMPLIANT"
            super_details = f"Zero supernumerary admissions in academic year {cohort_label}."
            super_affected = []

        rec_super = _upsert_reconciliation_record(
            session=session,
            institution_id=inst_id,
            program_id=program_id,
            academic_year=cohort_label,
            allocation_type="SUPERNUMERARY",
            category_or_scheme="ALL",
            approved_capacity=approved_super,
            actual_enrolment=super_enrolled,
            excess_count=super_excess,
            violation_type=super_violation,
            status=super_status,
            approval_status=super_approval_status,
            approval_ref=super_approval_ref,
            details=super_details,
            affected_student_ids=super_affected,
            user_id=user_id,
        )
        results.append(rec_super)

        _sync_validation_flag(
            session=session,
            institution_id=inst_id,
            program_id=program_id,
            rule_code="R7",
            severity="MEDIUM",
            message=super_details,
            recommended_action="Verify AICTE approval letters or submit regulatory override for supernumerary seats.",
            is_violation=(super_excess > 0),
        )

        # -------------------------------------------------------------------
        # 4. Reconcile Scheme-Specific Within-Intake Sub-Allocations
        # -------------------------------------------------------------------
        for scheme_code, alloc in within_map.items():
            scheme_students = [
                s for s in active_regular
                if (
                    (scheme_code == "NRI" and s.is_nri)
                    or (scheme_code != "NRI" and str(s.category).upper() == scheme_code)
                )
            ]
            scheme_enrolled = len(scheme_students)
            scheme_approved = alloc.approved_seats
            scheme_excess = max(0, scheme_enrolled - scheme_approved)
            scheme_violation = VIOLATION_TYPE_SCHEME if scheme_excess > 0 else VIOLATION_TYPE_NONE
            scheme_status = "VIOLATION" if scheme_excess > 0 else "COMPLIANT"
            scheme_details = (
                f"Within-intake scheme/category '{scheme_code}' enrolment ({scheme_enrolled}) exceeds approved sub-allocation ({scheme_approved}) by {scheme_excess} seat(s)."
                if scheme_excess > 0
                else f"Scheme/category '{scheme_code}' enrolment ({scheme_enrolled}/{scheme_approved}) compliant."
            )
            scheme_affected = [s.id for s in scheme_students[scheme_approved:]] if scheme_excess > 0 else []

            rec_scheme = _upsert_reconciliation_record(
                session=session,
                institution_id=inst_id,
                program_id=program_id,
                academic_year=cohort_label,
                allocation_type="WITHIN_INTAKE",
                category_or_scheme=scheme_code,
                approved_capacity=scheme_approved,
                actual_enrolment=scheme_enrolled,
                excess_count=scheme_excess,
                violation_type=scheme_violation,
                status=scheme_status,
                approval_status="VERIFIED",
                approval_ref=alloc.approval_ref,
                details=scheme_details,
                affected_student_ids=scheme_affected,
                user_id=user_id,
            )
            results.append(rec_scheme)

        # -------------------------------------------------------------------
        # 5. Reconcile Specific Supernumerary Scheme Sub-Allocations (FN, OCI, TFW)
        # -------------------------------------------------------------------
        for scheme_code, alloc in super_map.items():
            if scheme_code == "ALL":
                continue
            scheme_super_students = [
                s for s in active_super
                if (
                    (scheme_code == "FN" and s.is_foreign_national)
                    or (scheme_code == "OCI" and s.oci_status)
                    or (scheme_code == "NRI" and s.is_nri)
                    or (str(s.category).upper() == scheme_code)
                )
            ]
            ss_enrolled = len(scheme_super_students)
            ss_approved = alloc.approved_seats
            ss_excess = max(0, ss_enrolled - ss_approved)
            ss_violation = VIOLATION_TYPE_SCHEME if ss_excess > 0 else VIOLATION_TYPE_NONE
            ss_status = "VIOLATION" if ss_excess > 0 else "COMPLIANT"
            ss_details = (
                f"Supernumerary scheme '{scheme_code}' enrolment ({ss_enrolled}) exceeds authorized limit ({ss_approved}) by {ss_excess} seat(s)."
                if ss_excess > 0
                else f"Supernumerary scheme '{scheme_code}' enrolment ({ss_enrolled}/{ss_approved}) compliant."
            )
            ss_affected = [s.id for s in scheme_super_students[ss_approved:]] if ss_excess > 0 else []

            rec_ss = _upsert_reconciliation_record(
                session=session,
                institution_id=inst_id,
                program_id=program_id,
                academic_year=cohort_label,
                allocation_type="SUPERNUMERARY",
                category_or_scheme=scheme_code,
                approved_capacity=ss_approved,
                actual_enrolment=ss_enrolled,
                excess_count=ss_excess,
                violation_type=ss_violation,
                status=ss_status,
                approval_status="VERIFIED",
                approval_ref=alloc.approval_ref,
                details=ss_details,
                affected_student_ids=ss_affected,
                user_id=user_id,
            )
            results.append(rec_ss)

        # -------------------------------------------------------------------
        # 6. Reconcile Missing or Unverified Approvals (Overrides / Allocations)
        # -------------------------------------------------------------------
        unverified_students = []
        for s in active_students:
            # Check override reference
            if s.override_id:
                ov = session.get(RegulatoryOverride, s.override_id)
                if not ov or str(ov.verification_status).upper() != "VERIFIED":
                    unverified_students.append(s.id)
            # Check allocation reference
            if s.allocation_id:
                al = session.get(SeatAllocation, s.allocation_id)
                if not al or str(al.verification_status).upper() != "VERIFIED":
                    unverified_students.append(s.id)

        unverified_students = sorted(list(set(unverified_students)))
        if unverified_students:
            rec_unv = _upsert_reconciliation_record(
                session=session,
                institution_id=inst_id,
                program_id=program_id,
                academic_year=cohort_label,
                allocation_type="APPROVAL_AUDIT",
                category_or_scheme="ALL",
                approved_capacity=0,
                actual_enrolment=len(unverified_students),
                excess_count=len(unverified_students),
                violation_type=VIOLATION_TYPE_UNVERIFIED_APPROVAL,
                status="VIOLATION",
                approval_status="UNVERIFIED",
                approval_ref=None,
                details=f"{len(unverified_students)} active student(s) reference missing, draft, expired, or revoked regulatory approvals.",
                affected_student_ids=unverified_students,
                user_id=user_id,
            )
            results.append(rec_unv)

    # -----------------------------------------------------------------------
    # 7. Reconcile Academic-Year Mismatches
    # -----------------------------------------------------------------------
    # Students enrolled in this program record whose admission_year != program.academic_year start year
    mismatched_students: List[int] = []
    if prog_year_parsed:
        for s in all_students:
            if s.admission_year and s.admission_year != prog_year_parsed:
                mismatched_students.append(s.id)

    mismatched_students = sorted(list(set(mismatched_students)))
    mismatch_status = "REVIEW_REQUIRED" if mismatched_students else "COMPLIANT"
    mismatch_violation = VIOLATION_TYPE_YEAR_MISMATCH if mismatched_students else VIOLATION_TYPE_NONE
    mismatch_details = (
        f"{len(mismatched_students)} student(s) enrolled with admission_year different from program's sanctioned academic year ({program.academic_year})."
        if mismatched_students
        else f"All enrolled students match program academic year {program.academic_year}."
    )

    rec_mismatch = _upsert_reconciliation_record(
        session=session,
        institution_id=inst_id,
        program_id=program_id,
        academic_year=program.academic_year,
        allocation_type="ACADEMIC_YEAR",
        category_or_scheme="COHORT_MISMATCH",
        approved_capacity=0,
        actual_enrolment=len(mismatched_students),
        excess_count=len(mismatched_students),
        violation_type=mismatch_violation,
        status=mismatch_status,
        approval_status="VERIFIED" if not mismatched_students else "UNVERIFIED",
        approval_ref=None,
        details=mismatch_details,
        affected_student_ids=mismatched_students,
        user_id=user_id,
    )
    results.append(rec_mismatch)

    # -----------------------------------------------------------------------
    # 8. Reconcile Unclassified Admissions
    # -----------------------------------------------------------------------
    unclassified_students: List[int] = []
    unclassified_reasons: List[str] = []

    for s in all_students:
        reasons = []
        clean_adm = str(s.admission_type or "").strip().upper()
        if clean_adm not in ("REGULAR", "SUPERNUMERARY"):
            reasons.append("Invalid/missing admission_type")
        if not s.admission_year or s.admission_year <= 0:
            reasons.append("Missing admission_year")
        if not s.category or not str(s.category).strip():
            reasons.append("Missing social category")

        if reasons:
            unclassified_students.append(s.id)
            unclassified_reasons.append(f"Student #{s.id} ({s.student_id}): {', '.join(reasons)}")

    unclassified_students = sorted(list(set(unclassified_students)))
    unclass_status = "REVIEW_REQUIRED" if unclassified_students else "COMPLIANT"
    unclass_violation = VIOLATION_TYPE_UNCLASSIFIED if unclassified_students else VIOLATION_TYPE_NONE
    unclass_details = (
        f"{len(unclassified_students)} student(s) have incomplete admission classifications: {'; '.join(unclassified_reasons[:5])}"
        if unclassified_students
        else "All student records possess valid admission classifications."
    )

    rec_unclass = _upsert_reconciliation_record(
        session=session,
        institution_id=inst_id,
        program_id=program_id,
        academic_year=program.academic_year,
        allocation_type="CLASSIFICATION",
        category_or_scheme="UNCLASSIFIED",
        approved_capacity=0,
        actual_enrolment=len(unclassified_students),
        excess_count=len(unclassified_students),
        violation_type=unclass_violation,
        status=unclass_status,
        approval_status="VERIFIED" if not unclassified_students else "UNVERIFIED",
        approval_ref=None,
        details=unclass_details,
        affected_student_ids=unclassified_students,
        user_id=user_id,
    )
    results.append(rec_unclass)

    # Immutable Audit Logging
    total_excess = sum(r.excess_count for r in results if r.status == "VIOLATION")
    violation_count = sum(1 for r in results if r.status == "VIOLATION")
    audit_summary = (
        f"Reconciled Program '{program.name}' (ID: {program.id}): "
        f"{len(results)} allocation checks evaluated, {violation_count} violations detected, {total_excess} total excess seats."
    )

    log_action(
        session=session,
        user=user,
        action="HISTORICAL_RECONCILIATION",
        entity="PROGRAM",
        entity_id=str(program.id),
        details=audit_summary,
        commit=False,
    )

    if commit:
        session.commit()

    return results


def reconcile_institution(
    session: Session,
    institution_id: int,
    academic_year: Optional[str] = None,
    user: Optional[User] = None,
    commit: bool = True,
) -> List[HistoricalReconciliation]:
    """
    Reconcile all academic programs belonging to an educational institution.
    """
    institution = session.get(Institution, institution_id)
    if not institution:
        return []

    programs = session.exec(
        select(Program).where(Program.institution_id == institution_id)
    ).all()

    all_results: List[HistoricalReconciliation] = []
    for prog in programs:
        res = reconcile_program(
            session=session,
            program_id=prog.id,
            academic_year=academic_year,
            user=user,
            commit=False,
        )
        all_results.extend(res)

    total_violations = sum(1 for r in all_results if r.status == "VIOLATION")
    total_excess = sum(r.excess_count for r in all_results if r.status == "VIOLATION")

    log_action(
        session=session,
        user=user,
        action="HISTORICAL_RECONCILIATION",
        entity="INSTITUTION",
        entity_id=str(institution_id),
        details=(
            f"Institution-wide historical reconciliation for {institution.name}: "
            f"{len(programs)} programs evaluated, {total_violations} violations flagged, {total_excess} total excess seats."
        ),
        commit=False,
    )

    if commit:
        session.commit()

    return all_results


def reconcile_all_institutions(
    session: Session,
    academic_year: Optional[str] = None,
    user: Optional[User] = None,
    commit: bool = True,
) -> List[HistoricalReconciliation]:
    """
    Administrator batch reconciliation across all registered institutions.
    """
    institutions = session.exec(select(Institution)).all()
    all_results: List[HistoricalReconciliation] = []

    for inst in institutions:
        res = reconcile_institution(
            session=session,
            institution_id=inst.id,
            academic_year=academic_year,
            user=user,
            commit=False,
        )
        all_results.extend(res)

    if commit:
        session.commit()

    return all_results


def get_reconciliation_summary(
    session: Session,
    institution_id: Optional[int] = None,
    academic_year: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generate an aggregated reconciliation summary report for institutions and administrators.
    """
    query = select(HistoricalReconciliation)
    if institution_id:
        query = query.where(HistoricalReconciliation.institution_id == institution_id)
    if academic_year:
        query = query.where(HistoricalReconciliation.academic_year == academic_year)

    records = session.exec(query.order_by(HistoricalReconciliation.id.desc())).all()

    total_evaluations = len(records)
    total_violations = sum(1 for r in records if r.status == "VIOLATION")
    total_reviews = sum(1 for r in records if r.status == "REVIEW_REQUIRED")
    total_compliant = sum(1 for r in records if r.status == "COMPLIANT")
    total_excess = sum(r.excess_count for r in records if r.status == "VIOLATION")

    violations_by_type: Dict[str, int] = defaultdict(int)
    excess_by_type: Dict[str, int] = defaultdict(int)
    for r in records:
        if r.status in ("VIOLATION", "REVIEW_REQUIRED"):
            v_type = r.violation_type or "OTHER"
            violations_by_type[v_type] += 1
            excess_by_type[v_type] += r.excess_count

    programs_evaluated = len(set(r.program_id for r in records))
    institutions_evaluated = len(set(r.institution_id for r in records))

    # Preload program and institution names
    prog_map = {p.id: p.name for p in session.exec(select(Program)).all()}
    inst_map = {i.id: i.name for i in session.exec(select(Institution)).all()}

    serialized_records = []
    for r in records:
        serialized_records.append({
            "id": r.id,
            "institution_id": r.institution_id,
            "institution_name": inst_map.get(r.institution_id, f"Institution #{r.institution_id}"),
            "program_id": r.program_id,
            "program_name": prog_map.get(r.program_id, f"Program #{r.program_id}"),
            "academic_year": r.academic_year,
            "allocation_type": r.allocation_type,
            "category_or_scheme": r.category_or_scheme,
            "approved_capacity": r.approved_capacity,
            "actual_enrolment": r.actual_enrolment,
            "excess_count": r.excess_count,
            "violation_type": r.violation_type,
            "status": r.status,
            "approval_status": r.approval_status,
            "approval_ref": r.approval_ref,
            "details": r.details,
            "affected_student_count": r.affected_student_count,
            "reconciled_at": r.reconciled_at.strftime("%Y-%m-%d %H:%M:%S") if r.reconciled_at else None,
        })

    return {
        "institutions_evaluated": institutions_evaluated,
        "programs_evaluated": programs_evaluated,
        "total_evaluations": total_evaluations,
        "total_violations": total_violations,
        "total_reviews_required": total_reviews,
        "total_compliant": total_compliant,
        "total_excess_seats": total_excess,
        "violations_by_type": dict(violations_by_type),
        "excess_by_type": dict(excess_by_type),
        "records": serialized_records,
    }


def export_reconciliation_csv_string(
    session: Session,
    institution_id: Optional[int] = None,
    academic_year: Optional[str] = None,
) -> str:
    """
    Generate downloadable CSV reconciliation report string for institutional compliance and AICTE audits.
    """
    summary = get_reconciliation_summary(
        session=session,
        institution_id=institution_id,
        academic_year=academic_year,
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Reconciliation ID",
        "Institution ID",
        "Institution Name",
        "Program ID",
        "Program Name",
        "Academic Year",
        "Allocation Type",
        "Category or Scheme",
        "Approved Capacity",
        "Actual Enrolment",
        "Excess Count",
        "Violation Type",
        "Status",
        "Approval Status",
        "Approval Reference",
        "Affected Students Count",
        "Details",
        "Reconciled At",
    ])

    for r in summary["records"]:
        writer.writerow([
            r["id"],
            r["institution_id"],
            r["institution_name"],
            r["program_id"],
            r["program_name"],
            r["academic_year"],
            r["allocation_type"],
            r["category_or_scheme"],
            r["approved_capacity"],
            r["actual_enrolment"],
            r["excess_count"],
            r["violation_type"],
            r["status"],
            r["approval_status"],
            r["approval_ref"] or "",
            r["affected_student_count"],
            r["details"] or "",
            r["reconciled_at"] or "",
        ])

    return output.getvalue()

