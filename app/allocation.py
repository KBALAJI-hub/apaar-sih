"""
Regulatory Seat Allocation Engine (Phase 3).
SIH PS 26263 - APAAR Verify

Provides an extensible, approval-backed regulatory seat allocation data model:
1. Sanctioned Intake:
   - Primary approved base intake.
   - Reserved-category sub-allocations (SC, ST, OBC, EWS, GENERAL) within sanctioned intake.
2. Admission Schemes:
   - Specific scheme allocations within or supernumerary to intake (NRI, OCI, FN, TFW, PMSSS, KM).
   - NRI, OCI, SC, ST, OBC are NOT automatically supernumerary unless an explicit regulatory authorization exists.
3. Supernumerary Allocations:
   - Separately authorized additional seats over and above intake.
   - Strictly require verified authorization (DRAFT, EXPIRED, REVOKED, REJECTED are blocked).
4. Academic-Year-Specific:
   - Allocations belong to a specific academic year and program.
5. Overlap Prevention:
   - Contradictory or overlapping active approvals for the same program, year, and scheme are rejected.
6. Reservation Integrity:
   - Sum of within-intake reservations must not exceed sanctioned intake without explicit regulatory variance.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Set
from sqlmodel import Session, select, func

from app.models import Program, Student, SeatAllocation, utc_now
from app.validation import parse_academic_year


def validate_allocation_approval(
    session: Session,
    allocation: SeatAllocation,
    current_sanctioned_intake: Optional[int] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Validate a SeatAllocation record before saving or activating.
    Enforces regulatory integrity:
    1. Seat count must be non-negative.
    2. Verified status requires explicit issuing authority, approval reference, and validity check.
    3. Supernumerary allocations strictly require verified authorization details.
    4. Within-intake reservations must not sum to more than the sanctioned intake.
    5. Overlapping or contradictory active verified approvals for the same scheme are prevented.
    """
    if allocation.approved_seats < 0:
        return False, "Approved seats cannot be negative."

    clean_status = str(allocation.verification_status or "DRAFT").strip().upper()
    clean_type = str(allocation.allocation_type or "SANCTIONED").strip().upper()
    clean_scheme = str(allocation.category_or_scheme or "ALL").strip().upper()

    valid_statuses = {"DRAFT", "VERIFIED", "REJECTED", "EXPIRED", "REVOKED"}
    if clean_status not in valid_statuses:
        return False, f"Invalid verification status '{clean_status}'. Allowed: {', '.join(sorted(valid_statuses))}."

    valid_types = {"SANCTIONED", "WITHIN_INTAKE", "SUPERNUMERARY"}
    if clean_type not in valid_types:
        return False, f"Invalid allocation type '{clean_type}'. Allowed: {', '.join(sorted(valid_types))}."

    # If verification status is VERIFIED, validate approval evidence
    if clean_status == "VERIFIED":
        if not allocation.approval_ref or not str(allocation.approval_ref).strip() or "PENDING" in str(allocation.approval_ref).upper():
            return False, "Verified allocation requires a valid official approval reference (e.g. AICTE letter ref)."

        if not allocation.issuing_authority or not str(allocation.issuing_authority).strip():
            return False, "Verified allocation requires an issuing authority (e.g. AICTE, State Government, DTE)."

        # Check validity dates
        now = utc_now()
        if allocation.valid_to:
            val_to = allocation.valid_to if allocation.valid_to.tzinfo else allocation.valid_to.replace(tzinfo=timezone.utc)
            if val_to < now:
                return False, f"Allocation validity expired on {val_to.strftime('%Y-%m-%d')}. Status must be EXPIRED."

        if allocation.valid_from and allocation.valid_to:
            val_from = allocation.valid_from if allocation.valid_from.tzinfo else allocation.valid_from.replace(tzinfo=timezone.utc)
            val_to = allocation.valid_to if allocation.valid_to.tzinfo else allocation.valid_to.replace(tzinfo=timezone.utc)
            if val_from > val_to:
                return False, "valid_from date cannot be after valid_to date."

        # Check for overlapping or contradictory active verified approvals
        query = select(SeatAllocation).where(
            SeatAllocation.program_id == allocation.program_id,
            SeatAllocation.academic_year == allocation.academic_year,
            SeatAllocation.allocation_type == clean_type,
            SeatAllocation.category_or_scheme == clean_scheme,
            SeatAllocation.verification_status == "VERIFIED",
        )
        if allocation.id:
            query = query.where(SeatAllocation.id != allocation.id)

        conflicting = session.exec(query).first()
        if conflicting:
            return False, (
                f"Conflicting active verified approval already exists for {clean_type} scheme '{clean_scheme}' "
                f"in academic year {allocation.academic_year} (Existing Ref: '{conflicting.approval_ref}'). "
                f"Revoke or expire the previous approval before activating a new one."
            )

        # Integrity Check: Within-intake reservations sum must not exceed sanctioned intake
        if clean_type == "WITHIN_INTAKE":
            program = session.get(Program, allocation.program_id)
            sanctioned_limit = current_sanctioned_intake
            if sanctioned_limit is None:
                # Find active SANCTIONED allocation
                sanc_alloc = session.exec(
                    select(SeatAllocation).where(
                        SeatAllocation.program_id == allocation.program_id,
                        SeatAllocation.academic_year == allocation.academic_year,
                        SeatAllocation.allocation_type == "SANCTIONED",
                        SeatAllocation.verification_status == "VERIFIED",
                    )
                ).first()
                if sanc_alloc:
                    sanctioned_limit = sanc_alloc.approved_seats
                elif program:
                    sanctioned_limit = program.approved_intake
                else:
                    sanctioned_limit = 0

            # Sum other existing active within-intake allocations
            other_within = session.exec(
                select(SeatAllocation).where(
                    SeatAllocation.program_id == allocation.program_id,
                    SeatAllocation.academic_year == allocation.academic_year,
                    SeatAllocation.allocation_type == "WITHIN_INTAKE",
                    SeatAllocation.verification_status == "VERIFIED",
                )
            ).all()

            existing_sum = sum(a.approved_seats for a in other_within if a.id != allocation.id)
            total_projected = existing_sum + allocation.approved_seats
            if total_projected > sanctioned_limit:
                return False, (
                    f"Sum of within-intake reserved allocations ({total_projected}) exceeds sanctioned intake "
                    f"({sanctioned_limit}) for academic year {allocation.academic_year} without valid regulatory authorization."
                )

    return True, None


def get_program_allocations(
    session: Session,
    program_id: int,
    academic_year: Optional[str] = None,
) -> List[SeatAllocation]:
    """Retrieve all seat allocations for a program, optionally filtered by academic year."""
    query = select(SeatAllocation).where(SeatAllocation.program_id == program_id)
    if academic_year:
        query = query.where(SeatAllocation.academic_year == academic_year)
    return session.exec(query.order_by(SeatAllocation.id.asc())).all()


def get_active_allocations_summary(
    session: Session,
    program_id: int,
    academic_year: str,
    program: Optional[Program] = None,
) -> Dict[str, Any]:
    """
    Aggregate all active verified regulatory allocations for a program and academic year:
    - Sanctioned intake (approved regular base capacity)
    - Within-intake reservations (SC, ST, OBC, EWS, NRI within intake)
    - Supernumerary authorized quotas (TFW, PMSSS, KM, FN, OCI, etc.)
    Falls back gracefully to legacy Program model if no SeatAllocation records exist.
    """
    prog = program or session.get(Program, program_id)
    allocs = get_program_allocations(session, program_id, academic_year)

    has_allocations = len(allocs) > 0
    now = utc_now()

    sanctioned_alloc: Optional[SeatAllocation] = None
    within_intake_map: Dict[str, SeatAllocation] = {}
    supernumerary_map: Dict[str, SeatAllocation] = {}

    for a in allocs:
        # Check active status & validity
        clean_status = str(a.verification_status or "").strip().upper()
        if clean_status != "VERIFIED":
            continue

        if a.valid_to:
            val_to = a.valid_to if a.valid_to.tzinfo else a.valid_to.replace(tzinfo=timezone.utc)
            if val_to < now:
                continue

        if a.valid_from:
            val_from = a.valid_from if a.valid_from.tzinfo else a.valid_from.replace(tzinfo=timezone.utc)
            if val_from > now:
                continue

        clean_type = str(a.allocation_type or "").strip().upper()
        clean_scheme = str(a.category_or_scheme or "ALL").strip().upper()

        if clean_type == "SANCTIONED":
            sanctioned_alloc = a
        elif clean_type == "WITHIN_INTAKE":
            within_intake_map[clean_scheme] = a
        elif clean_type == "SUPERNUMERARY":
            supernumerary_map[clean_scheme] = a

    # Determine sanctioned intake
    if sanctioned_alloc is not None:
        sanctioned_seats = sanctioned_alloc.approved_seats
        has_explicit_sanctioned = True
    elif prog is not None:
        sanctioned_seats = prog.approved_intake
        has_explicit_sanctioned = False
    else:
        sanctioned_seats = 60
        has_explicit_sanctioned = False

    # Determine supernumerary authorized capacity
    if supernumerary_map:
        total_super_seats = sum(a.approved_seats for a in supernumerary_map.values())
        has_explicit_supernumerary = True
    else:
        total_super_seats = 0
        has_explicit_supernumerary = False

    return {
        "has_allocations": has_allocations,
        "has_explicit_sanctioned": has_explicit_sanctioned,
        "has_explicit_supernumerary": has_explicit_supernumerary,
        "sanctioned_allocation": sanctioned_alloc,
        "sanctioned_seats": sanctioned_seats,
        "within_intake_allocations": within_intake_map,
        "supernumerary_allocations": supernumerary_map,
        "total_supernumerary_authorized": total_super_seats,
        "all_records": allocs,
    }


def migrate_program_to_allocations(
    session: Session,
    program: Program,
    commit: bool = True,
) -> List[SeatAllocation]:
    """
    Legacy-Data Migration Strategy:
    Creates baseline SeatAllocation records for a legacy Program without inventing regulatory approval data:
    1. Base Sanctioned Intake:
       - Created from AICTE master record (Program.approved_intake)
       - Marked as VERIFIED with issuing authority AICTE.
    2. Generic Supernumerary Cap:
       - If Program.supernumerary_cap > 0, created with verification_status='DRAFT'
       - approval_ref='PENDING_REGULATORY_SUBMISSION'
       - Does NOT invent an approval letter; requires institution to provide explicit regulatory evidence.
    """
    created: List[SeatAllocation] = []
    existing = get_program_allocations(session, program.id, program.academic_year)
    existing_types = {(a.allocation_type, a.category_or_scheme) for a in existing}

    # 1. Sanctioned Intake
    if ("SANCTIONED", "ALL") not in existing_types:
        sanc = SeatAllocation(
            program_id=program.id,
            academic_year=program.academic_year,
            allocation_type="SANCTIONED",
            category_or_scheme="ALL",
            approved_seats=program.approved_intake,
            issuing_authority="AICTE",
            approval_ref=f"AICTE-EOA-MIGRATED-PROG-{program.id}",
            approval_date=program.created_at if hasattr(program, "created_at") and program.created_at else utc_now(),
            verification_status="VERIFIED",
            remarks="Migrated from AICTE approved master program intake.",
        )
        session.add(sanc)
        created.append(sanc)

    # 2. Supernumerary Quota (Unverified / Draft - no invented letters)
    prog_cap = program.supernumerary_cap if program.supernumerary_cap is not None else 0.10
    if prog_cap > 0 and ("SUPERNUMERARY", "ALL") not in existing_types:
        permitted_super = int(round(program.approved_intake * prog_cap))
        super_alloc = SeatAllocation(
            program_id=program.id,
            academic_year=program.academic_year,
            allocation_type="SUPERNUMERARY",
            category_or_scheme="ALL",
            approved_seats=permitted_super,
            issuing_authority="AICTE",
            approval_ref="PENDING_REGULATORY_EVIDENCE",
            verification_status="DRAFT",  # Treated as unverified until explicit approval document is uploaded
            remarks="Migrated baseline quota; unverified pending formal regulatory approval letter.",
        )
        session.add(super_alloc)
        created.append(super_alloc)

    if commit and created:
        session.commit()
        for c in created:
            session.refresh(c)

    return created

