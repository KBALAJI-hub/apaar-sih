"""
Secure Regulatory Admission Overrides Service (Phase 4).
Ensures exceptional admissions cannot be authorized using justification text alone.
Every override requires an approval-backed RegulatoryOverride entity verified by AICTE_ADMIN.
"""

from datetime import datetime
from typing import Any, Dict, Optional, Tuple, Union
from fastapi import HTTPException, status
from sqlmodel import Session, select

from app.audit import log_action
from app.models import Program, RegulatoryOverride, Student, User, utc_now

AUTHORIZED_OVERRIDE_CATEGORIES = frozenset({
    "AICTE_APPROVAL_LETTER",
    "COURT_DIRECTIVE",
    "GOVERNMENT_NOMINATION",
    "ADMISSION_RECONCILIATION",
})

OVERRIDE_STATUS_DRAFT = "DRAFT"
OVERRIDE_STATUS_VERIFIED = "VERIFIED"
OVERRIDE_STATUS_REJECTED = "REJECTED"
OVERRIDE_STATUS_EXPIRED = "EXPIRED"
OVERRIDE_STATUS_REVOKED = "REVOKED"


def create_regulatory_override(
    session: Session,
    user: Any,
    program_id: int,
    academic_year: Union[int, str],
    authorization_category: str,
    approval_ref: str,
    issuing_authority: str,
    document_ref: str,
    seat_buffer: int = 1,
    justification: str = "",
    valid_from: Optional[datetime] = None,
    valid_to: Optional[datetime] = None,
    verification_status: Optional[str] = None,
) -> RegulatoryOverride:
    """
    Create a regulatory admission override record.
    - Restricted to INSTITUTION and AICTE_ADMIN roles.
    - INSTITUTION requests always start in DRAFT status.
    - AICTE_ADMIN can create directly in VERIFIED status.
    - Strict validation of allowlisted categories, approval ref, authority, document ref, and min 20 char justification.
    """
    user_role = getattr(user, "role", None) if not isinstance(user, dict) else user.get("role")
    user_id = getattr(user, "id", None) if not isinstance(user, dict) else user.get("id")

    if user_role not in ("AICTE_ADMIN", "INSTITUTION"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: Role '{user_role}' is not authorized to create regulatory overrides.",
        )

    program = session.get(Program, program_id)
    if not program:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Program ID {program_id} not found.",
        )

    # Institution callers cannot create overrides for other institutions
    if user_role == "INSTITUTION":
        inst_id = getattr(user, "institution_id", None) if not isinstance(user, dict) else user.get("institution_id")
        if inst_id is not None and program.institution_id != inst_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Cannot create regulatory overrides for another institution's program.",
            )

    clean_category = str(authorization_category or "").strip().upper()
    if clean_category not in AUTHORIZED_OVERRIDE_CATEGORIES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Invalid authorization category '{clean_category}'. "
                f"Supported categories: {sorted(AUTHORIZED_OVERRIDE_CATEGORIES)}."
            ),
        )

    clean_ref = str(approval_ref or "").strip()
    if not clean_ref:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Approval reference is mandatory for regulatory overrides.",
        )

    clean_authority = str(issuing_authority or "").strip()
    if not clean_authority:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Issuing authority is mandatory for regulatory overrides.",
        )

    clean_doc = str(document_ref or "").strip()
    if not clean_doc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Supporting document reference or verification hash is mandatory for regulatory overrides.",
        )

    clean_just = str(justification or "").strip()
    if len(clean_just) < 20:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Regulatory justification must contain at least 20 characters explaining legal/statutory grounds.",
        )

    if seat_buffer < 1:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Seat buffer must be at least 1 seat.",
        )

    # Determine status and approver
    if user_role == "AICTE_ADMIN":
        target_status = verification_status or OVERRIDE_STATUS_VERIFIED
        approved_by = user_id if target_status == OVERRIDE_STATUS_VERIFIED else None
        approved_time = utc_now() if target_status == OVERRIDE_STATUS_VERIFIED else None
    else:
        # Institutions can only request DRAFT overrides
        target_status = OVERRIDE_STATUS_DRAFT
        approved_by = None
        approved_time = None

    override = RegulatoryOverride(
        institution_id=program.institution_id,
        program_id=program.id,
        academic_year=str(academic_year).strip(),
        authorization_category=clean_category,
        approval_ref=clean_ref,
        issuing_authority=clean_authority,
        document_ref=clean_doc,
        seat_buffer=seat_buffer,
        seats_utilized=0,
        valid_from=valid_from,
        valid_to=valid_to,
        verification_status=target_status,
        justification=clean_just,
        created_by_user_id=user_id,
        approved_by_user_id=approved_by,
        approved_at=approved_time,
        created_at=utc_now(),
        updated_at=utc_now(),
    )
    session.add(override)
    session.commit()
    session.refresh(override)

    log_action(
        session=session,
        user=user,
        action="CREATE_OVERRIDE",
        entity="REGULATORY_OVERRIDE",
        entity_id=str(override.id),
        details={
            "override_id": override.id,
            "program_id": program.id,
            "institution_id": program.institution_id,
            "academic_year": override.academic_year,
            "category": override.authorization_category,
            "approval_ref": override.approval_ref,
            "issuing_authority": override.issuing_authority,
            "seat_buffer": override.seat_buffer,
            "status": override.verification_status,
        },
    )

    return override


def approve_regulatory_override(
    session: Session,
    user: Any,
    override_id: int,
) -> RegulatoryOverride:
    """
    Approve/verify a regulatory override.
    STRICTLY RESTRICTED TO AICTE_ADMIN. Institutions cannot approve their own overrides.
    """
    user_role = getattr(user, "role", None) if not isinstance(user, dict) else user.get("role")
    user_id = getattr(user, "id", None) if not isinstance(user, dict) else user.get("id")

    if user_role != "AICTE_ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: requires role in ('AICTE_ADMIN',), got '{user_role}'",
        )

    override = session.get(RegulatoryOverride, override_id)
    if not override:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Regulatory override #{override_id} not found.",
        )

    if override.verification_status == OVERRIDE_STATUS_REVOKED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot approve REVOKED override #{override_id}.",
        )

    if override.verification_status == OVERRIDE_STATUS_EXPIRED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot approve EXPIRED override #{override_id}.",
        )

    override.verification_status = OVERRIDE_STATUS_VERIFIED
    override.approved_by_user_id = user_id
    override.approved_at = utc_now()
    override.rejection_reason = None
    override.updated_at = utc_now()

    session.add(override)
    session.commit()
    session.refresh(override)

    log_action(
        session=session,
        user=user,
        action="APPROVE_OVERRIDE",
        entity="REGULATORY_OVERRIDE",
        entity_id=str(override.id),
        details={
            "override_id": override.id,
            "approved_by_user_id": user_id,
            "approval_ref": override.approval_ref,
            "seat_buffer": override.seat_buffer,
            "program_id": override.program_id,
        },
    )

    return override


def reject_regulatory_override(
    session: Session,
    user: Any,
    override_id: int,
    reason: Optional[str] = None,
) -> RegulatoryOverride:
    """Reject a regulatory override (AICTE_ADMIN only)."""
    user_role = getattr(user, "role", None) if not isinstance(user, dict) else user.get("role")
    user_id = getattr(user, "id", None) if not isinstance(user, dict) else user.get("id")

    if user_role != "AICTE_ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: requires role in ('AICTE_ADMIN',), got '{user_role}'",
        )

    override = session.get(RegulatoryOverride, override_id)
    if not override:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Regulatory override #{override_id} not found.",
        )

    override.verification_status = OVERRIDE_STATUS_REJECTED
    override.rejection_reason = reason or "Rejected by AICTE regulatory authority."
    override.updated_at = utc_now()

    session.add(override)
    session.commit()
    session.refresh(override)

    log_action(
        session=session,
        user=user,
        action="REJECT_OVERRIDE",
        entity="REGULATORY_OVERRIDE",
        entity_id=str(override.id),
        details={"override_id": override.id, "reason": override.rejection_reason},
    )

    return override


def revoke_regulatory_override(
    session: Session,
    user: Any,
    override_id: int,
    reason: Optional[str] = None,
) -> RegulatoryOverride:
    """Revoke an existing regulatory override (AICTE_ADMIN only)."""
    user_role = getattr(user, "role", None) if not isinstance(user, dict) else user.get("role")
    user_id = getattr(user, "id", None) if not isinstance(user, dict) else user.get("id")

    if user_role != "AICTE_ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: requires role in ('AICTE_ADMIN',), got '{user_role}'",
        )

    override = session.get(RegulatoryOverride, override_id)
    if not override:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Regulatory override #{override_id} not found.",
        )

    override.verification_status = OVERRIDE_STATUS_REVOKED
    override.rejection_reason = reason or "Revoked by AICTE regulatory authority."
    override.updated_at = utc_now()

    session.add(override)
    session.commit()
    session.refresh(override)

    log_action(
        session=session,
        user=user,
        action="REVOKE_OVERRIDE",
        entity="REGULATORY_OVERRIDE",
        entity_id=str(override.id),
        details={"override_id": override.id, "reason": override.rejection_reason},
    )

    return override


def validate_override_request(
    program: Program,
    admission_type: str = "REGULAR",
    justification: Optional[str] = None,
    current_intake_data: Optional[Dict[str, Any]] = None,
    session: Optional[Session] = None,
    override_id: Optional[int] = None,
    override_record: Optional[RegulatoryOverride] = None,
    admission_year: Optional[Union[int, str]] = None,
    caller_user: Optional[Any] = None,
) -> Tuple[bool, Optional[str], Optional[RegulatoryOverride]]:
    """
    Validate authorized, approval-backed regulatory override requests (Phase 4):
    1. Reject justification-length-only authorization (text alone cannot grant seats).
    2. Require an actual RegulatoryOverride record in VERIFIED status.
    3. Verify authorization category is in AUTHORIZED_OVERRIDE_CATEGORIES.
    4. Verify approval reference, issuing authority, and supporting document exist.
    5. Verify applicable institution matches program.institution_id.
    6. Verify applicable program matches program.id.
    7. Verify academic year matches.
    8. Verify validity period (valid_from <= now <= valid_to).
    9. Verify seat buffer capacity (seats_utilized < seat_buffer).
    10. Verify justification is >= 20 characters.
    Returns (is_valid, error_message, override_record).
    """
    from app.validation import parse_academic_year

    clean_just = str(justification or "").strip()
    if clean_just and len(clean_just) < 20:
        return (
            False,
            "Invalid justification: An over-admission override strictly requires a formal regulatory "
            "explanation of at least 20 characters.",
            None,
        )

    # Missing authorization record: justification text alone is strictly rejected
    if override_record is None and override_id is None:
        return (
            False,
            "Missing regulatory authorization record: Exceptional admissions cannot be authorized "
            "using justification text alone. An official regulatory override record ID is required.",
            None,
        )

    # Fetch record if needed
    if override_record is None:
        if session is None:
            return (
                False,
                "Database session required to verify regulatory override record.",
                None,
            )
        override_record = session.get(RegulatoryOverride, override_id)
        if not override_record:
            return (
                False,
                f"Regulatory override record #{override_id} not found.",
                None,
            )

    # 1. Verification Status
    if override_record.verification_status != OVERRIDE_STATUS_VERIFIED:
        if override_record.verification_status == OVERRIDE_STATUS_REVOKED:
            return (
                False,
                f"Regulatory override #{override_record.id} has been REVOKED and cannot authorize admissions.",
                None,
            )
        elif override_record.verification_status == OVERRIDE_STATUS_EXPIRED:
            return (
                False,
                f"Regulatory override #{override_record.id} has EXPIRED.",
                None,
            )
        elif override_record.verification_status == OVERRIDE_STATUS_REJECTED:
            return (
                False,
                f"Regulatory override #{override_record.id} was REJECTED: {override_record.rejection_reason or 'Not approved'}.",
                None,
            )
        elif override_record.verification_status == OVERRIDE_STATUS_DRAFT:
            return (
                False,
                f"Regulatory override #{override_record.id} is in DRAFT status and pending AICTE regulatory verification.",
                None,
            )
        else:
            return (
                False,
                f"Regulatory override #{override_record.id} has invalid status '{override_record.verification_status}'. Must be VERIFIED.",
                None,
            )

    # 2. Allowlisted Category
    if override_record.authorization_category not in AUTHORIZED_OVERRIDE_CATEGORIES:
        return (
            False,
            f"Unsupported authorization category '{override_record.authorization_category}'. "
            f"Must be one of: {sorted(AUTHORIZED_OVERRIDE_CATEGORIES)}.",
            None,
        )

    # 3. Approval Reference, Issuing Authority, and Supporting Document
    if not override_record.approval_ref or not str(override_record.approval_ref).strip():
        return (False, "Regulatory override lacks valid approval reference.", None)
    if not override_record.issuing_authority or not str(override_record.issuing_authority).strip():
        return (False, "Regulatory override lacks valid issuing authority.", None)
    if not override_record.document_ref or not str(override_record.document_ref).strip():
        return (False, "Regulatory override lacks supporting document reference / verification hash.", None)

    # 4. Applicable Institution
    if override_record.institution_id != program.institution_id:
        return (
            False,
            f"Institution mismatch: Regulatory override belongs to institution ID {override_record.institution_id}, "
            f"but program belongs to institution ID {program.institution_id}.",
            None,
        )

    # 5. Applicable Program
    if override_record.program_id != program.id:
        return (
            False,
            f"Program mismatch: Regulatory override applies to program ID {override_record.program_id}, "
            f"not {program.id}.",
            None,
        )

    # 6. Applicable Academic Year
    if admission_year is not None:
        try:
            override_year_int = parse_academic_year(override_record.academic_year)
            adm_year_int = parse_academic_year(admission_year)
            if override_year_int != adm_year_int:
                return (
                    False,
                    f"Academic year mismatch: Regulatory override is valid for academic year '{override_record.academic_year}', "
                    f"but admission is for academic year '{admission_year}'.",
                    None,
                )
        except Exception:
            if str(override_record.academic_year).strip() != str(admission_year).strip():
                return (
                    False,
                    f"Academic year mismatch: Regulatory override is valid for '{override_record.academic_year}', "
                    f"not '{admission_year}'.",
                    None,
                )

    # 7. Validity Period
    now = utc_now()
    if override_record.valid_from and now < override_record.valid_from:
        return (
            False,
            f"Regulatory override #{override_record.id} is not yet effective (effective from {override_record.valid_from.isoformat()}).",
            None,
        )
    if override_record.valid_to and now > override_record.valid_to:
        return (
            False,
            f"Regulatory override #{override_record.id} has expired (expired at {override_record.valid_to.isoformat()}).",
            None,
        )

    # 8. Seat Buffer Capacity
    if override_record.seats_utilized >= override_record.seat_buffer:
        return (
            False,
            f"Regulatory override #{override_record.id} capacity exhausted "
            f"({override_record.seats_utilized}/{override_record.seat_buffer} authorized seats already utilized).",
            None,
        )

    # 9. Justification check on override entity
    if not override_record.justification or len(override_record.justification.strip()) < 20:
        return (
            False,
            "Regulatory override record lacks sufficient formal justification (minimum 20 characters required).",
            None,
        )

    # 10. Caller check: if an institution user is attempting to use another institution's override
    if caller_user:
        caller_inst_id = getattr(caller_user, "institution_id", None) if not isinstance(caller_user, dict) else caller_user.get("institution_id")
        if caller_inst_id is not None and caller_inst_id != override_record.institution_id:
            return (
                False,
                f"Unauthorized user: Caller institution ID {caller_inst_id} cannot access override #{override_record.id}.",
                None,
            )

    return True, None, override_record

