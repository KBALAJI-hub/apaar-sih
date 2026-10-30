"""
Centralized Authorization, Policy Enforcement, and Sanitized View Models for APAAR Verify.
Combines Role-Based Access Control (RBAC) and Attribute-Based Access Control (ABAC).
Enforces:
- No anonymous access to student certificates, records, or verification outcomes.
- Strict ownership checks for students (bound to session apaar_id).
- Institutional scoping for institutions (matching institution_id).
- Statutory regulatory oversight for AICTE_ADMIN with mandatory purpose audit.
- Least-privilege verification-only workflow for employers/verifiers (tier-filtered, 403 on certificates).
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from app.models import Institution, Program, Student, User


class VerificationPurpose(str, Enum):
    """Permitted verification purposes for third-party verifiers (SIH PS 26263)."""
    EMPLOYMENT_VERIFICATION = "EMPLOYMENT_VERIFICATION"
    EDUCATION_ADMISSION = "EDUCATION_ADMISSION"
    REGULATORY_AUDIT = "REGULATORY_AUDIT"
    BACKGROUND_CHECK = "BACKGROUND_CHECK"


VALID_PURPOSES: Set[str] = {p.value for p in VerificationPurpose}


# ---------------------------------------------------------------------------
# Sanitized View Models (Guarantees zero leakage of raw ORM models)
# ---------------------------------------------------------------------------

class CertificateView(BaseModel):
    """Sanitized model for printable certificate rendering (STUDENT, INSTITUTION, AICTE_ADMIN)."""
    student_pk: int
    full_name: str
    student_id: str  # Institutional roll number
    apaar_id: str    # 12-digit APAAR ID (required on official certificate)
    admission_year: int
    institution_name: str
    institution_state: str
    institution_aicte_id: str
    program_name: str
    signature: str
    signature_snippet: str
    verify_url: str
    qr_src: str


class VerificationView(BaseModel):
    """Sanitized tiered verification model for authorized verifiers and stakeholders."""
    tier: int  # -1 (Not Found), 0 (Authentic, details withheld), 1 (Directory), 2 (Full)
    result_status: str  # VALID, NO_CONSENT, NOT_FOUND, TAMPERED
    is_authentic: bool
    failure_message: Optional[str] = None

    # Tier 1 & 2 fields (None for Tier 0 or Not Found)
    institution_name: Optional[str] = None
    institution_aicte_id: Optional[str] = None
    program_name: Optional[str] = None
    admission_year: Optional[int] = None
    status: Optional[str] = None

    # Tier 2 fields only (None for Tier 0, Tier 1, or Not Found)
    full_name: Optional[str] = None
    student_id: Optional[str] = None  # Roll ID
    dob: Optional[str] = None
    gender: Optional[str] = None
    category: Optional[str] = None
    nationality: Optional[str] = None
    admission_type: Optional[str] = None
    record_signature: Optional[str] = None
    record_signature_snippet: Optional[str] = None
    qr_url: Optional[str] = None


# ---------------------------------------------------------------------------
# Core Policy & ABAC Functions
# ---------------------------------------------------------------------------

def get_effective_consent_tier(student_or_level: Any) -> int:
    """
    Safely resolves consent tier:
    - 0: Valid/authentic cryptographic status only; details withheld.
    - 1: Directory details (institution, program, year, status); personal details withheld.
    - 2: Full details explicitly authorized by student.
    Any None, missing, invalid, or out-of-range value strictly resolves to Tier 0.
    """
    if student_or_level is None:
        return 0
    if isinstance(student_or_level, Student):
        raw_level = student_or_level.consent_level
    else:
        raw_level = student_or_level

    try:
        tier_int = int(raw_level)
    except (ValueError, TypeError):
        return 0

    if tier_int in (1, 2):
        return tier_int
    return 0


def can_view_certificate(
    user: Optional[User],
    student: Optional[Student],
) -> Tuple[bool, str, int]:
    """
    Evaluates whether the user is authorized to view or print the student's certificate.
    Returns: (is_allowed, reason_code, suggested_status_code)

    Policy:
    - Anonymous: Denied (AUTH_REQUIRED, 401 / 303 redirect)
    - VERIFIER (Employer): Forbidden from certificates (FORBIDDEN_ROLE, 403)
    - STUDENT: Permitted ONLY for their own record bound to session apaar_id.
               Different student returns uniform NOT_FOUND (404) to avoid enumeration.
    - INSTITUTION: Permitted ONLY if student belongs to user.institution_id.
                   Different institution returns uniform NOT_FOUND (404).
    - AICTE_ADMIN: Permitted under statutory regulatory oversight (ALLOWED, 200).
    """
    if not user:
        return False, "AUTH_REQUIRED", 401

    if user.role == "VERIFIER":
        return False, "FORBIDDEN_ROLE", 403

    if not student:
        return False, "NOT_FOUND", 404

    if user.role == "STUDENT":
        if user.apaar_id and student.apaar_id == user.apaar_id:
            return True, "STUDENT_OWN_RECORD", 200
        return False, "NOT_FOUND", 404

    if user.role == "INSTITUTION":
        if user.institution_id and student.institution_id == user.institution_id:
            return True, "INSTITUTION_OWN_STUDENT", 200
        return False, "NOT_FOUND", 404

    if user.role == "AICTE_ADMIN":
        return True, "AICTE_REGULATORY_OVERSIGHT", 200

    return False, "FORBIDDEN", 403


def can_verify_student(
    user: Optional[User],
    student: Optional[Student],
    purpose: Optional[str],
) -> Tuple[bool, str, int, int]:
    """
    Evaluates whether the user is authorized to verify a student record and computes the permitted disclosure tier.
    Returns: (is_allowed, reason_code, http_status_code, effective_tier)

    Policy:
    - Anonymous: Denied (AUTH_REQUIRED, 401 / 303 redirect, tier 0)
    - VERIFIER: Requires valid purpose. Permitted disclosure is strictly bounded by student's consent tier.
    - STUDENT: Allowed to verify own record at Tier 2. Other student -> 404.
    - INSTITUTION: Allowed to verify own student at Tier 2. Other institution -> 404.
    - AICTE_ADMIN: Allowed under regulatory oversight at Tier 2.
    """
    if not user:
        return False, "AUTH_REQUIRED", 401, 0

    if not student:
        return True, "NOT_FOUND", 200, -1

    # 1. Student self-verification
    if user.role == "STUDENT":
        if user.apaar_id and student.apaar_id == user.apaar_id:
            return True, "STUDENT_OWN_RECORD", 200, 2
        return False, "NOT_FOUND", 404, 0

    # 2. Institution verification
    if user.role == "INSTITUTION":
        if user.institution_id and student.institution_id == user.institution_id:
            return True, "INSTITUTION_OWN_STUDENT", 200, 2
        return False, "NOT_FOUND", 404, 0

    # 3. AICTE Administrator
    if user.role == "AICTE_ADMIN":
        return True, "AICTE_REGULATORY_OVERSIGHT", 200, 2

    # 4. Third-Party Verifier / Employer
    if user.role == "VERIFIER":
        clean_purpose = str(purpose or "").strip()
        if not clean_purpose or clean_purpose not in VALID_PURPOSES:
            return False, "PURPOSE_REQUIRED", 400, 0

        tier = get_effective_consent_tier(student.consent_level)
        return True, "VERIFIER_ALLOWED", 200, tier

    return False, "FORBIDDEN", 403, 0


# ---------------------------------------------------------------------------
# View Model Builders
# ---------------------------------------------------------------------------

def build_certificate_view(
    student: Student,
    institution: Institution,
    program: Program,
    verify_url: str,
    qr_src: str,
    signature: Optional[str] = None,
) -> CertificateView:
    """Build sanitized CertificateView ensuring only allowed certificate fields are populated."""
    sig = signature or student.record_signature or ""
    sig_snippet = (sig[:48] + "...") if len(sig) > 48 else sig

    return CertificateView(
        student_pk=student.id or 0,
        full_name=student.full_name,
        student_id=student.student_id,
        apaar_id=student.apaar_id,
        admission_year=student.admission_year,
        institution_name=institution.name,
        institution_state=institution.state,
        institution_aicte_id=institution.aicte_id,
        program_name=program.name,
        signature=sig,
        signature_snippet=sig_snippet,
        verify_url=verify_url,
        qr_src=qr_src,
    )


def build_verification_view(
    student: Optional[Student],
    institution: Optional[Institution],
    program: Optional[Program],
    tier: int,
    is_authentic: bool,
    result_status: str,
    failure_message: Optional[str] = None,
    base_url: str = "",
) -> VerificationView:
    """Build sanitized VerificationView strictly adhering to the computed disclosure tier."""
    if not student or tier == -1:
        return VerificationView(
            tier=-1,
            result_status="NOT_FOUND",
            is_authentic=False,
            failure_message=failure_message or "No matching student record found.",
        )

    if not is_authentic:
        return VerificationView(
            tier=0,
            result_status="TAMPERED",
            is_authentic=False,
            failure_message=failure_message or "Cryptographic signature validation failed.",
        )

    if tier == 0:
        return VerificationView(
            tier=0,
            result_status=result_status or "NO_CONSENT",
            is_authentic=True,
            failure_message=None,
        )

    # Tier 1: Directory fields only
    inst_name = institution.name if institution else None
    inst_aic = institution.aicte_id if institution else None
    prog_name = program.name if program else None

    if tier == 1:
        return VerificationView(
            tier=1,
            result_status=result_status or "VALID",
            is_authentic=True,
            institution_name=inst_name,
            institution_aicte_id=inst_aic,
            program_name=prog_name,
            admission_year=student.admission_year,
            status=student.status,
        )

    # Tier 2: Full permissible verification fields
    sig = student.record_signature or ""
    sig_snippet = (sig[:16] + "...") if len(sig) > 16 else sig
    qr_url = f"{base_url.rstrip('/')}/verify/record/{student.student_id}/qr" if base_url else None

    return VerificationView(
        tier=2,
        result_status=result_status or "VALID",
        is_authentic=True,
        institution_name=inst_name,
        institution_aicte_id=inst_aic,
        program_name=prog_name,
        admission_year=student.admission_year,
        status=student.status,
        full_name=student.full_name,
        student_id=student.student_id,
        dob=student.dob,
        gender=student.gender,
        category=student.category,
        nationality=student.nationality,
        admission_type=student.admission_type,
        record_signature=sig,
        record_signature_snippet=sig_snippet,
        qr_url=qr_url,
    )

