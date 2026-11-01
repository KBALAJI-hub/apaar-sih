"""
SQLModel database tables for APAAR Verify.
Authoritative schema for Supabase PostgreSQL.
"""

from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import Index
from sqlmodel import Field, SQLModel


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class User(SQLModel, table=True):
    """System users with role-based access control."""
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    password_hash: str
    role: str = Field(index=True)  # AICTE_ADMIN, INSTITUTION, VERIFIER, STUDENT
    institution_id: Optional[int] = Field(default=None, foreign_key="institution.id")
    apaar_id: Optional[str] = Field(default=None, index=True)  # Students only
    full_name: str
    created_at: datetime = Field(default_factory=utc_now)


class Institution(SQLModel, table=True):
    """Educational institutions affiliated with AICTE."""
    __table_args__ = (
        Index("ix_institution_state_name", "state", "name"),
    )
    id: Optional[int] = Field(default=None, primary_key=True)
    aicte_id: str = Field(index=True, unique=True)
    name: str
    state: str
    type: str  # Engineering, PGDM, Pharmacy, Management, Polytechnic
    api_key: str = Field(index=True, unique=True)
    created_at: datetime = Field(default_factory=utc_now)


class Program(SQLModel, table=True):
    """Academic programs offered by institutions with intake quotas."""
    id: Optional[int] = Field(default=None, primary_key=True)
    institution_id: int = Field(foreign_key="institution.id", index=True)
    name: str
    level: str  # UG, PG, Diploma
    academic_year: str  # e.g. "2024-25"
    approved_intake: int = Field(default=60)
    supernumerary_cap: float = Field(default=0.10)  # 10% supernumerary quota
    course: Optional[str] = Field(default=None)
    programme: Optional[str] = Field(default=None)
    course_type: Optional[str] = Field(default=None)
    shift: Optional[str] = Field(default=None)
    availability: Optional[str] = Field(default=None)


class SeatAllocation(SQLModel, table=True):
    """
    Extensible, approval-backed regulatory seat allocation entity (Phase 3).
    Differentiates:
    - Sanctioned intake (SANCTIONED: base approved capacity)
    - Reserved-category & scheme sub-allocations within sanctioned intake (WITHIN_INTAKE: SC, ST, OBC, EWS, NRI)
    - Authorized supernumerary allocations over and above intake (SUPERNUMERARY: TFW, PMSSS, KM, FN, OCI)
    """
    __table_args__ = (
        Index("ix_seatalloc_prog_year_type", "program_id", "academic_year", "allocation_type", "category_or_scheme"),
        Index("ix_seatalloc_status", "verification_status"),
    )
    id: Optional[int] = Field(default=None, primary_key=True)
    program_id: int = Field(foreign_key="program.id", index=True)
    academic_year: str = Field(index=True)  # e.g. "2024-25"
    allocation_type: str = Field(index=True)  # SANCTIONED, WITHIN_INTAKE, SUPERNUMERARY
    category_or_scheme: str = Field(default="ALL", index=True)  # GENERAL, OBC, SC, ST, EWS, NRI, OCI, FN, TFW, PMSSS, KM, etc.
    approved_seats: int = Field(default=0, ge=0)
    issuing_authority: str = Field(default="AICTE")  # AICTE, State Government, DTE, University
    approval_ref: str = Field(index=True)  # Official letter / gazette notification ref
    approval_doc_ref: Optional[str] = Field(default=None)  # Document URI / PDF URL / verification hash
    approval_date: Optional[datetime] = Field(default=None)
    valid_from: Optional[datetime] = Field(default=None)
    valid_to: Optional[datetime] = Field(default=None)
    verification_status: str = Field(default="DRAFT", index=True)  # DRAFT, VERIFIED, REJECTED, EXPIRED, REVOKED
    rejection_reason: Optional[str] = Field(default=None)
    remarks: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class RegulatoryOverride(SQLModel, table=True):
    """
    Approval-backed regulatory admission override entity (Phase 4).
    Ensures that exceptional admissions exceeding sanctioned or quota capacity cannot be authorized
    by justification text alone, but strictly require a verified, auditable regulatory approval record
    issued by an authorized authority (e.g. AICTE Approval Letter, Court Directive, Government Nomination, Admission Reconciliation).
    """
    __table_args__ = (
        Index("ix_override_inst_prog_year", "institution_id", "program_id", "academic_year"),
        Index("ix_override_status", "verification_status"),
        Index("ix_override_approval_ref", "approval_ref"),
    )
    id: Optional[int] = Field(default=None, primary_key=True)
    institution_id: int = Field(foreign_key="institution.id", index=True)
    program_id: int = Field(foreign_key="program.id", index=True)
    academic_year: str = Field(index=True)  # e.g. "2024-25" or "2024"
    authorization_category: str = Field(index=True)  # AICTE_APPROVAL_LETTER, COURT_DIRECTIVE, GOVERNMENT_NOMINATION, ADMISSION_RECONCILIATION
    approval_ref: str = Field(index=True)  # Official order / letter / case ref
    issuing_authority: str  # e.g. "AICTE Executive Committee", "Supreme Court of India", "Ministry of Education"
    document_ref: Optional[str] = Field(default=None)  # Document URI / PDF URL / SHA256 verification hash
    seat_buffer: int = Field(default=1, ge=1)  # Specific number of exceptional seats authorized by this order
    seats_utilized: int = Field(default=0, ge=0)  # Number of students enrolled under this override
    valid_from: Optional[datetime] = Field(default=None)
    valid_to: Optional[datetime] = Field(default=None)
    verification_status: str = Field(default="DRAFT", index=True)  # DRAFT, VERIFIED, REJECTED, EXPIRED, REVOKED
    rejection_reason: Optional[str] = Field(default=None)
    justification: str  # Formal regulatory justification (min 20 characters)
    created_by_user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    approved_by_user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    approved_at: Optional[datetime] = Field(default=None)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class HistoricalReconciliation(SQLModel, table=True):
    """
    Historical Seat Allocation Reconciliation Entity (Phase 6).
    Records periodic and on-demand reconciliation of historical student enrolments
    against regulatory seat allocations, sanctioned intakes, and supernumerary caps.
    Identifies excess enrolments, missing approvals, and academic-year anomalies
    without modifying or deleting legitimate student records.
    """
    __table_args__ = (
        Index("ix_reconcil_prog_year_alloc_scheme", "program_id", "academic_year", "allocation_type", "category_or_scheme"),
        Index("ix_reconcil_inst_year", "institution_id", "academic_year"),
        Index("ix_reconcil_status", "status"),
        Index("ix_reconcil_violation_type", "violation_type"),
    )
    id: Optional[int] = Field(default=None, primary_key=True)
    institution_id: int = Field(foreign_key="institution.id", index=True)
    program_id: int = Field(foreign_key="program.id", index=True)
    academic_year: str = Field(index=True)  # e.g. "2024-25" or "2024"
    allocation_type: str = Field(index=True)  # SANCTIONED, SUPERNUMERARY, SCHEME_SPECIFIC, OVERALL, UNCLASSIFIED, MISMATCH
    category_or_scheme: str = Field(default="ALL", index=True)  # GENERAL, SC, ST, OBC, EWS, NRI, OCI, FN, etc.
    approved_capacity: int = Field(default=0)
    actual_enrolment: int = Field(default=0)
    excess_count: int = Field(default=0)  # max(0, actual_enrolment - approved_capacity)
    violation_type: Optional[str] = Field(default=None, index=True)
    # REGULAR_INTAKE_VIOLATION, SUPERNUMERARY_VIOLATION, SCHEME_SPECIFIC_VIOLATION,
    # MISSING_OR_UNVERIFIED_APPROVAL, ACADEMIC_YEAR_MISMATCH, UNCLASSIFIED_ADMISSION, NONE
    status: str = Field(default="COMPLIANT", index=True)  # COMPLIANT, VIOLATION, REVIEW_REQUIRED
    approval_status: str = Field(default="VERIFIED", index=True)  # VERIFIED, UNVERIFIED, MISSING, EXPIRED, REVOKED, PROGRAM_BASELINE
    approval_ref: Optional[str] = Field(default=None)
    details: Optional[str] = Field(default=None)  # Human-readable breakdown of the finding
    affected_student_count: int = Field(default=0)
    affected_student_ids: Optional[str] = Field(default=None)  # JSON-encoded array or comma-separated list
    reconciled_at: datetime = Field(default_factory=utc_now)
    reconciled_by_user_id: Optional[int] = Field(default=None, foreign_key="user.id")


class ApaarRegistry(SQLModel, table=True):
    """Mock central APAAR/DigiLocker registry for verification and match checks."""
    id: Optional[int] = Field(default=None, primary_key=True)
    apaar_id: str = Field(index=True, unique=True)  # Exactly 12 numeric digits
    full_name: str
    dob: str  # YYYY-MM-DD
    gender: str  # M, F, Other


class Student(SQLModel, table=True):
    """Enrolled student records within an institution."""
    __table_args__ = (
        Index("ix_student_inst_status", "institution_id", "status"),
        Index("ix_student_prog_status_type", "program_id", "status", "admission_type"),
        Index("ix_student_prog_status_year_type", "program_id", "status", "admission_year", "admission_type"),
    )
    id: Optional[int] = Field(default=None, primary_key=True)
    apaar_id: str = Field(index=True)
    institution_id: int = Field(foreign_key="institution.id", index=True)
    program_id: int = Field(foreign_key="program.id", index=True)
    student_id: str  # Institute roll number / enrollment ID
    full_name: str
    dob: str  # YYYY-MM-DD
    gender: str
    category: str = Field(default="GENERAL")
    admission_type: str = Field(default="REGULAR")  # REGULAR / SUPERNUMERARY
    is_nri: bool = Field(default=False)
    oci_status: bool = Field(default=False)
    is_foreign_national: bool = Field(default=False)
    nationality: str = Field(default="Indian")
    admission_year: int = Field(default=2024)
    mode: str = Field(default="FULL_TIME")  # FULL_TIME / PART_TIME
    status: str = Field(default="ACTIVE")  # ACTIVE / WITHDRAWN / GRADUATED
    consent_given: bool = Field(default=False)
    consent_level: Optional[int] = Field(default=1, nullable=True)  # 0: None, 1: Basic, 2: Full
    consent_timestamp: Optional[datetime] = Field(default=None)
    allocation_id: Optional[int] = Field(default=None, foreign_key="seatallocation.id", nullable=True)
    override_id: Optional[int] = Field(default=None, foreign_key="regulatoryoverride.id", nullable=True)
    record_signature: Optional[str] = Field(default=None)  # Ed25519 tamper-evident signature
    record_hash: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)



class ValidationFlag(SQLModel, table=True):
    """Flags generated by the validation engine (R1 to R12)."""
    __table_args__ = (
        Index("ix_validationflag_inst_status", "institution_id", "status"),
    )
    id: Optional[int] = Field(default=None, primary_key=True)
    institution_id: int = Field(foreign_key="institution.id", index=True)
    program_id: Optional[int] = Field(default=None, foreign_key="program.id")
    student_id: Optional[int] = Field(default=None, foreign_key="student.id")
    rule_code: str = Field(index=True)  # R1..R12
    severity: str  # HIGH, MEDIUM, LOW
    message: str
    recommended_action: str
    status: str = Field(default="OPEN")  # OPEN / RESOLVED
    created_at: datetime = Field(default_factory=utc_now)


class AnomalyAlert(SQLModel, table=True):
    """Alerts generated by statistical anomaly detection (A1 to A5)."""
    id: Optional[int] = Field(default=None, primary_key=True)
    institution_id: int = Field(foreign_key="institution.id", index=True)
    code: str = Field(index=True)  # A1..A5
    score: float
    reason: str
    created_at: datetime = Field(default_factory=utc_now)


class AuditLog(SQLModel, table=True):
    """Hash-chained immutable audit log for tamper evidence."""
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(default=None)
    username: str
    action: str  # LOGIN, LOGOUT, CSV_UPLOAD, STUDENT_ADD, etc.
    entity: str  # STUDENT, INSTITUTION, etc.
    entity_id: Optional[str] = Field(default=None)
    details: Optional[str] = Field(default=None)
    timestamp: datetime = Field(default_factory=utc_now)
    prev_hash: str  # Hash of previous row or 'GENESIS'
    row_hash: str  # SHA256 of prev_hash + canonical fields


class VerificationLog(SQLModel, table=True):
    """Third-party verification audit trail."""
    id: Optional[int] = Field(default=None, primary_key=True)
    verifier_id: Optional[int] = Field(default=None, foreign_key="user.id")
    apaar_id: str = Field(index=True)
    tier_shown: int  # 0, 1, or 2
    result: str  # VALID, INVALID, TAMPERED
    timestamp: datetime = Field(default_factory=utc_now)


class Setting(SQLModel, table=True):
    """Configurable system settings and threshold parameters."""
    id: Optional[int] = Field(default=None, primary_key=True)
    key: str = Field(index=True, unique=True)
    value: str
