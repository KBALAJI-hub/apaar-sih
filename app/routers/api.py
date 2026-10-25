"""
External Integration API Router for APAAR Verify (SIH PS 26263).
Provides REST endpoints for SIS/ERP bulk uploads, student updates, and live intake checks.
Secured via X-API-Key header matched to Institution.api_key.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Security, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field
from sqlmodel import Session, select

from app.audit import log_action
from app.database import get_session
from app.models import Institution, Program, Student, ValidationFlag, utc_now
from app.security import sign_record
from app.validation import (
    build_validation_context,
    intake_check,
    validate_program_intake,
    validate_student_row,
)

router = APIRouter(prefix="/api/v1", tags=["External Integration API"])

# Security Scheme for Swagger UI & Header Extraction
api_key_header = APIKeyHeader(
    name="X-API-Key",
    description="Institution secret API key (e.g. 'api-key-inst1-secret')",
    auto_error=False,
)


def get_institution_by_api_key(
    api_key: Optional[str] = Security(api_key_header),
    session: Session = Depends(get_session),
) -> Institution:
    """Validate X-API-Key header and resolve to authenticated Institution."""
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header in request",
        )
    institution = session.exec(
        select(Institution).where(Institution.api_key == api_key)
    ).first()
    if not institution:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or unauthorized X-API-Key",
        )
    return institution


# ---------------------------------------------------------------------------
# Pydantic Schemas with OpenAPI Examples
# ---------------------------------------------------------------------------

class StudentBulkItem(BaseModel):
    """Schema for individual student in a bulk JSON upload batch."""
    apaar_id: str = Field(..., description="12-digit numeric APAAR ID", examples=["100000000001"])
    student_id: str = Field(..., description="Institution roll number / enrollment ID", examples=["DTI-2024-001"])
    full_name: str = Field(..., description="Full student name as per APAAR registry", examples=["Aarav Sharma"])
    dob: str = Field(..., description="Date of birth in YYYY-MM-DD format", examples=["2004-05-12"])
    gender: str = Field(default="Other", description="Gender (M, F, Other)", examples=["M"])
    category: str = Field(default="GENERAL", description="Social category (GENERAL, OBC, SC, ST, EWS)", examples=["GENERAL"])
    program_name: Optional[str] = Field(default=None, description="Exact approved program title", examples=["B.Tech Computer Science and Engineering"])
    program_id: Optional[int] = Field(default=None, description="Approved program ID if known", examples=[1])
    admission_year: int = Field(default=2024, description="Academic admission year", examples=[2024])
    admission_type: str = Field(default="REGULAR", description="REGULAR or SUPERNUMERARY", examples=["REGULAR"])
    is_nri: bool = Field(default=False, description="NRI quota flag", examples=[False])
    oci_status: bool = Field(default=False, description="Overseas Citizen of India status", examples=[False])
    is_foreign_national: bool = Field(default=False, description="Foreign national student flag", examples=[False])
    nationality: str = Field(default="Indian", description="Country of citizenship", examples=["Indian"])
    mode: str = Field(default="FULL_TIME", description="Mode of education (FULL_TIME, PART_TIME, ODL)", examples=["FULL_TIME"])
    consent_given: bool = Field(default=True, description="Student DigiLocker verification consent", examples=[True])

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "apaar_id": "100000000001",
                "student_id": "DTI-2024-001",
                "full_name": "Aarav Sharma",
                "dob": "2004-05-12",
                "gender": "M",
                "category": "GENERAL",
                "program_name": "B.Tech Computer Science and Engineering",
                "admission_year": 2024,
                "admission_type": "REGULAR",
                "is_nri": False,
                "oci_status": False,
                "is_foreign_national": False,
                "nationality": "Indian",
                "mode": "FULL_TIME",
                "consent_given": True,
            }
        }
    )


class RowError(BaseModel):
    """Detailed error object for a rejected row in bulk upload."""
    index: int = Field(..., description="Zero-based index of the row in submitted array")
    apaar_id: Optional[str] = Field(None, description="Submitted APAAR ID")
    student_id: Optional[str] = Field(None, description="Submitted student roll ID")
    rule_codes: List[str] = Field(..., description="Violated critical AICTE rules (e.g. R1, R2, R9, R11)")
    errors: List[str] = Field(..., description="Human-readable rejection explanations")


class BulkUploadResponse(BaseModel):
    """Summary outcome of bulk student enrollment batch."""
    total: int = Field(..., description="Total student records evaluated in payload")
    accepted_clean: int = Field(..., description="Successfully enrolled with zero flags")
    accepted_with_warnings: int = Field(..., description="Successfully enrolled with non-blocking review flags")
    rejected: int = Field(..., description="Rejected records not saved to database")
    errors: List[RowError] = Field(default_factory=list, description="List of rejected rows and error reasons")


class StudentUpdateItem(BaseModel):
    """Schema for partial update of an enrolled student record."""
    full_name: Optional[str] = Field(None, description="Updated full name", examples=["Aarav Sharma"])
    dob: Optional[str] = Field(None, description="Updated date of birth (YYYY-MM-DD)", examples=["2004-05-12"])
    gender: Optional[str] = Field(None, description="Gender (M, F, Other)", examples=["M"])
    category: Optional[str] = Field(None, description="Category (GENERAL, OBC, SC, ST, EWS)", examples=["GENERAL"])
    program_id: Optional[int] = Field(None, description="Target program ID", examples=[1])
    admission_year: Optional[int] = Field(None, description="Admission year", examples=[2024])
    admission_type: Optional[str] = Field(None, description="REGULAR or SUPERNUMERARY", examples=["REGULAR"])
    is_nri: Optional[bool] = Field(None, description="NRI status", examples=[False])
    oci_status: Optional[bool] = Field(None, description="OCI card holder status", examples=[False])
    is_foreign_national: Optional[bool] = Field(None, description="Foreign national status", examples=[False])
    nationality: Optional[str] = Field(None, description="Country of citizenship", examples=["Indian"])
    mode: Optional[str] = Field(None, description="Mode of study", examples=["FULL_TIME"])
    status: Optional[str] = Field(None, description="Enrollment status (ACTIVE, INACTIVE, SUSPENDED, GRADUATED)", examples=["ACTIVE"])
    consent_level: Optional[int] = Field(None, ge=0, le=2, description="Consent level (0=None, 1=Basic, 2=Full)", examples=[2])
    override_justification: Optional[str] = Field(None, description="Mandatory justification text if target program is at BLOCK capacity", examples=["Special legal order variance"])

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "full_name": "Aarav Sharma",
                "dob": "2004-05-12",
                "gender": "M",
                "category": "GENERAL",
                "program_id": 1,
                "admission_year": 2024,
                "admission_type": "REGULAR",
                "is_nri": False,
                "nationality": "Indian",
                "status": "ACTIVE",
                "consent_level": 2,
            }
        }
    )


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/students/bulk",
    response_model=BulkUploadResponse,
    summary="Bulk Student JSON Upload",
    description="Bulk upload student enrollment records via JSON array authenticated by X-API-Key header. Executes full AICTE validation (R1-R12), rejects rows flagged R1, R2, R9, or R11, saves compliant students with flags, updates program quotas, and logs hash-chained audit record.",
)
def bulk_student_upload(
    students: List[StudentBulkItem] = Body(
        ...,
        description="Array of student records to validate and enroll",
        openapi_examples={
            "standard_batch": {
                "summary": "Standard Batch Upload Example",
                "description": "Two student records to validate and enroll.",
                "value": [
                    {
                        "apaar_id": "100000000001",
                        "student_id": "DTI-2024-001",
                        "full_name": "Aarav Sharma",
                        "dob": "2004-05-12",
                        "gender": "M",
                        "category": "GENERAL",
                        "program_name": "B.Tech Computer Science and Engineering",
                        "admission_year": 2024,
                        "admission_type": "REGULAR",
                        "is_nri": False,
                        "oci_status": False,
                        "is_foreign_national": False,
                        "nationality": "Indian",
                        "mode": "FULL_TIME",
                        "consent_given": True,
                    },
                    {
                        "apaar_id": "100000000002",
                        "student_id": "DTI-2024-002",
                        "full_name": "Diya Patel",
                        "dob": "2004-08-23",
                        "gender": "F",
                        "category": "OBC",
                        "program_name": "B.Tech Electronics and Communication",
                        "admission_year": 2024,
                        "admission_type": "REGULAR",
                        "is_nri": False,
                        "oci_status": False,
                        "is_foreign_national": False,
                        "nationality": "Indian",
                        "mode": "FULL_TIME",
                        "consent_given": True,
                    },
                ],
            }
        },
    ),
    institution: Institution = Depends(get_institution_by_api_key),
    session: Session = Depends(get_session),
):
    """
    Process JSON bulk student batch:
    - Preloads validation context in one batch (O(1) lookups).
    - Validates each row against R1 to R12 rules.
    - Rejects rows with R1, R2, R9, R11 and compiles per-row errors.
    - Saves accepted rows as Student and ValidationFlag records.
    - Re-evaluates program intake limits.
    - Appends hash-chained audit log entry.
    """
    inst_id = institution.id

    # Preload validation context once
    ctx = build_validation_context(inst_id, session)

    accepted_clean_count = 0
    accepted_warning_count = 0
    rejected_count = 0
    errors: List[RowError] = []
    affected_program_ids = set()

    for idx, item in enumerate(students):
        row_dict = item.model_dump()
        flags = validate_student_row(row_dict, ctx)
        reject_flags = [f for f in flags if f["rule_code"] in ["R1", "R2", "R9", "R11"]]

        if reject_flags:
            rejected_count += 1
            errors.append(
                RowError(
                    index=idx,
                    apaar_id=item.apaar_id,
                    student_id=item.student_id,
                    rule_codes=[f["rule_code"] for f in reject_flags],
                    errors=[f["message"] for f in reject_flags],
                )
            )
        else:
            # Resolve program
            prog_name_key = str(row_dict.get("program_name") or row_dict.get("program_id") or "").strip().lower()
            program = ctx["program_map"].get(prog_name_key)
            prog_id = program.id if program else None

            stu = Student(
                apaar_id=item.apaar_id.strip(),
                institution_id=inst_id,
                program_id=prog_id,
                student_id=item.student_id.strip(),
                full_name=item.full_name.strip(),
                dob=item.dob.strip(),
                gender=item.gender,
                category=item.category,
                admission_type=item.admission_type,
                is_nri=item.is_nri,
                oci_status=item.oci_status,
                is_foreign_national=item.is_foreign_national,
                nationality=item.nationality.strip(),
                admission_year=item.admission_year,
                mode=item.mode,
                status="ACTIVE",
                consent_level=2 if item.consent_given else 0,
                consent_timestamp=utc_now() if item.consent_given else None,
                created_at=utc_now(),
            )
            session.add(stu)
            session.commit()
            session.refresh(stu)

            # Generate Ed25519 digital signature
            stu.record_signature = sign_record(stu, session)
            session.add(stu)
            session.commit()

            if prog_id:
                affected_program_ids.add(prog_id)

            if flags:
                accepted_warning_count += 1
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
            else:
                accepted_clean_count += 1

    # Re-evaluate intake quotas for affected programs
    for pid in affected_program_ids:
        validate_program_intake(pid, session)

    # Hash-chained audit logging
    log_action(
        session=session,
        user=institution,
        action="API_BULK_UPLOAD",
        entity="INSTITUTION",
        entity_id=str(inst_id),
        details=f"API bulk upload: {accepted_clean_count} clean, {accepted_warning_count} with warnings, {rejected_count} rejected",
    )

    return BulkUploadResponse(
        total=len(students),
        accepted_clean=accepted_clean_count,
        accepted_with_warnings=accepted_warning_count,
        rejected=rejected_count,
        errors=errors,
    )


@router.put(
    "/students/{apaar_id}",
    summary="Update Student Record by APAAR ID",
    description="Update profile fields for an enrolled student by their 12-digit APAAR ID. Authenticated via X-API-Key and strictly restricted to the caller institution's own students. Enforces live Intake Guard checks if program is changed.",
)
def update_student_api(
    apaar_id: str = Path(..., description="12-digit numeric APAAR ID of the student to update", examples=["100000000001"]),
    data: StudentUpdateItem = Body(..., description="Fields to update on the student record"),
    institution: Institution = Depends(get_institution_by_api_key),
    session: Session = Depends(get_session),
):
    """Update student record identified by APAAR ID."""
    student = session.exec(
        select(Student).where(
            Student.apaar_id == apaar_id,
            Student.institution_id == institution.id,
        )
    ).first()

    if not student:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Student with APAAR ID {apaar_id} not found in institution {institution.name}",
        )

    old_program_id = student.program_id

    # If changing academic program, verify target program belongs to institution and check intake
    if data.program_id is not None and data.program_id != student.program_id:
        target_prog = session.get(Program, data.program_id)
        if not target_prog or target_prog.institution_id != institution.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Target program ID is invalid or does not belong to this institution.",
            )

        intake = intake_check(data.program_id, session)
        if intake["decision"] == "BLOCK" and not (data.override_justification and data.override_justification.strip()):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Target program intake quota is FULL (BLOCK). An override_justification text is strictly required.",
            )
        student.program_id = data.program_id

    # Update provided fields
    if data.full_name is not None:
        student.full_name = data.full_name.strip()
    if data.dob is not None:
        student.dob = data.dob.strip()
    if data.gender is not None:
        student.gender = data.gender
    if data.category is not None:
        student.category = data.category
    if data.admission_year is not None:
        student.admission_year = data.admission_year
    if data.admission_type is not None:
        student.admission_type = data.admission_type
    if data.is_nri is not None:
        student.is_nri = data.is_nri
    if data.oci_status is not None:
        student.oci_status = data.oci_status
    if data.is_foreign_national is not None:
        student.is_foreign_national = data.is_foreign_national
    if data.nationality is not None:
        student.nationality = data.nationality.strip()
    if data.status is not None:
        student.status = data.status
    if data.consent_level is not None:
        student.consent_level = data.consent_level
        if data.consent_level > 0 and not student.consent_timestamp:
            student.consent_timestamp = utc_now()

    student.updated_at = utc_now()
    # Re-sign record on update
    student.record_signature = sign_record(student, session)
    session.add(student)
    session.commit()
    session.refresh(student)

    # Re-evaluate intake if program changed
    if old_program_id != student.program_id:
        if old_program_id:
            validate_program_intake(old_program_id, session)
        if student.program_id:
            validate_program_intake(student.program_id, session)

    # Hash-chained audit logging
    audit_details = f"API updated student {student.full_name} (Roll: {student.student_id}, APAAR: {student.apaar_id})"
    if data.override_justification and data.override_justification.strip():
        audit_details += f" | Intake BLOCK Override Justification: {data.override_justification.strip()}"

    log_action(
        session=session,
        user=institution,
        action="STUDENT_EDIT",
        entity="STUDENT",
        entity_id=str(student.id),
        details=audit_details,
    )

    return {
        "status": "success",
        "message": f"Student record {student.apaar_id} updated successfully",
        "student": {
            "id": student.id,
            "apaar_id": student.apaar_id,
            "student_id": student.student_id,
            "full_name": student.full_name,
            "dob": student.dob,
            "gender": student.gender,
            "category": student.category,
            "program_id": student.program_id,
            "admission_year": student.admission_year,
            "admission_type": student.admission_type,
            "status": student.status,
            "consent_level": student.consent_level,
            "updated_at": student.updated_at.isoformat() if student.updated_at else None,
        },
    }


@router.get(
    "/programs/{program_id}/intake-check",
    summary="Live Program Intake & Quota Check",
    description="Returns live enrollment counts, remaining seats, fill ratio, and AICTE admission decision (ALLOW, WARN, BLOCK) for an academic program.",
)
def program_intake_check_api(
    program_id: int = Path(..., description="ID of the approved academic program", examples=[1]),
    session: Session = Depends(get_session),
):
    """AJAX / public endpoint returning live seat meter calculation for a program."""
    program = session.get(Program, program_id)
    if not program:
        raise HTTPException(status_code=404, detail=f"Program with ID {program_id} not found")
    return intake_check(program_id, session)
