"""
Validation Engine for APAAR Verify.
Implements AICTE compliance rules R1 to R12, batch context preloading, and Intake Guard.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from sqlmodel import Session, select

from app.apaar_registry import validate_apaar_format, validate_dob_format
from app.models import ApaarRegistry, Program, Setting, Student, ValidationFlag, utc_now


def rule_r1_apaar_format(apaar_id: Any) -> Optional[Dict[str, str]]:
    """R1: APAAR missing or not exactly 12 ASCII numeric digits (HIGH - Reject row)."""
    if not validate_apaar_format(apaar_id):
        return {
            "rule_code": "R1",
            "severity": "HIGH",
            "message": f"APAAR ID '{apaar_id}' is invalid. Must be exactly 12 numeric digits.",
            "recommended_action": "Verify student APAAR card or Aadhaar-linked APAAR allotment.",
        }
    return None


def rule_r2_registry_lookup(apaar_id: str, registry_map: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """R2: APAAR not found in central registry (HIGH - Reject row)."""
    if str(apaar_id) not in registry_map:
        return {
            "rule_code": "R2",
            "severity": "HIGH",
            "message": f"APAAR ID '{apaar_id}' was not found in the central APAAR/DigiLocker registry.",
            "recommended_action": "Check whether student has completed APAAR generation on DigiLocker.",
        }
    return None


def rule_r3_identity_mismatch(
    apaar_id: str, name: str, dob: Any, registry_map: Dict[str, Any]
) -> Optional[Dict[str, str]]:
    """R3: Name fuzzy mismatch or DOB mismatch vs registry (MEDIUM)."""
    reg = registry_map.get(str(apaar_id))
    if not reg:
        return None  # R2 already handles missing registry

    # Name check
    input_name = str(name or "").strip().lower()
    reg_name = str(reg.get("full_name") or "").strip().lower()
    name_ok = False
    if input_name and reg_name:
        try:
            from rapidfuzz import fuzz
            name_sim = fuzz.token_sort_ratio(input_name, reg_name)
        except ImportError:
            import difflib
            name_sim = difflib.SequenceMatcher(None, input_name, reg_name).ratio() * 100
        name_ok = name_sim >= 85

    # DOB check
    input_dob = validate_dob_format(dob)
    reg_dob = validate_dob_format(reg.get("dob"))
    dob_ok = bool(input_dob and reg_dob and input_dob == reg_dob)

    if not name_ok or not dob_ok:
        mismatch_parts = []
        if not name_ok:
            mismatch_parts.append(f"Name mismatch (Submitted: '{name}' vs Registry: '{reg.get('full_name')}')")
        if not dob_ok:
            mismatch_parts.append(f"DOB mismatch (Submitted: '{dob}' vs Registry: '{reg.get('dob')}')")
        return {
            "rule_code": "R3",
            "severity": "MEDIUM",
            "message": "; ".join(mismatch_parts),
            "recommended_action": "Request student to update institution admission profile or DigiLocker record.",
        }
    return None


def rule_r4_duplicate_within_institution(
    apaar_id: str,
    inst_apaar_set: Set[str],
    batch_seen_apaars: Set[str],
) -> Optional[Dict[str, str]]:
    """R4: Duplicate APAAR inside the same institution (HIGH)."""
    apaar_str = str(apaar_id)
    if apaar_str in inst_apaar_set or apaar_str in batch_seen_apaars:
        return {
            "rule_code": "R4",
            "severity": "HIGH",
            "message": f"APAAR ID '{apaar_str}' is already enrolled within this institution.",
            "recommended_action": "Review duplicate student entry or previous enrollment status.",
        }
    return None


def rule_r5_cross_institution_duplicate(
    apaar_id: str,
    institution_id: int,
    all_active_fulltime_apaars: Dict[str, int],
) -> Optional[Dict[str, str]]:
    """R5: Same APAAR actively enrolled full-time at another institution (HIGH)."""
    apaar_str = str(apaar_id)
    other_inst_id = all_active_fulltime_apaars.get(apaar_str)
    if other_inst_id is not None and other_inst_id != institution_id:
        return {
            "rule_code": "R5",
            "severity": "HIGH",
            "message": f"APAAR ID '{apaar_str}' is concurrently enrolled full-time at another institution (ID: {other_inst_id}).",
            "recommended_action": "Flag for AICTE cross-verification and obtain migration/clearance certificate.",
        }
    return None


def rule_r8_inconsistency(row: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """R8: Data inconsistencies: NRI/FN confusion, FN with Indian nationality, future admission (MEDIUM)."""
    is_nri = bool(row.get("is_nri"))
    is_fn = bool(row.get("is_foreign_national"))
    nationality = str(row.get("nationality") or "").strip().lower()
    admission_year = row.get("admission_year")

    # Inconsistent NRI & FN
    if is_nri and is_fn:
        return {
            "rule_code": "R8",
            "severity": "MEDIUM",
            "message": "Student marked as both NRI and Foreign National simultaneously.",
            "recommended_action": "Clarify citizenship status in student profile.",
        }

    # Foreign national with nationality India
    if is_fn and nationality in ["india", "indian"]:
        return {
            "rule_code": "R8",
            "severity": "MEDIUM",
            "message": "Foreign National student has nationality recorded as Indian.",
            "recommended_action": "Update valid country of citizenship on passport verification.",
        }

    # Future admission year
    current_year = datetime.utcnow().year + 1
    if admission_year:
        try:
            if int(admission_year) > current_year:
                return {
                    "rule_code": "R8",
                    "severity": "MEDIUM",
                    "message": f"Admission year {admission_year} is in the future.",
                    "recommended_action": "Correct academic admission year.",
                }
        except (ValueError, TypeError):
            pass

    return None


def rule_r9_mandatory_fields(row: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """R9: Mandatory fields missing: name, DOB, program, admission year (HIGH - Reject row)."""
    missing = []
    if not str(row.get("full_name") or "").strip():
        missing.append("full_name")
    if not row.get("dob") or not validate_dob_format(row.get("dob")):
        missing.append("valid_dob (YYYY-MM-DD)")
    if not str(row.get("program_name") or row.get("program_id") or "").strip():
        missing.append("program")
    if not row.get("admission_year"):
        missing.append("admission_year")

    if missing:
        return {
            "rule_code": "R9",
            "severity": "HIGH",
            "message": f"Mandatory fields missing or malformed: {', '.join(missing)}.",
            "recommended_action": "Fill in all mandatory profile fields before submission.",
        }
    return None


def rule_r10_consent(consent_given: Any) -> Optional[Dict[str, str]]:
    """R10: Consent not captured (LOW)."""
    is_consented = False
    if isinstance(consent_given, bool):
        is_consented = consent_given
    elif isinstance(consent_given, (int, str)):
        is_consented = str(consent_given).lower() in ["1", "true", "yes", "2"]

    if not is_consented:
        return {
            "rule_code": "R10",
            "severity": "LOW",
            "message": "Student DigiLocker verification consent has not been logged.",
            "recommended_action": "Collect student digital consent for verification sharing.",
        }
    return None


def rule_r11_program_existence(
    program_ref: Any, program_map: Dict[str, Any]
) -> Optional[Dict[str, str]]:
    """R11: Program not found for this institution and year (HIGH - Reject row)."""
    prog_key = str(program_ref).strip().lower()
    if prog_key not in program_map:
        return {
            "rule_code": "R11",
            "severity": "HIGH",
            "message": f"Program '{program_ref}' is not registered under this institution's AICTE approved quota.",
            "recommended_action": "Check AICTE approved program titles and academic year.",
        }
    return None


def rule_r12_duplicate_student_id(
    student_id: str, inst_roll_set: Set[str], batch_seen_rolls: Set[str]
) -> Optional[Dict[str, str]]:
    """R12: Duplicate student roll number within institution (MEDIUM)."""
    roll_str = str(student_id or "").strip()
    if roll_str and (roll_str in inst_roll_set or roll_str in batch_seen_rolls):
        return {
            "rule_code": "R12",
            "severity": "MEDIUM",
            "message": f"Student Roll ID '{roll_str}' is already assigned within this institution.",
            "recommended_action": "Ensure unique institutional roll numbering.",
        }
    return None


def build_validation_context(institution_id: int, session: Session) -> Dict[str, Any]:
    """
    Preload all registry entries, institutional programs, and existing student sets.
    Enables single-query $O(1)$ validation across an entire CSV upload batch.
    """
    from app.apaar_registry import load_registry_map

    # 1. Central registry map
    registry_map = load_registry_map(session)

    # 2. Programs for this institution
    progs = session.exec(
        select(Program).where(Program.institution_id == institution_id)
    ).all()
    program_map = {}
    for p in progs:
        program_map[p.name.strip().lower()] = p
        program_map[str(p.id)] = p

    # 3. Existing APAAR IDs in this institution
    inst_students = session.exec(
        select(Student).where(Student.institution_id == institution_id)
    ).all()
    inst_apaar_set = {s.apaar_id for s in inst_students}
    inst_roll_set = {s.student_id for s in inst_students if s.student_id}

    # 4. Active full-time students across ALL institutions
    all_ft_students = session.exec(
        select(Student.apaar_id, Student.institution_id)
        .where(Student.mode == "FULL_TIME", Student.status == "ACTIVE")
    ).all()
    all_active_fulltime_apaars = {s[0]: s[1] for s in all_ft_students}

    return {
        "institution_id": institution_id,
        "registry_map": registry_map,
        "program_map": program_map,
        "inst_apaar_set": inst_apaar_set,
        "inst_roll_set": inst_roll_set,
        "all_active_fulltime_apaars": all_active_fulltime_apaars,
        "batch_seen_apaars": set(),
        "batch_seen_rolls": set(),
    }


def validate_student_row(row: Dict[str, Any], ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Validate a single student row against all rules R1 to R12.
    Returns a list of violation flag dicts.
    """
    flags = []
    apaar_id = str(row.get("apaar_id") or "").strip()
    full_name = str(row.get("full_name") or "").strip()
    dob = row.get("dob")
    program_ref = row.get("program_name") or row.get("program_id")
    student_id = str(row.get("student_id") or "").strip()

    # R9: Mandatory fields check
    f9 = rule_r9_mandatory_fields(row)
    if f9:
        flags.append(f9)

    # R1: APAAR format check
    f1 = rule_r1_apaar_format(apaar_id)
    if f1:
        flags.append(f1)
    else:
        # R2: Registry lookup
        f2 = rule_r2_registry_lookup(apaar_id, ctx["registry_map"])
        if f2:
            flags.append(f2)
        else:
            # R3: Identity fuzzy match
            f3 = rule_r3_identity_mismatch(apaar_id, full_name, dob, ctx["registry_map"])
            if f3:
                flags.append(f3)

        # R4: Duplicate within institution
        f4 = rule_r4_duplicate_within_institution(
            apaar_id, ctx["inst_apaar_set"], ctx["batch_seen_apaars"]
        )
        if f4:
            flags.append(f4)

        # R5: Cross-institution duplicate
        f5 = rule_r5_cross_institution_duplicate(
            apaar_id, ctx["institution_id"], ctx["all_active_fulltime_apaars"]
        )
        if f5:
            flags.append(f5)

    # R11: Program registered check
    if program_ref:
        f11 = rule_r11_program_existence(program_ref, ctx["program_map"])
        if f11:
            flags.append(f11)

    # R12: Duplicate roll number check
    if student_id:
        f12 = rule_r12_duplicate_student_id(
            student_id, ctx["inst_roll_set"], ctx["batch_seen_rolls"]
        )
        if f12:
            flags.append(f12)

    # R8: Data inconsistency check
    f8 = rule_r8_inconsistency(row)
    if f8:
        flags.append(f8)

    # R10: Consent check
    f10 = rule_r10_consent(row.get("consent_given"))
    if f10:
        flags.append(f10)

    # Record seen keys in batch to detect intra-file duplicate rows
    if apaar_id:
        ctx["batch_seen_apaars"].add(apaar_id)
    if student_id:
        ctx["batch_seen_rolls"].add(student_id)

    return flags


def intake_check(program_id: int, session: Session) -> Dict[str, Any]:
    """
    Intake Guard (D1):
    Checks seat intake quota for a program and determines status:
    - ALLOW: fill ratio under 90%
    - WARN: fill ratio 90% - 100%
    - BLOCK: one more admission would exceed approved intake
    """
    program = session.get(Program, program_id)
    if not program:
        raise ValueError(f"Program ID {program_id} not found")

    # Count active regular students in this program
    regular_count = len(
        session.exec(
            select(Student.id).where(
                Student.program_id == program_id,
                Student.admission_type == "REGULAR",
                Student.status == "ACTIVE",
            )
        ).all()
    )

    # Count active supernumerary students
    super_count = len(
        session.exec(
            select(Student.id).where(
                Student.program_id == program_id,
                Student.admission_type == "SUPERNUMERARY",
                Student.status == "ACTIVE",
            )
        ).all()
    )

    approved = program.approved_intake
    remaining = max(0, approved - regular_count)
    fill_ratio = regular_count / approved if approved > 0 else 1.0

    if regular_count >= approved:
        decision = "BLOCK"
    elif fill_ratio >= 0.90:
        decision = "WARN"
    else:
        decision = "ALLOW"

    return {
        "program_id": program_id,
        "program_name": program.name,
        "academic_year": program.academic_year,
        "approved_intake": approved,
        "enrolled_regular": regular_count,
        "enrolled_supernumerary": super_count,
        "supernumerary_cap": int(approved * program.supernumerary_cap),
        "remaining_seats": remaining,
        "fill_ratio": round(fill_ratio, 3),
        "decision": decision,
    }


def validate_program_intake(program_id: int, session: Session) -> List[ValidationFlag]:
    """
    Evaluate program-level rules:
    - R6: Regular admissions exceed approved intake (HIGH)
    - R7: Supernumerary admissions exceed cap (MEDIUM)
    Updates or creates ValidationFlag records accordingly.
    """
    program = session.get(Program, program_id)
    if not program:
        return []

    flags = []
    intake_data = intake_check(program_id, session)

    # R6 check
    if intake_data["enrolled_regular"] > intake_data["approved_intake"]:
        excess = intake_data["enrolled_regular"] - intake_data["approved_intake"]
        flag = ValidationFlag(
            institution_id=program.institution_id,
            program_id=program.id,
            rule_code="R6",
            severity="HIGH",
            message=f"Regular admissions ({intake_data['enrolled_regular']}) exceed approved intake ({intake_data['approved_intake']}) by {excess} seat(s).",
            recommended_action="Freeze regular admissions and report over-admission justification to AICTE.",
            status="OPEN",
            created_at=utc_now(),
        )
        session.add(flag)
        flags.append(flag)

    # R7 check
    if intake_data["enrolled_supernumerary"] > intake_data["supernumerary_cap"]:
        flag = ValidationFlag(
            institution_id=program.institution_id,
            program_id=program.id,
            rule_code="R7",
            severity="MEDIUM",
            message=f"Supernumerary admissions ({intake_data['enrolled_supernumerary']}) exceed quota cap ({intake_data['supernumerary_cap']}).",
            recommended_action="Verify AICTE approval letters for supernumerary seats.",
            status="OPEN",
            created_at=utc_now(),
        )
        session.add(flag)
        flags.append(flag)

    session.commit()
    return flags
