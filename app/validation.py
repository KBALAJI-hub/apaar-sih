"""
Validation Engine for APAAR Verify.
Implements AICTE compliance rules R1 to R12, batch context preloading, and Intake Guard.
"""

from datetime import datetime
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple
from sqlmodel import Session, select, func

from app.apaar_registry import validate_apaar_format, validate_dob_format
from app.models import ApaarRegistry, Program, Setting, Student, ValidationFlag, utc_now

# Canonical hard rejection rules and override limits
HARD_REJECT_RULE_CODES = frozenset({"R1", "R2", "R9", "R11"})
MAX_OVERRIDE_BUFFER_RATIO = 1.05  # Deprecated: generic hard ceilings removed in Phase 4 in favor of approval records
from app.override import (
    AUTHORIZED_OVERRIDE_CATEGORIES,
    validate_override_request,
)


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
    all_active_fulltime_apaars: Dict[str, Set[int]],
) -> Optional[Dict[str, str]]:
    """R5: Same APAAR actively enrolled full-time at another institution (HIGH)."""
    apaar_str = str(apaar_id)
    other_institutions = all_active_fulltime_apaars.get(apaar_str, set()) - {institution_id}
    if other_institutions:
        institution_list = ", ".join(str(inst_id) for inst_id in sorted(other_institutions))
        return {
            "rule_code": "R5",
            "severity": "HIGH",
            "message": f"APAAR ID '{apaar_str}' is concurrently enrolled full-time at another institution (ID: {institution_list}).",
            "recommended_action": "Flag for AICTE cross-verification and obtain migration/clearance certificate.",
        }
    return None


def rule_r8_inconsistency(row: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """R8: Data inconsistencies: NRI/FN confusion, FN with Indian nationality, future admission (MEDIUM)."""
    def as_bool(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        return str(value or "").strip().lower() in {"1", "true", "yes", "y"}

    is_nri = as_bool(row.get("is_nri"))
    is_fn = as_bool(row.get("is_foreign_national"))
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


def parse_academic_year(year_val: Any) -> Optional[int]:
    """
    Parse an academic year string or integer into its 4-digit start year integer.
    Handles '2024-25', '2024-2025', '2024/25', '2024', 2024, '2023-24', etc.
    Returns None if missing, empty, or unparseable.
    """
    if year_val is None:
        return None
    if isinstance(year_val, int):
        return year_val if 1900 <= year_val <= 2100 else None

    val_str = str(year_val).strip()
    if not val_str:
        return None

    import re
    m = re.match(r"^(\d{4})", val_str)
    if m:
        try:
            yr = int(m.group(1))
            return yr if 1900 <= yr <= 2100 else None
        except ValueError:
            return None
    return None


def validate_student_admission_year(
    admission_year: Any,
    program_academic_year: Any,
) -> Tuple[bool, Optional[int], Optional[str]]:
    """
    Validate student admission year against program academic year.
    Returns (is_valid, parsed_admission_year, error_message).
    """
    if admission_year is None or not str(admission_year).strip():
        return False, None, "Mandatory fields missing: admission_year."

    parsed_adm_year = parse_academic_year(admission_year)
    if parsed_adm_year is None:
        return False, None, f"Invalid academic admission year: '{admission_year}'. Must be a valid 4-digit year (YYYY)."

    current_max_year = datetime.utcnow().year + 1
    if parsed_adm_year > current_max_year:
        return False, parsed_adm_year, f"Admission year {parsed_adm_year} is in the future."

    parsed_prog_year = parse_academic_year(program_academic_year)
    if parsed_prog_year is not None and parsed_adm_year != parsed_prog_year:
        return False, parsed_adm_year, (
            f"Admission year {parsed_adm_year} does not match program academic year "
            f"'{program_academic_year}' (expected {parsed_prog_year})."
        )

    return True, parsed_adm_year, None


def rule_r9_mandatory_fields(row: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """R9: Mandatory fields missing: name, DOB, program, admission year (HIGH - Reject row)."""
    missing = []
    if not str(row.get("full_name") or "").strip():
        missing.append("full_name")
    if not row.get("dob") or not validate_dob_format(row.get("dob")):
        missing.append("valid_dob (YYYY-MM-DD)")
    if not str(row.get("program_name") or row.get("program_id") or "").strip():
        missing.append("program")

    raw_year = row.get("admission_year")
    if raw_year is None or not str(raw_year).strip():
        missing.append("admission_year")
    else:
        parsed = parse_academic_year(raw_year)
        if parsed is None:
            missing.append("valid_admission_year (YYYY)")

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


def resolve_program(
    program_ref: Any, program_map: Dict[Any, Any], admission_year: Any = None
) -> Optional[Program]:
    """Resolve program from program_map with fallback for 'Engineering' suffix and year matching."""
    if not program_ref:
        return None
    prog_key = str(program_ref).strip().lower()
    try:
        submitted_year = int(admission_year) if admission_year else None
    except (ValueError, TypeError):
        submitted_year = None

    def find_program(key: str, year: Optional[int]):
        if year and (key, year) in program_map:
            return program_map[(key, year)]
        if key in program_map:
            return program_map[key]
        if key.endswith(" engineering"):
            short_key = key[:-12].strip()
            if year and (short_key, year) in program_map:
                return program_map[(short_key, year)]
            if short_key in program_map:
                return program_map[short_key]
        elif not key.endswith(" engineering"):
            long_key = f"{key} engineering"
            if year and (long_key, year) in program_map:
                return program_map[(long_key, year)]
            if long_key in program_map:
                return program_map[long_key]
        return None

    program = find_program(prog_key, submitted_year)
    if program is not None and submitted_year:
        try:
            program_start_year = int(str(program.academic_year).split("-", 1)[0])
            if submitted_year != program_start_year:
                alt = find_program(prog_key, submitted_year)
                if alt and int(str(alt.academic_year).split("-", 1)[0]) == submitted_year:
                    return alt
        except (AttributeError, TypeError, ValueError):
            pass

    return program


def rule_r11_program_existence(
    program_ref: Any, program_map: Dict[str, Any], admission_year: Any = None
) -> Optional[Dict[str, str]]:
    """R11: Program not found for this institution and year (HIGH - Reject row)."""
    program = resolve_program(program_ref, program_map, admission_year)
    if program is None:
        return {
            "rule_code": "R11",
            "severity": "HIGH",
            "message": f"Program '{program_ref}' is not registered under this institution's AICTE approved quota.",
            "recommended_action": "Check AICTE approved program titles and academic year.",
        }

    try:
        submitted_year = int(admission_year) if admission_year else None
    except (ValueError, TypeError):
        submitted_year = None

    if submitted_year:
        try:
            program_start_year = int(str(program.academic_year).split("-", 1)[0])
            if submitted_year != program_start_year:
                return {
                    "rule_code": "R11",
                    "severity": "HIGH",
                    "message": f"Program '{program_ref}' is not approved for admission year {submitted_year}.",
                    "recommended_action": "Select the program version approved for the student's admission year.",
                }
        except (AttributeError, TypeError, ValueError):
            pass

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
        p_name = p.name.strip().lower()
        program_map[p_name] = p
        program_map[str(p.id)] = p
        start_yr = parse_academic_year(p.academic_year)
        if start_yr:
            program_map[(p_name, start_yr)] = p
            program_map[(str(p.id), start_yr)] = p

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
    all_active_fulltime_apaars: Dict[str, Set[int]] = {}
    for apaar_id, active_institution_id in all_ft_students:
        all_active_fulltime_apaars.setdefault(apaar_id, set()).add(active_institution_id)

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
        f11 = rule_r11_program_existence(
            program_ref, ctx["program_map"], row.get("admission_year")
        )
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


def run_full_validation(institution_id: int, session: Session) -> List[ValidationFlag]:
    """Rebuild open row and program validation flags for one institution."""
    students = session.exec(
        select(Student).where(Student.institution_id == institution_id)
    ).all()
    programs = session.exec(
        select(Program).where(Program.institution_id == institution_id)
    ).all()
    program_by_id = {program.id: program for program in programs}
    apaar_counts = Counter(student.apaar_id for student in students)
    roll_counts = Counter(student.student_id for student in students if student.student_id)

    old_flags = session.exec(
        select(ValidationFlag).where(
            ValidationFlag.institution_id == institution_id,
            ValidationFlag.status == "OPEN",
        )
    ).all()
    for flag in old_flags:
        flag.status = "RESOLVED"
    session.flush()

    ctx = build_validation_context(institution_id, session)
    created_flags: List[ValidationFlag] = []
    for student in students:
        row = {
            "apaar_id": student.apaar_id,
            "student_id": student.student_id,
            "full_name": student.full_name,
            "dob": student.dob,
            "program_name": (
                program_by_id[student.program_id].name
                if student.program_id in program_by_id
                else ""
            ),
            "admission_year": student.admission_year,
            "gender": student.gender,
            "admission_type": student.admission_type,
            "is_nri": student.is_nri,
            "oci_status": student.oci_status,
            "is_foreign_national": student.is_foreign_national,
            "nationality": student.nationality,
            "consent_given": student.consent_level > 0,
        }
        row_ctx = dict(ctx)
        row_ctx["inst_apaar_set"] = (
            {student.apaar_id} if apaar_counts[student.apaar_id] > 1 else set()
        )
        row_ctx["inst_roll_set"] = (
            {student.student_id}
            if student.student_id and roll_counts[student.student_id] > 1
            else set()
        )
        row_ctx["batch_seen_apaars"] = set()
        row_ctx["batch_seen_rolls"] = set()

        for flag in validate_student_row(row, row_ctx):
            record = ValidationFlag(
                institution_id=institution_id,
                program_id=student.program_id,
                student_id=student.id,
                rule_code=flag["rule_code"],
                severity=flag["severity"],
                message=flag["message"],
                recommended_action=flag["recommended_action"],
                status="OPEN",
                created_at=utc_now(),
            )
            session.add(record)
            created_flags.append(record)

    session.flush()
    for program in programs:
        created_flags.extend(validate_program_intake(program.id, session))
    session.commit()
    return created_flags


def get_intake_settings(session: Session) -> Dict[str, str]:
    """Fetch intake threshold settings once."""
    return {
        setting.key: setting.value
        for setting in session.exec(
            select(Setting).where(
                Setting.key.in_([
                    "intake_warn_threshold",
                    "intake_block_threshold",
                    "supernumerary_cap_default",
                ])
            )
        ).all()
    }


def intake_check(
    program_id: int,
    session: Session,
    program: Optional[Program] = None,
    settings: Optional[Dict[str, str]] = None,
    regular_count: Optional[int] = None,
    super_count: Optional[int] = None,
    target_admission_type: Optional[str] = None,
    exclude_student_id: Optional[int] = None,
    admission_year: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Intake Guard (D1) & Multi-Dimension Seat Meter:
    Independently enforces:
    1. Regular enrolment <= AICTE-approved intake
    2. Supernumerary enrolment <= permitted supernumerary seats
    3. Total enrolment <= approved intake + permitted supernumerary seats
    """
    if program is None:
        program = session.get(Program, program_id)
        if not program:
            raise ValueError(f"Program ID {program_id} not found")

    target_year = admission_year or (parse_academic_year(program.academic_year) if program else None)

    if regular_count is None or super_count is None:
        count_stmt = (
            select(Student.admission_type, func.count(Student.id))
            .where(Student.program_id == program_id, Student.status == "ACTIVE")
        )
        if target_year is not None:
            count_stmt = count_stmt.where(Student.admission_year == target_year)
        if exclude_student_id is not None:
            count_stmt = count_stmt.where(Student.id != exclude_student_id)
        counts = dict(
            session.exec(
                count_stmt.group_by(Student.admission_type)
            ).all()
        )
        if regular_count is None:
            regular_count = counts.get("REGULAR", 0)
        if super_count is None:
            super_count = counts.get("SUPERNUMERARY", 0)

    if settings is None:
        settings = get_intake_settings(session)

    try:
        warning_threshold = float(settings.get("intake_warn_threshold", "0.90"))
        block_threshold = float(settings.get("intake_block_threshold", "1.00"))
        default_super_cap = float(settings.get("supernumerary_cap_default", "0.10"))
    except ValueError as exc:
        raise ValueError("Intake policy settings must contain numeric values") from exc

    # Phase 3: Regulatory Seat Allocation Integration
    from app.allocation import get_active_allocations_summary
    alloc_summary = get_active_allocations_summary(session, program_id, program.academic_year, program=program)
    has_allocations = alloc_summary["has_allocations"]

    if has_allocations:
        approved = alloc_summary["sanctioned_seats"]
        permitted_super = alloc_summary["total_supernumerary_authorized"]
    else:
        # Legacy fallback
        approved = program.approved_intake
        prog_cap = program.supernumerary_cap if program.supernumerary_cap is not None else default_super_cap
        if prog_cap >= 1.0:
            permitted_super = int(prog_cap)
        else:
            permitted_super = int(approved * prog_cap)

    total_capacity = approved + permitted_super
    total_count = regular_count + super_count

    # Independent fill ratios
    regular_fill_ratio = regular_count / approved if approved > 0 else 1.0
    super_fill_ratio = super_count / permitted_super if permitted_super > 0 else (0.0 if super_count == 0 else 1.0)
    total_fill_ratio = total_count / total_capacity if total_capacity > 0 else 1.0

    # Independent remaining seats
    regular_remaining = max(0, approved - regular_count)
    super_remaining = max(0, permitted_super - super_count)
    total_remaining = max(0, total_capacity - total_count)

    # Rule 1 Decision (Regular: N_regular <= approved)
    if regular_count >= approved or regular_fill_ratio >= block_threshold:
        regular_decision = "BLOCK"
    elif regular_fill_ratio >= warning_threshold:
        regular_decision = "WARN"
    else:
        regular_decision = "ALLOW"

    # Rule 2 Decision (Supernumerary: N_super <= permitted_super)
    if super_count >= permitted_super or super_fill_ratio >= block_threshold:
        super_decision = "BLOCK"
    elif super_fill_ratio >= warning_threshold:
        super_decision = "WARN"
    else:
        super_decision = "ALLOW"

    # Rule 3 Decision (Total: N_total <= total_capacity)
    if total_count >= total_capacity or total_fill_ratio >= block_threshold:
        total_decision = "BLOCK"
    elif total_fill_ratio >= warning_threshold:
        total_decision = "WARN"
    else:
        total_decision = "ALLOW"

    # Detect all specific rule violations
    violations: List[str] = []
    if regular_count > approved:
        violations.append(f"Regular admissions ({regular_count}) exceed approved intake ({approved}) by {regular_count - approved} seat(s).")
    if super_count > permitted_super:
        violations.append(f"Supernumerary admissions ({super_count}) exceed quota cap ({permitted_super}) by {super_count - permitted_super} seat(s).")
    if total_count > total_capacity:
        violations.append(f"Total admissions ({total_count}) exceed approved capacity ({total_capacity}) by {total_count - total_capacity} seat(s).")

    # Determine overall decision based on target admission type if specified, or default regular admission check
    clean_type = str(target_admission_type or "").strip().upper()
    if clean_type == "SUPERNUMERARY":
        if super_decision == "BLOCK" or total_decision == "BLOCK":
            effective_decision = "BLOCK"
        elif super_decision == "WARN" or total_decision == "WARN":
            effective_decision = "WARN"
        else:
            effective_decision = "ALLOW"
    elif clean_type == "REGULAR":
        if regular_decision == "BLOCK" or total_decision == "BLOCK":
            effective_decision = "BLOCK"
        elif regular_decision == "WARN" or total_decision == "WARN":
            effective_decision = "WARN"
        else:
            effective_decision = "ALLOW"
    else:
        # Default admission check evaluates regular capacity and total capacity
        if regular_decision == "BLOCK" or total_decision == "BLOCK":
            effective_decision = "BLOCK"
        elif regular_decision == "WARN" or total_decision == "WARN":
            effective_decision = "WARN"
        else:
            effective_decision = "ALLOW"

    return {
        # Backward-compatible keys
        "program_id": program_id,
        "program_name": program.name,
        "academic_year": program.academic_year,
        "approved_intake": approved,
        "enrolled_regular": regular_count,
        "enrolled_supernumerary": super_count,
        "supernumerary_cap": permitted_super,
        "remaining_seats": regular_remaining,
        "fill_ratio": round(regular_fill_ratio, 3),
        "decision": effective_decision,

        # Independent rule status breakdowns
        "permitted_supernumerary": permitted_super,
        "total_capacity": total_capacity,
        "total_enrolled": total_count,
        "total_remaining": total_remaining,
        "total_fill_ratio": round(total_fill_ratio, 3),
        "regular_status": {
            "approved": approved,
            "enrolled": regular_count,
            "remaining": regular_remaining,
            "fill_ratio": round(regular_fill_ratio, 3),
            "decision": regular_decision,
        },
        "supernumerary_status": {
            "permitted": permitted_super,
            "enrolled": super_count,
            "remaining": super_remaining,
            "fill_ratio": round(super_fill_ratio, 3),
            "decision": super_decision,
        },
        "total_status": {
            "capacity": total_capacity,
            "enrolled": total_count,
            "remaining": total_remaining,
            "fill_ratio": round(total_fill_ratio, 3),
            "decision": total_decision,
        },
        "violations": violations,
        "allocations_summary": alloc_summary,
        "has_explicit_allocations": has_allocations,
    }


def batch_intake_check(
    programs: List[Program],
    session: Session,
    target_admission_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    High-performance batch intake check for multiple programs.
    Eliminates N+1 queries by fetching settings once and aggregating student counts
    across all programs in a single SQL GROUP BY query.
    """
    if not programs:
        return []

    settings = get_intake_settings(session)
    prog_ids = [p.id for p in programs]

    counts_rows = session.exec(
        select(Student.program_id, Student.admission_year, Student.admission_type, func.count(Student.id))
        .where(Student.program_id.in_(prog_ids), Student.status == "ACTIVE")
        .group_by(Student.program_id, Student.admission_year, Student.admission_type)
    ).all()

    counts_by_prog: Dict[Tuple[int, Optional[int]], Dict[str, int]] = defaultdict(lambda: {"REGULAR": 0, "SUPERNUMERARY": 0})
    for p_id, adm_yr, adm_type, cnt in counts_rows:
        counts_by_prog[(p_id, adm_yr)][adm_type] = cnt

    return [
        intake_check(
            program_id=p.id,
            session=session,
            program=p,
            settings=settings,
            regular_count=counts_by_prog[(p.id, parse_academic_year(p.academic_year))]["REGULAR"],
            super_count=counts_by_prog[(p.id, parse_academic_year(p.academic_year))]["SUPERNUMERARY"],
            target_admission_type=target_admission_type,
            admission_year=parse_academic_year(p.academic_year),
        )
        for p in programs
    ]


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

    existing_flags = session.exec(
        select(ValidationFlag).where(
            ValidationFlag.program_id == program_id,
            ValidationFlag.rule_code.in_(["R6", "R7"]),
            ValidationFlag.status == "OPEN",
        )
    ).all()
    for existing_flag in existing_flags:
        existing_flag.status = "RESOLVED"

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
    if intake_data["enrolled_supernumerary"] > intake_data["permitted_supernumerary"]:
        excess = intake_data["enrolled_supernumerary"] - intake_data["permitted_supernumerary"]
        flag = ValidationFlag(
            institution_id=program.institution_id,
            program_id=program.id,
            rule_code="R7",
            severity="MEDIUM",
            message=f"Supernumerary admissions ({intake_data['enrolled_supernumerary']}) exceed quota cap ({intake_data['permitted_supernumerary']}) by {excess} seat(s).",
            recommended_action="Verify AICTE approval letters for supernumerary seats.",
            status="OPEN",
            created_at=utc_now(),
        )
        session.add(flag)
        flags.append(flag)

    session.commit()
    return flags


class CapacityValidationResult:
    """Outcome of an admission capacity validation."""

    def __init__(
        self,
        allowed: bool,
        decision: str,  # "ALLOW", "WARN", "BLOCK"
        reason: Optional[str] = None,
        rule_codes: Optional[List[str]] = None,
        program: Optional[Program] = None,
        intake_data: Optional[Dict[str, Any]] = None,
        is_override: bool = False,
        allocation: Optional[Any] = None,
        allocation_id: Optional[int] = None,
        override_id: Optional[int] = None,
    ):
        self.allowed = allowed
        self.decision = decision
        self.reason = reason
        self.rule_codes = rule_codes or []
        self.program = program
        self.intake_data = intake_data or {}
        self.is_override = is_override
        self.allocation = allocation
        self.allocation_id = allocation_id or (allocation.id if allocation and hasattr(allocation, "id") else None)
        self.override_id = override_id

    def __bool__(self) -> bool:
        return self.allowed


class BatchCapacityTracker:
    """
    In-memory batch tracker for multi-row operations (CSV and JSON bulk uploads).
    Tracks active seats accepted within the current batch to prevent intra-batch over-admission.
    Rejected students do not consume capacity.
    Differentiates active seats by academic year and scheme/category to enforce regulatory allocations.
    """

    def __init__(self, session: Session, institution_id: int):
        self.session = session
        self.institution_id = institution_id
        programs = session.exec(select(Program).where(Program.institution_id == institution_id)).all()
        self.program_map: Dict[int, Program] = {p.id: p for p in programs}
        self.settings = get_intake_settings(session)
        counts_rows = session.exec(
            select(Student.program_id, Student.admission_year, Student.admission_type, func.count(Student.id))
            .where(
                Student.institution_id == institution_id,
                Student.status == "ACTIVE",
            )
            .group_by(Student.program_id, Student.admission_year, Student.admission_type)
        ).all()
        self.db_counts: Dict[Tuple[int, Optional[int]], Dict[str, int]] = defaultdict(lambda: {"REGULAR": 0, "SUPERNUMERARY": 0})
        for p_id, adm_yr, adm_type, cnt in counts_rows:
            self.db_counts[(p_id, adm_yr)][str(adm_type).upper()] = cnt

        self.batch_allocated: Dict[Tuple[int, Optional[int]], Dict[str, int]] = defaultdict(lambda: {"REGULAR": 0, "SUPERNUMERARY": 0})

        # Track category and scheme allocations
        self.db_scheme_counts: Dict[Tuple[int, Optional[int], str], int] = defaultdict(int)
        self.batch_allocated_schemes: Dict[Tuple[int, Optional[int], str], int] = defaultdict(int)

        scheme_counts_rows = session.exec(
            select(Student.program_id, Student.admission_year, Student.category, func.count(Student.id))
            .where(
                Student.institution_id == institution_id,
                Student.status == "ACTIVE",
            )
            .group_by(Student.program_id, Student.admission_year, Student.category)
        ).all()
        for p_id, adm_yr, cat, cnt in scheme_counts_rows:
            self.db_scheme_counts[(p_id, adm_yr, str(cat).upper())] = cnt

        nri_rows = session.exec(
            select(Student.program_id, Student.admission_year, func.count(Student.id))
            .where(
                Student.institution_id == institution_id,
                Student.status == "ACTIVE",
                Student.is_nri == True,
            )
            .group_by(Student.program_id, Student.admission_year)
        ).all()
        for p_id, adm_yr, cnt in nri_rows:
            self.db_scheme_counts[(p_id, adm_yr, "NRI")] = cnt

        fn_rows = session.exec(
            select(Student.program_id, Student.admission_year, func.count(Student.id))
            .where(
                Student.institution_id == institution_id,
                Student.status == "ACTIVE",
                Student.is_foreign_national == True,
            )
            .group_by(Student.program_id, Student.admission_year)
        ).all()
        for p_id, adm_yr, cnt in fn_rows:
            self.db_scheme_counts[(p_id, adm_yr, "FN")] = cnt

    def ensure_program(self, program_id: int) -> Optional[Program]:
        """Fetch and cache program metadata and baseline active counts if not already loaded."""
        if program_id not in self.program_map:
            p = self.session.get(Program, program_id)
            if p:
                self.program_map[program_id] = p
                counts_rows = self.session.exec(
                    select(Student.admission_year, Student.admission_type, func.count(Student.id))
                    .where(
                        Student.program_id == program_id,
                        Student.status == "ACTIVE",
                    )
                    .group_by(Student.admission_year, Student.admission_type)
                ).all()
                for adm_yr, adm_type, cnt in counts_rows:
                    self.db_counts[(program_id, adm_yr)][str(adm_type).upper()] = cnt
        return self.program_map.get(program_id)

    def get_counts(self, program_id: int, admission_year: Optional[int] = None) -> Tuple[int, int]:
        """Return combined (regular, supernumerary) counts for an academic year: DB baseline + accepted in this batch."""
        p = self.ensure_program(program_id)
        target_year = admission_year or (parse_academic_year(p.academic_year) if p else None)
        key = (program_id, target_year)
        reg = self.db_counts[key]["REGULAR"] + self.batch_allocated[key]["REGULAR"]
        sup = self.db_counts[key]["SUPERNUMERARY"] + self.batch_allocated[key]["SUPERNUMERARY"]
        return reg, sup

    def get_scheme_count(self, program_id: int, admission_year: Optional[int], scheme_code: str) -> int:
        """Return count for a specific category or scheme: DB baseline + accepted in this batch."""
        p = self.ensure_program(program_id)
        target_year = admission_year or (parse_academic_year(p.academic_year) if p else None)
        key = (program_id, target_year, str(scheme_code).upper())
        return self.db_scheme_counts[key] + self.batch_allocated_schemes[key]

    def accept(
        self,
        program_id: int,
        admission_type: str,
        admission_year: Optional[int] = None,
        scheme_or_category: Optional[str] = None,
    ) -> None:
        """Mark one seat as allocated within this batch for a specific academic year and scheme."""
        p = self.ensure_program(program_id)
        target_year = admission_year or (parse_academic_year(p.academic_year) if p else None)
        adm_type = str(admission_type or "REGULAR").strip().upper() or "REGULAR"
        self.batch_allocated[(program_id, target_year)][adm_type] += 1
        if scheme_or_category:
            self.batch_allocated_schemes[(program_id, target_year, str(scheme_or_category).upper())] += 1


def validate_admission_capacity(
    session: Session,
    program_id: int,
    admission_type: str = "REGULAR",
    target_status: str = "ACTIVE",
    admission_year: Optional[Any] = None,
    category: Optional[str] = "GENERAL",
    scheme_code: Optional[str] = None,
    is_nri: bool = False,
    oci_status: bool = False,
    is_foreign_national: bool = False,
    existing_student: Optional[Student] = None,
    batch_tracker: Optional[BatchCapacityTracker] = None,
    override_id: Optional[int] = None,
    override_record: Optional[Any] = None,
    override_justification: Optional[str] = None,
    allow_override: bool = False,
    caller_user: Optional[Any] = None,
) -> CapacityValidationResult:
    """
    Centralized Admission Capacity Enforcement Service (Phase 1, 2 & 3).
    Enforces the canonical AICTE constraints before any insertion or modification:
    1. Regular enrolment <= approved sanctioned intake.
    2. Supernumerary enrolment <= authorized supernumerary capacity (requires verified approval).
    3. Within-intake reserved-category & scheme sub-allocations are strictly capped.
    4. Total enrolment <= combined capacity.

    Strictly validates academic year and regulatory seat allocations.
    """
    clean_admission_type = str(admission_type or "REGULAR").strip().upper() or "REGULAR"
    clean_target_status = str(target_status or "ACTIVE").strip().upper() or "ACTIVE"
    clean_category = str(category or (existing_student.category if existing_student else "GENERAL") or "GENERAL").strip().upper()
    clean_is_nri = is_nri or (existing_student.is_nri if existing_student else False)
    clean_oci = oci_status or (existing_student.oci_status if existing_student else False)
    clean_fn = is_foreign_national or (existing_student.is_foreign_national if existing_student else False)

    if clean_admission_type not in ("REGULAR", "SUPERNUMERARY"):
        return CapacityValidationResult(
            allowed=False,
            decision="BLOCK",
            reason=f"Invalid admission type '{admission_type}'. Allowed types are REGULAR or SUPERNUMERARY.",
            rule_codes=["R8"],
        )

    # 1. Resolve program
    if batch_tracker:
        program = batch_tracker.ensure_program(program_id)
    else:
        program = session.get(Program, program_id)

    if not program:
        return CapacityValidationResult(
            allowed=False,
            decision="BLOCK",
            reason=f"Program ID {program_id} not found.",
            rule_codes=["R11"],
        )

    # 2. Inactive students (WITHDRAWN, GRADUATED) do not claim an active capacity seat
    if clean_target_status != "ACTIVE":
        return CapacityValidationResult(
            allowed=True,
            decision="ALLOW",
            program=program,
        )

    # 3. Academic Year Validation
    prog_year = parse_academic_year(program.academic_year)
    if prog_year is None:
        return CapacityValidationResult(
            allowed=False,
            decision="BLOCK",
            reason=f"Program '{program.name}' has invalid or unparseable academic_year '{program.academic_year}'.",
            rule_codes=["R11"],
            program=program,
        )

    if admission_year is not None:
        valid_yr, parsed_adm_year, yr_err = validate_student_admission_year(admission_year, program.academic_year)
        if not valid_yr:
            rule_code = "R9" if ("missing" in (yr_err or "").lower()) else "R11"
            if "future" in (yr_err or "").lower():
                rule_code = "R8"
            return CapacityValidationResult(
                allowed=False,
                decision="BLOCK",
                reason=yr_err,
                rule_codes=[rule_code],
                program=program,
            )
        effective_year = parsed_adm_year
    elif existing_student is not None:
        effective_year = existing_student.admission_year
    else:
        effective_year = prog_year

    # 4. Existing student retaining their existing active seat in the same academic year
    if existing_student is not None:
        is_retaining_existing_seat = (
            existing_student.status == "ACTIVE"
            and existing_student.program_id == program_id
            and str(existing_student.admission_type).upper() == clean_admission_type
            and existing_student.admission_year == effective_year
            and str(existing_student.category).upper() == clean_category
            and bool(existing_student.is_nri) == bool(clean_is_nri)
            and bool(existing_student.oci_status) == bool(clean_oci)
            and bool(existing_student.is_foreign_national) == bool(clean_fn)
        )
        if is_retaining_existing_seat:
            intake_data = intake_check(
                program_id=program_id,
                session=session,
                program=program,
                target_admission_type=clean_admission_type,
                admission_year=effective_year,
            )
            return CapacityValidationResult(
                allowed=True,
                decision="ALLOW",
                program=program,
                intake_data=intake_data,
                allocation_id=existing_student.allocation_id,
            )

    # 5. Regulatory Seat Allocation Evaluation (Phase 3)
    from app.allocation import get_active_allocations_summary
    alloc_summary = get_active_allocations_summary(session, program_id, program.academic_year, program=program)
    has_allocations = alloc_summary["has_allocations"]
    matched_allocation = None

    exclude_id = existing_student.id if existing_student is not None else None

    if has_allocations:
        if clean_admission_type == "SUPERNUMERARY":
            # Determine target scheme
            if scheme_code:
                target_scheme = str(scheme_code).strip().upper()
            elif clean_fn:
                target_scheme = "FN"
            elif clean_oci:
                target_scheme = "OCI"
            elif clean_is_nri:
                target_scheme = "NRI"
            else:
                target_scheme = "ALL"

            matched_super_alloc = alloc_summary["supernumerary_allocations"].get(target_scheme) or alloc_summary["supernumerary_allocations"].get("ALL")
            if not matched_super_alloc:
                # Check if there is an unverified / draft / expired / revoked supernumerary record
                unverified_record = next(
                    (a for a in alloc_summary["all_records"] if str(a.allocation_type).upper() == "SUPERNUMERARY" and (str(a.category_or_scheme).upper() in (target_scheme, "ALL"))),
                    None
                )
                if unverified_record:
                    status_label = unverified_record.verification_status
                    return CapacityValidationResult(
                        allowed=False,
                        decision="BLOCK",
                        reason=(
                            f"Supernumerary admission requires verified regulatory approval. "
                            f"Authorization for scheme '{target_scheme}' is {status_label} "
                            f"(Approval Ref: '{unverified_record.approval_ref}'). Formal authorization is required."
                        ),
                        rule_codes=["R7"],
                        program=program,
                    )
                return CapacityValidationResult(
                    allowed=False,
                    decision="BLOCK",
                    reason=(
                        f"Supernumerary admission rejected: No verified regulatory supernumerary allocation exists "
                        f"for program '{program.name}' (academic year {program.academic_year})."
                    ),
                    rule_codes=["R7"],
                    program=program,
                )

            # Scheme-specific limit check
            if batch_tracker:
                scheme_count = batch_tracker.get_scheme_count(program_id, effective_year, target_scheme)
            else:
                scheme_stmt = select(func.count(Student.id)).where(
                    Student.program_id == program_id,
                    Student.status == "ACTIVE",
                    Student.admission_year == effective_year,
                    Student.admission_type == "SUPERNUMERARY",
                )
                if target_scheme == "FN":
                    scheme_stmt = scheme_stmt.where(Student.is_foreign_national == True)
                elif target_scheme == "OCI":
                    scheme_stmt = scheme_stmt.where(Student.oci_status == True)
                elif target_scheme == "NRI":
                    scheme_stmt = scheme_stmt.where(Student.is_nri == True)
                if exclude_id is not None:
                    scheme_stmt = scheme_stmt.where(Student.id != exclude_id)
                scheme_count = session.exec(scheme_stmt).one()

            if scheme_count >= matched_super_alloc.approved_seats:
                return CapacityValidationResult(
                    allowed=False,
                    decision="BLOCK",
                    reason=(
                        f"Supernumerary quota capacity exceeded for scheme '{target_scheme}' "
                        f"({matched_super_alloc.approved_seats} permitted). New admissions over permitted quota are rejected."
                    ),
                    rule_codes=["R7"],
                    program=program,
                    allocation=matched_super_alloc,
                )
            matched_allocation = matched_super_alloc

        elif clean_admission_type == "REGULAR":
            target_scheme = "NRI" if clean_is_nri else clean_category
            within_alloc = alloc_summary["within_intake_allocations"].get(target_scheme)
            if within_alloc:
                if batch_tracker:
                    cat_count = batch_tracker.get_scheme_count(program_id, effective_year, target_scheme)
                else:
                    cat_stmt = select(func.count(Student.id)).where(
                        Student.program_id == program_id,
                        Student.status == "ACTIVE",
                        Student.admission_year == effective_year,
                        Student.admission_type == "REGULAR",
                    )
                    if target_scheme == "NRI":
                        cat_stmt = cat_stmt.where(Student.is_nri == True)
                    else:
                        cat_stmt = cat_stmt.where(Student.category == target_scheme)
                    if exclude_id is not None:
                        cat_stmt = cat_stmt.where(Student.id != exclude_id)
                    cat_count = session.exec(cat_stmt).one()

                if cat_count >= within_alloc.approved_seats:
                    return CapacityValidationResult(
                        allowed=False,
                        decision="BLOCK",
                        reason=(
                            f"Reserved allocation capacity exceeded for category/scheme '{target_scheme}' "
                            f"({within_alloc.approved_seats} seats sanctioned within intake). "
                            f"New admissions over sanctioned quota are rejected."
                        ),
                        rule_codes=["R6"],
                        program=program,
                        allocation=within_alloc,
                    )
                matched_allocation = within_alloc
            else:
                matched_allocation = alloc_summary["sanctioned_allocation"]

    # 6. Determine current counts for (program_id, effective_year)
    if batch_tracker:
        reg_count, super_count = batch_tracker.get_counts(program_id, effective_year)
        settings = batch_tracker.settings
    else:
        settings = get_intake_settings(session)
        count_stmt = (
            select(Student.admission_type, func.count(Student.id))
            .where(
                Student.program_id == program_id,
                Student.status == "ACTIVE",
                Student.admission_year == effective_year,
            )
        )
        if exclude_id is not None:
            count_stmt = count_stmt.where(Student.id != exclude_id)
        counts = dict(session.exec(count_stmt.group_by(Student.admission_type)).all())
        reg_count = counts.get("REGULAR", 0)
        super_count = counts.get("SUPERNUMERARY", 0)

    # 7. Run intake calculation
    intake_data = intake_check(
        program_id=program_id,
        session=session,
        program=program,
        settings=settings,
        regular_count=reg_count,
        super_count=super_count,
        target_admission_type=clean_admission_type,
        exclude_student_id=exclude_id,
        admission_year=effective_year,
    )

    approved_lim = intake_data["approved_intake"]
    super_lim = intake_data["permitted_supernumerary"]
    total_lim = intake_data["total_capacity"]
    curr_total = reg_count + super_count

    # 8. Check the general constraints
    is_quota_rejected = False
    quota_reason = ""
    rule_codes: List[str] = []

    if clean_admission_type == "REGULAR":
        if reg_count >= approved_lim:
            is_quota_rejected = True
            rule_codes.append("R6")
            quota_reason = (
                f"Regular intake capacity exceeded for program '{program.name}' "
                f"({approved_lim} sanctioned). New admissions over approved capacity are rejected."
            )
        elif curr_total >= total_lim:
            is_quota_rejected = True
            rule_codes.extend(["R6", "R7"])
            quota_reason = (
                f"Total program capacity exceeded for program '{program.name}' "
                f"({total_lim} total capacity). New admissions over capacity are rejected."
            )
    elif clean_admission_type == "SUPERNUMERARY":
        if super_count >= super_lim:
            is_quota_rejected = True
            rule_codes.append("R7")
            quota_reason = (
                f"Supernumerary quota capacity exceeded for program '{program.name}' "
                f"({super_lim} permitted). New admissions over permitted quota are rejected."
            )
        elif curr_total >= total_lim:
            is_quota_rejected = True
            rule_codes.extend(["R6", "R7"])
            quota_reason = (
                f"Total program capacity exceeded for program '{program.name}' "
                f"({total_lim} total capacity). New admissions over capacity are rejected."
            )

    if not is_quota_rejected and intake_data["decision"] == "BLOCK":
        is_quota_rejected = True
        quota_label = "Regular intake" if clean_admission_type == "REGULAR" else "Supernumerary quota"
        rule_codes = ["R6"] if clean_admission_type == "REGULAR" else ["R7"]
        quota_reason = f"{quota_label} is FULL (BLOCK)."

    if is_quota_rejected:
        if allow_override:
            is_valid_override, override_err, override_rec = validate_override_request(
                program=program,
                admission_type=clean_admission_type,
                justification=override_justification,
                current_intake_data=intake_data,
                session=session,
                override_id=override_id,
                override_record=override_record,
                admission_year=effective_year,
                caller_user=caller_user,
            )
            if is_valid_override and override_rec:
                return CapacityValidationResult(
                    allowed=True,
                    decision="WARN",
                    reason=None,
                    rule_codes=[],
                    program=program,
                    intake_data=intake_data,
                    is_override=True,
                    allocation=matched_allocation,
                    override_id=override_rec.id,
                )
            else:
                quota_label = "Regular intake" if clean_admission_type == "REGULAR" else "Supernumerary quota"
                err_msg = override_err or (
                    f"{quota_label} is FULL (BLOCK). An approved regulatory override record is strictly "
                    f"required to admit students beyond approved capacity."
                )
                return CapacityValidationResult(
                    allowed=False,
                    decision="BLOCK",
                    reason=err_msg,
                    rule_codes=rule_codes,
                    program=program,
                    intake_data=intake_data,
                    is_override=False,
                    allocation=matched_allocation,
                    override_id=None,
                )
        else:
            return CapacityValidationResult(
                allowed=False,
                decision="BLOCK",
                reason=quota_reason,
                rule_codes=rule_codes,
                program=program,
                intake_data=intake_data,
                is_override=False,
                allocation=matched_allocation,
                override_id=None,
            )

    return CapacityValidationResult(
        allowed=True,
        decision=intake_data["decision"],
        reason=None,
        rule_codes=[],
        program=program,
        intake_data=intake_data,
        is_override=False,
        allocation=matched_allocation,
    )
