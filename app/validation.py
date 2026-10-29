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
MAX_OVERRIDE_BUFFER_RATIO = 1.05  # Statutory AICTE emergency buffer: at most 105% of capacity
MAX_OVERRIDE_BUFFER_SEATS = 3     # Or at most +3 seats (whichever is greater)
AUTHORIZED_OVERRIDE_CATEGORIES = frozenset({
    "AICTE_APPROVAL_LETTER",
    "COURT_DIRECTIVE",
    "GOVERNMENT_NOMINATION",
    "ADMISSION_RECONCILIATION",
})


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
    program_ref: Any, program_map: Dict[str, Any], admission_year: Any = None
) -> Optional[Dict[str, str]]:
    """R11: Program not found for this institution and year (HIGH - Reject row)."""
    prog_key = str(program_ref).strip().lower()
    try:
        submitted_year = int(admission_year) if admission_year else None
    except (ValueError, TypeError):
        submitted_year = None

    # Helper to lookup program with fallback for 'Engineering' suffix
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
    if program is None:
        return {
            "rule_code": "R11",
            "severity": "HIGH",
            "message": f"Program '{program_ref}' is not registered under this institution's AICTE approved quota.",
            "recommended_action": "Check AICTE approved program titles and academic year.",
        }

    if submitted_year:
        try:
            program_start_year = int(str(program.academic_year).split("-", 1)[0])
            if submitted_year != program_start_year:
                alt = find_program(prog_key, submitted_year)
                if alt and int(str(alt.academic_year).split("-", 1)[0]) == submitted_year:
                    pass
                else:
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
        try:
            start_yr = int(str(p.academic_year).split("-", 1)[0])
            program_map[(p_name, start_yr)] = p
        except (ValueError, TypeError):
            pass

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


def validate_override_request(
    program: Program,
    admission_type: str,
    justification: Optional[str],
    current_intake_data: Dict[str, Any],
) -> Tuple[bool, Optional[str]]:
    """
    Validate authorized, auditable override requests:
    - Rejects if justification is empty or < 20 characters.
    - Rejects if enrolment has reached statutory hard ceiling (> 105% capacity or +3 seats).
    Returns (is_valid, error_message).
    """
    total_capacity = current_intake_data["total_capacity"]
    total_enrolled = current_intake_data["total_enrolled"]

    # Statutory hard ceiling: at most 105% of capacity (or +3 seats, whichever is greater)
    hard_ceiling = max(int(total_capacity * MAX_OVERRIDE_BUFFER_RATIO), total_capacity + MAX_OVERRIDE_BUFFER_SEATS)
    if total_enrolled >= hard_ceiling:
        return False, (
            f"Statutory Hard Ceiling Reached: Total enrolment ({total_enrolled}) has reached the "
            f"statutory limit ({hard_ceiling}) for program '{program.name}'. "
            f"AICTE regulations strictly forbid further admissions."
        )

    clean_just = str(justification or "").strip()
    if len(clean_just) < 20:
        return False, (
            "Invalid justification: An over-admission override strictly requires a formal regulatory "
            "explanation of at least 20 characters (e.g. AICTE approval letter ref, court directive, or reconciliation details)."
        )

    return True, None


def intake_check(
    program_id: int,
    session: Session,
    program: Optional[Program] = None,
    settings: Optional[Dict[str, str]] = None,
    regular_count: Optional[int] = None,
    super_count: Optional[int] = None,
    target_admission_type: Optional[str] = None,
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

    if regular_count is None or super_count is None:
        counts = dict(
            session.exec(
                select(Student.admission_type, func.count(Student.id))
                .where(Student.program_id == program_id, Student.status == "ACTIVE")
                .group_by(Student.admission_type)
            ).all()
        )
        if regular_count is None:
            regular_count = counts.get("REGULAR", 0)
        if super_count is None:
            super_count = counts.get("SUPERNUMERARY", 0)

    approved = program.approved_intake

    if settings is None:
        settings = get_intake_settings(session)

    try:
        warning_threshold = float(settings.get("intake_warn_threshold", "0.90"))
        block_threshold = float(settings.get("intake_block_threshold", "1.00"))
        default_super_cap = float(settings.get("supernumerary_cap_default", "0.10"))
    except ValueError as exc:
        raise ValueError("Intake policy settings must contain numeric values") from exc

    # Respect program-level supernumerary cap; fallback to system default if None
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
        select(Student.program_id, Student.admission_type, func.count(Student.id))
        .where(Student.program_id.in_(prog_ids), Student.status == "ACTIVE")
        .group_by(Student.program_id, Student.admission_type)
    ).all()

    counts_by_prog: Dict[int, Dict[str, int]] = defaultdict(lambda: {"REGULAR": 0, "SUPERNUMERARY": 0})
    for p_id, adm_type, cnt in counts_rows:
        counts_by_prog[p_id][adm_type] = cnt

    return [
        intake_check(
            program_id=p.id,
            session=session,
            program=p,
            settings=settings,
            regular_count=counts_by_prog[p.id]["REGULAR"],
            super_count=counts_by_prog[p.id]["SUPERNUMERARY"],
            target_admission_type=target_admission_type,
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
