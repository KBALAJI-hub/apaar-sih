"""
APAAR Registry Adapter

Mock adapter for the central APAAR (Automated Permanent Academic Account Registry) / DigiLocker service.
Provides format validation, registry lookups, and identity matching.
"""

from datetime import date, datetime
from typing import Any, Dict, Optional, Tuple
from sqlmodel import Session, select

from app.models import ApaarRegistry


def validate_apaar_format(apaar_id: Any) -> bool:
    """
    Validate that an APAAR ID has valid formatting.

    Returns True only for exactly 12 ASCII numeric digits ('0'-'9').
    Non-string types and non-ASCII unicode digits (e.g. Arabic/Devanagari) are rejected.
    """
    if not isinstance(apaar_id, str):
        return False
    if len(apaar_id) != 12:
        return False
    return all("0" <= char <= "9" for char in apaar_id)


def validate_dob_format(dob: Any) -> Optional[str]:
    """
    Validate and normalize date of birth to standard YYYY-MM-DD format matching the data model.
    Accepts string 'YYYY-MM-DD' or date/datetime objects.
    Returns normalized 'YYYY-MM-DD' string if valid, None otherwise.
    """
    if isinstance(dob, (date, datetime)):
        return dob.strftime("%Y-%m-%d")

    if not isinstance(dob, str):
        return None

    dob_str = dob.strip()
    try:
        parsed = datetime.strptime(dob_str, "%Y-%m-%d")
        return parsed.strftime("%Y-%m-%d")
    except ValueError:
        return None


def lookup_apaar(apaar_id: str, session: Session) -> Optional[Dict[str, Any]]:
    """
    Query the ApaarRegistry table and return record as a dictionary, or None if not found.
    Database errors are NOT swallowed; they propagate up for proper error handling.
    """
    # NOTE: lookup_apaar is the single place to swap in the real APAAR/DigiLocker API.
    if not validate_apaar_format(apaar_id):
        return None

    if session is None:
        raise ValueError("A valid SQLModel/SQLAlchemy Session is required for lookup_apaar")

    statement = select(ApaarRegistry).where(ApaarRegistry.apaar_id == apaar_id)
    record = session.exec(statement).first()
    if not record:
        return None

    return {
        "apaar_id": record.apaar_id,
        "full_name": record.full_name,
        "dob": record.dob,
        "gender": record.gender,
    }


def load_registry_map(session: Session) -> Dict[str, Dict[str, Any]]:
    """
    Load all ApaarRegistry records into a dictionary keyed by apaar_id.
    Enables bulk validation to run with a single query rather than one query per row.
    """
    if session is None:
        raise ValueError("A valid SQLModel/SQLAlchemy Session is required for load_registry_map")

    statement = select(ApaarRegistry)
    records = session.exec(statement).all()
    return {
        r.apaar_id: {
            "apaar_id": r.apaar_id,
            "full_name": r.full_name,
            "dob": r.dob,
            "gender": r.gender,
        }
        for r in records
    }


def match_identity(
    apaar_id: str,
    name: str,
    dob: Any,
    session: Session,
) -> Tuple[bool, bool]:
    """
    Verify identity by comparing submitted name and DOB against registry record.

    Guards:
    - Empty or whitespace-only names never match (name_ok = False).
    - DOB must strictly match the YYYY-MM-DD model specification.

    Returns:
        (name_ok, dob_ok): Tuple of booleans indicating matching results.
    """
    record = lookup_apaar(apaar_id, session)
    if not record:
        return (False, False)

    # Clean and guard input names
    input_name = str(name or "").strip()
    registry_name = str(record.get("full_name") or "").strip()

    if not input_name or not registry_name:
        name_ok = False
    else:
        # Fuzzy match on student name (threshold: 85%)
        try:
            from rapidfuzz import fuzz

            name_similarity = fuzz.token_sort_ratio(input_name.lower(), registry_name.lower())
        except ImportError:
            import difflib

            name_similarity = (
                difflib.SequenceMatcher(None, input_name.lower(), registry_name.lower()).ratio() * 100
            )

        name_ok = name_similarity >= 85

    # Validate and compare DOB format (YYYY-MM-DD)
    norm_input_dob = validate_dob_format(dob)
    norm_registry_dob = validate_dob_format(record.get("dob"))

    dob_ok = bool(
        norm_input_dob
        and norm_registry_dob
        and norm_input_dob == norm_registry_dob
    )

    return (name_ok, dob_ok)
