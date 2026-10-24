"""
APAAR Registry Adapter

Mock adapter for the central APAAR (Automated Permanent Academic Account Registry) / DigiLocker service.
"""

from typing import Any, Optional, Tuple


def validate_apaar_format(apaar_id: Any) -> bool:
    """
    Validate that an APAAR ID has valid formatting.

    Returns True only if apaar_id is a string of exactly 12 numeric digits.
    """
    if not isinstance(apaar_id, str):
        return False
    return len(apaar_id) == 12 and apaar_id.isdigit()


def lookup_apaar(apaar_id: str, session: Any = None) -> Optional[dict]:
    """
    Query the ApaarRegistry table and return record as a dictionary or None if not found.
    """
    # NOTE: lookup_apaar is the single place to swap in the real APAAR/DigiLocker API.
    if not validate_apaar_format(apaar_id) or session is None:
        return None

    try:
        from sqlmodel import select
        from app.models import ApaarRegistry

        statement = select(ApaarRegistry).where(ApaarRegistry.apaar_id == apaar_id)
        record = session.exec(statement).first()
        if not record:
            return None

        return {
            "apaar_id": record.apaar_id,
            "full_name": record.full_name,
            "dob": str(record.dob) if record.dob else None,
            "gender": record.gender,
        }
    except Exception:
        # Fallback when database or models are not yet initialized
        return None


def match_identity(
    apaar_id: str, name: str, dob: Any, session: Any = None
) -> Tuple[bool, bool]:
    """
    Verify identity by comparing submitted name and DOB against registry record.

    Returns:
        (name_ok, dob_ok): Tuple of booleans indicating match results.
    """
    record = lookup_apaar(apaar_id, session)
    if not record:
        return (False, False)

    registry_name = str(record.get("full_name") or "").strip().lower()
    input_name = str(name or "").strip().lower()

    # Fuzzy match on student name (threshold: 85%)
    try:
        from rapidfuzz import fuzz

        name_similarity = fuzz.token_sort_ratio(input_name, registry_name)
    except ImportError:
        # Fallback using standard library difflib before rapidfuzz is installed
        import difflib

        name_similarity = (
            difflib.SequenceMatcher(None, input_name, registry_name).ratio() * 100
        )

    name_ok = name_similarity >= 85

    # Exact match on DOB string
    registry_dob = str(record.get("dob") or "").strip()
    input_dob = str(dob or "").strip()
    dob_ok = bool(registry_dob and input_dob and registry_dob == input_dob)

    return (name_ok, dob_ok)
