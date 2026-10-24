"""
Immutable, hash-chained audit logging for APAAR Verify.
Every event is linked to the previous entry via SHA256 hashes to ensure tamper evidence.
"""

from datetime import datetime
import hashlib
import json
from typing import Any, Optional, Tuple
from sqlmodel import Session, select

from app.models import AuditLog, User, utc_now


def compute_row_hash(
    prev_hash: str,
    user_id: Optional[int],
    username: str,
    action: str,
    entity: str,
    entity_id: Optional[str],
    details: Optional[str],
    timestamp: datetime,
) -> str:
    """
    Calculate SHA256 hash across canonical JSON serialization of row fields.
    Guarantees deterministic, reproducible hashes.
    """
    payload = {
        "prev_hash": prev_hash,
        "user_id": user_id,
        "username": username,
        "action": action,
        "entity": entity,
        "entity_id": str(entity_id) if entity_id is not None else None,
        "details": details,
        "timestamp": timestamp.isoformat(),
    }
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def log_action(
    session: Session,
    user: Any,
    action: str,
    entity: str,
    entity_id: Any = None,
    details: Any = None,
) -> AuditLog:
    """
    Record an immutable audit log entry chained to the previous record.
    The first row uses 'GENESIS' as its prev_hash.
    """
    # Extract user ID and username from User model, dict, string, or fallback
    if isinstance(user, User):
        user_id = user.id
        username = user.username
    elif isinstance(user, dict):
        user_id = user.get("id")
        username = user.get("username", "anonymous")
    elif isinstance(user, str):
        user_id = None
        username = user
    else:
        user_id = None
        username = "system"

    # Normalize entity ID and details
    entity_id_str = str(entity_id) if entity_id is not None else None
    if isinstance(details, (dict, list)):
        details_str = json.dumps(details, sort_keys=True)
    else:
        details_str = str(details) if details is not None else None

    # Fetch the latest audit row to chain hashes
    statement = select(AuditLog).order_by(AuditLog.id.desc()).limit(1)
    last_entry = session.exec(statement).first()
    prev_hash = last_entry.row_hash if last_entry else "GENESIS"

    # Current timezone-aware timestamp
    timestamp = utc_now()

    # Compute row SHA256 hash
    row_hash = compute_row_hash(
        prev_hash=prev_hash,
        user_id=user_id,
        username=username,
        action=action,
        entity=entity,
        entity_id=entity_id_str,
        details=details_str,
        timestamp=timestamp,
    )

    # Persist the new chained log entry
    log_entry = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        entity=entity,
        entity_id=entity_id_str,
        details=details_str,
        timestamp=timestamp,
        prev_hash=prev_hash,
        row_hash=row_hash,
    )
    session.add(log_entry)
    session.commit()
    session.refresh(log_entry)
    return log_entry


def verify_chain(session: Session) -> Tuple[bool, Optional[int]]:
    """
    Walk all audit log rows in ascending ID order to verify cryptographic chain integrity.
    Returns:
        (True, None) if the hash chain is fully intact.
        (False, broken_id) with the ID of the first tampered or disconnected row.
    """
    statement = select(AuditLog).order_by(AuditLog.id.asc())
    rows = session.exec(statement).all()

    if not rows:
        return (True, None)

    expected_prev_hash = "GENESIS"

    for row in rows:
        # Check linkage to previous row's hash
        if row.prev_hash != expected_prev_hash:
            return (False, row.id)

        # Recompute and verify current row's SHA256 hash
        computed_hash = compute_row_hash(
            prev_hash=row.prev_hash,
            user_id=row.user_id,
            username=row.username,
            action=row.action,
            entity=row.entity,
            entity_id=row.entity_id,
            details=row.details,
            timestamp=row.timestamp,
        )

        if row.row_hash != computed_hash:
            return (False, row.id)

        expected_prev_hash = row.row_hash

    return (True, None)
