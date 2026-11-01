"""
Atomic Admission Capacity Concurrency and Locking Service (Phase 5).
Guarantees database-level consistency and race-condition prevention across
single admissions, updates, transfers, and bulk uploads.

Supports:
- PostgreSQL: SELECT ... FOR UPDATE row-level locking on Program, SeatAllocation, and RegulatoryOverride records in consistent ascending ID order.
- SQLite: Thread synchronization and PRAGMA busy_timeout write-serialization.
"""

from contextlib import contextmanager
import threading
from typing import Any, Dict, Iterable, List, Optional, Set, Union
from fastapi import HTTPException, status
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlmodel import Session, select

from app.models import Program, RegulatoryOverride, SeatAllocation

# Process-level reentrant lock for SQLite serialization across threads
_sqlite_lock = threading.RLock()


def get_dialect_name(session: Session) -> str:
    """Detect database dialect name (postgresql, sqlite, etc.)."""
    try:
        bind = session.get_bind()
        return bind.dialect.name.lower()
    except Exception:
        return "postgresql"


def acquire_admission_locks(
    session: Session,
    program_ids: Union[int, Iterable[int]],
    allocation_ids: Optional[Union[int, Iterable[int]]] = None,
    override_ids: Optional[Union[int, Iterable[int]]] = None,
    nowait: bool = False,
    timeout_seconds: Optional[float] = 10.0,
) -> Dict[str, Any]:
    """
    Acquire exclusive database locks on relevant admission capacity entities.
    Strictly orders locks in ascending numeric ID order across entity types
    to eliminate deadlock cycles:
    1. Program (ascending ID)
    2. SeatAllocation (ascending ID)
    3. RegulatoryOverride (ascending ID)
    """
    dialect = get_dialect_name(session)

    # Normalize and sort IDs in ascending order
    p_ids: List[int] = sorted(set(filter(None, [program_ids] if isinstance(program_ids, int) else program_ids)))
    a_ids: List[int] = sorted(set(filter(None, [allocation_ids] if isinstance(allocation_ids, int) else (allocation_ids or []))))
    o_ids: List[int] = sorted(set(filter(None, [override_ids] if isinstance(override_ids, int) else (override_ids or []))))

    locked_programs: Dict[int, Program] = {}
    locked_allocations: Dict[int, SeatAllocation] = {}
    locked_overrides: Dict[int, RegulatoryOverride] = {}

    if dialect == "postgresql":
        # Configure local transaction lock timeout to avoid hanging indefinitely
        if timeout_seconds is not None:
            ms = max(int(timeout_seconds * 1000), 100)
            try:
                session.exec(text(f"SET LOCAL lock_timeout = '{ms}ms';"))
            except Exception:
                pass

        # 1. Lock Program records in ascending order
        for pid in p_ids:
            stmt = select(Program).where(Program.id == pid)
            stmt = stmt.with_for_update(nowait=nowait)
            prog = session.exec(stmt).first()
            if prog:
                locked_programs[pid] = prog

        # 2. Lock SeatAllocation records in ascending order
        for aid in a_ids:
            stmt = select(SeatAllocation).where(SeatAllocation.id == aid)
            stmt = stmt.with_for_update(nowait=nowait)
            alloc = session.exec(stmt).first()
            if alloc:
                locked_allocations[aid] = alloc

        # 3. Lock RegulatoryOverride records in ascending order
        for oid in o_ids:
            stmt = select(RegulatoryOverride).where(RegulatoryOverride.id == oid)
            stmt = stmt.with_for_update(nowait=nowait)
            ov = session.exec(stmt).first()
            if ov:
                locked_overrides[oid] = ov

    else:
        # SQLite dialect
        try:
            session.exec(text("PRAGMA busy_timeout = 30000;"))
        except Exception:
            pass

        for pid in p_ids:
            prog = session.get(Program, pid)
            if prog:
                locked_programs[pid] = prog

        for aid in a_ids:
            alloc = session.get(SeatAllocation, aid)
            if alloc:
                locked_allocations[aid] = alloc

        for oid in o_ids:
            ov = session.get(RegulatoryOverride, oid)
            if ov:
                locked_overrides[oid] = ov

    return {
        "programs": locked_programs,
        "allocations": locked_allocations,
        "overrides": locked_overrides,
    }


@contextmanager
def atomic_admission_scope(
    session: Session,
    program_ids: Union[int, Iterable[int]],
    allocation_ids: Optional[Union[int, Iterable[int]]] = None,
    override_ids: Optional[Union[int, Iterable[int]]] = None,
    timeout_seconds: Optional[float] = 10.0,
    nowait: bool = False,
):
    """
    Context manager establishing an atomic admission transaction boundary.
    - Locks affected Program, SeatAllocation, and RegulatoryOverride records in consistent order.
    - Serializes concurrent admission attempts for the same program/allocation.
    - Handles automatic rollback on any validation failure or error.
    - Maps concurrency lock timeouts or deadlocks to HTTP 409 Conflict.
    """
    dialect = get_dialect_name(session)
    sqlite_acquired = False

    try:
        if dialect == "sqlite":
            _sqlite_lock.acquire()
            sqlite_acquired = True

        locked_entities = acquire_admission_locks(
            session=session,
            program_ids=program_ids,
            allocation_ids=allocation_ids,
            override_ids=override_ids,
            nowait=nowait,
            timeout_seconds=timeout_seconds,
        )

        yield locked_entities

    except (OperationalError, DBAPIError) as e:
        session.rollback()
        err_str = str(e).lower()
        if (
            "lock timeout" in err_str
            or "deadlock" in err_str
            or "database is locked" in err_str
            or "could not obtain lock" in err_str
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Admission capacity conflict: Program seat allocation is currently locked "
                    "by a concurrent transaction. Please retry your request."
                ),
            ) from e
        raise
    except Exception:
        session.rollback()
        raise
    finally:
        if sqlite_acquired:
            _sqlite_lock.release()

