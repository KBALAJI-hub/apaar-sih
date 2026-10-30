"""
Database configuration, session management, and connection resilience for APAAR Verify.
Supabase PostgreSQL is the sole, authoritative database for the project.
Compliant with SIH PS 26263 Implementation Plan.
"""

import os
import re
import sys
from pathlib import Path
from typing import Generator, Dict, Any, Optional
from dotenv import load_dotenv
from sqlalchemy import text
from sqlmodel import SQLModel, Session, create_engine, select

# ---------------------------------------------------------------------------
# Environment Variable Loading
# ---------------------------------------------------------------------------
# Search multiple common locations for .env files to ensure reliable loading
_current_file = Path(__file__).resolve()
_app_dir = _current_file.parent
_root_dir = _app_dir.parent

# Load from project root, then app/.env
load_dotenv(_root_dir / ".env")
load_dotenv(_app_dir / ".env")
load_dotenv()  # Fallback to current working directory

# ---------------------------------------------------------------------------
# Authoritative Database URL Resolution (Supabase PostgreSQL)
# ---------------------------------------------------------------------------
DATABASE_URL = (
    os.getenv("SUPABASE_DATABASE_URL")
    or os.getenv("DATABASE_URL")
    or os.getenv("POSTGRES_URL")
)

if not DATABASE_URL or not any(
    DATABASE_URL.startswith(p)
    for p in ("postgresql://", "postgres://", "postgresql+")
):
    raise RuntimeError(
        "Supabase PostgreSQL is the authoritative database for APAAR Verify. "
        "Please provide a valid PostgreSQL connection URL in SUPABASE_DATABASE_URL or DATABASE_URL."
    )

# Normalize legacy postgres:// scheme and select available DBAPI driver
driver = None
try:
    import psycopg  # psycopg v3 (default in requirements.txt)
    driver = "psycopg"
except ImportError:
    try:
        import psycopg2  # psycopg2 fallback
        driver = "psycopg2"
    except ImportError:
        pass

if DATABASE_URL.startswith("postgresql://") or DATABASE_URL.startswith("postgres://"):
    target_driver = f"+{driver}" if driver else ""
    DATABASE_URL = re.sub(r"^postgres(?:ql)?://", f"postgresql{target_driver}://", DATABASE_URL)

IS_POSTGRES = True
IS_SQLITE = False


def init_test_db(force_refresh: bool = False) -> None:
    """
    Backwards compatibility stub.
    Supabase PostgreSQL is the sole authoritative database; no local test DB initialization required.
    """
    pass


# ---------------------------------------------------------------------------
# Supabase PostgreSQL Engine Configuration
# ---------------------------------------------------------------------------
# Supabase / PostgreSQL Session Pooler configuration:
# - pool_pre_ping=True: validates connections before query execution
# - pool_recycle=300: prevents stale connections dropped by pooler (5 min timeout)
# - pool_size & max_overflow: handles concurrent requests smoothly
# - prepare_threshold=None: disables client-side prepared statements on transaction poolers (:6543)
pg_connect_args = {}
if ":6543" in DATABASE_URL:
    pg_connect_args["prepare_threshold"] = None

engine = create_engine(
    DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    pool_recycle=300,
    pool_size=10,
    max_overflow=20,
    connect_args=pg_connect_args,
)
fallback_engine = engine

# ---------------------------------------------------------------------------
# Model Imports for Metadata Registration
# ---------------------------------------------------------------------------
from app.models import (
    User,
    Institution,
    Program,
    ApaarRegistry,
    Student,
    ValidationFlag,
    AnomalyAlert,
    AuditLog,
    VerificationLog,
    Setting,
)

# ---------------------------------------------------------------------------
# Default Policy Thresholds (SIH PS 26263 D7)
# ---------------------------------------------------------------------------
DEFAULT_SYSTEM_SETTINGS = {
    "intake_warn_threshold": "0.90",
    "intake_block_threshold": "1.00",
    "nri_outlier_threshold": "0.25",
    "yoy_surge_threshold": "2.00",
    "supernumerary_cap_default": "0.10",
}


def init_default_settings(session: Session) -> None:
    """Ensure baseline system threshold settings exist in the database."""
    try:
        existing_keys = {
            s.key for s in session.exec(select(Setting)).all()
        }
        added = False
        for key, val in DEFAULT_SYSTEM_SETTINGS.items():
            if key not in existing_keys:
                session.add(Setting(key=key, value=val))
                added = True
        if added:
            session.commit()
    except Exception:
        session.rollback()


def create_db_and_tables():
    """
    Ensure all registered SQLModel tables exist on Supabase PostgreSQL.
    SQLModel.metadata.create_all uses checkfirst=True by default to only create missing tables safely.
    """
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        init_default_settings(session)


def reset_db():
    """
    SAFETY GUARD: Resetting the live Supabase PostgreSQL database is strictly prohibited.
    """
    raise RuntimeError(
        "CRITICAL SAFETY GUARD: reset_db() is strictly prohibited on PostgreSQL / Supabase "
        "to prevent accidental deletion or modification of remote datasets."
    )


def get_session() -> Generator[Session, None, None]:
    """FastAPI dependency yielding an active SQLModel session."""
    with Session(engine) as session:
        yield session


def get_db_session() -> Session:
    """Synchronous helper returning an active SQLModel Session."""
    return Session(engine)


def redact_credentials(text_or_url: str) -> str:
    """
    Remove passwords, usernames, and complete connection URLs from string.
    Replaces patterns like ://user:pass@host with ://***:***@host or redacts auth tokens.
    """
    if not text_or_url:
        return ""
    # Mask user:password@ or user@ in connection URI
    redacted = re.sub(r"://[^@\s]+@", r"://***:***@", str(text_or_url))
    # Mask password parameters in query string
    redacted = re.sub(r"(password|pwd|secret)=([^&\s]+)", r"\1=***", redacted, flags=re.IGNORECASE)
    return redacted


def get_sanitized_database_name() -> str:
    """
    Extract safe database identifier (e.g. 'postgres')
    without complete connection URLs, hostnames, usernames, or passwords.
    """
    if not engine.url.database:
        return "postgres"
    return Path(engine.url.database).name


def check_db_connection() -> Dict[str, Any]:
    """
    Diagnostic helper to test database connectivity, dialect, and status.
    Strictly redacts usernames, passwords, and sensitive connection details.
    Never returns a complete database connection URL.
    """
    safe_db = get_sanitized_database_name()
    try:
        with engine.connect() as conn:
            version = conn.execute(text("SELECT version();")).scalar()
            return {
                "status": "healthy",
                "mode": "supabase_postgresql",
                "dialect": "postgresql",
                "database": safe_db,
                "connected": True,
                "version": version,
            }
    except Exception as e:
        return {
            "status": "unhealthy",
            "mode": "supabase_postgresql",
            "dialect": "postgresql",
            "database": safe_db,
            "connected": False,
            "error": redact_credentials(str(e)),
        }


# ---------------------------------------------------------------------------
# High-Performance In-Memory Cache Helpers for Bulk Validation
# (Prevents hundreds of network round-trips to Supabase during CSV uploads)
# ---------------------------------------------------------------------------
def get_cached_registry_apaar_ids(session: Session) -> set[str]:
    """Load all valid APAAR IDs from ApaarRegistry into an in-memory set for O(1) checks."""
    result = session.exec(select(ApaarRegistry.apaar_id)).all()
    return set(result)


def get_cached_existing_apaar_ids(session: Session) -> set[str]:
    """Load all enrolled APAAR IDs from Student into an in-memory set for O(1) duplicate checks."""
    result = session.exec(select(Student.apaar_id)).all()
    return set(result)
