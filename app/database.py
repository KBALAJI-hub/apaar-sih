"""
Database configuration, session management, and connection resilience for APAAR Verify.
Supports SQLite (local fallback) and Supabase PostgreSQL via DATABASE_URL.
Compliant with SIH PS 26263 Implementation Plan.
"""

import os
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

# Resolve database URL from either DATABASE_URL or DB_URL, or use disposable test db
TEST_DB_FILENAME = "test_apaar.db"
PRIMARY_DB_FILENAME = "apaar.db"
TEST_DB_PATH = _root_dir / TEST_DB_FILENAME
PRIMARY_DB_PATH = _root_dir / PRIMARY_DB_FILENAME

import sys
import re
import shutil

IS_TESTING = (
    os.getenv("TESTING", "").lower() in ("1", "true", "yes")
    or "pytest" in sys.modules
    or any("unittest" in arg or "test" in Path(arg).name.lower() for arg in sys.argv)
)


def init_test_db(force_refresh: bool = False) -> None:
    """
    Initializes a disposable SQLite test database (test_apaar.db).
    Copies seeded data from apaar.db if available to preserve baseline test fixtures,
    preventing any automated test suite from modifying primary apaar.db.
    """
    if PRIMARY_DB_PATH.exists() and (force_refresh or not TEST_DB_PATH.exists()):
        try:
            if "engine" in globals():
                engine.dispose()
        except Exception:
            pass
        shutil.copyfile(PRIMARY_DB_PATH, TEST_DB_PATH)


if IS_TESTING:
    init_test_db(force_refresh=False)
    DATABASE_URL = f"sqlite:///{TEST_DB_FILENAME}"
else:
    DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("DB_URL")
    if not DATABASE_URL:
        DATABASE_URL = "sqlite:///apaar.db"

# Normalise legacy postgres:// scheme to postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

IS_POSTGRES = DATABASE_URL.startswith("postgresql")
IS_SQLITE = DATABASE_URL.startswith("sqlite")

# ---------------------------------------------------------------------------
# Engine Configuration
# ---------------------------------------------------------------------------
LOCAL_SQLITE_URL = "sqlite:///apaar.db"

if IS_SQLITE:
    engine = create_engine(
        DATABASE_URL,
        echo=False,
        connect_args={"check_same_thread": False},
    )
    fallback_engine = engine
else:
    # Supabase / PostgreSQL Session Pooler configuration:
    # - pool_pre_ping=True: validates connections before query execution
    # - pool_recycle=300: prevents stale connections dropped by pooler (5 min timeout)
    # - pool_size & max_overflow: handles concurrent requests smoothly
    engine = create_engine(
        DATABASE_URL,
        echo=False,
        pool_pre_ping=True,
        pool_recycle=300,
        pool_size=10,
        max_overflow=20,
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
    except Exception as e:
        # Avoid crashing startup if table is not yet accessible
        session.rollback()


def create_db_and_tables():
    """Create all registered SQLModel tables and ensure baseline settings."""
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        init_default_settings(session)


def reset_db():
    """
    Drop all tables and recreate them cleanly.
    SAFETY GUARD: Resetting a shared PostgreSQL/Supabase database is strictly prohibited.
    """
    if IS_POSTGRES:
        raise RuntimeError(
            "CRITICAL SAFETY GUARD: reset_db() is strictly prohibited on PostgreSQL / Supabase "
            "to prevent accidental deletion or modification of shared remote datasets."
        )
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        init_default_settings(session)


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
    Extract safe database identifier (e.g. 'apaar.db' or 'postgres')
    without complete connection URLs, hostnames, usernames, or passwords.
    """
    if not engine.url.database:
        return "apaar.db"
    return Path(engine.url.database).name


def check_db_connection() -> Dict[str, Any]:
    """
    Diagnostic helper to test database connectivity, dialect, and status.
    Strictly redacts usernames, passwords, and sensitive connection details.
    Never returns a complete database connection URL.
    """
    safe_db = get_sanitized_database_name()

    if IS_POSTGRES:
        try:
            with engine.connect() as conn:
                version = conn.execute(text("SELECT version();")).scalar()
                return {
                    "status": "healthy",
                    "mode": "primary (supabase postgresql)",
                    "dialect": "postgresql",
                    "database": safe_db,
                    "connected": True,
                    "version": version,
                }
        except Exception as e:
            return {
                "status": "unhealthy",
                "mode": "primary (supabase postgresql)",
                "dialect": "postgresql",
                "database": safe_db,
                "connected": False,
                "error": redact_credentials(str(e)),
            }

    try:
        with engine.connect() as conn:
            version = conn.execute(text("SELECT sqlite_version();")).scalar()
            return {
                "status": "healthy",
                "mode": "sqlite",
                "dialect": "sqlite",
                "database": safe_db,
                "connected": True,
                "version": version,
            }
    except Exception as e:
        return {
            "status": "unhealthy",
            "mode": "sqlite",
            "dialect": "sqlite",
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
