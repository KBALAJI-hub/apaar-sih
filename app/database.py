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

# Resolve database URL from either DATABASE_URL or DB_URL
DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("DB_URL")
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///apaar.db"

# Normalise legacy postgres:// scheme to postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

IS_POSTGRES = DATABASE_URL.startswith("postgresql")
IS_SQLITE = DATABASE_URL.startswith("sqlite")

# ---------------------------------------------------------------------------
# Engine Configuration with Resilient Connection Pooling
# ---------------------------------------------------------------------------
if IS_SQLITE:
    engine = create_engine(
        DATABASE_URL,
        echo=False,
        connect_args={"check_same_thread": False},
    )
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
    SAFETY GUARD: If connected to hosted PostgreSQL (e.g. Supabase),
    refuses to drop tables unless ALLOW_RESET_DB=true is explicitly set in .env.
    """
    if IS_POSTGRES:
        allow = os.getenv("ALLOW_RESET_DB", "false").lower() in ("true", "1", "yes")
        if not allow:
            raise RuntimeError(
                "CRITICAL SAFETY WARNING: reset_db() was called while connected to a PostgreSQL/Supabase database! "
                "This would drop all AICTE institutions, programs, and student records. "
                "To force a wipe, set ALLOW_RESET_DB=true in your .env file."
            )
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        init_default_settings(session)


def get_session() -> Generator[Session, None, None]:
    """FastAPI dependency yielding an active SQLModel session."""
    with Session(engine) as session:
        yield session


def check_db_connection() -> Dict[str, Any]:
    """
    Diagnostic helper to test database connectivity, dialect, and latency.
    Useful for health checks and status reporting.
    """
    try:
        with engine.connect() as conn:
            version = conn.execute(
                text("SELECT sqlite_version();" if IS_SQLITE else "SELECT version();")
            ).scalar()
            return {
                "status": "healthy",
                "dialect": "sqlite" if IS_SQLITE else "postgresql",
                "connected": True,
                "version": version,
            }
    except Exception as e:
        return {
            "status": "unhealthy",
            "dialect": "sqlite" if IS_SQLITE else "postgresql",
            "connected": False,
            "error": str(e),
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
