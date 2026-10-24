"""
Database configuration and session management for APAAR Verify.
Supports SQLite (local fallback) and PostgreSQL via DATABASE_URL.
"""

import os
from typing import Generator
from dotenv import load_dotenv
from sqlmodel import SQLModel, Session, create_engine

# Load environment variables from .env
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///apaar.db"

# Normalise postgres:// scheme if provided by hosted platforms
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Configure engine with dialect-appropriate pooling
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        echo=False,
        connect_args={"check_same_thread": False},
    )
else:
    engine = create_engine(
        DATABASE_URL,
        echo=False,
        pool_pre_ping=True,
        pool_recycle=300,
    )

# Import all models before create_all to ensure registration in SQLModel metadata
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


def create_db_and_tables():
    """Create all tables registered in SQLModel metadata."""
    SQLModel.metadata.create_all(engine)


def reset_db():
    """Drop all tables and recreate them cleanly."""
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)


def get_session() -> Generator[Session, None, None]:
    """FastAPI dependency yielding an active SQLModel session."""
    with Session(engine) as session:
        yield session
