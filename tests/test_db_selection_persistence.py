"""
Targeted Tests for Supabase PostgreSQL Database Selection and Persistence for APAAR Verify.
Validates:
1. PostgreSQL dialect and Supabase URL configuration
2. Database connection health and /health endpoint
3. Presence of all 10 registered tables and non-empty record counts in Supabase
4. Database session consistency without silent fallback
5. Supabase safety guard preventing remote database drops
6. Data persistence across connection pool resets / engine restarts
7. Intake guard decisions (ALLOW, WARN, BLOCK)
8. Database diagnostics containing no leaked credentials
"""

import sys
import unittest
from fastapi.testclient import TestClient
from sqlmodel import Session, select, func
from sqlalchemy import text

from app.main import app
from app.database import (
    DATABASE_URL,
    IS_SQLITE,
    IS_POSTGRES,
    engine,
    fallback_engine,
    get_session,
    get_db_session,
    check_db_connection,
    reset_db,
)
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

client = TestClient(app, raise_server_exceptions=False)


class TestDatabaseSelectionAndPersistence(unittest.TestCase):
    def test_01_supabase_postgres_dialect_selection(self):
        """Confirm PostgreSQL is the selected dialect and flags are correctly set for Supabase."""
        self.assertEqual(engine.dialect.name, "postgresql", f"Expected postgresql dialect, got {engine.dialect.name}")
        self.assertTrue(IS_POSTGRES, "IS_POSTGRES flag must be True")
        self.assertFalse(IS_SQLITE, "IS_SQLITE flag must be False")
        self.assertTrue(str(engine.url).startswith("postgresql"), f"Engine URL must start with postgresql: {engine.url}")
        self.assertIn("postgres", str(engine.url).lower(), f"Engine URL must point to Supabase postgres: {engine.url}")

    def test_02_database_connection_health(self):
        """Confirm database connection check returns healthy PostgreSQL diagnostic."""
        diag = check_db_connection()
        self.assertEqual(diag.get("status"), "healthy")
        self.assertEqual(diag.get("mode"), "supabase_postgresql")
        self.assertEqual(diag.get("dialect"), "postgresql")
        self.assertTrue(diag.get("connected"))
        self.assertIsNotNone(diag.get("version"))
        self.assertIn("postgres", diag.get("database", "").lower())

        # Verify /health endpoint returns 200 and matches
        resp = client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("status"), "ok")
        self.assertEqual(data.get("database", {}).get("dialect"), "postgresql")
        self.assertTrue(data.get("database", {}).get("connected"))

    def test_03_all_ten_tables_exist_and_populated(self):
        """Confirm all 10 expected tables exist in Supabase and contain seeded data."""
        expected_models = [
            (User, "user"),
            (Institution, "institution"),
            (Program, "program"),
            (ApaarRegistry, "apaarregistry"),
            (Student, "student"),
            (ValidationFlag, "validationflag"),
            (AnomalyAlert, "anomalyalert"),
            (AuditLog, "auditlog"),
            (VerificationLog, "verificationlog"),
            (Setting, "setting"),
        ]

        with Session(engine) as session:
            for model_cls, table_name in expected_models:
                count = session.exec(select(func.count()).select_from(model_cls)).one()
                self.assertGreater(
                    count,
                    0,
                    f"Table {table_name} ({model_cls.__name__}) must exist and have records (found {count})",
                )

    def test_04_session_consistency_no_silent_fallback(self):
        """Confirm sessions consistently bind to engine without silent switching."""
        self.assertIs(
            engine,
            fallback_engine,
            "engine and fallback_engine must reference the same engine instance",
        )

        # get_db_session returns Session bound to engine
        sync_session = get_db_session()
        self.assertIs(sync_session.get_bind(), engine)
        sync_session.close()

        # FastAPI dependency yields Session bound to engine
        session_gen = get_session()
        dep_session = next(session_gen)
        self.assertIs(dep_session.get_bind(), engine)
        try:
            next(session_gen)
        except StopIteration:
            pass

    def test_05_safety_guard_prevents_supabase_reset(self):
        """Confirm reset_db() strictly rejects execution on Supabase PostgreSQL."""
        with self.assertRaises(RuntimeError) as ctx:
            reset_db()
        self.assertIn("CRITICAL SAFETY GUARD", str(ctx.exception))

    def test_06_data_persistence_across_connection_restarts(self):
        """Confirm committed data persists across connection pool disposal."""
        canary_key = "test_persistence_canary"
        canary_val = "verified_persisted_value_123"

        # 1. Insert canary record
        with Session(engine) as session:
            existing = session.exec(select(Setting).where(Setting.key == canary_key)).first()
            if existing:
                session.delete(existing)
                session.commit()
            session.add(Setting(key=canary_key, value=canary_val))
            session.commit()

        # 2. Simulate server restart: dispose connection pool
        engine.dispose()

        # 3. Re-read from a completely fresh connection pool
        with Session(engine) as session:
            canary = session.exec(select(Setting).where(Setting.key == canary_key)).first()
            self.assertIsNotNone(canary, "Canary record must persist after engine connection pool disposal")
            self.assertEqual(canary.value, canary_val)

            # Cleanup canary record
            session.delete(canary)
            session.commit()

        # 4. Verify cleanup persisted
        engine.dispose()
        with Session(engine) as session:
            cleaned = session.exec(select(Setting).where(Setting.key == canary_key)).first()
            self.assertIsNone(cleaned, "Canary record cleanup must persist")

    def test_07_intake_guard_decisions_allow_warn_block(self):
        """Explicitly assert ALLOW, WARN, and BLOCK decisions from the intake check engine."""
        from app.validation import intake_check

        # 1. ALLOW assertion: Program 3
        resp_allow = client.get("/api/v1/programs/3/intake-check")
        self.assertEqual(resp_allow.status_code, 200)
        data_allow = resp_allow.json()
        self.assertEqual(data_allow.get("decision"), "ALLOW", f"Expected ALLOW decision for Program 3, got {data_allow}")
        self.assertLess(data_allow.get("fill_ratio"), 0.90)

        # 2. BLOCK assertion: Program 1
        resp_block = client.get("/api/v1/programs/1/intake-check")
        self.assertEqual(resp_block.status_code, 200)
        data_block = resp_block.json()
        self.assertEqual(data_block.get("decision"), "BLOCK", f"Expected BLOCK decision for Program 1, got {data_block}")
        self.assertGreaterEqual(data_block.get("fill_ratio"), 1.0)

        # 3. WARN assertion: Program with fill ratio between 90% and 100%
        with Session(engine) as session:
            inst = session.exec(select(Institution)).first()
            test_prog = Program(
                name="Intake Test Program",
                level="UG",
                approved_intake=10,
                academic_year="2024-25",
                institution_id=inst.id,
                supernumerary_cap=0.1,
            )
            session.add(test_prog)
            session.commit()
            session.refresh(test_prog)

            test_students = []
            try:
                for i in range(9):
                    st = Student(
                        apaar_id=f"9997000000{i:02d}",
                        student_id=f"INTAKE-DBTEST-{i:02d}",
                        full_name=f"Intake DB Test {i}",
                        dob="2003-01-01",
                        gender="M",
                        category="General",
                        institution_id=inst.id,
                        program_id=test_prog.id,
                        admission_year=2024,
                        admission_type="REGULAR",
                        status="ACTIVE",
                        consent_level=1,
                    )
                    session.add(st)
                    test_students.append(st)
                session.commit()

                # Test via API
                resp_warn = client.get(f"/api/v1/programs/{test_prog.id}/intake-check")
                self.assertEqual(resp_warn.status_code, 200)
                data_warn = resp_warn.json()
                self.assertEqual(data_warn.get("decision"), "WARN", f"Expected WARN decision, got {data_warn}")
                self.assertEqual(data_warn.get("fill_ratio"), 0.9)

                # Direct engine intake_check assertion
                calc = intake_check(test_prog.id, session)
                self.assertEqual(calc["decision"], "WARN")
            finally:
                for st in test_students:
                    session.delete(st)
                session.commit()
                session.delete(test_prog)
                session.commit()

    def test_08_database_diagnostics_contain_no_credentials(self):
        """Confirm database diagnostics and /health endpoint never expose credentials or full URLs."""
        from app.database import redact_credentials, get_sanitized_database_name

        # 1. Check /health endpoint response
        resp = client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        db_info = data.get("database", {})

        # Must not contain connection URL schemes, credentials, or sensitive keywords
        raw_resp = resp.text
        self.assertNotIn("postgresql://", raw_resp)
        self.assertNotIn("postgres://", raw_resp)
        self.assertNotIn("sqlite:///", raw_resp)
        self.assertNotIn("@", raw_resp)
        self.assertNotIn("password", raw_resp.lower())

        # Preserves useful diagnostic info
        self.assertEqual(db_info.get("status"), "healthy")
        self.assertEqual(db_info.get("dialect"), "postgresql")
        self.assertTrue(db_info.get("connected"))
        self.assertIsNotNone(db_info.get("version"))
        self.assertIn("postgres", db_info.get("database", "").lower())

        # 2. Test redact_credentials function directly on sample connection strings
        sensitive_url = "postgresql://my_db_user:SuperSecretPassword123@aws-pooler.supabase.com:6543/production_apaar_db?sslmode=require"
        redacted = redact_credentials(sensitive_url)
        self.assertNotIn("my_db_user", redacted)
        self.assertNotIn("SuperSecretPassword123", redacted)
        self.assertIn("://***:***@", redacted)

        # 3. Test safe database name extractor
        self.assertIn("postgres", get_sanitized_database_name().lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
