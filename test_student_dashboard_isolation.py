"""
Focused Security Regression Test Suite for Student Dashboard Account-to-Record Isolation.
Complies with P0 Security Requirements (SIH PS 26263):
1. Correct student mapping.
2. No matching student (controlled 404).
3. Duplicate matching records (controlled 409).
4. Conflicting APAAR ID and username mappings (controlled 409).
5. Missing or insufficient identifiers (fail closed, controlled 400).
6. Database lookup failure (controlled 500 with safe logging).
7. Confirming that a failed mapping NEVER exposes another student's data.
"""

import logging
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from sqlalchemy.exc import OperationalError

from app.main import app
from app.database import engine
from app.models import Student, User, Institution, Program
from app.security import sign_record
from app.auth import create_access_token
from app.routers.verify import mask_identifier, resolve_authenticated_student


class TestStudentDashboardIsolation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up test institution, program, and isolated test students."""
        cls.client = TestClient(app, raise_server_exceptions=False)

        with Session(engine) as session:
            inst = session.exec(select(Institution)).first()
            if not inst:
                inst = Institution(
                    aicte_id="1-TEST-INST-01",
                    name="Test Engineering College",
                    state="Karnataka",
                    type="Engineering",
                    api_key="test-api-key-isolation-01",
                )
                session.add(inst)
                session.commit()
                session.refresh(inst)

            prog = session.exec(select(Program).where(Program.institution_id == inst.id)).first()
            if not prog:
                prog = Program(
                    institution_id=inst.id,
                    name="Computer Science and Engineering",
                    level="UG",
                    academic_year="2024-25",
                    approved_intake=60,
                )
                session.add(prog)
                session.commit()
                session.refresh(prog)

            cls.inst_id = inst.id
            cls.prog_id = prog.id

            # Student Alpha (Primary Test Student)
            cls.stu_alpha = session.exec(
                select(Student).where(Student.apaar_id == "888000000001")
            ).first()
            if not cls.stu_alpha:
                cls.stu_alpha = Student(
                    apaar_id="888000000001",
                    student_id="SEC-ISO-001",
                    full_name="Target Student Alpha",
                    dob="2003-05-10",
                    gender="M",
                    category="GENERAL",
                    institution_id=cls.inst_id,
                    program_id=cls.prog_id,
                    admission_year=2024,
                    admission_type="REGULAR",
                    status="ACTIVE",
                    consent_level=1,
                )
                session.add(cls.stu_alpha)
                session.commit()
                session.refresh(cls.stu_alpha)
            cls.stu_alpha.record_signature = sign_record(cls.stu_alpha, session)
            session.add(cls.stu_alpha)

            # Student Beta (Other Student - must never be leaked)
            cls.stu_beta = session.exec(
                select(Student).where(Student.apaar_id == "888000000002")
            ).first()
            if not cls.stu_beta:
                cls.stu_beta = Student(
                    apaar_id="888000000002",
                    student_id="SEC-ISO-002",
                    full_name="Other Student Beta",
                    dob="2003-11-20",
                    gender="F",
                    category="GENERAL",
                    institution_id=cls.inst_id,
                    program_id=cls.prog_id,
                    admission_year=2024,
                    admission_type="REGULAR",
                    status="ACTIVE",
                    consent_level=2,
                )
                session.add(cls.stu_beta)
                session.commit()
                session.refresh(cls.stu_beta)
            cls.stu_beta.record_signature = sign_record(cls.stu_beta, session)
            session.add(cls.stu_beta)

            # User for Student Alpha (roll number user)
            u_alpha = session.exec(select(User).where(User.username == "SEC-ISO-001")).first()
            if not u_alpha:
                u_alpha = User(
                    username="SEC-ISO-001",
                    role="STUDENT",
                    full_name="Target Student Alpha",
                    password_hash="mock_hash",
                    apaar_id=None,
                )
                session.add(u_alpha)

            # User for non-existent roll number
            u_unmapped = session.exec(select(User).where(User.username == "ROLL-NONEXISTENT-999")).first()
            if not u_unmapped:
                u_unmapped = User(
                    username="ROLL-NONEXISTENT-999",
                    role="STUDENT",
                    full_name="Unmapped Roll Student",
                    password_hash="mock_hash",
                    apaar_id=None,
                )
                session.add(u_unmapped)

            session.commit()

    def get_auth_client(self, claims: dict) -> TestClient:
        """Create a TestClient authenticated with a JWT containing the given claims."""
        token = create_access_token(claims)
        client = TestClient(app, cookies={"access_token": token}, raise_server_exceptions=False)
        return client

    # -----------------------------------------------------------------------
    # 1. Correct student mapping
    # -----------------------------------------------------------------------
    def test_01_correct_student_mapping_via_apaar(self):
        """Authenticated student with verified APAAR ID maps unambiguously to their own record."""
        client = self.get_auth_client({
            "sub": "student:888000000001",
            "role": "STUDENT",
            "apaar_id": "888000000001",
        })
        resp = client.get("/student/dashboard")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Target Student Alpha", resp.text)
        self.assertIn("SEC-ISO-001", resp.text)
        self.assertIn("8880 0000 0001", resp.text)
        # Verify Other Student Beta is not exposed
        self.assertNotIn("Other Student Beta", resp.text)
        self.assertNotIn("SEC-ISO-002", resp.text)

    def test_01b_correct_student_mapping_via_student_id(self):
        """Authenticated student with verified roll number (student_id) maps unambiguously."""
        client = self.get_auth_client({
            "sub": "SEC-ISO-001",
            "role": "STUDENT",
        })
        resp = client.get("/student/dashboard")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Target Student Alpha", resp.text)
        self.assertIn("SEC-ISO-001", resp.text)
        self.assertNotIn("Other Student Beta", resp.text)

    # -----------------------------------------------------------------------
    # 2. No matching student (Controlled HTTP 404)
    # -----------------------------------------------------------------------
    def test_02_no_matching_student_returns_404(self):
        """Authenticated student whose identifiers do not exist returns controlled HTTP 404."""
        # Non-existent APAAR ID
        client = self.get_auth_client({
            "sub": "student:888999999999",
            "role": "STUDENT",
            "apaar_id": "888999999999",
        })
        resp = client.get("/student/dashboard")
        self.assertEqual(resp.status_code, 404)
        self.assertIn("not found", resp.json().get("detail", "").lower())
        # Zero student data leakage
        self.assertNotIn("Target Student Alpha", resp.text)
        self.assertNotIn("Other Student Beta", resp.text)

    def test_02b_no_matching_roll_number_returns_404(self):
        """Authenticated student whose roll number does not exist returns controlled HTTP 404."""
        client = self.get_auth_client({
            "sub": "ROLL-NONEXISTENT-999",
            "role": "STUDENT",
        })
        resp = client.get("/student/dashboard")
        self.assertEqual(resp.status_code, 404)
        self.assertIn("not found", resp.json().get("detail", "").lower())
        self.assertNotIn("Target Student Alpha", resp.text)
        self.assertNotIn("Other Student Beta", resp.text)

    # -----------------------------------------------------------------------
    # 3. Duplicate matching records (Controlled HTTP 409)
    # -----------------------------------------------------------------------
    def test_03_duplicate_matching_records_returns_409(self):
        """Duplicate matching records for the same identifier trigger controlled HTTP 409."""
        dup_apaar = "888000000099"
        with Session(engine) as session:
            # Create two student records with the same APAAR ID
            s1 = Student(
                apaar_id=dup_apaar,
                student_id="DUP-ISO-01",
                full_name="Duplicate One",
                dob="2003-01-01",
                gender="M",
                category="GENERAL",
                institution_id=self.inst_id,
                program_id=self.prog_id,
                admission_year=2024,
                status="ACTIVE",
            )
            s2 = Student(
                apaar_id=dup_apaar,
                student_id="DUP-ISO-02",
                full_name="Duplicate Two",
                dob="2003-02-02",
                gender="F",
                category="GENERAL",
                institution_id=self.inst_id,
                program_id=self.prog_id,
                admission_year=2024,
                status="ACTIVE",
            )
            session.add(s1)
            session.add(s2)
            session.commit()

        try:
            client = self.get_auth_client({
                "sub": f"student:{dup_apaar}",
                "role": "STUDENT",
                "apaar_id": dup_apaar,
            })
            resp = client.get("/student/dashboard")
            self.assertEqual(resp.status_code, 409)
            self.assertIn("multiple matching", resp.json().get("detail", "").lower())
            # Ensure neither duplicate is exposed
            self.assertNotIn("Duplicate One", resp.text)
            self.assertNotIn("Duplicate Two", resp.text)
            self.assertNotIn("Target Student Alpha", resp.text)
        finally:
            # Clean up duplicates
            with Session(engine) as session:
                dups = session.exec(select(Student).where(Student.apaar_id == dup_apaar)).all()
                for d in dups:
                    session.delete(d)
                session.commit()

    # -----------------------------------------------------------------------
    # 4. Conflicting APAAR ID and username mappings (Controlled HTTP 409)
    # -----------------------------------------------------------------------
    def test_04a_conflicting_apaar_and_username_student_ids_returns_409(self):
        """When APAAR ID maps to Student Alpha and username maps to Student Beta, reject with 409."""
        client = self.get_auth_client({
            "sub": "SEC-ISO-002",  # Belongs to Student Beta
            "role": "STUDENT",
            "apaar_id": "888000000001",  # Belongs to Student Alpha
        })
        resp = client.get("/student/dashboard")
        self.assertEqual(resp.status_code, 409)
        self.assertIn("conflicting", resp.json().get("detail", "").lower())
        # Zero student data leaked
        self.assertNotIn("Target Student Alpha", resp.text)
        self.assertNotIn("Other Student Beta", resp.text)

    def test_04b_conflicting_apaar_in_token_username_prefix_returns_409(self):
        """When user.apaar_id conflicts with username 'student:<different_apaar>', reject with 409."""
        client = self.get_auth_client({
            "sub": "student:888000000002",  # Beta's APAAR
            "role": "STUDENT",
            "apaar_id": "888000000001",  # Alpha's APAAR
        })
        resp = client.get("/student/dashboard")
        self.assertEqual(resp.status_code, 409)
        self.assertIn("mismatch", resp.json().get("detail", "").lower())
        self.assertNotIn("Target Student Alpha", resp.text)
        self.assertNotIn("Other Student Beta", resp.text)

    def test_04c_candidate_apaar_conflicts_with_user_apaar_returns_409(self):
        """When student resolved by username has an APAAR ID differing from token's apaar_id, reject with 409."""
        client = self.get_auth_client({
            "sub": "SEC-ISO-002",  # Resolves to Student Beta (apaar: 888000000002)
            "role": "STUDENT",
            "apaar_id": "888999000111",  # Unrelated APAAR
        })
        resp = client.get("/student/dashboard")
        self.assertEqual(resp.status_code, 409)
        self.assertIn("conflicting", resp.json().get("detail", "").lower())
        self.assertNotIn("Other Student Beta", resp.text)

    # -----------------------------------------------------------------------
    # 5. Missing identifiers (Fail closed, Controlled HTTP 400)
    # -----------------------------------------------------------------------
    def test_05a_missing_all_identifiers_fails_closed(self):
        """User with no APAAR ID and empty username fails closed with HTTP 400; never guesses."""
        # Using User model directly with resolve_authenticated_student
        with Session(engine) as session:
            empty_user = User(
                id=99991,
                username="",
                role="STUDENT",
                apaar_id=None,
                full_name="Empty User",
                password_hash="",
            )
            with self.assertRaises(Exception) as cm:
                resolve_authenticated_student(empty_user, session)
            self.assertEqual(cm.exception.status_code, 400)
            self.assertIn("missing or insufficient", cm.exception.detail.lower())

    def test_05b_insufficient_username_prefix_fails_closed(self):
        """User with username='student:' without APAAR suffix and apaar_id=None fails closed with 400."""
        with Session(engine) as session:
            malformed_user = User(
                id=99992,
                username="student:",
                role="STUDENT",
                apaar_id=None,
                full_name="Malformed User",
                password_hash="",
            )
            with self.assertRaises(Exception) as cm:
                resolve_authenticated_student(malformed_user, session)
            self.assertEqual(cm.exception.status_code, 400)
            self.assertIn("missing or insufficient", cm.exception.detail.lower())

    def test_05c_whitespace_only_identifiers_fails_closed(self):
        """User with whitespace-only identifiers fails closed with 400."""
        with Session(engine) as session:
            ws_user = User(
                id=99993,
                username="   ",
                role="STUDENT",
                apaar_id="   ",
                full_name="Whitespace User",
                password_hash="",
            )
            with self.assertRaises(Exception) as cm:
                resolve_authenticated_student(ws_user, session)
            self.assertEqual(cm.exception.status_code, 400)
            self.assertIn("missing or insufficient", cm.exception.detail.lower())

    # -----------------------------------------------------------------------
    # 6. Database lookup failure (Controlled HTTP 500 & Safe Logging)
    # -----------------------------------------------------------------------
    def test_06_database_error_returns_controlled_500_safely_logged(self):
        """Simulated DB error returns controlled HTTP 500 without leaking sensitive info."""
        # Use existing SEC-ISO-001 user so get_current_user succeeds via select(User)
        client = self.get_auth_client({
            "sub": "SEC-ISO-001",
            "role": "STUDENT",
        })

        real_exec = Session.exec

        def failing_exec(sess_self, statement, *args, **kwargs):
            stmt_str = str(statement).lower()
            if "student" in stmt_str and "user" not in stmt_str:
                raise OperationalError("connection lost", {}, None)
            return real_exec(sess_self, statement, *args, **kwargs)

        with patch.object(Session, "exec", side_effect=failing_exec, autospec=True):
            with self.assertLogs("app.routers.verify", level="ERROR") as log_capture:
                resp = client.get("/student/dashboard")
                self.assertEqual(resp.status_code, 500)
                self.assertIn("database error", resp.json().get("detail", "").lower())
                # Verify that the full APAAR ID is NOT logged in the error log
                for log_msg in log_capture.output:
                    self.assertNotIn("888000000001", log_msg)

    def test_06b_resolve_authenticated_student_db_error_direct(self):
        """Direct call to resolve_authenticated_student on DB error logs safely and raises HTTP 500."""
        with Session(engine) as session:
            test_user = User(
                id=99994,
                username="SEC-ISO-001",
                role="STUDENT",
                apaar_id="888000000001",
                full_name="Test Student",
                password_hash="",
            )
            with patch.object(Session, "exec", side_effect=OperationalError("connection lost", {}, None)):
                with self.assertLogs("app.routers.verify", level="ERROR") as log_capture:
                    from fastapi import HTTPException
                    with self.assertRaises(HTTPException) as cm:
                        resolve_authenticated_student(test_user, session)
                    self.assertEqual(cm.exception.status_code, 500)
                    self.assertIn("database error", cm.exception.detail.lower())
                    for log_msg in log_capture.output:
                        self.assertNotIn("888000000001", log_msg)

    # -----------------------------------------------------------------------
    # 7. Failed mapping never exposes another student's data
    # -----------------------------------------------------------------------
    def test_07_failed_mappings_never_expose_other_students(self):
        """Every failure scenario must never return another student's academic or personal data."""
        test_cases = [
            # 404: Nonexistent student
            {"sub": "student:999000000000", "role": "STUDENT", "apaar_id": "999000000000"},
            # 409: Conflicting student IDs
            {"sub": "SEC-ISO-002", "role": "STUDENT", "apaar_id": "888000000001"},
            # 409: Mismatch within token credentials
            {"sub": "student:888000000002", "role": "STUDENT", "apaar_id": "888000000001"},
        ]

        # Sensitive strings belonging to Alpha and Beta
        forbidden_strings = [
            "Target Student Alpha",
            "Other Student Beta",
            "SEC-ISO-001",
            "SEC-ISO-002",
            "8880 0000 0001",
            "8880 0000 0002",
        ]

        for claims in test_cases:
            client = self.get_auth_client(claims)
            resp = client.get("/student/dashboard")
            self.assertNotEqual(resp.status_code, 200, f"Expected non-200 for claims {claims}")
            for forbidden in forbidden_strings:
                self.assertNotIn(
                    forbidden,
                    resp.text,
                    f"Forbidden student string '{forbidden}' leaked in response for claims {claims}!",
                )

    # -----------------------------------------------------------------------
    # 8. Companion POST endpoint (/student/dashboard/consent) isolation
    # -----------------------------------------------------------------------
    def test_08_post_dashboard_consent_enforces_isolation(self):
        """POST /student/dashboard/consent enforces same record isolation and reject conflicts."""
        # Non-matching student rejected with 404
        client_404 = self.get_auth_client({
            "sub": "student:888999999999",
            "role": "STUDENT",
            "apaar_id": "888999999999",
        })
        resp = client_404.post("/student/dashboard/consent", data={"consent_level": "2"}, follow_redirects=False)
        self.assertEqual(resp.status_code, 404)

        # Conflicting student rejected with 409
        client_409 = self.get_auth_client({
            "sub": "SEC-ISO-002",
            "role": "STUDENT",
            "apaar_id": "888000000001",
        })
        resp = client_409.post("/student/dashboard/consent", data={"consent_level": "2"}, follow_redirects=False)
        self.assertEqual(resp.status_code, 409)

    # -----------------------------------------------------------------------
    # 9. Mask identifier helper verification
    # -----------------------------------------------------------------------
    def test_09_mask_identifier_avoids_logging_full_sensitive_data(self):
        """Helper correctly masks identifiers, preserving safety."""
        self.assertEqual(mask_identifier(None), "<none>")
        self.assertEqual(mask_identifier(""), "<none>")
        self.assertEqual(mask_identifier("123"), "***")
        self.assertEqual(mask_identifier("1234"), "***")
        self.assertEqual(mask_identifier("888000000001"), "***0001")
        self.assertNotIn("888000000001", mask_identifier("888000000001"))


if __name__ == "__main__":
    unittest.main()
