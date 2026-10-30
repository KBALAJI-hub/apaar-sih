"""
Security Edge Case Verification Suite for APAAR Verify (SIH PS 26263).
Validates:
1. Missing and invalid Ed25519 signatures
2. Tampering with signed student fields
3. Verification without automatic signature regeneration
4. Unauthorized access to protected roles and routes (RBAC)
5. Consent-tier masking of protected student fields (Tier 0, 1, 2)
6. Missing and invalid API keys
7. Audit-chain integrity after modification
"""

import sys
import unittest
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from sqlalchemy import text

from app.main import app
from app.database import engine
from app.models import Student, Institution, Program, AuditLog, User
from app.security import sign_record, verify_signature
from app.audit import verify_chain, log_action

client = TestClient(app, raise_server_exceptions=False)


class TestSecurityEdgeCases(unittest.TestCase):
    def get_verifier_client(self):
        temp = TestClient(app, raise_server_exceptions=False)
        resp = temp.post("/login", data={"username": "employer1", "password": "Verify@123"}, follow_redirects=False)
        cookie = resp.cookies.get("access_token")
        return TestClient(app, cookies={"access_token": cookie}, raise_server_exceptions=False)

    def get_admin_client(self):
        temp = TestClient(app, raise_server_exceptions=False)
        resp = temp.post("/login", data={"username": "aicte_admin", "password": "Admin@123"}, follow_redirects=False)
        cookie = resp.cookies.get("access_token")
        return TestClient(app, cookies={"access_token": cookie}, raise_server_exceptions=False)

    def test_01_missing_and_invalid_ed25519_signatures(self):
        """Test verification handling of missing and invalid Ed25519 signatures."""
        with Session(engine) as session:
            inst = session.exec(select(Institution)).first()
            prog = session.exec(select(Program).where(Program.institution_id == inst.id)).first()

            # Create isolated test student with NO signature
            test_stu = Student(
                apaar_id="999000000101",
                student_id="SEC-TEST-001",
                full_name="Security Test Student",
                dob="2003-01-01",
                gender="M",
                category="General",
                institution_id=inst.id,
                program_id=prog.id,
                admission_year=2024,
                admission_type="REGULAR",
                status="ACTIVE",
                consent_level=2,
                record_signature=None,
            )
            session.add(test_stu)
            session.commit()
            session.refresh(test_stu)

            try:
                ver_client = self.get_verifier_client()
                # 1. Missing signature verification
                resp_missing = ver_client.get(f"/verify/record/{test_stu.student_id}")
                self.assertEqual(resp_missing.status_code, 200)
                self.assertIn("No Ed25519 cryptographic signature", resp_missing.text)
                self.assertIn("TAMPERED", resp_missing.text)

                # 2. Invalid / corrupted signature verification
                invalid_sig = "dGhpcy1pcy1hbi1pbnZhbGlkLWVkMjU1MTktc2lnbmF0dXJl"
                resp_invalid = ver_client.get(f"/verify/record/{test_stu.student_id}?sig={invalid_sig}")
                self.assertEqual(resp_invalid.status_code, 200)
                self.assertIn("failed validation", resp_invalid.text)
                self.assertIn("TAMPERED", resp_invalid.text)

                # Direct verify_signature function returns False for invalid
                self.assertFalse(verify_signature(test_stu, invalid_sig, session=session))
                self.assertFalse(verify_signature(test_stu, None, session=session))
                self.assertFalse(verify_signature(test_stu, "", session=session))
            finally:
                session.delete(test_stu)
                session.commit()

    def test_02_tampering_with_signed_student_fields(self):
        """Test that altering any canonical signed field invalidates the signature."""
        with Session(engine) as session:
            inst = session.exec(select(Institution)).first()
            prog = session.exec(select(Program).where(Program.institution_id == inst.id)).first()

            # Create and sign an isolated student
            test_stu = Student(
                apaar_id="999000000102",
                student_id="SEC-TEST-002",
                full_name="Original Name",
                dob="2003-05-15",
                gender="F",
                category="General",
                institution_id=inst.id,
                program_id=prog.id,
                admission_year=2024,
                admission_type="REGULAR",
                status="ACTIVE",
                consent_level=2,
            )
            sign_record(test_stu, session)
            session.add(test_stu)
            session.commit()
            session.refresh(test_stu)

            try:
                # Valid initially
                self.assertTrue(verify_signature(test_stu, test_stu.record_signature, session=session))

                # Tamper full_name
                test_stu.full_name = "Tampered Name"
                session.add(test_stu)
                session.commit()
                session.refresh(test_stu)

                self.assertFalse(verify_signature(test_stu, test_stu.record_signature, session=session))
                ver_client = self.get_verifier_client()
                resp_tampered = ver_client.get(f"/verify/record/{test_stu.student_id}?sig={test_stu.record_signature}")
                self.assertIn("TAMPERED", resp_tampered.text)

                # Tamper dob
                test_stu.full_name = "Original Name"
                test_stu.dob = "2000-01-01"
                session.add(test_stu)
                session.commit()
                session.refresh(test_stu)

                self.assertFalse(verify_signature(test_stu, test_stu.record_signature, session=session))

                # Tamper admission_year
                test_stu.dob = "2003-05-15"
                test_stu.admission_year = 2020
                session.add(test_stu)
                session.commit()
                session.refresh(test_stu)

                self.assertFalse(verify_signature(test_stu, test_stu.record_signature, session=session))
            finally:
                session.delete(test_stu)
                session.commit()

    def test_03_verification_without_automatic_signature_regeneration(self):
        """Confirm verification of an unsigned record does not automatically generate and persist a signature."""
        with Session(engine) as session:
            inst = session.exec(select(Institution)).first()
            prog = session.exec(select(Program).where(Program.institution_id == inst.id)).first()

            test_stu = Student(
                apaar_id="999000000103",
                student_id="SEC-TEST-003",
                full_name="Unsigned Student",
                dob="2002-11-20",
                gender="M",
                category="General",
                institution_id=inst.id,
                program_id=prog.id,
                admission_year=2024,
                admission_type="REGULAR",
                status="ACTIVE",
                consent_level=2,
                record_signature=None,
            )
            session.add(test_stu)
            session.commit()
            session.refresh(test_stu)

            try:
                ver_client = self.get_verifier_client()
                # 1. Trigger verification endpoint
                resp = ver_client.get(f"/verify/record/{test_stu.student_id}")
                self.assertEqual(resp.status_code, 200)

                # 2. Trigger QR endpoint (authorized admin generates QR; verifier is rejected with 403)
                admin_client = self.get_admin_client()
                resp_qr = admin_client.get(f"/verify/record/{test_stu.student_id}/qr")
                self.assertEqual(resp_qr.status_code, 200)
                self.assertEqual(ver_client.get(f"/verify/record/{test_stu.student_id}/qr").status_code, 403)

                # 3. Trigger verifier portal post
                resp_post = ver_client.post("/verify", data={"apaar_id": test_stu.apaar_id, "purpose": "EMPLOYMENT_VERIFICATION"})
                self.assertEqual(resp_post.status_code, 200)

                # Re-fetch from database to verify signature was NOT regenerated by any verification endpoint
                session.expire_all()
                db_stu = session.get(Student, test_stu.id)
                self.assertIsNone(
                    db_stu.record_signature,
                    "Student record_signature must NOT be automatically generated/persisted during verification lookup",
                )
            finally:
                session.delete(test_stu)
                session.commit()

    def test_04_unauthorized_access_to_protected_roles_and_routes(self):
        """Test RBAC enforcement across unauthenticated and cross-role requests."""
        # 1. Unauthenticated requests to protected dashboards
        resp_inst_anon = client.get("/institution/dashboard", follow_redirects=False)
        self.assertIn(resp_inst_anon.status_code, (302, 303, 307))
        self.assertIn("/login", resp_inst_anon.headers.get("Location", ""))

        resp_aicte_anon = client.get("/aicte/dashboard", follow_redirects=False)
        self.assertIn(resp_aicte_anon.status_code, (302, 303, 307))
        self.assertIn("/login", resp_aicte_anon.headers.get("Location", ""))

        # 2. Institution user accessing AICTE admin route
        resp_login_inst = client.post("/login", data={"username": "inst1", "password": "Inst@123"}, follow_redirects=False)
        inst_cookie = resp_login_inst.cookies.get("access_token")
        inst_client = TestClient(app, cookies={"access_token": inst_cookie}, raise_server_exceptions=False)

        resp_cross_aicte = inst_client.get("/aicte/dashboard", follow_redirects=False)
        self.assertEqual(resp_cross_aicte.status_code, 403)

        # 3. Verifier accessing Institution student creation route
        resp_login_ver = client.post("/login", data={"username": "employer1", "password": "Verify@123"}, follow_redirects=False)
        ver_cookie = resp_login_ver.cookies.get("access_token")
        ver_client = TestClient(app, cookies={"access_token": ver_cookie}, raise_server_exceptions=False)

        resp_cross_inst = ver_client.get("/institution/dashboard", follow_redirects=False)
        self.assertEqual(resp_cross_inst.status_code, 403)

    def test_05_consent_tier_masking_of_protected_student_fields(self):
        """Test consent-tier masking across verifier portal and public QR verification (Tier 0, 1, 2)."""
        resp_login_ver = client.post("/login", data={"username": "employer1", "password": "Verify@123"}, follow_redirects=False)
        ver_cookie = resp_login_ver.cookies.get("access_token")
        ver_client = TestClient(app, cookies={"access_token": ver_cookie}, raise_server_exceptions=False)

        with Session(engine) as session:
            inst = session.exec(select(Institution)).first()
            prog = session.exec(select(Program).where(Program.institution_id == inst.id)).first()

            # Create test student for testing all 3 consent tiers
            test_stu = Student(
                apaar_id="999000000105",
                student_id="SEC-CONSENT-005",
                full_name="Confidential Student",
                dob="1999-12-31",
                gender="F",
                category="Special-Cat-Secret",
                institution_id=inst.id,
                program_id=prog.id,
                admission_year=2024,
                admission_type="REGULAR",
                status="ACTIVE",
                consent_level=0,
            )
            sign_record(test_stu, session)
            session.add(test_stu)
            session.commit()
            session.refresh(test_stu)

            try:
                # -------------------------------------------------------------
                # Tier 0: No personal or institutional details disclosed
                # -------------------------------------------------------------
                # A) Verifier portal lookup
                resp_t0 = ver_client.post("/verify", data={"apaar_id": test_stu.apaar_id})
                self.assertEqual(resp_t0.status_code, 200)
                self.assertIn("student has not consented to share details", resp_t0.text)
                self.assertNotIn("Confidential Student", resp_t0.text)
                self.assertNotIn(test_stu.student_id, resp_t0.text)
                self.assertNotIn("1999-12-31", resp_t0.text)
                self.assertNotIn("Special-Cat-Secret", resp_t0.text)
                self.assertNotIn(inst.name, resp_t0.text)
                self.assertNotIn(prog.name, resp_t0.text)

                # B) Public verification / QR route (signed valid record, but Tier 0 consent)
                resp_pub_t0 = ver_client.get(f"/verify/record/{test_stu.student_id}?sig={test_stu.record_signature}")
                self.assertEqual(resp_pub_t0.status_code, 200)
                self.assertIn("Authentic record", resp_pub_t0.text)
                self.assertIn("VERIFIED", resp_pub_t0.text)
                self.assertIn("APAAR valid, student has not consented to share details", resp_pub_t0.text)
                self.assertNotIn("Confidential Student", resp_pub_t0.text)
                self.assertNotIn(test_stu.student_id, resp_pub_t0.text)
                self.assertNotIn("1999-12-31", resp_pub_t0.text)
                self.assertNotIn("Special-Cat-Secret", resp_pub_t0.text)
                self.assertNotIn(inst.name, resp_pub_t0.text)
                self.assertNotIn(inst.aicte_id, resp_pub_t0.text)
                self.assertNotIn(prog.name, resp_pub_t0.text)
                self.assertNotIn(str(test_stu.admission_year), resp_pub_t0.text)

                # -------------------------------------------------------------
                # Tier 1: Directory details disclosed; personal identity hidden
                # -------------------------------------------------------------
                test_stu.consent_level = 1
                session.add(test_stu)
                session.commit()

                # A) Verifier portal lookup
                resp_t1 = ver_client.post("/verify", data={"apaar_id": test_stu.apaar_id})
                self.assertEqual(resp_t1.status_code, 200)
                self.assertIn("Directory Verification (Tier 1)", resp_t1.text)
                self.assertIn(inst.name, resp_t1.text)
                self.assertIn(prog.name, resp_t1.text)
                self.assertNotIn("Confidential Student", resp_t1.text)
                self.assertNotIn(test_stu.student_id, resp_t1.text)
                self.assertNotIn("1999-12-31", resp_t1.text)
                self.assertNotIn("Special-Cat-Secret", resp_t1.text)

                # B) Public verification / QR route
                resp_pub_t1 = ver_client.get(f"/verify/record/{test_stu.student_id}?sig={test_stu.record_signature}")
                self.assertEqual(resp_pub_t1.status_code, 200)
                self.assertIn("Authentic record", resp_pub_t1.text)
                self.assertIn("VERIFIED", resp_pub_t1.text)
                self.assertIn("Directory Verification (Tier 1)", resp_pub_t1.text)
                self.assertIn(inst.name, resp_pub_t1.text)
                self.assertIn(prog.name, resp_pub_t1.text)
                self.assertNotIn("Confidential Student", resp_pub_t1.text)
                self.assertNotIn(test_stu.student_id, resp_pub_t1.text)
                self.assertNotIn("1999-12-31", resp_pub_t1.text)
                self.assertNotIn("Special-Cat-Secret", resp_pub_t1.text)

                # -------------------------------------------------------------
                # Tier 2: Full authorized academic and identity verification
                # -------------------------------------------------------------
                test_stu.consent_level = 2
                session.add(test_stu)
                session.commit()

                # A) Verifier portal lookup
                resp_t2 = ver_client.post("/verify", data={"apaar_id": test_stu.apaar_id})
                self.assertEqual(resp_t2.status_code, 200)
                self.assertIn("Full Authentic Credential (Tier 2)", resp_t2.text)
                self.assertIn("Confidential Student", resp_t2.text)
                self.assertIn(test_stu.student_id, resp_t2.text)
                self.assertIn("1999-12-31", resp_t2.text)
                self.assertIn("Special-Cat-Secret", resp_t2.text)
                self.assertIn("AUTHENTIC", resp_t2.text)

                # B) Public verification / QR route
                resp_pub_t2 = ver_client.get(f"/verify/record/{test_stu.student_id}?sig={test_stu.record_signature}")
                self.assertEqual(resp_pub_t2.status_code, 200)
                self.assertIn("Authentic record", resp_pub_t2.text)
                self.assertIn("VERIFIED", resp_pub_t2.text)
                self.assertIn("Full Credential Verification (Tier 2)", resp_pub_t2.text)
                self.assertIn("Confidential Student", resp_pub_t2.text)
                self.assertIn(test_stu.student_id, resp_pub_t2.text)
                self.assertIn(inst.name, resp_pub_t2.text)
                self.assertIn(prog.name, resp_pub_t2.text)
            finally:
                session.delete(test_stu)
                session.commit()

    def test_06_missing_and_invalid_api_keys(self):
        """Test API endpoints enforce 401 for missing and 403 for invalid X-API-Key."""
        sample_payload = [
            {
                "apaar_id": "999900009999",
                "student_id": "API-SEC-001",
                "full_name": "API Security Student",
                "dob": "2003-01-01",
                "gender": "M",
                "category": "General",
                "program_name": "Computer Science",
                "admission_year": 2024,
                "admission_type": "REGULAR",
                "is_nri": False,
                "oci_status": False,
                "is_foreign_national": False,
                "nationality": "Indian",
                "mode": "FULL_TIME",
                "consent_given": True,
            }
        ]

        # 1. Missing X-API-Key header -> 401 Unauthorized
        resp_missing = client.post("/api/v1/students/bulk", json=sample_payload)
        self.assertEqual(resp_missing.status_code, 401)
        self.assertIn("Missing X-API-Key", resp_missing.json().get("detail", ""))

        # 2. Invalid X-API-Key header -> 403 Forbidden
        resp_invalid = client.post(
            "/api/v1/students/bulk",
            headers={"X-API-Key": "completely-invalid-key-999"},
            json=sample_payload,
        )
        self.assertEqual(resp_invalid.status_code, 403)
        self.assertIn("Invalid or unauthorized X-API-Key", resp_invalid.json().get("detail", ""))

        # 3. Valid X-API-Key header -> 200 OK
        with Session(engine) as session:
            inst = session.exec(select(Institution)).first()
            valid_key = inst.api_key

        resp_valid = client.post(
            "/api/v1/students/bulk",
            headers={"X-API-Key": valid_key},
            json=sample_payload,
        )
        self.assertEqual(resp_valid.status_code, 200)

    def test_07_audit_chain_integrity_after_modification(self):
        """Test cryptographic hash-chained audit log detects tampering."""
        with Session(engine) as session:
            # Confirm current audit chain is valid
            valid_init, broken_init = verify_chain(session)
            self.assertTrue(valid_init, f"Audit chain should initially be valid, broken at {broken_init}")

            # Insert an isolated audit log row
            test_log = log_action(
                session=session,
                user={"id": 9999, "username": "security_test_user"},
                action="SECURITY_TEST_AUDIT",
                entity="SYSTEM",
                entity_id="TEST-001",
                details="Audit integrity test record",
            )
            session.commit()
            session.refresh(test_log)

            try:
                # Valid after adding
                valid_after_add, _ = verify_chain(session)
                self.assertTrue(valid_after_add)

                # Tamper with the details directly in the database
                orig_details = test_log.details
                test_log.details = "TAMPERED_DETAILS_INSERTED"
                session.add(test_log)
                session.commit()

                # Verify chain detects break at test_log.id
                valid_tampered, broken_id = verify_chain(session)
                self.assertFalse(valid_tampered)
                self.assertEqual(broken_id, test_log.id)

                # Revert tampering
                test_log.details = orig_details
                session.add(test_log)
                session.commit()

                # Chain is restored
                valid_restored, _ = verify_chain(session)
                self.assertTrue(valid_restored)
            finally:
                # Clean up the test audit row
                session.delete(test_log)
                session.commit()

    def test_08_database_diagnostics_redact_credentials(self):
        """Confirm /health endpoint and db connection diagnostics redact credentials and passwords."""
        from app.database import redact_credentials, get_sanitized_database_name

        resp = client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        db_info = data.get("database", {})

        # Ensure no URL schemes, passwords, or usernames are leaked
        raw_body = resp.text
        self.assertNotIn("postgresql://", raw_body)
        self.assertNotIn("postgres://", raw_body)
        self.assertNotIn("sqlite:///", raw_body)
        self.assertNotIn("@", raw_body)

        # Confirm status values are preserved
        self.assertEqual(data.get("status"), "ok")
        self.assertEqual(db_info.get("status"), "healthy")
        self.assertEqual(db_info.get("dialect"), "postgresql")
        self.assertTrue(db_info.get("connected"))

        # Test redact_credentials function directly
        secret_url = "postgresql://sec_user:MySecretPassword123@supabase.pooler:6543/apaardb"
        sanitized = redact_credentials(secret_url)
        self.assertNotIn("sec_user", sanitized)
        self.assertNotIn("MySecretPassword123", sanitized)
        self.assertIn("://***:***@", sanitized)


    def test_09_invalid_and_out_of_range_consent_values_fail_closed_to_tier_0(self):
        """
        Verify that out-of-range, malformed, or missing stored consent values (-1, 3, 99, None)
        strictly fail closed to Tier 0 across both public verification and authenticated verifier portal.
        Never interpret unknown consent as Tier 2.
        """
        resp_login_ver = client.post("/login", data={"username": "employer1", "password": "Verify@123"}, follow_redirects=False)
        ver_cookie = resp_login_ver.cookies.get("access_token")
        ver_client = TestClient(app, cookies={"access_token": ver_cookie}, raise_server_exceptions=False)

        with Session(engine) as session:
            inst = session.exec(select(Institution)).first()
            prog = session.exec(select(Program).where(Program.institution_id == inst.id)).first()

            test_stu = Student(
                apaar_id="999000000109",
                student_id="SEC-CONSENT-009",
                full_name="Secret Consent Student",
                dob="2001-09-09",
                gender="M",
                category="OBC",
                institution_id=inst.id,
                program_id=prog.id,
                admission_year=2024,
                admission_type="REGULAR",
                status="ACTIVE",
                consent_level=99,
            )
            sign_record(test_stu, session)
            session.add(test_stu)
            session.commit()
            session.refresh(test_stu)

            try:
                from app.routers.verify import get_effective_consent_tier
                self.assertEqual(get_effective_consent_tier(None), 0)
                self.assertEqual(get_effective_consent_tier("xyz"), 0)
                self.assertEqual(get_effective_consent_tier(-1), 0)
                self.assertEqual(get_effective_consent_tier(99), 0)
                self.assertEqual(get_effective_consent_tier(3), 0)
                self.assertEqual(get_effective_consent_tier(0), 0)
                self.assertEqual(get_effective_consent_tier(1), 1)
                self.assertEqual(get_effective_consent_tier(2), 2)

                for bad_consent in [-1, 3, 99]:
                    test_stu.consent_level = bad_consent
                    session.add(test_stu)
                    session.commit()
                    session.refresh(test_stu)

                    # 1. Verifier portal lookup must fail closed to Tier 0
                    resp_v = ver_client.post("/verify", data={"apaar_id": test_stu.apaar_id})
                    self.assertEqual(resp_v.status_code, 200)
                    self.assertIn("student has not consented to share details", resp_v.text)
                    self.assertNotIn("Secret Consent Student", resp_v.text)
                    self.assertNotIn(test_stu.student_id, resp_v.text)
                    self.assertNotIn("2001-09-09", resp_v.text)
                    self.assertNotIn(inst.name, resp_v.text)
                    self.assertNotIn(prog.name, resp_v.text)

                    # 2. Public verification must fail closed to Tier 0
                    resp_p = ver_client.get(f"/verify/record/{test_stu.student_id}?sig={test_stu.record_signature}")
                    self.assertEqual(resp_p.status_code, 200)
                    self.assertIn("Authentic record", resp_p.text)
                    self.assertIn("VERIFIED", resp_p.text)
                    self.assertIn("student has not consented to share details", resp_p.text)
                    self.assertNotIn("Secret Consent Student", resp_p.text)
                    self.assertNotIn(test_stu.student_id, resp_p.text)
                    self.assertNotIn("2001-09-09", resp_p.text)
                    self.assertNotIn(inst.name, resp_p.text)
                    self.assertNotIn(prog.name, resp_p.text)
            finally:
                session.delete(test_stu)
                session.exec(text(f"DELETE FROM verificationlog WHERE apaar_id = '999000000109'"))
                session.commit()

    def test_10_invalid_consent_updates_rejected_with_422(self):
        """
        Confirm that invalid consent update requests are rejected with HTTP 422:
        - Values -1, 3, 99, malformed strings, and missing values.
        """
        with Session(engine) as session:
            stu = session.exec(select(Student)).first()
            apaar_id = stu.apaar_id

        # 1. POST /student/consent (authenticated student)
        resp_login_consent = client.post("/student/consent", data={"action": "login", "apaar_id": apaar_id, "otp": "123456"})
        auth_cookie = resp_login_consent.cookies.get("access_token")
        auth_client = TestClient(app, cookies={"access_token": auth_cookie}, raise_server_exceptions=False)
        bad_values = ["-1", "3", "99", "malformed", ""]
        for bad_val in bad_values:
            resp = auth_client.post(
                "/student/consent",
                data={"apaar_id": apaar_id, "action": "update_consent", "consent_level": bad_val},
            )
            self.assertEqual(resp.status_code, 422, f"Expected 422 for consent_level='{bad_val}', got {resp.status_code}")

        # Missing consent_level
        resp_missing = auth_client.post(
            "/student/consent",
            data={"apaar_id": apaar_id, "action": "update_consent"},
        )
        self.assertEqual(resp_missing.status_code, 422)

        # 2. POST /student/dashboard/consent (as student)
        resp_login = client.post("/login", data={"username": "student1", "password": "Student@123"}, follow_redirects=False)
        std_cookie = resp_login.cookies.get("access_token")
        std_client = TestClient(app, cookies={"access_token": std_cookie}, raise_server_exceptions=False)

        for bad_val in ["-1", "3", "99", "invalid"]:
            resp = std_client.post("/student/dashboard/consent", data={"consent_level": bad_val}, follow_redirects=False)
            self.assertEqual(resp.status_code, 422, f"Expected 422 for student dashboard consent '{bad_val}', got {resp.status_code}")

        # 3. PUT /api/v1/students/{apaar_id}
        with Session(engine) as session:
            inst = session.exec(select(Institution)).first()
            api_key = inst.api_key
            test_stu = session.exec(select(Student).where(Student.institution_id == inst.id)).first()

        for bad_int in [-1, 3, 99]:
            resp = client.put(
                f"/api/v1/students/{test_stu.apaar_id}",
                headers={"X-API-Key": api_key},
                json={"consent_level": bad_int},
            )
            self.assertEqual(resp.status_code, 422, f"Expected 422 for API consent_level={bad_int}, got {resp.status_code}")

    def test_11_public_verification_url_signature_policy(self):
        """
        Verify explicit public verification policy:
        - URL signature (?sig=...) is strictly required.
        - Missing, empty, or invalid signatures fail verification (TAMPERED/FAILED).
        - No student details are leaked when verification fails.
        """
        with Session(engine) as session:
            inst = session.exec(select(Institution)).first()
            prog = session.exec(select(Program).where(Program.institution_id == inst.id)).first()

            test_stu = Student(
                apaar_id="999000000111",
                student_id="SEC-SIG-011",
                full_name="Signed Private Student",
                dob="2002-02-02",
                gender="F",
                category="General",
                institution_id=inst.id,
                program_id=prog.id,
                admission_year=2024,
                admission_type="REGULAR",
                status="ACTIVE",
                consent_level=2,
            )
            sign_record(test_stu, session)
            session.add(test_stu)
            session.commit()
            session.refresh(test_stu)

            try:
                ver_client = self.get_verifier_client()
                # 1. Missing signature (?sig omitted) -> Fails verification, zero details leaked
                resp_no_sig = ver_client.get(f"/verify/record/{test_stu.student_id}")
                self.assertEqual(resp_no_sig.status_code, 200)
                self.assertIn("TAMPERED or not found", resp_no_sig.text)
                self.assertIn("No Ed25519 cryptographic signature provided", resp_no_sig.text)
                self.assertNotIn("Signed Private Student", resp_no_sig.text)
                self.assertNotIn("2002-02-02", resp_no_sig.text)
                self.assertNotIn(inst.name, resp_no_sig.text)
                self.assertNotIn(prog.name, resp_no_sig.text)

                # 2. Empty signature (?sig=) -> Fails verification, zero details leaked
                resp_empty_sig = ver_client.get(f"/verify/record/{test_stu.student_id}?sig=")
                self.assertEqual(resp_empty_sig.status_code, 200)
                self.assertIn("TAMPERED or not found", resp_empty_sig.text)
                self.assertNotIn("Signed Private Student", resp_empty_sig.text)

                # 3. Invalid signature -> Fails verification, zero details leaked
                resp_bad_sig = ver_client.get(f"/verify/record/{test_stu.student_id}?sig=invalid_sig_bytes")
                self.assertEqual(resp_bad_sig.status_code, 200)
                self.assertIn("TAMPERED or not found", resp_bad_sig.text)
                self.assertIn("failed validation", resp_bad_sig.text)
                self.assertNotIn("Signed Private Student", resp_bad_sig.text)

                # 4. Valid signature -> Passes verification
                resp_valid = ver_client.get(f"/verify/record/{test_stu.student_id}?sig={test_stu.record_signature}")
                self.assertEqual(resp_valid.status_code, 200)
                self.assertIn("Authentic record", resp_valid.text)
                self.assertIn("VERIFIED", resp_valid.text)
                self.assertIn("Signed Private Student", resp_valid.text)
            finally:
                session.delete(test_stu)
                session.exec(text(f"DELETE FROM verificationlog WHERE apaar_id = '999000000111'"))
                session.commit()

    def test_12_tampered_records_never_leak_restricted_details(self):
        """
        Verify that tampered fields cause verification failure and NEVER disclose restricted student details.
        """
        with Session(engine) as session:
            inst = session.exec(select(Institution)).first()
            prog = session.exec(select(Program).where(Program.institution_id == inst.id)).first()

            test_stu = Student(
                apaar_id="999000000112",
                student_id="SEC-TAMPER-012",
                full_name="Authentic Student 12",
                dob="2003-03-03",
                gender="M",
                category="General",
                institution_id=inst.id,
                program_id=prog.id,
                admission_year=2024,
                admission_type="REGULAR",
                status="ACTIVE",
                consent_level=2,
            )
            sign_record(test_stu, session)
            session.add(test_stu)
            session.commit()
            session.refresh(test_stu)
            valid_sig = test_stu.record_signature

            try:
                # Tamper student name in database
                test_stu.full_name = "Forged Altered Name"
                session.add(test_stu)
                session.commit()

                ver_client = self.get_verifier_client()
                resp_tampered = ver_client.get(f"/verify/record/{test_stu.student_id}?sig={valid_sig}")
                self.assertEqual(resp_tampered.status_code, 200)
                self.assertIn("TAMPERED or not found", resp_tampered.text)
                self.assertNotIn("Authentic record", resp_tampered.text)
                # Verify restricted details are NOT in the response
                self.assertNotIn("Forged Altered Name", resp_tampered.text)
                self.assertNotIn("Authentic Student 12", resp_tampered.text)
                self.assertNotIn("2003-03-03", resp_tampered.text)
                self.assertNotIn(inst.name, resp_tampered.text)
                self.assertNotIn(prog.name, resp_tampered.text)
            finally:
                session.delete(test_stu)
                session.exec(text(f"DELETE FROM verificationlog WHERE apaar_id = '999000000112'"))
                session.commit()

    def test_13_verification_and_qr_do_not_regenerate_signatures(self):
        """
        Confirm verification lookups and QR generation never regenerate or mutate record signatures.
        """
        with Session(engine) as session:
            inst = session.exec(select(Institution)).first()
            prog = session.exec(select(Program).where(Program.institution_id == inst.id)).first()

            test_stu = Student(
                apaar_id="999000000113",
                student_id="SEC-MUT-013",
                full_name="No Mutate Student",
                dob="2002-12-12",
                gender="F",
                category="General",
                institution_id=inst.id,
                program_id=prog.id,
                admission_year=2024,
                admission_type="REGULAR",
                status="ACTIVE",
                consent_level=2,
                record_signature=None,
            )
            session.add(test_stu)
            session.commit()
            session.refresh(test_stu)

            try:
                # Trigger verification endpoints
                client.get(f"/verify/record/{test_stu.student_id}")
                client.get(f"/verify/record/{test_stu.student_id}?sig=test_dummy")
                client.get(f"/verify/record/{test_stu.student_id}/qr")
                client.post("/verify", data={"apaar_id": test_stu.apaar_id})

                # Refresh from DB
                session.expire_all()
                db_stu = session.get(Student, test_stu.id)
                self.assertIsNone(db_stu.record_signature, "record_signature must remain None after all lookups")
            finally:
                session.delete(test_stu)
                session.exec(text(f"DELETE FROM verificationlog WHERE apaar_id = '999000000113'"))
                session.commit()


if __name__ == "__main__":
    unittest.main(verbosity=2)
