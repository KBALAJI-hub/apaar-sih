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

from app.main import app
from app.database import engine
from app.models import Student, Institution, Program, AuditLog, User
from app.security import sign_record, verify_signature
from app.audit import verify_chain, log_action

client = TestClient(app, raise_server_exceptions=False)


class TestSecurityEdgeCases(unittest.TestCase):
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
                # 1. Missing signature verification
                resp_missing = client.get(f"/verify/record/{test_stu.student_id}")
                self.assertEqual(resp_missing.status_code, 200)
                self.assertIn("No Ed25519 cryptographic signature", resp_missing.text)
                self.assertIn("TAMPERED", resp_missing.text)

                # 2. Invalid / corrupted signature verification
                invalid_sig = "dGhpcy1pcy1hbi1pbnZhbGlkLWVkMjU1MTktc2lnbmF0dXJl"
                resp_invalid = client.get(f"/verify/record/{test_stu.student_id}?sig={invalid_sig}")
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
                resp_tampered = client.get(f"/verify/record/{test_stu.student_id}?sig={test_stu.record_signature}")
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
                # 1. Trigger verification endpoint
                resp = client.get(f"/verify/record/{test_stu.student_id}")
                self.assertEqual(resp.status_code, 200)

                # 2. Trigger QR endpoint
                resp_qr = client.get(f"/verify/record/{test_stu.student_id}/qr")
                self.assertEqual(resp_qr.status_code, 200)

                # 3. Trigger verifier portal post
                resp_post = client.post("/verify", data={"apaar_id": test_stu.apaar_id})
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
                self.assertNotIn("1999-12-31", resp_t0.text)
                self.assertNotIn("Special-Cat-Secret", resp_t0.text)

                # B) Public verification / QR route (signed valid record, but Tier 0 consent)
                resp_pub_t0 = client.get(f"/verify/record/{test_stu.student_id}?sig={test_stu.record_signature}")
                self.assertEqual(resp_pub_t0.status_code, 200)
                self.assertIn("Authentic record", resp_pub_t0.text)
                self.assertIn("VERIFIED", resp_pub_t0.text)
                self.assertIn("APAAR valid, student has not consented to share details", resp_pub_t0.text)
                self.assertNotIn("Confidential Student", resp_pub_t0.text)
                self.assertNotIn("1999-12-31", resp_pub_t0.text)
                self.assertNotIn("Special-Cat-Secret", resp_pub_t0.text)
                self.assertNotIn(inst.name, resp_pub_t0.text)
                self.assertNotIn(prog.name, resp_pub_t0.text)

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
                self.assertNotIn("1999-12-31", resp_t1.text)
                self.assertNotIn("Special-Cat-Secret", resp_t1.text)

                # B) Public verification / QR route
                resp_pub_t1 = client.get(f"/verify/record/{test_stu.student_id}?sig={test_stu.record_signature}")
                self.assertEqual(resp_pub_t1.status_code, 200)
                self.assertIn("Authentic record", resp_pub_t1.text)
                self.assertIn("VERIFIED", resp_pub_t1.text)
                self.assertIn("Directory Verification (Tier 1)", resp_pub_t1.text)
                self.assertIn(inst.name, resp_pub_t1.text)
                self.assertIn(prog.name, resp_pub_t1.text)
                self.assertNotIn("Confidential Student", resp_pub_t1.text)
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
                self.assertIn("1999-12-31", resp_t2.text)
                self.assertIn("Special-Cat-Secret", resp_t2.text)
                self.assertIn("AUTHENTIC", resp_t2.text)

                # B) Public verification / QR route
                resp_pub_t2 = client.get(f"/verify/record/{test_stu.student_id}?sig={test_stu.record_signature}")
                self.assertEqual(resp_pub_t2.status_code, 200)
                self.assertIn("Authentic record", resp_pub_t2.text)
                self.assertIn("VERIFIED", resp_pub_t2.text)
                self.assertIn("Full Credential Verification (Tier 2)", resp_pub_t2.text)
                self.assertIn("Confidential Student", resp_pub_t2.text)
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
        self.assertEqual(db_info.get("dialect"), "sqlite")
        self.assertTrue(db_info.get("connected"))

        # Test redact_credentials function directly
        secret_url = "postgresql://sec_user:MySecretPassword123@supabase.pooler:6543/apaardb"
        sanitized = redact_credentials(secret_url)
        self.assertNotIn("sec_user", sanitized)
        self.assertNotIn("MySecretPassword123", sanitized)
        self.assertIn("://***:***@", sanitized)


if __name__ == "__main__":
    unittest.main(verbosity=2)
