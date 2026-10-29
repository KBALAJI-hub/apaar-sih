"""
Regression Test Suite for Student Consent Authorization Security (SIH PS 26263).
Validates:
1. Anonymous updates rejected with HTTP 401
2. Invalid and expired session tokens rejected with HTTP 401 across both endpoints
3. Non-student roles (AICTE_ADMIN, INSTITUTION, VERIFIER) rejected with HTTP 403
4. Cross-student updates rejected with HTTP 403; Student A cannot change Student B
5. Valid self-updates succeed for Tiers 0, 1, 2 with Ed25519 signatures and audit logging
6. Invalid consent tiers rejected with HTTP 422
7. Database, signature, and audit state remain strictly unchanged after rejected requests
8. Demo OTP 123456 workflow preserved and cannot bypass authorization
9. CSRF validation rejects cross-site, malformed, and opaque origins (e.g. Origin: null) across both endpoints
10. Atomic rollback: Audit logging failure rolls back consent mutation, signatures, and timestamps
11. Valid self-update via student dashboard consent endpoint
"""

from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from jose import jwt

from app.main import app
from app.database import engine
from app.models import Student, User, AuditLog, Institution, Program
from app.security import sign_record, verify_signature
from app.audit import verify_chain
from app.auth import SECRET_KEY, ALGORITHM, create_access_token


class TestStudentConsentSecurity(unittest.TestCase):
    def setUp(self):
        """Ensure test students exist in database with known initial state and clean client."""
        self.client = TestClient(app, raise_server_exceptions=False)
        self.client.cookies.clear()

        with Session(engine) as session:
            inst = session.exec(select(Institution)).first()
            prog = session.exec(select(Program).where(Program.institution_id == inst.id)).first()

            # Student A
            stu_a = session.exec(select(Student).where(Student.apaar_id == "999111222001")).first()
            if not stu_a:
                stu_a = Student(
                    apaar_id="999111222001",
                    student_id="REG-STU-001",
                    full_name="Alice Student",
                    dob="2003-01-15",
                    gender="F",
                    institution_id=inst.id,
                    program_id=prog.id,
                    consent_level=1,
                    status="ACTIVE",
                )
                session.add(stu_a)
                session.commit()
                session.refresh(stu_a)
            stu_a.consent_level = 1
            stu_a.record_signature = sign_record(stu_a, session)
            session.add(stu_a)

            # Student B
            stu_b = session.exec(select(Student).where(Student.apaar_id == "999111222002")).first()
            if not stu_b:
                stu_b = Student(
                    apaar_id="999111222002",
                    student_id="REG-STU-002",
                    full_name="Bob Student",
                    dob="2003-06-20",
                    gender="M",
                    institution_id=inst.id,
                    program_id=prog.id,
                    consent_level=2,
                    status="ACTIVE",
                )
                session.add(stu_b)
                session.commit()
                session.refresh(stu_b)
            stu_b.consent_level = 2
            stu_b.record_signature = sign_record(stu_b, session)
            session.add(stu_b)

            session.commit()

    def test_01_anonymous_consent_mutation_rejected_401(self):
        """Anonymous consent mutation requests must strictly return HTTP 401."""
        # 1. Anonymous update on /student/consent
        resp = self.client.post(
            "/student/consent",
            data={"action": "update_consent", "apaar_id": "999111222001", "consent_level": "2"},
        )
        self.assertEqual(resp.status_code, 401, f"Expected 401 for anonymous update, got {resp.status_code}")
        self.assertIn("detail", resp.json())

        # 2. Anonymous update attempting to pass demo OTP to bypass
        resp_otp_bypass = self.client.post(
            "/student/consent",
            data={"action": "update_consent", "apaar_id": "999111222001", "otp": "123456", "consent_level": "2"},
        )
        self.assertEqual(resp_otp_bypass.status_code, 401)

        # 3. Anonymous update on /student/dashboard/consent
        resp_dash = self.client.post(
            "/student/dashboard/consent",
            data={"consent_level": "2"},
        )
        self.assertEqual(resp_dash.status_code, 401, f"Expected 401 for anonymous dashboard update, got {resp_dash.status_code}")

    def test_02_invalid_or_expired_session_rejected_401(self):
        """Invalid, malformed, or expired session tokens must strictly return HTTP 401 across both endpoints."""
        past_time = datetime.now(timezone.utc) - timedelta(hours=2)
        expired_payload = {
            "sub": "student:999111222001",
            "role": "STUDENT",
            "apaar_id": "999111222001",
            "exp": past_time,
        }
        expired_token = jwt.encode(expired_payload, SECRET_KEY, algorithm=ALGORITHM)
        forged_token = jwt.encode({"sub": "student:999111222001", "role": "STUDENT"}, "wrong-secret-key", algorithm=ALGORITHM)

        endpoints = [
            ("/student/consent", {"action": "update_consent", "consent_level": "2"}),
            ("/student/dashboard/consent", {"consent_level": "2"}),
        ]

        for url, form_data in endpoints:
            # 1. Malformed token in cookie
            bad_client = TestClient(app, cookies={"access_token": "malformed.invalid.token"}, raise_server_exceptions=False)
            resp_bad = bad_client.post(url, data=form_data)
            self.assertEqual(resp_bad.status_code, 401, f"Expected 401 on {url} for malformed token, got {resp_bad.status_code}")

            # 2. Expired JWT token
            exp_client = TestClient(app, cookies={"access_token": expired_token}, raise_server_exceptions=False)
            resp_exp = exp_client.post(url, data=form_data)
            self.assertEqual(resp_exp.status_code, 401, f"Expected 401 on {url} for expired token, got {resp_exp.status_code}")

            # 3. Forged token with invalid signature
            forged_client = TestClient(app, cookies={"access_token": forged_token}, raise_server_exceptions=False)
            resp_forged = forged_client.post(url, data=form_data)
            self.assertEqual(resp_forged.status_code, 401, f"Expected 401 on {url} for forged token, got {resp_forged.status_code}")

    def test_03_non_student_users_rejected_403(self):
        """Authenticated users with non-STUDENT roles must strictly return HTTP 403."""
        # 1. AICTE Admin attempting consent mutation
        resp_admin_login = self.client.post("/login", data={"username": "aicte_admin", "password": "Admin@123"}, follow_redirects=False)
        admin_cookie = resp_admin_login.cookies.get("access_token")
        admin_client = TestClient(app, cookies={"access_token": admin_cookie}, raise_server_exceptions=False)

        resp_admin = admin_client.post(
            "/student/consent",
            data={"action": "update_consent", "apaar_id": "999111222001", "consent_level": "2"},
        )
        self.assertEqual(resp_admin.status_code, 403)
        self.assertIn("STUDENT", resp_admin.text)

        # Dashboard consent route
        resp_admin_dash = admin_client.post(
            "/student/dashboard/consent",
            data={"consent_level": "2"},
        )
        self.assertEqual(resp_admin_dash.status_code, 403)

        # 2. Institution user attempting consent mutation
        resp_inst_login = self.client.post("/login", data={"username": "inst1", "password": "Inst@123"}, follow_redirects=False)
        inst_cookie = resp_inst_login.cookies.get("access_token")
        inst_client = TestClient(app, cookies={"access_token": inst_cookie}, raise_server_exceptions=False)

        resp_inst = inst_client.post(
            "/student/consent",
            data={"action": "update_consent", "apaar_id": "999111222001", "consent_level": "2"},
        )
        self.assertEqual(resp_inst.status_code, 403)

        # 3. Verifier attempting consent mutation
        resp_ver_login = self.client.post("/login", data={"username": "employer1", "password": "Verify@123"}, follow_redirects=False)
        ver_cookie = resp_ver_login.cookies.get("access_token")
        ver_client = TestClient(app, cookies={"access_token": ver_cookie}, raise_server_exceptions=False)

        resp_ver = ver_client.post(
            "/student/consent",
            data={"action": "update_consent", "apaar_id": "999111222001", "consent_level": "2"},
        )
        self.assertEqual(resp_ver.status_code, 403)

    def test_04_cross_student_mutation_rejected_403_and_student_b_unchanged(self):
        """Student A cannot modify Student B's consent. Cross-student attempt must return 403."""
        # Authenticate as Student A (Alice)
        resp_login_a = self.client.post(
            "/student/consent",
            data={"action": "login", "apaar_id": "999111222001", "otp": "123456"},
        )
        self.assertEqual(resp_login_a.status_code, 200)
        cookie_a = resp_login_a.cookies.get("access_token")
        client_a = TestClient(app, cookies={"access_token": cookie_a}, raise_server_exceptions=False)

        # Snapshot Student B's state prior to attack
        with Session(engine) as s:
            stu_b_before = s.exec(select(Student).where(Student.apaar_id == "999111222002")).one()
            b_level_before = stu_b_before.consent_level
            b_sig_before = stu_b_before.record_signature
            b_ts_before = stu_b_before.consent_timestamp

        # Student A submits update targeting Student B's APAAR ID
        resp_attack = client_a.post(
            "/student/consent",
            data={"action": "update_consent", "apaar_id": "999111222002", "consent_level": "0"},
        )
        self.assertEqual(resp_attack.status_code, 403, f"Expected 403 for cross-student update, got {resp_attack.status_code}")
        self.assertIn("cannot modify", resp_attack.text.lower())

        # Verify Student B's state remains strictly untouched
        with Session(engine) as s:
            stu_b_after = s.exec(select(Student).where(Student.apaar_id == "999111222002")).one()
            self.assertEqual(stu_b_after.consent_level, b_level_before)
            self.assertEqual(stu_b_after.record_signature, b_sig_before)
            self.assertEqual(stu_b_after.consent_timestamp, b_ts_before)

    def test_05_valid_self_updates_and_cryptographic_audit_trail(self):
        """Valid student self-updates succeed across Tiers 0, 1, 2 with signatures and audit logging."""
        # Authenticate as Student A
        resp_login = self.client.post(
            "/student/consent",
            data={"action": "login", "apaar_id": "999111222001", "otp": "123456"},
        )
        cookie_a = resp_login.cookies.get("access_token")
        client_a = TestClient(app, cookies={"access_token": cookie_a}, raise_server_exceptions=False)

        # Test updating to each tier: 0, 1, 2
        for target_tier in [0, 1, 2]:
            # Client can omit apaar_id form field; identity is resolved from authenticated session
            resp_update = client_a.post(
                "/student/consent",
                data={"action": "update_consent", "consent_level": str(target_tier)},
            )
            self.assertEqual(resp_update.status_code, 200)
            self.assertIn(f"Tier {target_tier}", resp_update.text)

            with Session(engine) as s:
                stu = s.exec(select(Student).where(Student.apaar_id == "999111222001")).one()
                self.assertEqual(stu.consent_level, target_tier)
                if target_tier > 0:
                    self.assertIsNotNone(stu.consent_timestamp)
                else:
                    self.assertIsNone(stu.consent_timestamp)

                # Verify Ed25519 digital signature is valid
                self.assertTrue(
                    verify_signature(stu, stu.record_signature, session=s),
                    f"Signature must be valid for Tier {target_tier}",
                )

                # Verify hash-chain integrity
                chain_valid, broken_at = verify_chain(s)
                self.assertTrue(chain_valid, f"Audit hash chain must remain valid after Tier {target_tier} update, broken at {broken_at}")

    def test_06_invalid_consent_tiers_rejected_422(self):
        """Invalid consent tier values (-1, 3, 99, malformed, empty) are rejected with HTTP 422."""
        # Authenticate as Student A
        resp_login = self.client.post(
            "/student/consent",
            data={"action": "login", "apaar_id": "999111222001", "otp": "123456"},
        )
        cookie_a = resp_login.cookies.get("access_token")
        client_a = TestClient(app, cookies={"access_token": cookie_a}, raise_server_exceptions=False)

        invalid_tiers = ["-1", "3", "99", "invalid_tier", ""]
        for bad_tier in invalid_tiers:
            # /student/consent
            r1 = client_a.post(
                "/student/consent",
                data={"action": "update_consent", "consent_level": bad_tier},
            )
            self.assertEqual(r1.status_code, 422, f"Expected 422 for consent_level='{bad_tier}', got {r1.status_code}")

            # /student/dashboard/consent
            r2 = client_a.post(
                "/student/dashboard/consent",
                data={"consent_level": bad_tier},
            )
            self.assertEqual(r2.status_code, 422, f"Expected 422 on dashboard for consent_level='{bad_tier}', got {r2.status_code}")

    def test_07_database_and_signature_state_unchanged_after_rejected_requests(self):
        """Database student state, signatures, and audit logs remain unchanged after all rejected requests."""
        with Session(engine) as s:
            stu_before = s.exec(select(Student).where(Student.apaar_id == "999111222001")).one()
            orig_level = stu_before.consent_level
            orig_sig = stu_before.record_signature
            orig_ts = stu_before.consent_timestamp
            orig_updated_at = stu_before.updated_at

        # 1. Anonymous attempt
        anon_client = TestClient(app, raise_server_exceptions=False)
        anon_client.post("/student/consent", data={"action": "update_consent", "consent_level": "2"})

        # 2. Malformed token attempt
        bad_client = TestClient(app, cookies={"access_token": "bad.token.value"}, raise_server_exceptions=False)
        bad_client.post("/student/consent", data={"action": "update_consent", "consent_level": "2"})

        # 3. Non-student user attempt
        admin_login = self.client.post("/login", data={"username": "aicte_admin", "password": "Admin@123"}, follow_redirects=False)
        admin_cookie = admin_login.cookies.get("access_token")
        admin_client = TestClient(app, cookies={"access_token": admin_cookie}, raise_server_exceptions=False)
        admin_client.post(
            "/student/consent",
            data={"action": "update_consent", "apaar_id": "999111222001", "consent_level": "2"},
        )

        # 4. Invalid consent tier attempt
        stu_login = self.client.post("/student/consent", data={"action": "login", "apaar_id": "999111222001", "otp": "123456"})
        stu_cookie = stu_login.cookies.get("access_token")
        stu_client = TestClient(app, cookies={"access_token": stu_cookie}, raise_server_exceptions=False)
        stu_client.post(
            "/student/consent",
            data={"action": "update_consent", "consent_level": "99"},
        )

        # Confirm all state is strictly unchanged
        with Session(engine) as s:
            stu_after = s.exec(select(Student).where(Student.apaar_id == "999111222001")).one()
            self.assertEqual(stu_after.consent_level, orig_level)
            self.assertEqual(stu_after.record_signature, orig_sig)
            self.assertEqual(stu_after.consent_timestamp, orig_ts)
            self.assertEqual(stu_after.updated_at, orig_updated_at)

            # Ensure no CONSENT_UPDATE audit log was inserted for rejected attempts
            rejected_audit = s.exec(
                select(AuditLog).where(
                    AuditLog.entity == "STUDENT",
                    AuditLog.entity_id == str(stu_after.id),
                    AuditLog.action == "CONSENT_UPDATE",
                    AuditLog.details.like("%99%"),
                )
            ).all()
            self.assertEqual(len(rejected_audit), 0)

    def test_08_demo_otp_workflow_preserved(self):
        """Preserve hardcoded demo OTP 123456 and existing simulated login workflow."""
        # 1. Valid OTP succeeds
        resp_valid = self.client.post(
            "/student/consent",
            data={"action": "login", "apaar_id": "999111222001", "otp": "123456"},
        )
        self.assertEqual(resp_valid.status_code, 200)
        self.assertIn("authenticated successfully", resp_valid.text)
        cookie = resp_valid.cookies.get("access_token")
        self.assertIsNotNone(cookie)

        # 2. Invalid OTP fails with 400
        resp_invalid_otp = self.client.post(
            "/student/consent",
            data={"action": "login", "apaar_id": "999111222001", "otp": "999999"},
        )
        self.assertEqual(resp_invalid_otp.status_code, 400)
        self.assertIn("Invalid OTP", resp_invalid_otp.text)

        # 3. Nonexistent student returns 404
        resp_missing_student = self.client.post(
            "/student/consent",
            data={"action": "login", "apaar_id": "000000000000", "otp": "123456"},
        )
        self.assertEqual(resp_missing_student.status_code, 404)

    def test_09_csrf_origin_validation_and_malformed_origins(self):
        """CSRF validation must reject cross-site, malformed, and opaque origins across both consent endpoints."""
        # Authenticate student
        resp_login = self.client.post(
            "/student/consent",
            data={"action": "login", "apaar_id": "999111222001", "otp": "123456"},
        )
        cookie = resp_login.cookies.get("access_token")
        auth_client = TestClient(app, cookies={"access_token": cookie}, raise_server_exceptions=False)

        endpoints = [
            ("/student/consent", {"action": "update_consent", "consent_level": "2"}),
            ("/student/dashboard/consent", {"consent_level": "2"}),
        ]

        for url, form_data in endpoints:
            # 1. Forged cross-site Origin
            resp_cross = auth_client.post(url, headers={"Origin": "https://malicious-attacker.com"}, data=form_data)
            self.assertEqual(resp_cross.status_code, 403, f"Expected 403 on {url} for cross-site origin")
            self.assertIn("Cross-site request forgery", resp_cross.text)

            # 2. Opaque Origin: null
            resp_null = auth_client.post(url, headers={"Origin": "null"}, data=form_data)
            self.assertEqual(resp_null.status_code, 403, f"Expected 403 on {url} for Origin: null")
            self.assertIn("Cross-site request forgery", resp_null.text)

            # 3. Malformed scheme Origin: about:blank
            resp_about = auth_client.post(url, headers={"Origin": "about:blank"}, data=form_data)
            self.assertEqual(resp_about.status_code, 403, f"Expected 403 on {url} for Origin: about:blank")

            # 4. Malformed non-URL Origin
            resp_malformed = auth_client.post(url, headers={"Origin": "not_a_valid_url"}, data=form_data)
            self.assertEqual(resp_malformed.status_code, 403, f"Expected 403 on {url} for malformed Origin")

            # 5. Port mismatch Origin
            resp_port = auth_client.post(url, headers={"Origin": "http://testserver:9999"}, data=form_data)
            self.assertEqual(resp_port.status_code, 403, f"Expected 403 on {url} for port mismatch Origin")

            # 6. Legitimate same-origin succeeds
            resp_ok = auth_client.post(url, headers={"Origin": "http://testserver"}, data=form_data)
            self.assertIn(resp_ok.status_code, (200, 303), f"Expected 200/303 on {url} for valid origin")

    def test_10_atomic_rollback_on_audit_failure(self):
        """Simulating audit logging failure must rollback the consent update, timestamp, and signature completely."""
        # Authenticate as Student A
        resp_login = self.client.post(
            "/student/consent",
            data={"action": "login", "apaar_id": "999111222001", "otp": "123456"},
        )
        cookie = resp_login.cookies.get("access_token")
        auth_client = TestClient(app, cookies={"access_token": cookie}, raise_server_exceptions=False)

        # Ensure student is at Tier 1 before the test
        with Session(engine) as s:
            stu = s.exec(select(Student).where(Student.apaar_id == "999111222001")).one()
            stu.consent_level = 1
            stu.record_signature = sign_record(stu, s)
            s.add(stu)
            s.commit()
            s.refresh(stu)

            initial_level = stu.consent_level
            initial_sig = stu.record_signature
            initial_ts = stu.consent_timestamp
            initial_updated_at = stu.updated_at
            audit_count_before = len(s.exec(select(AuditLog)).all())

        # Test A: Simulated audit failure on /student/consent
        with patch("app.routers.verify.log_action", side_effect=RuntimeError("Simulated database failure during audit log insertion")):
            resp_err = auth_client.post(
                "/student/consent",
                data={"action": "update_consent", "consent_level": "2"},
            )
            self.assertEqual(resp_err.status_code, 500, f"Expected 500 when audit failure raises, got {resp_err.status_code}")

        # Verify database state after simulated failure on /student/consent
        with Session(engine) as s:
            stu_after = s.exec(select(Student).where(Student.apaar_id == "999111222001")).one()
            self.assertEqual(stu_after.consent_level, initial_level, "Consent level must NOT be updated if audit fails")
            self.assertEqual(stu_after.record_signature, initial_sig, "Record signature must NOT change if audit fails")
            self.assertEqual(stu_after.consent_timestamp, initial_ts, "Consent timestamp must NOT change if audit fails")
            self.assertEqual(stu_after.updated_at, initial_updated_at, "Updated_at must NOT change if audit fails")

            audit_count_after = len(s.exec(select(AuditLog)).all())
            self.assertEqual(audit_count_after, audit_count_before, "No orphan audit log row must be committed")

            chain_valid, broken_at = verify_chain(s)
            self.assertTrue(chain_valid, f"Audit chain must remain valid after rollback, broken at {broken_at}")

        # Test B: Simulated audit failure on /student/dashboard/consent
        with patch("app.routers.verify.log_action", side_effect=RuntimeError("Simulated dashboard audit failure")):
            resp_err_dash = auth_client.post(
                "/student/dashboard/consent",
                data={"consent_level": "2"},
            )
            self.assertEqual(resp_err_dash.status_code, 500)

        # Verify database state after simulated failure on dashboard
        with Session(engine) as s:
            stu_dash_after = s.exec(select(Student).where(Student.apaar_id == "999111222001")).one()
            self.assertEqual(stu_dash_after.consent_level, initial_level)
            self.assertEqual(stu_dash_after.record_signature, initial_sig)
            self.assertEqual(stu_dash_after.consent_timestamp, initial_ts)
            self.assertEqual(len(s.exec(select(AuditLog)).all()), audit_count_before)
            chain_valid, broken_at = verify_chain(s)
            self.assertTrue(chain_valid)

    def test_11_valid_dashboard_self_update(self):
        """Valid consent update via student dashboard endpoint succeeds and records audit log."""
        # Authenticate as Student A
        resp_login = self.client.post(
            "/student/consent",
            data={"action": "login", "apaar_id": "999111222001", "otp": "123456"},
        )
        cookie = resp_login.cookies.get("access_token")
        auth_client = TestClient(app, cookies={"access_token": cookie}, raise_server_exceptions=False)

        resp_dash = auth_client.post(
            "/student/dashboard/consent",
            data={"consent_level": "2"},
            follow_redirects=False,
        )
        self.assertEqual(resp_dash.status_code, 303)
        self.assertEqual(resp_dash.headers.get("location"), "/student/dashboard")

        with Session(engine) as s:
            stu = s.exec(select(Student).where(Student.apaar_id == "999111222001")).one()
            self.assertEqual(stu.consent_level, 2)
            self.assertIsNotNone(stu.consent_timestamp)
            self.assertTrue(verify_signature(stu, stu.record_signature, session=s))

            # Verify audit entry recorded
            audit_entry = s.exec(
                select(AuditLog)
                .where(AuditLog.entity == "STUDENT", AuditLog.action == "UPDATE_CONSENT", AuditLog.entity_id == str(stu.id))
                .order_by(AuditLog.id.desc())
            ).first()
            self.assertIsNotNone(audit_entry)
            self.assertIn("Tier 2", audit_entry.details)

            chain_valid, broken_at = verify_chain(s)
            self.assertTrue(chain_valid)


if __name__ == "__main__":
    unittest.main()
