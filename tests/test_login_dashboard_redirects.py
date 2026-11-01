"""
Automated Verification Suite for Login & Dashboard Role-Based Redirects.
Validates:
1. Direct login redirect to respective dashboards (AICTE Admin, Institution, Verifier, Student).
2. Prevention of /verify query parameter hijacking for non-verifiers.
3. Preservation of legitimate role-specific next destinations (e.g. /aicte/reports, /institution/students).
4. Direct dashboard redirection for authenticated users accessing / or /login.
5. Ability to switch accounts when /login?switch=1 is accessed.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


import unittest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app, raise_server_exceptions=True)


class TestLoginDashboardRedirects(unittest.TestCase):
    def test_01_aicte_admin_login_redirects(self):
        # 1a. Normal login without next parameter
        resp = client.post("/login", data={"username": "aicte_admin", "password": "Admin@123"}, follow_redirects=False)
        self.assertIn(resp.status_code, (302, 303))
        self.assertEqual(resp.headers.get("location"), "/aicte/dashboard")

        # 1b. Login with hijacked next=/verify query param - MUST still redirect to /aicte/dashboard
        resp_hijack = client.post("/login?next=/verify", data={"username": "aicte_admin", "password": "Admin@123"}, follow_redirects=False)
        self.assertIn(resp_hijack.status_code, (302, 303))
        self.assertEqual(resp_hijack.headers.get("location"), "/aicte/dashboard")

        # 1c. Login with legitimate admin next param - should honor /aicte/reports
        resp_legit = client.post("/login?next=/aicte/reports", data={"username": "aicte_admin", "password": "Admin@123"}, follow_redirects=False)
        self.assertIn(resp_legit.status_code, (302, 303))
        self.assertEqual(resp_legit.headers.get("location"), "/aicte/reports")

    def test_02_institution_login_redirects(self):
        # 2a. Normal login without next parameter
        resp = client.post("/login", data={"username": "inst1", "password": "Inst@123"}, follow_redirects=False)
        self.assertIn(resp.status_code, (302, 303))
        self.assertEqual(resp.headers.get("location"), "/institution/dashboard")

        # 2b. Login with hijacked next=/verify query param - MUST still redirect to /institution/dashboard
        resp_hijack = client.post("/login?next=/verify", data={"username": "inst1", "password": "Inst@123"}, follow_redirects=False)
        self.assertIn(resp_hijack.status_code, (302, 303))
        self.assertEqual(resp_hijack.headers.get("location"), "/institution/dashboard")

        # 2c. Login with legitimate institution next param - should honor /institution/students
        resp_legit = client.post("/login?next=/institution/students", data={"username": "inst1", "password": "Inst@123"}, follow_redirects=False)
        self.assertIn(resp_legit.status_code, (302, 303))
        self.assertEqual(resp_legit.headers.get("location"), "/institution/students")

    def test_03_verifier_login_redirects(self):
        # 3a. Normal login without next parameter -> /verify
        resp = client.post("/login", data={"username": "employer1", "password": "Verify@123"}, follow_redirects=False)
        self.assertIn(resp.status_code, (302, 303))
        self.assertEqual(resp.headers.get("location"), "/verify")

        # 3b. Login with next=/verify -> /verify
        resp_v = client.post("/login?next=/verify", data={"username": "employer1", "password": "Verify@123"}, follow_redirects=False)
        self.assertIn(resp_v.status_code, (302, 303))
        self.assertEqual(resp_v.headers.get("location"), "/verify")

    def test_04_student_login_redirects(self):
        # 4a. Normal login without next parameter -> /student/dashboard
        resp = client.post("/login", data={"username": "student1", "password": "Student@123"}, follow_redirects=False)
        self.assertIn(resp.status_code, (302, 303))
        self.assertEqual(resp.headers.get("location"), "/student/dashboard")

        # 4b. Login with hijacked next=/verify query param -> /student/dashboard
        resp_hijack = client.post("/login?next=/verify", data={"username": "student1", "password": "Student@123"}, follow_redirects=False)
        self.assertIn(resp_hijack.status_code, (302, 303))
        self.assertEqual(resp_hijack.headers.get("location"), "/student/dashboard")

    def test_05_authenticated_user_navigation(self):
        # Authenticate as AICTE Admin
        login_resp = client.post("/login", data={"username": "aicte_admin", "password": "Admin@123"}, follow_redirects=False)
        cookie = login_resp.cookies.get("access_token")
        self.assertIsNotNone(cookie)

        auth_client = TestClient(app, cookies={"access_token": cookie}, raise_server_exceptions=True)

        # GET / should redirect authenticated admin to /aicte/dashboard
        resp_root = auth_client.get("/", follow_redirects=False)
        self.assertIn(resp_root.status_code, (302, 303))
        self.assertEqual(resp_root.headers.get("location"), "/aicte/dashboard")

        # GET /login should redirect authenticated admin to /aicte/dashboard
        resp_login = auth_client.get("/login", follow_redirects=False)
        self.assertIn(resp_login.status_code, (302, 303))
        self.assertEqual(resp_login.headers.get("location"), "/aicte/dashboard")

        # GET /login?switch=1 should render login page for account switching
        resp_switch = auth_client.get("/login?switch=1", follow_redirects=False)
        self.assertEqual(resp_switch.status_code, 200)
        self.assertIn("Welcome back", resp_switch.text)


if __name__ == "__main__":
    unittest.main()

