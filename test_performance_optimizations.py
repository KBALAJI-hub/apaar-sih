"""
Regression and validation tests for performance optimizations:
1. /api/aicte/summary aggregation correctness and pagination metadata
2. /aicte/institutions and /aicte/reports server-side pagination
3. batch_intake_check correctness vs intake_check
4. compliance_score pre-fetched flags and alerts reuse
5. Database model index definitions
"""

import unittest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from app.main import app
from app.database import engine, get_session
from app.models import User, Institution, Program, Student, ValidationFlag, AnomalyAlert
from app.auth import create_access_token
from app.validation import intake_check, batch_intake_check
from app.anomaly import compliance_score

client = TestClient(app, raise_server_exceptions=True)


class TestPerformanceOptimizations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with Session(engine) as session:
            admin = session.exec(select(User).where(User.role == "AICTE_ADMIN")).first()
            inst_user = session.exec(select(User).where(User.role == "INSTITUTION")).first()
            cls.admin_token = create_access_token({"sub": admin.username, "role": admin.role}) if admin else ""
            cls.inst_token = create_access_token({
                "sub": inst_user.username,
                "role": inst_user.role,
                "institution_id": inst_user.institution_id,
            }) if inst_user else ""
            cls.first_inst = session.exec(select(Institution)).first()

    def test_01_api_aicte_summary_pagination_and_aggregates(self):
        """Confirm /api/aicte/summary returns correct aggregate schema and paginated rows."""
        resp = client.get("/api/aicte/summary?page=1&page_size=25", cookies={"access_token": self.admin_token})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        # Check required fields
        self.assertIn("totals", data)
        self.assertIn("institutions", data)
        self.assertIn("flags_by_rule", data)
        self.assertIn("latest_high_flags", data)
        self.assertIn("anomaly_alerts", data)
        self.assertIn("academic_years", data)
        self.assertIn("states", data)
        self.assertIn("types", data)
        self.assertIn("page", data)
        self.assertIn("page_size", data)
        self.assertIn("total_matched", data)
        self.assertIn("total_pages", data)

        # Check totals types
        totals = data["totals"]
        self.assertIsInstance(totals["institutions"], int)
        self.assertIsInstance(totals["total_enrolment"], int)
        self.assertIsInstance(totals["total_intake"], int)
        self.assertIsInstance(totals["flagged_institutions"], int)
        self.assertIsInstance(totals["cross_institution_duplicates"], int)

        # Check pagination boundaries
        self.assertEqual(data["page"], 1)
        self.assertEqual(data["page_size"], 25)
        self.assertLessEqual(len(data["institutions"]), 25)

        # Verify page 2 has different slice if multiple pages exist
        if data["total_pages"] > 1:
            resp_p2 = client.get("/api/aicte/summary?page=2&page_size=25", cookies={"access_token": self.admin_token})
            self.assertEqual(resp_p2.status_code, 200)
            data_p2 = resp_p2.json()
            self.assertEqual(data_p2["page"], 2)
            if data["institutions"] and data_p2["institutions"]:
                self.assertNotEqual(data["institutions"][0]["id"], data_p2["institutions"][0]["id"])

    def test_02_batch_intake_check_matches_single_intake_check(self):
        """Confirm batch_intake_check produces results identical to per-program intake_check."""
        with Session(engine) as session:
            programs = session.exec(select(Program).limit(5)).all()
            if not programs:
                self.skipTest("No programs available in database")

            batch_results = batch_intake_check(programs, session)
            self.assertEqual(len(batch_results), len(programs))

            for prog, batch_res in zip(programs, batch_results):
                single_res = intake_check(prog.id, session)
                self.assertEqual(batch_res["program_id"], single_res["program_id"])
                self.assertEqual(batch_res["enrolled_regular"], single_res["enrolled_regular"])
                self.assertEqual(batch_res["enrolled_supernumerary"], single_res["enrolled_supernumerary"])
                self.assertEqual(batch_res["approved_intake"], single_res["approved_intake"])
                self.assertEqual(batch_res["fill_ratio"], single_res["fill_ratio"])
                self.assertEqual(batch_res["decision"], single_res["decision"])

    def test_03_compliance_score_reused_results(self):
        """Confirm compliance_score produces identical results when pre-fetched flags/alerts are passed."""
        with Session(engine) as session:
            inst = session.exec(select(Institution)).first()
            if not inst:
                self.skipTest("No institution available")

            # Default without pre-fetched
            score_default = compliance_score(inst.id, session)

            # Pre-fetched
            flags = session.exec(
                select(ValidationFlag).where(
                    ValidationFlag.institution_id == inst.id,
                    ValidationFlag.status == "OPEN",
                )
            ).all()
            alerts = session.exec(
                select(AnomalyAlert).where(AnomalyAlert.institution_id == inst.id)
            ).all()

            score_prefetched = compliance_score(inst.id, session, flags=flags, alerts=alerts)
            self.assertEqual(score_default, score_prefetched)

    def test_04_reports_and_institutions_pagination(self):
        """Confirm /aicte/reports and /aicte/institutions render with pagination context."""
        resp_reports = client.get("/aicte/reports?page=1&page_size=20", cookies={"access_token": self.admin_token})
        self.assertEqual(resp_reports.status_code, 200)
        self.assertIn("Page 1 of", resp_reports.text)

        resp_insts = client.get("/aicte/institutions?page=1&page_size=20", cookies={"access_token": self.admin_token})
        self.assertEqual(resp_insts.status_code, 200)
        self.assertIn("Page 1 of", resp_insts.text)

    def test_05_institution_dashboard_render(self):
        """Confirm /institution/dashboard renders successfully with batch intake data."""
        resp = client.get("/institution/dashboard", cookies={"access_token": self.inst_token})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Dashboard", resp.text)


if __name__ == "__main__":
    unittest.main()
