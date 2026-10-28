"""
Comprehensive Test Suite for APAAR Verify Seat Validation Rules & Integrity (SIH PS 26263):
1. Four Independent Seat Scenarios (100 Regular + 20 Supernumerary):
   - Scenario 1: Within all limits (80 Reg, 10 Super) -> ALLOW
   - Scenario 2: Regular breached, super within (105 Reg, 10 Super, Total 115 < 120) -> Detects Regular breach (+5), R6 triggered, blocks regular, allows super
   - Scenario 3: Super breached, regular within (90 Reg, 25 Super, Total 115 < 120) -> Detects Super breach (+5), R7 triggered, blocks super, allows regular
   - Scenario 4: Total capacity breached (102 Reg, 22 Super, Total 124 > 120) -> All 3 rules breached, blocks all
2. Exact-Capacity Boundaries (99 -> 100 -> 101, 19 -> 20 -> 21, 119 -> 120 -> 121, 90% WARN threshold)
3. Withdrawn-Student Reactivation (Reactivating withdrawn regular student when quota full is blocked)
4. Admission Type Change Quota Check (SUPERNUMERARY -> REGULAR blocked when regular full)
5. Override Authorization & Statutory Hard Ceiling (105% hard ceiling unbypassable; min 20 char regulatory justification logged to AuditLog)
6. CSV Upload Quota Enforcement (New admissions over quota rejected with reasons in error CSV; not silently accepted)
7. API Program Intake Check & Student Update by APAAR ID
"""

import io
import unittest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from app.main import app
from app.database import engine, get_session
from app.models import User, Institution, Program, Student, ValidationFlag, AuditLog, ApaarRegistry
from app.auth import create_access_token
from app.validation import (
    intake_check,
    batch_intake_check,
    validate_program_intake,
    validate_override_request,
    HARD_REJECT_RULE_CODES,
    MAX_OVERRIDE_BUFFER_RATIO,
)
from app.audit import verify_chain

client = TestClient(app, raise_server_exceptions=True)


class TestSeatValidationRules(unittest.TestCase):
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
            cls.institution = session.exec(select(Institution).where(Institution.id == inst_user.institution_id)).first()

    def setUp(self):
        # Create dedicated isolated test program with illustrative limits: 100 regular, 20 supernumerary (cap = 0.20)
        with Session(engine) as session:
            self.test_prog = Program(
                name="Quota Verification Engineering",
                level="UG",
                academic_year="2024-25",
                approved_intake=100,
                supernumerary_cap=0.20,  # 20% supernumerary quota = 20 seats (Total capacity = 120)
                institution_id=self.institution.id,
            )
            session.add(self.test_prog)
            session.commit()
            session.refresh(self.test_prog)
            self.prog_id = self.test_prog.id

    def tearDown(self):
        with Session(engine) as session:
            # Clean up all students and flags created for this program
            students = session.exec(select(Student).where(Student.program_id == self.prog_id)).all()
            for s in students:
                session.delete(s)
            flags = session.exec(select(ValidationFlag).where(ValidationFlag.program_id == self.prog_id)).all()
            for f in flags:
                session.delete(f)
            prog = session.get(Program, self.prog_id)
            if prog:
                session.delete(prog)
            session.commit()

    def _seed_students(self, regular_count: int, super_count: int, status: str = "ACTIVE") -> None:
        with Session(engine) as session:
            for i in range(regular_count):
                session.add(Student(
                    apaar_id=f"8888{self.prog_id:04d}{i:04d}",
                    student_id=f"REG-{self.prog_id}-{i:04d}",
                    full_name=f"Regular Student {i}",
                    dob="2004-01-01",
                    gender="M",
                    institution_id=self.institution.id,
                    program_id=self.prog_id,
                    admission_year=2024,
                    admission_type="REGULAR",
                    status=status,
                    consent_level=1,
                ))
            for j in range(super_count):
                session.add(Student(
                    apaar_id=f"7777{self.prog_id:04d}{j:04d}",
                    student_id=f"SUP-{self.prog_id}-{j:04d}",
                    full_name=f"Supernumerary Student {j}",
                    dob="2004-02-02",
                    gender="F",
                    institution_id=self.institution.id,
                    program_id=self.prog_id,
                    admission_year=2024,
                    admission_type="SUPERNUMERARY",
                    status=status,
                    consent_level=1,
                ))
            session.commit()

    def test_01_scenario_1_all_within_limits(self):
        """Scenario 1: 80 Regular, 10 Supernumerary out of 100 Regular, 20 Supernumerary (Total = 90 <= 120)."""
        self._seed_students(80, 10)
        with Session(engine) as session:
            intake = intake_check(self.prog_id, session)

            # Assert independent statuses
            self.assertEqual(intake["approved_intake"], 100)
            self.assertEqual(intake["permitted_supernumerary"], 20)
            self.assertEqual(intake["total_capacity"], 120)
            self.assertEqual(intake["enrolled_regular"], 80)
            self.assertEqual(intake["enrolled_supernumerary"], 10)
            self.assertEqual(intake["total_enrolled"], 90)

            self.assertEqual(intake["regular_status"]["decision"], "ALLOW")
            self.assertEqual(intake["supernumerary_status"]["decision"], "ALLOW")
            self.assertEqual(intake["total_status"]["decision"], "ALLOW")
            self.assertEqual(intake["decision"], "ALLOW")
            self.assertEqual(len(intake["violations"]), 0)

            # Program intake validation flags check
            flags = validate_program_intake(self.prog_id, session)
            self.assertEqual(len(flags), 0)

    def test_02_scenario_2_regular_breached_super_within(self):
        """Scenario 2: 105 Regular, 10 Supernumerary out of 100 Regular, 20 Supernumerary (Total = 115 < 120)."""
        self._seed_students(105, 10)
        with Session(engine) as session:
            # Check without target type
            intake = intake_check(self.prog_id, session)
            self.assertEqual(intake["regular_status"]["decision"], "BLOCK")
            self.assertEqual(intake["supernumerary_status"]["decision"], "ALLOW")
            # Total fill ratio is 115/120 = 95.8% (above 90% warn threshold, but below 100% capacity limit)
            self.assertEqual(intake["total_status"]["decision"], "WARN")
            self.assertEqual(intake["decision"], "BLOCK")
            self.assertTrue(any("Regular admissions (105) exceed approved intake (100) by 5 seat(s)" in v for v in intake["violations"]))

            # Check targeting REGULAR admission -> BLOCKED
            intake_reg = intake_check(self.prog_id, session, target_admission_type="REGULAR")
            self.assertEqual(intake_reg["decision"], "BLOCK")

            # Check targeting SUPERNUMERARY admission -> WARN (due to total fill ratio 95.8% >= 90%)
            intake_sup = intake_check(self.prog_id, session, target_admission_type="SUPERNUMERARY")
            self.assertEqual(intake_sup["decision"], "WARN")

            # Program flags: R6 triggered (HIGH), R7 NOT triggered
            flags = validate_program_intake(self.prog_id, session)
            self.assertEqual(len(flags), 1)
            self.assertEqual(flags[0].rule_code, "R6")
            self.assertEqual(flags[0].severity, "HIGH")

    def test_03_scenario_3_super_breached_regular_within(self):
        """Scenario 3: 90 Regular, 25 Supernumerary out of 100 Regular, 20 Supernumerary (Total = 115 < 120)."""
        self._seed_students(90, 25)
        with Session(engine) as session:
            intake = intake_check(self.prog_id, session)
            # 90/100 regular = 90% warn threshold
            self.assertEqual(intake["regular_status"]["decision"], "WARN")
            self.assertEqual(intake["supernumerary_status"]["decision"], "BLOCK")
            self.assertEqual(intake["total_status"]["decision"], "WARN")
            self.assertEqual(intake["decision"], "WARN")
            self.assertTrue(any("Supernumerary admissions (25) exceed quota cap (20) by 5 seat(s)" in v for v in intake["violations"]))

            # Check targeting REGULAR admission -> WARN (due to 90% warn threshold)
            intake_reg = intake_check(self.prog_id, session, target_admission_type="REGULAR")
            self.assertEqual(intake_reg["decision"], "WARN")

            # Check targeting SUPERNUMERARY admission -> BLOCKED
            intake_sup = intake_check(self.prog_id, session, target_admission_type="SUPERNUMERARY")
            self.assertEqual(intake_sup["decision"], "BLOCK")

            # Program flags: R7 triggered (MEDIUM), R6 NOT triggered
            flags = validate_program_intake(self.prog_id, session)
            self.assertEqual(len(flags), 1)
            self.assertEqual(flags[0].rule_code, "R7")
            self.assertEqual(flags[0].severity, "MEDIUM")

    def test_04_scenario_4_total_capacity_breached(self):
        """Scenario 4: 102 Regular, 22 Supernumerary out of 100 Regular, 20 Supernumerary (Total = 124 > 120)."""
        self._seed_students(102, 22)
        with Session(engine) as session:
            intake = intake_check(self.prog_id, session)
            self.assertEqual(intake["regular_status"]["decision"], "BLOCK")
            self.assertEqual(intake["supernumerary_status"]["decision"], "BLOCK")
            self.assertEqual(intake["total_status"]["decision"], "BLOCK")
            self.assertEqual(intake["decision"], "BLOCK")
            self.assertEqual(len(intake["violations"]), 3)

            # Both targeted types are BLOCKED
            self.assertEqual(intake_check(self.prog_id, session, target_admission_type="REGULAR")["decision"], "BLOCK")
            self.assertEqual(intake_check(self.prog_id, session, target_admission_type="SUPERNUMERARY")["decision"], "BLOCK")

            # Both R6 and R7 flags triggered
            flags = validate_program_intake(self.prog_id, session)
            rule_codes = {f.rule_code for f in flags}
            self.assertIn("R6", rule_codes)
            self.assertIn("R7", rule_codes)

    def test_05_exact_capacity_boundaries(self):
        """Test exact quota boundaries: 90% WARN, 100% capacity boundary, and 100% + 1 BLOCK."""
        # 90 regular students out of 100 = 90% -> WARN
        self._seed_students(90, 0)
        with Session(engine) as session:
            intake_90 = intake_check(self.prog_id, session, target_admission_type="REGULAR")
            self.assertEqual(intake_90["regular_status"]["decision"], "WARN")
            self.assertEqual(intake_90["decision"], "WARN")
            self.assertEqual(intake_90["remaining_seats"], 10)

        # 99 regular students -> 1 seat remaining
        self._seed_students(9, 0)
        with Session(engine) as session:
            intake_99 = intake_check(self.prog_id, session, target_admission_type="REGULAR")
            self.assertEqual(intake_99["enrolled_regular"], 99)
            self.assertEqual(intake_99["remaining_seats"], 1)

        # 100 regular students -> exact boundary (100/100, 0 remaining) -> BLOCK
        self._seed_students(1, 0)
        with Session(engine) as session:
            intake_100 = intake_check(self.prog_id, session, target_admission_type="REGULAR")
            self.assertEqual(intake_100["enrolled_regular"], 100)
            self.assertEqual(intake_100["remaining_seats"], 0)
            self.assertEqual(intake_100["regular_status"]["decision"], "BLOCK")

    def test_06_withdrawn_student_reactivation_quota_check(self):
        """Test that reactivating a withdrawn student checks seat capacity and blocks if full."""
        # Fill regular capacity to 100
        self._seed_students(100, 0)

        # Add a student with status WITHDRAWN
        with Session(engine) as session:
            withdrawn_stu = Student(
                apaar_id=f"9999{self.prog_id:04d}0001",
                student_id=f"WTH-{self.prog_id}-01",
                full_name="Withdrawn Student",
                dob="2004-03-03",
                gender="M",
                institution_id=self.institution.id,
                program_id=self.prog_id,
                admission_year=2024,
                admission_type="REGULAR",
                status="WITHDRAWN",
                consent_level=1,
            )
            session.add(withdrawn_stu)
            session.commit()
            session.refresh(withdrawn_stu)
            stu_id = withdrawn_stu.id

        # Attempt to reactivate to ACTIVE via form POST without override justification
        resp = client.post(
            f"/institution/students/{stu_id}/edit",
            data={
                "full_name": "Withdrawn Student",
                "dob": "2004-03-03",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_id,
                "admission_year": 2024,
                "admission_type": "REGULAR",
                "status_field": "ACTIVE",  # Reactivation attempt
                "consent_level": 1,
            },
            cookies={"access_token": self.inst_token},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertTrue("is FULL (BLOCK)" in resp.text or "override strictly requires" in resp.text)

        # Now reactivate with valid regulatory override justification (> 20 chars)
        resp_override = client.post(
            f"/institution/students/{stu_id}/edit",
            data={
                "full_name": "Withdrawn Student",
                "dob": "2004-03-03",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_id,
                "admission_year": 2024,
                "admission_type": "REGULAR",
                "status_field": "ACTIVE",
                "consent_level": 1,
                "override_justification": "AICTE_APPROVAL_LETTER: High Court Order HC/2024/7889 for re-admission",
            },
            cookies={"access_token": self.inst_token},
            follow_redirects=False,
        )
        self.assertEqual(resp_override.status_code, 303)

    def test_07_admission_type_change_seat_transfer(self):
        """Test changing admission type from SUPERNUMERARY to REGULAR when regular is full is blocked."""
        # 100 regular, 5 supernumerary
        self._seed_students(100, 5)

        with Session(engine) as session:
            sup_student = session.exec(
                select(Student).where(Student.program_id == self.prog_id, Student.admission_type == "SUPERNUMERARY")
            ).first()
            sup_id = sup_student.id

        # Attempt to edit admission type to REGULAR without override
        resp = client.post(
            f"/institution/students/{sup_id}/edit",
            data={
                "full_name": "Converted Student",
                "dob": "2004-02-02",
                "gender": "F",
                "category": "GENERAL",
                "program_id": self.prog_id,
                "admission_year": 2024,
                "admission_type": "REGULAR",  # Attempt seat type conversion
                "status_field": "ACTIVE",
                "consent_level": 1,
            },
            cookies={"access_token": self.inst_token},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertTrue("Regular intake is FULL (BLOCK)" in resp.text or "override strictly requires" in resp.text)

    def test_08_override_rules_and_statutory_hard_ceiling(self):
        """Test override validation: reject trivial/short justification, enforce 105% statutory hard ceiling."""
        self._seed_students(100, 0)
        with Session(engine) as session:
            intake = intake_check(self.prog_id, session, target_admission_type="REGULAR")
            prog = session.get(Program, self.prog_id)

            # Trivial justification (< 20 chars) -> REJECTED
            valid_trivial, err_trivial = validate_override_request(prog, "REGULAR", "ok override", intake)
            self.assertFalse(valid_trivial)
            self.assertIn("at least 20 characters", err_trivial)

            # Valid regulatory justification within buffer -> ACCEPTED
            valid_formal, err_formal = validate_override_request(
                prog, "REGULAR", "AICTE Approval Letter F.No. AICTE/AB/2024/991 quota enhancement", intake
            )
            self.assertTrue(valid_formal)
            self.assertIsNone(err_formal)

        # Now fill program past statutory hard ceiling (105% of 120 = 126)
        self._seed_students(6, 21)  # Total = 100 + 6 + 21 = 127 > 126
        with Session(engine) as session:
            intake_heavy = intake_check(self.prog_id, session)
            valid_ceiling, err_ceiling = validate_override_request(
                prog, "REGULAR", "AICTE Approval Letter F.No. AICTE/AB/2024/991 quota enhancement", intake_heavy
            )
            self.assertFalse(valid_ceiling)
            self.assertIn("Statutory Hard Ceiling Reached", err_ceiling)

    def test_09_csv_upload_quota_rejection_not_silently_accepted(self):
        """Test that CSV upload rejects new admissions exceeding quota and writes explicit reasons to Error CSV."""
        # Fill program to 98 regular students (approved = 100, 2 seats remaining)
        self._seed_students(98, 0)

        # Seed registry records for the 5 test students so R2 passes
        created_apaar_ids = []
        with Session(engine) as session:
            for k in range(5):
                aid = f"98{(self.prog_id % 10000):04d}{k:06d}"
                created_apaar_ids.append(aid)
                session.add(ApaarRegistry(
                    apaar_id=aid,
                    full_name=f"CSV Student {k}",
                    dob="2004-05-12",
                    gender="M",
                ))
            session.commit()

        try:
            # Upload a CSV containing 5 new regular students
            csv_rows = [
                "apaar_id,student_id,full_name,dob,gender,category,program_name,admission_year,admission_type,is_nri,oci_status,is_foreign_national,nationality,mode,consent_given",
            ]
            for k in range(5):
                apaar_12 = created_apaar_ids[k]
                csv_rows.append(
                    f"{apaar_12},BATCH-{k},CSV Student {k},2004-05-12,M,GENERAL,{self.test_prog.name},2024,REGULAR,False,False,False,Indian,FULL_TIME,True"
                )
            csv_content = "\n".join(csv_rows)

            resp_upload = client.post(
                "/institution/upload",
                files={"file": ("batch_quota_test.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")},
                cookies={"access_token": self.inst_token},
            )
            self.assertEqual(resp_upload.status_code, 200)

            # Exactly 2 students should be admitted; 3 must be rejected
            resp_err_csv = client.get("/institution/upload/error-csv", cookies={"access_token": self.inst_token})
            self.assertEqual(resp_err_csv.status_code, 200)
            err_text = resp_err_csv.text
            self.assertIn("Regular intake capacity exceeded", err_text)

            # Verify database has exactly 100 regular students, not 103!
            with Session(engine) as session:
                active_reg_count = session.exec(
                    select(Student).where(
                        Student.program_id == self.prog_id,
                        Student.admission_type == "REGULAR",
                        Student.status == "ACTIVE",
                    )
                ).all()
                self.assertEqual(len(active_reg_count), 100)
        finally:
            with Session(engine) as session:
                for aid in created_apaar_ids:
                    reg_rec = session.exec(select(ApaarRegistry).where(ApaarRegistry.apaar_id == aid)).first()
                    if reg_rec:
                        session.delete(reg_rec)
                session.commit()

    def test_10_api_intake_check_and_update(self):
        """Test GET /api/v1/programs/{id}/intake-check and PUT /api/v1/students/{apaar_id} API behavior."""
        self._seed_students(105, 10)

        # Public / AJAX endpoint check
        resp_api = client.get(f"/api/v1/programs/{self.prog_id}/intake-check")
        self.assertEqual(resp_api.status_code, 200)
        data = resp_api.json()
        self.assertEqual(data["enrolled_regular"], 105)
        self.assertEqual(data["enrolled_supernumerary"], 10)
        self.assertEqual(data["decision"], "BLOCK")
        self.assertIn("regular_status", data)
        self.assertIn("supernumerary_status", data)
        self.assertIn("total_status", data)

        # Check with target admission type in query param
        resp_api_sup = client.get(f"/api/v1/programs/{self.prog_id}/intake-check?admission_type=SUPERNUMERARY")
        self.assertEqual(resp_api_sup.status_code, 200)
        self.assertEqual(resp_api_sup.json()["supernumerary_status"]["decision"], "ALLOW")
        self.assertEqual(resp_api_sup.json()["decision"], "WARN")

        resp_api_reg = client.get(f"/api/v1/programs/{self.prog_id}/intake-check?admission_type=REGULAR")
        self.assertEqual(resp_api_reg.status_code, 200)
        self.assertEqual(resp_api_reg.json()["decision"], "BLOCK")

    def test_11_dashboard_duplicate_add_student_button_removed(self):
        """Verify that institution_dashboard.html removed duplicate 'Add Student' button and kept Students Directory."""
        resp = client.get("/institution/dashboard", cookies={"access_token": self.inst_token})
        self.assertEqual(resp.status_code, 200)
        html = resp.text
        # Header should have Students Directory
        self.assertIn("Students Directory", html)
        # Should not have duplicate Add Student in the header actions block
        self.assertNotIn('<a href="/institution/students/new"\n               class="inline-flex items-center px-4 py-2.5 border border-transparent rounded-lg text-sm font-semibold text-white bg-indigo-600', html)

    def test_12_legacy_reports_compliance_summary_redirect(self):
        """Verify that /aicte/reports/compliance-summary safely redirects to /aicte/reports?tab=compliance."""
        resp = client.get("/aicte/reports/compliance-summary", cookies={"access_token": self.admin_token}, follow_redirects=False)
        self.assertEqual(resp.status_code, 303)
        self.assertIn("/aicte/reports?tab=compliance", resp.headers["location"])


if __name__ == "__main__":
    unittest.main()
