"""
Comprehensive Test Suite for Phase 2: Academic-Year-Specific Seat Validation.
SIH PS 26263 - APAAR Verify

Verifies:
1. Two academic years with independent capacities (filling one does not block the other).
2. Multiple students in the same program and academic year enforce capacity limits correctly.
3. Historical students from previous academic years do not consume current-year capacity.
4. Missing admission year is rejected explicitly across single entry, CSV, and JSON bulk.
5. Invalid academic-year formats (non-integer, future, mismatch with program) are rejected.
6. Student transfer or update across academic years handles capacity correctly and updates records.
7. CSV and JSON uploads with different academic years validate against respective programs independently.
"""

import io
import unittest
from fastapi.testclient import TestClient
from sqlmodel import Session, select, func

from app.main import app
from app.database import engine
from app.models import User, Institution, Program, Student, ValidationFlag, ApaarRegistry
from app.auth import create_access_token
from app.validation import (
    validate_admission_capacity,
    BatchCapacityTracker,
    intake_check,
    parse_academic_year,
    validate_student_admission_year,
)

client = TestClient(app, raise_server_exceptions=True)


class TestAcademicYearCapacity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with Session(engine) as session:
            inst_user = session.exec(select(User).where(User.role == "INSTITUTION")).first()
            cls.institution = session.exec(select(Institution).where(Institution.id == inst_user.institution_id)).first()
            cls.inst_token = create_access_token({
                "sub": inst_user.username,
                "role": inst_user.role,
                "institution_id": inst_user.institution_id,
            })
            cls.api_key = cls.institution.api_key

    def setUp(self):
        # Create two distinct academic year programs: 2023-24 (intake 2) and 2024-25 (intake 2)
        with Session(engine) as session:
            self.prog_2023 = Program(
                name="Computer Science 2023",
                level="UG",
                academic_year="2023-24",
                approved_intake=2,
                supernumerary_cap=0.0,
                institution_id=self.institution.id,
            )
            self.prog_2024 = Program(
                name="Computer Science 2024",
                level="UG",
                academic_year="2024-25",
                approved_intake=2,
                supernumerary_cap=0.0,
                institution_id=self.institution.id,
            )
            session.add(self.prog_2023)
            session.add(self.prog_2024)
            session.commit()
            session.refresh(self.prog_2023)
            session.refresh(self.prog_2024)
            self.prog_2023_id = self.prog_2023.id
            self.prog_2024_id = self.prog_2024.id

    def tearDown(self):
        with Session(engine) as session:
            for pid in (self.prog_2023_id, self.prog_2024_id):
                students = session.exec(select(Student).where(Student.program_id == pid)).all()
                for s in students:
                    session.delete(s)
                flags = session.exec(select(ValidationFlag).where(ValidationFlag.program_id == pid)).all()
                for f in flags:
                    session.delete(f)
                prog = session.get(Program, pid)
                if prog:
                    session.delete(prog)
            session.commit()

    def _seed_student(self, index: int, program_id: int, admission_year: int, adm_type: str = "REGULAR", status: str = "ACTIVE") -> Student:
        """Seed a student with a valid central registry record so R2 passes."""
        aid = f"81{program_id % 10000:04d}{index:06d}"
        with Session(engine) as session:
            reg = session.exec(select(ApaarRegistry).where(ApaarRegistry.apaar_id == aid)).first()
            if not reg:
                session.add(ApaarRegistry(
                    apaar_id=aid,
                    full_name=f"Student {index}",
                    dob="2004-01-01",
                    gender="M",
                ))
            stu = Student(
                apaar_id=aid,
                student_id=f"ROLL-{program_id}-{index:04d}",
                full_name=f"Student {index}",
                dob="2004-01-01",
                gender="M",
                category="GENERAL",
                institution_id=self.institution.id,
                program_id=program_id,
                admission_year=admission_year,
                admission_type=adm_type,
                status=status,
                consent_level=1,
            )
            session.add(stu)
            session.commit()
            session.refresh(stu)
            return stu

    def _seed_registry_only(self, index: int, prefix: int = 82) -> str:
        """Seed only central registry record without creating an institutional enrollment."""
        aid = f"{prefix}{self.prog_2024_id % 10000:04d}{index:06d}"
        with Session(engine) as session:
            reg = session.exec(select(ApaarRegistry).where(ApaarRegistry.apaar_id == aid)).first()
            if not reg:
                session.add(ApaarRegistry(
                    apaar_id=aid,
                    full_name=f"Batch Student {index}",
                    dob="2004-01-01",
                    gender="M",
                ))
                session.commit()
        return aid

    # -------------------------------------------------------------------------
    # 1. Two academic years with independent capacities
    # -------------------------------------------------------------------------
    def test_01_two_academic_years_independent_capacities(self):
        """Test that filling intake for 2023-24 does not consume or block seats in 2024-25."""
        # Fill 2023-24 program to capacity (2/2)
        self._seed_student(1, self.prog_2023_id, 2023, "REGULAR")
        self._seed_student(2, self.prog_2023_id, 2023, "REGULAR")

        with Session(engine) as session:
            # 2023-24 must be blocked for a 3rd admission
            res_2023 = validate_admission_capacity(
                session=session,
                program_id=self.prog_2023_id,
                admission_type="REGULAR",
                admission_year=2023,
                allow_override=False,
            )
            self.assertFalse(res_2023.allowed)
            self.assertEqual(res_2023.decision, "BLOCK")

            # 2024-25 program must still have full 2 seats available
            res_2024 = validate_admission_capacity(
                session=session,
                program_id=self.prog_2024_id,
                admission_type="REGULAR",
                admission_year=2024,
                allow_override=False,
            )
            self.assertTrue(res_2024.allowed)
            self.assertEqual(res_2024.intake_data["enrolled_regular"], 0)
            self.assertEqual(res_2024.intake_data["remaining_seats"], 2)

    # -------------------------------------------------------------------------
    # 2. Multiple students in the same program and academic year
    # -------------------------------------------------------------------------
    def test_02_multiple_students_same_program_and_year(self):
        """Test sequential admissions in the same program and academic year."""
        with Session(engine) as session:
            # Seat 1
            res1 = validate_admission_capacity(
                session=session,
                program_id=self.prog_2024_id,
                admission_type="REGULAR",
                admission_year=2024,
            )
            self.assertTrue(res1.allowed)

        self._seed_student(11, self.prog_2024_id, 2024, "REGULAR")

        with Session(engine) as session:
            # Seat 2
            res2 = validate_admission_capacity(
                session=session,
                program_id=self.prog_2024_id,
                admission_type="REGULAR",
                admission_year=2024,
            )
            self.assertTrue(res2.allowed)
            self.assertEqual(res2.intake_data["remaining_seats"], 1)

        self._seed_student(12, self.prog_2024_id, 2024, "REGULAR")

        with Session(engine) as session:
            # Seat 3 -> Over capacity
            res3 = validate_admission_capacity(
                session=session,
                program_id=self.prog_2024_id,
                admission_type="REGULAR",
                admission_year=2024,
            )
            self.assertFalse(res3.allowed)
            self.assertEqual(res3.decision, "BLOCK")

    # -------------------------------------------------------------------------
    # 3. Historical students from previous academic years do not pollute capacity
    # -------------------------------------------------------------------------
    def test_03_historical_students_do_not_consume_capacity(self):
        """Active historical students (e.g. from 2021 or 2022) must not count toward 2024 capacity."""
        # Seed 5 historical active students into prog_2024 with admission_year=2022
        for i in range(5):
            self._seed_student(20 + i, self.prog_2024_id, 2022, "REGULAR", status="ACTIVE")

        with Session(engine) as session:
            # Check intake check specifically for academic year 2024
            data_2024 = intake_check(
                program_id=self.prog_2024_id,
                session=session,
                admission_year=2024,
            )
            # Enrolled regular for 2024 must be 0, not 5
            self.assertEqual(data_2024["enrolled_regular"], 0)
            self.assertEqual(data_2024["remaining_seats"], 2)

            # Capacity validation for 2024 must ALLOW
            res = validate_admission_capacity(
                session=session,
                program_id=self.prog_2024_id,
                admission_type="REGULAR",
                admission_year=2024,
            )
            self.assertTrue(res.allowed)

    # -------------------------------------------------------------------------
    # 4. Missing admission year is rejected explicitly
    # -------------------------------------------------------------------------
    def test_04_missing_admission_year_rejected(self):
        """Missing admission year is rejected across single entry, CSV, and JSON bulk."""
        aid1 = self._seed_registry_only(41)

        # 4a. Single-entry web route
        resp_web = client.post(
            "/institution/students/new",
            data={
                "apaar_id": aid1,
                "student_id": "NO-YR-01",
                "full_name": "Batch Student 41",
                "dob": "2004-01-01",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_2024_id,
                # admission_year omitted entirely
                "admission_type": "REGULAR",
                "consent_level": 1,
            },
            cookies={"access_token": self.inst_token},
        )
        self.assertEqual(resp_web.status_code, 400)
        self.assertIn("Admission year is required", resp_web.text)

        # 4b. CSV upload with empty admission_year
        aid2 = self._seed_registry_only(42)
        csv_content = (
            "apaar_id,student_id,full_name,dob,gender,category,program_name,admission_year,admission_type,consent_given\n"
            f"{aid2},CSV-NO-YR,Batch Student 42,2004-01-01,M,GENERAL,{self.prog_2024.name},,REGULAR,true\n"
        )
        resp_csv = client.post(
            "/institution/upload",
            files={"file": ("no_year.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")},
            cookies={"access_token": self.inst_token},
        )
        # CSV upload displays error report
        self.assertEqual(resp_csv.status_code, 200)
        self.assertTrue("admission_year" in resp_csv.text.lower())

        # 4c. JSON bulk upload with missing admission_year
        aid3 = self._seed_registry_only(43)
        resp_json = client.post(
            "/api/v1/students/bulk",
            headers={"X-API-Key": self.api_key},
            json=[{
                "apaar_id": aid3,
                "student_id": "JSON-NO-YR",
                "full_name": "Batch Student 43",
                "dob": "2004-01-01",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_2024_id,
                "admission_year": None,
                "admission_type": "REGULAR",
                "consent_given": True,
            }],
        )
        self.assertEqual(resp_json.status_code, 200)
        data = resp_json.json()
        self.assertEqual(data["rejected"], 1)
        self.assertIn("R9", data["errors"][0]["rule_codes"])

    # -------------------------------------------------------------------------
    # 5. Invalid academic-year formats are rejected
    # -------------------------------------------------------------------------
    def test_05_invalid_academic_year_formats(self):
        """Invalid formats (non-integer, future, mismatch) are rejected."""
        # 5a. Direct validation service checks
        val_res, _, err = validate_student_admission_year(2050, "2024-25")
        self.assertFalse(val_res)
        self.assertIn("is in the future", err)

        val_res_str, _, err_str = validate_student_admission_year("invalid_year", "2024-25")
        self.assertFalse(val_res_str)
        self.assertIn("Invalid academic admission year", err_str)

        # 5b. Future year via API rejected
        aid_future = self._seed_registry_only(51)
        resp_future = client.post(
            "/api/v1/students/bulk",
            headers={"X-API-Key": self.api_key},
            json=[{
                "apaar_id": aid_future,
                "student_id": "FUT-01",
                "full_name": "Batch Student 51",
                "dob": "2004-01-01",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_2024_id,
                "admission_year": 2045,
                "admission_type": "REGULAR",
                "consent_given": True,
            }],
        )
        self.assertEqual(resp_future.status_code, 200)
        self.assertEqual(resp_future.json()["rejected"], 1)

        # 5c. Year mismatch between student admission_year and Program academic_year
        aid_mismatch = self._seed_registry_only(52)
        resp_mismatch = client.post(
            "/api/v1/students/bulk",
            headers={"X-API-Key": self.api_key},
            json=[{
                "apaar_id": aid_mismatch,
                "student_id": "MIS-01",
                "full_name": "Batch Student 52",
                "dob": "2004-01-01",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_2024_id,  # Program is 2024-25
                "admission_year": 2023,             # Student year is 2023
                "admission_type": "REGULAR",
                "consent_given": True,
            }],
        )
        self.assertEqual(resp_mismatch.status_code, 200)
        self.assertEqual(resp_mismatch.json()["rejected"], 1)
        self.assertIn("not approved for admission year 2023", resp_mismatch.json()["errors"][0]["errors"][0])

    # -------------------------------------------------------------------------
    # 6. Student transfer or update across academic years
    # -------------------------------------------------------------------------
    def test_06_student_update_across_academic_years(self):
        """Updating a student to a different program and academic year checks target capacity and updates properly."""
        # Fill 2024 program to capacity (2/2)
        stu_61 = self._seed_student(61, self.prog_2024_id, 2024, "REGULAR")
        self._seed_student(62, self.prog_2024_id, 2024, "REGULAR")

        # Student in 2023 program
        stu_2023 = self._seed_student(63, self.prog_2023_id, 2023, "REGULAR")

        # Attempt to transfer stu_2023 into 2024 program (which is FULL) without override
        resp_blocked = client.put(
            f"/api/v1/students/{stu_2023.apaar_id}",
            headers={"X-API-Key": self.api_key},
            json={
                "program_id": self.prog_2024_id,
                "admission_year": 2024,
            },
        )
        self.assertEqual(resp_blocked.status_code, 400)
        detail = resp_blocked.json()["detail"].lower()
        self.assertTrue("capacity" in detail or "override" in detail or "justification" in detail)

        # Now free a seat in 2024 program by marking student 61 WITHDRAWN
        resp_withdraw = client.put(
            f"/api/v1/students/{stu_61.apaar_id}",
            headers={"X-API-Key": self.api_key},
            json={"status": "WITHDRAWN"},
        )
        self.assertEqual(resp_withdraw.status_code, 200)

        # Now transfer stu_2023 into 2024 program (now that 1 seat is freed)
        resp_transfer = client.put(
            f"/api/v1/students/{stu_2023.apaar_id}",
            headers={"X-API-Key": self.api_key},
            json={
                "program_id": self.prog_2024_id,
                "admission_year": 2024,
            },
        )
        self.assertEqual(resp_transfer.status_code, 200)

        # Verify transfer in database
        with Session(engine) as session:
            updated = session.exec(select(Student).where(Student.apaar_id == stu_2023.apaar_id)).first()
            self.assertEqual(updated.program_id, self.prog_2024_id)
            self.assertEqual(updated.admission_year, 2024)

    # -------------------------------------------------------------------------
    # 7. CSV and JSON uploads with different academic years
    # -------------------------------------------------------------------------
    def test_07_csv_and_json_uploads_with_different_academic_years(self):
        """Batch uploads containing records for multiple academic years validate against respective programs independently."""
        aid_a = self._seed_registry_only(71)
        aid_b = self._seed_registry_only(72)
        aid_24_1 = self._seed_registry_only(73)
        aid_24_2 = self._seed_registry_only(74)
        aid_24_3 = self._seed_registry_only(75)

        # 7a. JSON Bulk Upload with interleaved academic years
        # prog_2023 capacity=2, prog_2024 capacity=2
        # We send 2 for 2023 (should accept both) and 3 for 2024 (should accept 2, reject 3rd)
        json_batch = [
            # 2023 program (2 allowed)
            {
                "apaar_id": aid_a,
                "student_id": "BATCH-23-1",
                "full_name": "Batch Student 71",
                "dob": "2004-01-01",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_2023_id,
                "admission_year": 2023,
                "admission_type": "REGULAR",
                "consent_given": True,
            },
            {
                "apaar_id": aid_b,
                "student_id": "BATCH-23-2",
                "full_name": "Batch Student 72",
                "dob": "2004-01-01",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_2023_id,
                "admission_year": 2023,
                "admission_type": "REGULAR",
                "consent_given": True,
            },
            # 2024 program (intake=2, sending 3: 1st & 2nd accepted, 3rd rejected)
            {
                "apaar_id": aid_24_1,
                "student_id": "BATCH-24-1",
                "full_name": "Batch Student 73",
                "dob": "2004-01-01",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_2024_id,
                "admission_year": 2024,
                "admission_type": "REGULAR",
                "consent_given": True,
            },
            {
                "apaar_id": aid_24_2,
                "student_id": "BATCH-24-2",
                "full_name": "Batch Student 74",
                "dob": "2004-01-01",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_2024_id,
                "admission_year": 2024,
                "admission_type": "REGULAR",
                "consent_given": True,
            },
            {
                "apaar_id": aid_24_3,
                "student_id": "BATCH-24-3",
                "full_name": "Batch Student 75",
                "dob": "2004-01-01",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_2024_id,
                "admission_year": 2024,
                "admission_type": "REGULAR",
                "consent_given": True,
            },
        ]

        resp = client.post(
            "/api/v1/students/bulk",
            headers={"X-API-Key": self.api_key},
            json=json_batch,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["accepted_clean"], 4)
        self.assertEqual(data["rejected"], 1)
        self.assertEqual(data["errors"][0]["index"], 4)
        self.assertIn("capacity exceeded", data["errors"][0]["errors"][0].lower())

        # 7b. CSV Upload with multiple academic years
        aid_csv_23 = self._seed_registry_only(81)
        aid_csv_24 = self._seed_registry_only(82)
        # Note: 2023 is already full (2/2) and 2024 is full (2/2)
        csv_content = (
            "apaar_id,student_id,full_name,dob,gender,category,program_name,admission_year,admission_type,consent_given\n"
            f"{aid_csv_23},CSV-MULTI-23,Batch Student 81,2004-01-01,M,GENERAL,{self.prog_2023.name},2023,REGULAR,true\n"
            f"{aid_csv_24},CSV-MULTI-24,Batch Student 82,2004-01-01,M,GENERAL,{self.prog_2024.name},2024,REGULAR,true\n"
        )
        resp_csv = client.post(
            "/institution/upload",
            files={"file": ("multi_year.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")},
            cookies={"access_token": self.inst_token},
        )
        self.assertEqual(resp_csv.status_code, 200)
        # Both programs were full; both rows rejected due to capacity exceeded
        self.assertIn("capacity exceeded", resp_csv.text.lower())


if __name__ == "__main__":
    unittest.main()
