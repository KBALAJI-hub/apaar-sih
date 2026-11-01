"""
Comprehensive Test Suite for Phase 1: Unified Admission Capacity Enforcement.
SIH PS 26263 - APAAR Verify

Verifies:
1. Regular capacity cannot be exceeded.
2. Supernumerary capacity cannot be exceeded.
3. Combined capacity cannot be exceeded.
4. JSON bulk upload rejects excess admissions.
5. CSV and JSON bulk uploads enforce identical capacity rules.
6. Single-entry admission follows the same rules.
7. Updating an existing student does not incorrectly consume an additional seat.
8. Rejected students are not inserted.
9. Mixed valid and invalid bulk uploads handle each row correctly (rejected rows do not consume capacity).
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
)

client = TestClient(app, raise_server_exceptions=True)


class TestUnifiedCapacityEnforcement(unittest.TestCase):
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
        # Create a small, dedicated test program with approved_intake=3, supernumerary_cap=1 (cap=1 seat, total=4)
        with Session(engine) as session:
            self.test_prog = Program(
                name="Unified Capacity Test Engineering",
                level="UG",
                academic_year="2024-25",
                approved_intake=3,
                supernumerary_cap=1.0,  # Exactly 1 supernumerary seat (Total capacity = 4)
                institution_id=self.institution.id,
            )
            session.add(self.test_prog)
            session.commit()
            session.refresh(self.test_prog)
            self.prog_id = self.test_prog.id

    def tearDown(self):
        with Session(engine) as session:
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

    def _seed_student(self, index: int, adm_type: str = "REGULAR", status: str = "ACTIVE") -> Student:
        """Seed a student with a valid central registry record so R2 passes."""
        aid = f"71{self.prog_id % 10000:04d}{index:06d}"
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
                student_id=f"ROLL-{self.prog_id}-{index:04d}",
                full_name=f"Student {index}",
                dob="2004-01-01",
                gender="M",
                category="GENERAL",
                institution_id=self.institution.id,
                program_id=self.prog_id,
                admission_year=2024,
                admission_type=adm_type,
                status=status,
                consent_level=1,
            )
            session.add(stu)
            session.commit()
            session.refresh(stu)
            return stu

    def _seed_registry_only(self, index: int) -> str:
        """Seed only central registry record without creating an institutional enrollment."""
        aid = f"72{self.prog_id % 10000:04d}{index:06d}"
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
    # 1. Regular capacity cannot be exceeded
    # -------------------------------------------------------------------------
    def test_01_regular_capacity_cannot_be_exceeded(self):
        """Test that regular enrollment cannot exceed approved intake."""
        # Approved intake is 3. Seed 3 regular students.
        for i in range(3):
            self._seed_student(i, "REGULAR")

        with Session(engine) as session:
            # Service level check
            result = validate_admission_capacity(
                session=session,
                program_id=self.prog_id,
                admission_type="REGULAR",
                target_status="ACTIVE",
                allow_override=False,
            )
            self.assertFalse(result.allowed)
            self.assertEqual(result.decision, "BLOCK")
            self.assertIn("Regular intake capacity exceeded", result.reason)
            self.assertIn("R6", result.rule_codes)

    # -------------------------------------------------------------------------
    # 2. Supernumerary capacity cannot be exceeded
    # -------------------------------------------------------------------------
    def test_02_supernumerary_capacity_cannot_be_exceeded(self):
        """Test that supernumerary enrollment cannot exceed permitted quota."""
        # Supernumerary cap is 1. Seed 1 supernumerary student.
        self._seed_student(10, "SUPERNUMERARY")

        with Session(engine) as session:
            # Service level check
            result = validate_admission_capacity(
                session=session,
                program_id=self.prog_id,
                admission_type="SUPERNUMERARY",
                target_status="ACTIVE",
                allow_override=False,
            )
            self.assertFalse(result.allowed)
            self.assertEqual(result.decision, "BLOCK")
            self.assertIn("Supernumerary quota capacity exceeded", result.reason)
            self.assertIn("R7", result.rule_codes)

    # -------------------------------------------------------------------------
    # 3. Combined capacity cannot be exceeded
    # -------------------------------------------------------------------------
    def test_03_combined_capacity_cannot_be_exceeded(self):
        """Test that total enrollment cannot exceed combined capacity."""
        # Total capacity is 3 (reg) + 1 (super) = 4.
        # Seed 2 regular and 2 super (e.g. past override on super made super=2).
        # Total = 4. Regular is 2 (< 3).
        # Admitting a REGULAR student must be BLOCKED because total capacity (4) is reached!
        self._seed_student(20, "REGULAR")
        self._seed_student(21, "REGULAR")
        self._seed_student(22, "SUPERNUMERARY")
        self._seed_student(23, "SUPERNUMERARY")

        with Session(engine) as session:
            result = validate_admission_capacity(
                session=session,
                program_id=self.prog_id,
                admission_type="REGULAR",
                target_status="ACTIVE",
                allow_override=False,
            )
            self.assertFalse(result.allowed)
            self.assertEqual(result.decision, "BLOCK")
            self.assertIn("Total program capacity exceeded", result.reason)

    # -------------------------------------------------------------------------
    # 4. JSON bulk upload rejects excess admissions
    # -------------------------------------------------------------------------
    def test_04_json_bulk_upload_rejects_excess_admissions(self):
        """Test that JSON bulk upload rejects admissions exceeding intake capacity."""
        # Fill program to 2/3 regular seats
        self._seed_student(30, "REGULAR")
        self._seed_student(31, "REGULAR")

        # Submit a batch of 3 new regular students via /api/v1/students/bulk.
        # Exactly 1 should be accepted, and 2 should be rejected.
        aids = [self._seed_registry_only(32 + k) for k in range(3)]
        payload = [
            {
                "apaar_id": aids[k],
                "student_id": f"BULK-TEST-{k}",
                "full_name": f"Batch Student {32 + k}",
                "dob": "2004-01-01",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_id,
                "admission_year": 2024,
                "admission_type": "REGULAR",
                "is_nri": False,
                "oci_status": False,
                "is_foreign_national": False,
                "nationality": "Indian",
                "mode": "FULL_TIME",
                "consent_given": True,
            }
            for k in range(3)
        ]

        resp = client.post(
            "/api/v1/students/bulk",
            headers={"X-API-Key": self.api_key},
            json=payload,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertEqual(data["total"], 3)
        self.assertEqual(data["accepted_clean"], 1)
        self.assertEqual(data["rejected"], 2)
        self.assertEqual(len(data["errors"]), 2)
        # Check that error rule codes and reasons are meaningful
        self.assertIn("R6", data["errors"][0]["rule_codes"])
        self.assertIn("Regular intake capacity exceeded", data["errors"][0]["errors"][0])

        # Verify DB has exactly 3 regular students (2 pre-seeded + 1 accepted)
        with Session(engine) as session:
            count = session.exec(
                select(func.count(Student.id)).where(
                    Student.program_id == self.prog_id,
                    Student.status == "ACTIVE",
                )
            ).one()
            self.assertEqual(count, 3)

    # -------------------------------------------------------------------------
    # 5. CSV and JSON bulk uploads enforce identical capacity rules
    # -------------------------------------------------------------------------
    def test_05_csv_and_json_enforce_identical_capacity_rules(self):
        """Test that CSV and JSON bulk endpoints enforce identical capacity decisions."""
        # Program approved intake = 3, super = 1, total = 4.
        # We test both endpoints on an identical 5-student sequence:
        # [REGULAR, REGULAR, REGULAR, REGULAR (excess), SUPERNUMERARY]
        # Expected: Rows 0, 1, 2 accepted (REGULAR filled); Row 3 rejected; Row 4 accepted (SUPERNUMERARY).

        # Test CSV upload
        csv_aids = [self._seed_registry_only(40 + k) for k in range(5)]
        csv_lines = [
            "apaar_id,student_id,full_name,dob,gender,category,program_name,admission_year,admission_type,is_nri,oci_status,is_foreign_national,nationality,mode,consent_given",
            f"{csv_aids[0]},CSV-0,Batch Student 40,2004-01-01,M,GENERAL,{self.test_prog.name},2024,REGULAR,False,False,False,Indian,FULL_TIME,True",
            f"{csv_aids[1]},CSV-1,Batch Student 41,2004-01-01,M,GENERAL,{self.test_prog.name},2024,REGULAR,False,False,False,Indian,FULL_TIME,True",
            f"{csv_aids[2]},CSV-2,Batch Student 42,2004-01-01,M,GENERAL,{self.test_prog.name},2024,REGULAR,False,False,False,Indian,FULL_TIME,True",
            f"{csv_aids[3]},CSV-3,Batch Student 43,2004-01-01,M,GENERAL,{self.test_prog.name},2024,REGULAR,False,False,False,Indian,FULL_TIME,True",
            f"{csv_aids[4]},CSV-4,Batch Student 44,2004-01-01,M,GENERAL,{self.test_prog.name},2024,SUPERNUMERARY,False,False,False,Indian,FULL_TIME,True",
        ]
        csv_content = "\n".join(csv_lines)
        resp_csv = client.post(
            "/institution/upload",
            files={"file": ("capacity_test.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")},
            cookies={"access_token": self.inst_token},
        )
        self.assertEqual(resp_csv.status_code, 200)

        # Download error CSV: Row 3 should be rejected with Regular capacity exceeded
        resp_err = client.get("/institution/upload/error-csv", cookies={"access_token": self.inst_token})
        self.assertEqual(resp_err.status_code, 200)
        self.assertIn("Regular intake capacity exceeded", resp_err.text)

        # Clear students for JSON test
        with Session(engine) as session:
            for s in session.exec(select(Student).where(Student.program_id == self.prog_id)).all():
                session.delete(s)
            session.commit()

        # Test JSON bulk upload with the exact same sequence
        json_aids = [self._seed_registry_only(50 + k) for k in range(5)]
        json_payload = [
            {
                "apaar_id": json_aids[k],
                "student_id": f"JSON-{k}",
                "full_name": f"Batch Student {50 + k}",
                "dob": "2004-01-01",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_id,
                "admission_year": 2024,
                "admission_type": "SUPERNUMERARY" if k == 4 else "REGULAR",
                "is_nri": False,
                "oci_status": False,
                "is_foreign_national": False,
                "nationality": "Indian",
                "mode": "FULL_TIME",
                "consent_given": True,
            }
            for k in range(5)
        ]
        resp_json = client.post(
            "/api/v1/students/bulk",
            headers={"X-API-Key": self.api_key},
            json=json_payload,
        )
        self.assertEqual(resp_json.status_code, 200)
        json_data = resp_json.json()

        # Both endpoints accepted exactly 4 (3 clean regular + 1 clean supernumerary) and rejected index 3
        self.assertEqual(json_data["accepted_clean"], 4)
        self.assertEqual(json_data["rejected"], 1)
        self.assertEqual(json_data["errors"][0]["index"], 3)
        self.assertIn("Regular intake capacity exceeded", json_data["errors"][0]["errors"][0])

    # -------------------------------------------------------------------------
    # 6. Single-entry admission follows the same rules
    # -------------------------------------------------------------------------
    def test_06_single_entry_follows_same_rules(self):
        """Test that single student creation endpoint enforces capacity limits."""
        # Fill all 3 regular seats
        for i in range(3):
            self._seed_student(60 + i, "REGULAR")

        new_aid = self._seed_registry_only(69)
        # Attempt to create 4th regular student without override
        resp = client.post(
            "/institution/students/new",
            data={
                "apaar_id": new_aid,
                "student_id": "SINGLE-OVER-01",
                "full_name": "Batch Student 69",
                "dob": "2004-01-01",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_id,
                "admission_year": 2024,
                "admission_type": "REGULAR",
                "consent_level": 1,
            },
            cookies={"access_token": self.inst_token},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertTrue("Regular intake" in resp.text or "capacity exceeded" in resp.text)

        # Verify not inserted
        with Session(engine) as session:
            stu = session.exec(select(Student).where(Student.apaar_id == new_aid)).first()
            self.assertIsNone(stu)

    # -------------------------------------------------------------------------
    # 7. Updating an existing student does not incorrectly consume an additional seat
    # -------------------------------------------------------------------------
    def test_07_updating_existing_student_does_not_consume_additional_seat(self):
        """Test that updating personal fields of an existing enrolled student is never blocked by full intake."""
        # Fill all 3 regular seats
        students = [self._seed_student(70 + i, "REGULAR") for i in range(3)]
        target_student = students[0]

        # 1. Update via web form (/institution/students/{id}/edit)
        resp_web = client.post(
            f"/institution/students/{target_student.id}/edit",
            data={
                "full_name": "Updated Name Web",
                "dob": "2004-01-01",
                "gender": "M",
                "category": "OBC",
                "program_id": self.prog_id,
                "admission_year": 2024,
                "admission_type": "REGULAR",
                "status_field": "ACTIVE",
                "consent_level": 1,
            },
            cookies={"access_token": self.inst_token},
            follow_redirects=False,
        )
        self.assertEqual(resp_web.status_code, 303)  # Redirects to directory on success

        # 2. Update via REST API (/api/v1/students/{apaar_id})
        resp_api = client.put(
            f"/api/v1/students/{target_student.apaar_id}",
            headers={"X-API-Key": self.api_key},
            json={
                "full_name": "Updated Name API",
                "category": "SC",
            },
        )
        self.assertEqual(resp_api.status_code, 200)
        self.assertEqual(resp_api.json()["student"]["full_name"], "Updated Name API")

        # Verify still exactly 3 students
        with Session(engine) as session:
            count = session.exec(
                select(func.count(Student.id)).where(
                    Student.program_id == self.prog_id,
                    Student.status == "ACTIVE",
                )
            ).one()
            self.assertEqual(count, 3)

    # -------------------------------------------------------------------------
    # 8. Rejected students are not inserted
    # -------------------------------------------------------------------------
    def test_08_rejected_students_are_not_inserted(self):
        """Test that students rejected for capacity are never persisted to the database."""
        # Fill regular capacity (3)
        for i in range(3):
            self._seed_student(80 + i, "REGULAR")

        excess_aid_1 = self._seed_registry_only(85)
        excess_aid_2 = self._seed_registry_only(86)

        payload = [
            {
                "apaar_id": excess_aid_1,
                "student_id": "REJECT-01",
                "full_name": "Batch Student 85",
                "dob": "2004-01-01",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_id,
                "admission_year": 2024,
                "admission_type": "REGULAR",
                "consent_given": True,
            },
            {
                "apaar_id": excess_aid_2,
                "student_id": "REJECT-02",
                "full_name": "Batch Student 86",
                "dob": "2004-01-01",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_id,
                "admission_year": 2024,
                "admission_type": "REGULAR",
                "consent_given": True,
            },
        ]

        resp = client.post(
            "/api/v1/students/bulk",
            headers={"X-API-Key": self.api_key},
            json=payload,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["rejected"], 2)

        # Confirm neither APAAR ID exists in database
        with Session(engine) as session:
            stu1 = session.exec(select(Student).where(Student.apaar_id == excess_aid_1)).first()
            stu2 = session.exec(select(Student).where(Student.apaar_id == excess_aid_2)).first()
            self.assertIsNone(stu1)
            self.assertIsNone(stu2)

    # -------------------------------------------------------------------------
    # 9. Mixed valid and invalid bulk uploads handle each row correctly
    # -------------------------------------------------------------------------
    def test_09_mixed_valid_and_invalid_bulk_uploads(self):
        """Test that invalid compliance rows do not consume capacity, allowing subsequent valid rows to enroll."""
        # Program has approved_intake=3, supernumerary=1. Currently 0 enrolled.
        valid_aid_1 = self._seed_registry_only(91)
        valid_aid_2 = self._seed_registry_only(92)
        valid_aid_3 = self._seed_registry_only(93)
        valid_super_aid = self._seed_registry_only(94)

        payload = [
            # Row 0: Valid regular -> ACCEPTED (1/3)
            {
                "apaar_id": valid_aid_1,
                "student_id": "MIX-01",
                "full_name": "Batch Student 91",
                "dob": "2004-01-01",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_id,
                "admission_year": 2024,
                "admission_type": "REGULAR",
                "consent_given": True,
            },
            # Row 1: Invalid APAAR format (11 digits, R1 violation) -> REJECTED (must not consume capacity)
            {
                "apaar_id": "12345678901",  # 11 digits
                "student_id": "MIX-02-INVALID",
                "full_name": "Invalid APAAR",
                "dob": "2004-01-01",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_id,
                "admission_year": 2024,
                "admission_type": "REGULAR",
                "consent_given": True,
            },
            # Row 2: Valid regular -> ACCEPTED (2/3)
            {
                "apaar_id": valid_aid_2,
                "student_id": "MIX-03",
                "full_name": "Batch Student 92",
                "dob": "2004-01-01",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_id,
                "admission_year": 2024,
                "admission_type": "REGULAR",
                "consent_given": True,
            },
            # Row 3: Missing DOB (R9 violation) -> REJECTED (must not consume capacity)
            {
                "apaar_id": "111122223333",
                "student_id": "MIX-04-INVALID",
                "full_name": "Missing DOB",
                "dob": "",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_id,
                "admission_year": 2024,
                "admission_type": "REGULAR",
                "consent_given": True,
            },
            # Row 4: Valid regular -> ACCEPTED (3/3, regular full)
            {
                "apaar_id": valid_aid_3,
                "student_id": "MIX-05",
                "full_name": "Batch Student 93",
                "dob": "2004-01-01",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_id,
                "admission_year": 2024,
                "admission_type": "REGULAR",
                "consent_given": True,
            },
            # Row 5: Valid supernumerary -> ACCEPTED (1/1 supernumerary, 4/4 total)
            {
                "apaar_id": valid_super_aid,
                "student_id": "MIX-06",
                "full_name": "Batch Student 94",
                "dob": "2004-01-01",
                "gender": "F",
                "category": "GENERAL",
                "program_id": self.prog_id,
                "admission_year": 2024,
                "admission_type": "SUPERNUMERARY",
                "consent_given": True,
            },
        ]

        resp = client.post(
            "/api/v1/students/bulk",
            headers={"X-API-Key": self.api_key},
            json=payload,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertEqual(data["total"], 6)
        self.assertEqual(data["accepted_clean"], 4)
        self.assertEqual(data["rejected"], 2)
        self.assertEqual(len(data["errors"]), 2)
        # Error indices should be 1 (R1) and 3 (R9)
        self.assertEqual(data["errors"][0]["index"], 1)
        self.assertIn("R1", data["errors"][0]["rule_codes"])
        self.assertEqual(data["errors"][1]["index"], 3)
        self.assertIn("R9", data["errors"][1]["rule_codes"])

        # Exactly 4 students enrolled in DB
        with Session(engine) as session:
            enrolled = session.exec(select(Student).where(Student.program_id == self.prog_id)).all()
            self.assertEqual(len(enrolled), 4)
            enrolled_aids = {s.apaar_id for s in enrolled}
            self.assertEqual(enrolled_aids, {valid_aid_1, valid_aid_2, valid_aid_3, valid_super_aid})


if __name__ == "__main__":
    unittest.main()

