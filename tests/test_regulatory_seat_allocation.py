"""
Comprehensive Test Suite for Phase 3: Regulatory Seat Allocation Data Model.
SIH PS 26263 - APAAR Verify

Verifies:
1. Regular sanctioned intake (SANCTIONED allocation).
2. Reserved-category allocations within sanctioned intake (WITHIN_INTAKE: SC, ST, OBC, EWS).
3. Separate NRI/OCI/FN allocations (not automatically supernumerary).
4. Authorized supernumerary seats (SUPERNUMERARY with valid approval reference).
5. Missing approval evidence (DRAFT / unverified supernumerary rejected).
6. Expired and revoked approvals (blocked from admission).
7. Different academic years with independent allocations.
8. Allocation exceeding sanctioned intake or conflicting approvals rejected by validation.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


import io
import unittest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlmodel import Session, select, func

from app.main import app
from app.database import engine
from app.models import User, Institution, Program, Student, ValidationFlag, ApaarRegistry, SeatAllocation, utc_now
from app.auth import create_access_token
from app.allocation import (
    validate_allocation_approval,
    get_program_allocations,
    get_active_allocations_summary,
    migrate_program_to_allocations,
)
from app.validation import validate_admission_capacity, BatchCapacityTracker, intake_check

client = TestClient(app, raise_server_exceptions=True)


class TestRegulatorySeatAllocation(unittest.TestCase):
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
        with Session(engine) as session:
            # Create test program
            self.test_prog = Program(
                name="Regulatory Allocation Test Program",
                level="UG",
                academic_year="2024-25",
                approved_intake=4,
                supernumerary_cap=0.0,
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
            allocs = session.exec(select(SeatAllocation).where(SeatAllocation.program_id == self.prog_id)).all()
            for a in allocs:
                session.delete(a)
            flags = session.exec(select(ValidationFlag).where(ValidationFlag.program_id == self.prog_id)).all()
            for f in flags:
                session.delete(f)
            prog = session.get(Program, self.prog_id)
            if prog:
                session.delete(prog)
            session.commit()

    def _seed_student(self, index: int, adm_type: str = "REGULAR", category: str = "GENERAL", is_nri: bool = False, is_fn: bool = False, scheme_code: str = None) -> Student:
        """Seed a student with a valid central registry record so R2 passes."""
        aid = f"91{self.prog_id % 10000:04d}{index:06d}"
        with Session(engine) as session:
            reg = session.exec(select(ApaarRegistry).where(ApaarRegistry.apaar_id == aid)).first()
            if not reg:
                session.add(ApaarRegistry(
                    apaar_id=aid,
                    full_name=f"Alloc Student {index}",
                    dob="2004-01-01",
                    gender="M",
                ))
            stu = Student(
                apaar_id=aid,
                student_id=f"ROLL-ALLOC-{index:04d}",
                full_name=f"Alloc Student {index}",
                dob="2004-01-01",
                gender="M",
                category=category,
                institution_id=self.institution.id,
                program_id=self.prog_id,
                admission_year=2024,
                admission_type=adm_type,
                is_nri=is_nri,
                is_foreign_national=is_fn,
                status="ACTIVE",
                consent_level=1,
            )
            session.add(stu)
            session.commit()
            session.refresh(stu)
            return stu

    def _seed_registry_only(self, index: int) -> str:
        aid = f"92{self.prog_id % 10000:04d}{index:06d}"
        with Session(engine) as session:
            reg = session.exec(select(ApaarRegistry).where(ApaarRegistry.apaar_id == aid)).first()
            if not reg:
                session.add(ApaarRegistry(
                    apaar_id=aid,
                    full_name=f"Alloc Batch {index}",
                    dob="2004-01-01",
                    gender="M",
                ))
                session.commit()
        return aid

    # -------------------------------------------------------------------------
    # 1. Regular Sanctioned Intake
    # -------------------------------------------------------------------------
    def test_01_regular_sanctioned_intake_enforced(self):
        """Sanctioned intake allocation of 2 seats permits exactly 2 regular students and blocks 3rd."""
        with Session(engine) as session:
            # Create verified SANCTIONED allocation of 2 seats
            sanc = SeatAllocation(
                program_id=self.prog_id,
                academic_year="2024-25",
                allocation_type="SANCTIONED",
                category_or_scheme="ALL",
                approved_seats=2,
                issuing_authority="AICTE",
                approval_ref="AICTE/AB/2024/SANC-01",
                verification_status="VERIFIED",
            )
            session.add(sanc)
            session.commit()

        # Seed 2 regular students
        self._seed_student(1, "REGULAR", "GENERAL")
        self._seed_student(2, "REGULAR", "GENERAL")

        # 3rd regular student must be BLOCKED
        with Session(engine) as session:
            res = validate_admission_capacity(
                session=session,
                program_id=self.prog_id,
                admission_type="REGULAR",
                admission_year=2024,
                category="GENERAL",
            )
            self.assertFalse(res.allowed)
            self.assertEqual(res.decision, "BLOCK")
            self.assertIn("Regular intake capacity exceeded", res.reason)

    # -------------------------------------------------------------------------
    # 2. Reserved-Category Allocations within Sanctioned Intake
    # -------------------------------------------------------------------------
    def test_02_reserved_category_allocations_enforced(self):
        """Reserved categories within intake are strictly capped at their allocated seats."""
        with Session(engine) as session:
            # Sanctioned = 4, OBC allocation = 1, SC allocation = 1
            session.add(SeatAllocation(
                program_id=self.prog_id,
                academic_year="2024-25",
                allocation_type="SANCTIONED",
                category_or_scheme="ALL",
                approved_seats=4,
                issuing_authority="AICTE",
                approval_ref="AICTE/AB/2024/SANC-02",
                verification_status="VERIFIED",
            ))
            session.add(SeatAllocation(
                program_id=self.prog_id,
                academic_year="2024-25",
                allocation_type="WITHIN_INTAKE",
                category_or_scheme="OBC",
                approved_seats=1,
                issuing_authority="State Government",
                approval_ref="GOVT/RES/2024/OBC-01",
                verification_status="VERIFIED",
            ))
            session.commit()

        # 1st OBC student admitted
        self._seed_student(11, "REGULAR", "OBC")

        with Session(engine) as session:
            # 2nd OBC student must be BLOCKED because OBC allocation (1) is full,
            # even though total regular seats (4) are not full!
            res_obc = validate_admission_capacity(
                session=session,
                program_id=self.prog_id,
                admission_type="REGULAR",
                admission_year=2024,
                category="OBC",
            )
            self.assertFalse(res_obc.allowed)
            self.assertIn("Reserved allocation capacity exceeded for category/scheme 'OBC'", res_obc.reason)

            # A GENERAL student can still be admitted against regular sanctioned intake
            res_gen = validate_admission_capacity(
                session=session,
                program_id=self.prog_id,
                admission_type="REGULAR",
                admission_year=2024,
                category="GENERAL",
            )
            self.assertTrue(res_gen.allowed)

    # -------------------------------------------------------------------------
    # 3. Separate NRI/OCI/FN Allocations (Not automatically supernumerary)
    # -------------------------------------------------------------------------
    def test_03_separate_nri_allocation_within_intake(self):
        """NRI is evaluated against its explicit within-intake allocation and not treated as supernumerary."""
        with Session(engine) as session:
            # Sanctioned = 4, NRI quota within intake = 1 seat
            session.add(SeatAllocation(
                program_id=self.prog_id,
                academic_year="2024-25",
                allocation_type="SANCTIONED",
                category_or_scheme="ALL",
                approved_seats=4,
                issuing_authority="AICTE",
                approval_ref="AICTE/AB/2024/SANC-03",
                verification_status="VERIFIED",
            ))
            session.add(SeatAllocation(
                program_id=self.prog_id,
                academic_year="2024-25",
                allocation_type="WITHIN_INTAKE",
                category_or_scheme="NRI",
                approved_seats=1,
                issuing_authority="AICTE",
                approval_ref="AICTE/AB/2024/NRI-01",
                verification_status="VERIFIED",
            ))
            session.commit()

        # 1st NRI student admitted
        self._seed_student(21, "REGULAR", "GENERAL", is_nri=True)

        with Session(engine) as session:
            # 2nd NRI student is BLOCKED because NRI within-intake quota (1) is full
            res_nri2 = validate_admission_capacity(
                session=session,
                program_id=self.prog_id,
                admission_type="REGULAR",
                admission_year=2024,
                is_nri=True,
            )
            self.assertFalse(res_nri2.allowed)
            self.assertIn("Reserved allocation capacity exceeded for category/scheme 'NRI'", res_nri2.reason)

    # -------------------------------------------------------------------------
    # 4. Authorized Supernumerary Seats
    # -------------------------------------------------------------------------
    def test_04_authorized_supernumerary_seats_enforced(self):
        """Supernumerary seats require verified regulatory authorization and enforce scheme caps."""
        with Session(engine) as session:
            session.add(SeatAllocation(
                program_id=self.prog_id,
                academic_year="2024-25",
                allocation_type="SANCTIONED",
                category_or_scheme="ALL",
                approved_seats=2,
                issuing_authority="AICTE",
                approval_ref="AICTE/AB/2024/SANC-04",
                verification_status="VERIFIED",
            ))
            # Authorized Supernumerary quota for Tuition Fee Waiver (TFW) = 1 seat
            session.add(SeatAllocation(
                program_id=self.prog_id,
                academic_year="2024-25",
                allocation_type="SUPERNUMERARY",
                category_or_scheme="TFW",
                approved_seats=1,
                issuing_authority="AICTE",
                approval_ref="AICTE/AB/2024/TFW-01",
                verification_status="VERIFIED",
            ))
            session.commit()

        # Admitting 1st TFW supernumerary student succeeds
        with Session(engine) as session:
            res1 = validate_admission_capacity(
                session=session,
                program_id=self.prog_id,
                admission_type="SUPERNUMERARY",
                admission_year=2024,
                scheme_code="TFW",
            )
            self.assertTrue(res1.allowed)
            self.assertIsNotNone(res1.allocation)
            self.assertEqual(res1.allocation.category_or_scheme, "TFW")

        # Seed 1st TFW student
        self._seed_student(31, "SUPERNUMERARY", "GENERAL")

        # Admitting 2nd TFW student is BLOCKED
        with Session(engine) as session:
            res2 = validate_admission_capacity(
                session=session,
                program_id=self.prog_id,
                admission_type="SUPERNUMERARY",
                admission_year=2024,
                scheme_code="TFW",
            )
            self.assertFalse(res2.allowed)
            self.assertIn("Supernumerary quota capacity exceeded for scheme 'TFW'", res2.reason)

    # -------------------------------------------------------------------------
    # 5. Missing Approval Evidence / Unverified Supernumerary
    # -------------------------------------------------------------------------
    def test_05_missing_approval_evidence_blocks_admission(self):
        """Supernumerary admissions are rejected if the allocation is DRAFT / unverified."""
        with Session(engine) as session:
            session.add(SeatAllocation(
                program_id=self.prog_id,
                academic_year="2024-25",
                allocation_type="SANCTIONED",
                category_or_scheme="ALL",
                approved_seats=4,
                issuing_authority="AICTE",
                approval_ref="AICTE/AB/2024/SANC-05",
                verification_status="VERIFIED",
            ))
            # DRAFT supernumerary allocation without verified authorization
            session.add(SeatAllocation(
                program_id=self.prog_id,
                academic_year="2024-25",
                allocation_type="SUPERNUMERARY",
                category_or_scheme="FN",
                approved_seats=2,
                issuing_authority="AICTE",
                approval_ref="PENDING_REGULATORY_EVIDENCE",
                verification_status="DRAFT",  # UNVERIFIED
            ))
            session.commit()

        with Session(engine) as session:
            res = validate_admission_capacity(
                session=session,
                program_id=self.prog_id,
                admission_type="SUPERNUMERARY",
                admission_year=2024,
                is_foreign_national=True,
            )
            self.assertFalse(res.allowed)
            self.assertIn("Supernumerary admission requires verified regulatory approval", res.reason)
            self.assertIn("DRAFT", res.reason)

    # -------------------------------------------------------------------------
    # 6. Expired and Revoked Approvals
    # -------------------------------------------------------------------------
    def test_06_expired_and_revoked_approvals_block_admissions(self):
        """Expired or revoked approvals cannot grant admission capacity."""
        with Session(engine) as session:
            session.add(SeatAllocation(
                program_id=self.prog_id,
                academic_year="2024-25",
                allocation_type="SANCTIONED",
                category_or_scheme="ALL",
                approved_seats=4,
                issuing_authority="AICTE",
                approval_ref="AICTE/AB/2024/SANC-06",
                verification_status="VERIFIED",
            ))
            # EXPIRED allocation
            session.add(SeatAllocation(
                program_id=self.prog_id,
                academic_year="2024-25",
                allocation_type="SUPERNUMERARY",
                category_or_scheme="PMSSS",
                approved_seats=2,
                issuing_authority="AICTE",
                approval_ref="AICTE/PMSSS/EXPIRED",
                valid_to=utc_now() - timedelta(days=30),  # Expired
                verification_status="EXPIRED",
            ))
            # REVOKED allocation
            session.add(SeatAllocation(
                program_id=self.prog_id,
                academic_year="2024-25",
                allocation_type="SUPERNUMERARY",
                category_or_scheme="KM",
                approved_seats=1,
                issuing_authority="AICTE",
                approval_ref="AICTE/KM/REVOKED",
                verification_status="REVOKED",
            ))
            session.commit()

        with Session(engine) as session:
            # PMSSS is EXPIRED -> blocked
            res_exp = validate_admission_capacity(
                session=session,
                program_id=self.prog_id,
                admission_type="SUPERNUMERARY",
                admission_year=2024,
                scheme_code="PMSSS",
            )
            self.assertFalse(res_exp.allowed)
            self.assertIn("EXPIRED", res_exp.reason)

            # KM is REVOKED -> blocked
            res_rev = validate_admission_capacity(
                session=session,
                program_id=self.prog_id,
                admission_type="SUPERNUMERARY",
                admission_year=2024,
                scheme_code="KM",
            )
            self.assertFalse(res_rev.allowed)
            self.assertIn("REVOKED", res_rev.reason)

    # -------------------------------------------------------------------------
    # 7. Different Academic Years with Independent Allocations
    # -------------------------------------------------------------------------
    def test_07_different_academic_years_independent_allocations(self):
        """Allocations are strictly isolated by academic year."""
        with Session(engine) as session:
            # 2023-24 has a verified supernumerary allocation
            session.add(SeatAllocation(
                program_id=self.prog_id,
                academic_year="2023-24",
                allocation_type="SANCTIONED",
                category_or_scheme="ALL",
                approved_seats=2,
                issuing_authority="AICTE",
                approval_ref="AICTE/2023/SANC",
                verification_status="VERIFIED",
            ))
            session.add(SeatAllocation(
                program_id=self.prog_id,
                academic_year="2023-24",
                allocation_type="SUPERNUMERARY",
                category_or_scheme="FN",
                approved_seats=1,
                issuing_authority="AICTE",
                approval_ref="AICTE/2023/FN-SUPER",
                verification_status="VERIFIED",
            ))
            # 2024-25 has ONLY sanctioned intake (no supernumerary)
            session.add(SeatAllocation(
                program_id=self.prog_id,
                academic_year="2024-25",
                allocation_type="SANCTIONED",
                category_or_scheme="ALL",
                approved_seats=2,
                issuing_authority="AICTE",
                approval_ref="AICTE/2024/SANC",
                verification_status="VERIFIED",
            ))
            session.commit()

        # Update program academic year to 2023-24 and check FN
        with Session(engine) as session:
            prog = session.get(Program, self.prog_id)
            prog.academic_year = "2023-24"
            session.add(prog)
            session.commit()

            res_2023 = validate_admission_capacity(
                session=session,
                program_id=self.prog_id,
                admission_type="SUPERNUMERARY",
                admission_year=2023,
                is_foreign_national=True,
            )
            self.assertTrue(res_2023.allowed)

            # Switch back to 2024-25; 2024-25 has no FN supernumerary allocation
            prog.academic_year = "2024-25"
            session.add(prog)
            session.commit()

            res_2024 = validate_admission_capacity(
                session=session,
                program_id=self.prog_id,
                admission_type="SUPERNUMERARY",
                admission_year=2024,
                is_foreign_national=True,
            )
            self.assertFalse(res_2024.allowed)
            self.assertIn("No verified regulatory supernumerary allocation exists", res_2024.reason)

    # -------------------------------------------------------------------------
    # 8. Allocation Exceeding Sanctioned Intake or Conflicting Approvals
    # -------------------------------------------------------------------------
    def test_08_allocation_integrity_and_overlap_prevention(self):
        """Within-intake allocations exceeding sanctioned intake or conflicting approvals are rejected."""
        with Session(engine) as session:
            # 1. Sanctioned intake = 10
            sanc = SeatAllocation(
                program_id=self.prog_id,
                academic_year="2024-25",
                allocation_type="SANCTIONED",
                category_or_scheme="ALL",
                approved_seats=10,
                issuing_authority="AICTE",
                approval_ref="AICTE/SANC-10",
                verification_status="VERIFIED",
            )
            session.add(sanc)
            session.commit()

            # Attempting to verify a within-intake allocation of 12 (> 10 sanctioned)
            invalid_within = SeatAllocation(
                program_id=self.prog_id,
                academic_year="2024-25",
                allocation_type="WITHIN_INTAKE",
                category_or_scheme="OBC",
                approved_seats=12,
                issuing_authority="State Govt",
                approval_ref="GOVT/OBC-12",
                verification_status="VERIFIED",
            )
            is_valid, err = validate_allocation_approval(session, invalid_within, current_sanctioned_intake=10)
            self.assertFalse(is_valid)
            self.assertIn("exceeds sanctioned intake", err)

            # Valid within-intake allocation of 5
            valid_within = SeatAllocation(
                program_id=self.prog_id,
                academic_year="2024-25",
                allocation_type="WITHIN_INTAKE",
                category_or_scheme="OBC",
                approved_seats=5,
                issuing_authority="State Govt",
                approval_ref="GOVT/OBC-05",
                verification_status="VERIFIED",
            )
            session.add(valid_within)
            session.commit()

            # Attempting to activate a conflicting/overlapping active approval for the same OBC scheme
            conflicting_obc = SeatAllocation(
                program_id=self.prog_id,
                academic_year="2024-25",
                allocation_type="WITHIN_INTAKE",
                category_or_scheme="OBC",
                approved_seats=4,
                issuing_authority="State Govt",
                approval_ref="GOVT/OBC-CONFLICT",
                verification_status="VERIFIED",
            )
            is_valid_conf, conf_err = validate_allocation_approval(session, conflicting_obc, current_sanctioned_intake=10)
            self.assertFalse(is_valid_conf)
            self.assertIn("Conflicting active verified approval already exists", conf_err)


if __name__ == "__main__":
    unittest.main()

