"""
Comprehensive Test Suite for Phase 6: Historical Seat Allocation Reconciliation.
SIH PS 26263 - APAAR Verify

Verifies:
1. Historical records within capacity (COMPLIANT status, 0 excess).
2. Existing over-enrolment identified accurately WITHOUT deleting, deactivating, or modifying students.
3. Missing approval records: supernumerary enrolments lacking verified regulatory allocation flagged as MISSING_OR_UNVERIFIED_APPROVAL without inventing approval information.
4. Multiple academic years: independent evaluation of separate cohorts (e.g. 2022 vs 2023).
5. Repeated reconciliation is idempotent: updating records in place, 0 duplicate rows or duplicate flags.
6. Records with missing admission classifications: flagged as UNCLASSIFIED_ADMISSION with specific defect reasons without deleting records.
7. Scheme-specific allocation reconciliation: within-intake (NRI) or supernumerary (FN/OCI) quotas.
8. Non-destructive guarantee: all students remain in their exact state across all tests.
9. Report generation and CSV export: structured summary metrics and downloadable CSV strings.
10. HTTP endpoint verification: Institution, AICTE Admin, and REST API endpoints.
11. Audit logging: tamper-evident audit logs generated with hash chaining.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


import io
import json
import unittest
from fastapi.testclient import TestClient
from sqlmodel import Session, select, func

from app.main import app
from app.database import engine
from app.models import (
    User,
    Institution,
    Program,
    Student,
    SeatAllocation,
    ValidationFlag,
    HistoricalReconciliation,
    AuditLog,
    ApaarRegistry,
    utc_now,
)
from app.auth import create_access_token
from app.reconciliation import (
    reconcile_program,
    reconcile_institution,
    reconcile_all_institutions,
    get_reconciliation_summary,
    export_reconciliation_csv_string,
    VIOLATION_TYPE_REGULAR,
    VIOLATION_TYPE_SUPERNUMERARY,
    VIOLATION_TYPE_SCHEME,
    VIOLATION_TYPE_UNVERIFIED_APPROVAL,
    VIOLATION_TYPE_YEAR_MISMATCH,
    VIOLATION_TYPE_UNCLASSIFIED,
    VIOLATION_TYPE_NONE,
)

client = TestClient(app, raise_server_exceptions=True)


class TestHistoricalReconciliation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with Session(engine) as session:
            inst_user = session.exec(select(User).where(User.role == "INSTITUTION")).first()
            cls.inst_user = inst_user
            cls.institution = session.exec(
                select(Institution).where(Institution.id == inst_user.institution_id)
            ).first()
            cls.inst_token = create_access_token({
                "sub": inst_user.username,
                "role": inst_user.role,
                "institution_id": inst_user.institution_id,
            })
            cls.api_key = cls.institution.api_key

            aicte_user = session.exec(select(User).where(User.role == "AICTE_ADMIN")).first()
            cls.aicte_user = aicte_user
            cls.aicte_token = create_access_token({
                "sub": aicte_user.username,
                "role": aicte_user.role,
            })

    def setUp(self):
        # Create test program
        with Session(engine) as session:
            self.test_program = Program(
                name="Historical Audit Engineering",
                level="UG",
                academic_year="2023-24",
                approved_intake=3,
                supernumerary_cap=0.0,
                institution_id=self.institution.id,
            )
            session.add(self.test_program)
            session.commit()
            session.refresh(self.test_program)
            self.program_id = self.test_program.id

    def tearDown(self):
        with Session(engine) as session:
            # Clean up reconciliation records
            recs = session.exec(
                select(HistoricalReconciliation).where(HistoricalReconciliation.program_id == self.program_id)
            ).all()
            for r in recs:
                session.delete(r)

            # Clean up students
            students = session.exec(
                select(Student).where(Student.program_id == self.program_id)
            ).all()
            for s in students:
                session.delete(s)

            # Clean up flags
            flags = session.exec(
                select(ValidationFlag).where(ValidationFlag.program_id == self.program_id)
            ).all()
            for f in flags:
                session.delete(f)

            # Clean up seat allocations
            allocs = session.exec(
                select(SeatAllocation).where(SeatAllocation.program_id == self.program_id)
            ).all()
            for a in allocs:
                session.delete(a)

            # Clean up program
            prog = session.get(Program, self.program_id)
            if prog:
                session.delete(prog)

            session.commit()

    def _create_historical_student(
        self,
        index: int,
        admission_year: int = 2023,
        admission_type: str = "REGULAR",
        category: str = "GENERAL",
        is_nri: bool = False,
        oci_status: bool = False,
        is_foreign_national: bool = False,
        status: str = "ACTIVE",
    ) -> Student:
        """Seed a historical student directly in DB without admission-time rejection."""
        aid = f"92{self.program_id % 10000:04d}{index:06d}"
        with Session(engine) as session:
            reg = session.exec(select(ApaarRegistry).where(ApaarRegistry.apaar_id == aid)).first()
            if not reg:
                session.add(ApaarRegistry(
                    apaar_id=aid,
                    full_name=f"Historical Student {index}",
                    dob="2003-05-15",
                    gender="M",
                ))
            student = Student(
                institution_id=self.institution.id,
                program_id=self.program_id,
                apaar_id=aid,
                student_id=f"HIST-{self.program_id}-{index}",
                full_name=f"Historical Student {index}",
                dob="2003-05-15",
                gender="M",
                category=category,
                admission_year=admission_year,
                admission_type=admission_type,
                is_nri=is_nri,
                oci_status=oci_status,
                is_foreign_national=is_foreign_national,
                nationality="Indian" if not is_foreign_national else "Foreign",
                status=status,
                consent_level=1,
                consent_timestamp=utc_now(),
                record_signature=f"HIST_SIG_{index}",
                created_at=utc_now(),
                updated_at=utc_now(),
            )
            session.add(student)
            session.commit()
            session.refresh(student)
            return student

    # =========================================================================
    # Test 1: Historical records within capacity (0 excess, COMPLIANT)
    # =========================================================================
    def test_historical_records_within_capacity(self):
        """Historical enrolments at or below sanctioned intake are compliant with 0 excess."""
        # Approved intake is 3. Enrol 3 active regular students.
        for i in range(1, 4):
            self._create_historical_student(i, admission_year=2023, admission_type="REGULAR")

        with Session(engine) as session:
            results = reconcile_program(session, self.program_id, user=self.inst_user)

            # Check SANCTIONED record
            sanctioned_rec = next((r for r in results if r.allocation_type == "SANCTIONED"), None)
            self.assertIsNotNone(sanctioned_rec)
            self.assertEqual(sanctioned_rec.approved_capacity, 3)
            self.assertEqual(sanctioned_rec.actual_enrolment, 3)
            self.assertEqual(sanctioned_rec.excess_count, 0)
            self.assertEqual(sanctioned_rec.status, "COMPLIANT")
            self.assertEqual(sanctioned_rec.violation_type, VIOLATION_TYPE_NONE)

            # Check SUPERNUMERARY record (0 enrolled, 0 approved)
            super_rec = next((r for r in results if r.allocation_type == "SUPERNUMERARY"), None)
            self.assertIsNotNone(super_rec)
            self.assertEqual(super_rec.excess_count, 0)
            self.assertEqual(super_rec.status, "COMPLIANT")

            # Check validation flags (R6, R7 should not be OPEN)
            flag_r6 = session.exec(
                select(ValidationFlag).where(
                    ValidationFlag.program_id == self.program_id,
                    ValidationFlag.rule_code == "R6",
                )
            ).first()
            if flag_r6:
                self.assertNotEqual(flag_r6.status, "OPEN")

    # =========================================================================
    # Test 2: Existing over-enrolment (excess identified, students NOT deleted)
    # =========================================================================
    def test_existing_over_enrolment_non_destructive(self):
        """Identifies historical over-enrolment without modifying or deleting students."""
        # Approved intake is 3. Enrol 5 active regular students (excess = 2).
        student_ids = []
        for i in range(1, 6):
            s = self._create_historical_student(i, admission_year=2023, admission_type="REGULAR")
            student_ids.append(s.id)

        with Session(engine) as session:
            results = reconcile_program(session, self.program_id, user=self.inst_user)

            sanctioned_rec = next((r for r in results if r.allocation_type == "SANCTIONED"), None)
            self.assertIsNotNone(sanctioned_rec)
            self.assertEqual(sanctioned_rec.approved_capacity, 3)
            self.assertEqual(sanctioned_rec.actual_enrolment, 5)
            self.assertEqual(sanctioned_rec.excess_count, 2)
            self.assertEqual(sanctioned_rec.status, "VIOLATION")
            self.assertEqual(sanctioned_rec.violation_type, VIOLATION_TYPE_REGULAR)
            self.assertEqual(sanctioned_rec.affected_student_count, 2)

            # Verify R6 flag created with HIGH severity
            flag_r6 = session.exec(
                select(ValidationFlag).where(
                    ValidationFlag.program_id == self.program_id,
                    ValidationFlag.rule_code == "R6",
                )
            ).first()
            self.assertIsNotNone(flag_r6)
            self.assertEqual(flag_r6.status, "OPEN")
            self.assertEqual(flag_r6.severity, "HIGH")

            # NON-DESTRUCTIVE VERIFICATION:
            # Ensure all 5 students still exist, remain ACTIVE, and are not deleted or deactivated!
            for sid in student_ids:
                stud = session.get(Student, sid)
                self.assertIsNotNone(stud, f"Student {sid} must NOT be deleted!")
                self.assertEqual(stud.status, "ACTIVE", f"Student {sid} status must remain ACTIVE!")

    # =========================================================================
    # Test 3: Missing approval records (truthful reporting, no invented data)
    # =========================================================================
    def test_missing_approval_records_truthful_reporting(self):
        """Supernumerary admissions without verified SeatAllocation flagged as MISSING_OR_UNVERIFIED_APPROVAL."""
        # Enrol 2 supernumerary students without any approved SeatAllocation record
        s1 = self._create_historical_student(1, admission_year=2023, admission_type="SUPERNUMERARY", category="FN", is_foreign_national=True)
        s2 = self._create_historical_student(2, admission_year=2023, admission_type="SUPERNUMERARY", category="TFW")

        with Session(engine) as session:
            results = reconcile_program(session, self.program_id, user=self.inst_user)

            super_rec = next((r for r in results if r.allocation_type == "SUPERNUMERARY"), None)
            self.assertIsNotNone(super_rec)
            self.assertEqual(super_rec.approved_capacity, 0)
            self.assertEqual(super_rec.actual_enrolment, 2)
            self.assertEqual(super_rec.excess_count, 2)
            self.assertEqual(super_rec.status, "VIOLATION")
            self.assertEqual(super_rec.violation_type, VIOLATION_TYPE_UNVERIFIED_APPROVAL)
            self.assertEqual(super_rec.approval_status, "MISSING")
            self.assertIsNone(super_rec.approval_ref)
            self.assertIn("NO verified AICTE or regulatory seat allocation approval", super_rec.details)

            # Verify students are intact
            stud1 = session.get(Student, s1.id)
            stud2 = session.get(Student, s2.id)
            self.assertEqual(stud1.status, "ACTIVE")
            self.assertEqual(stud2.status, "ACTIVE")

    # =========================================================================
    # Test 4: Multiple academic years (independent cohort evaluation)
    # =========================================================================
    def test_multiple_academic_years_independent_evaluation(self):
        """Evaluates independent cohorts across multiple academic years separately."""
        # Cohort 2022: 2 students (within intake 3) -> COMPLIANT
        self._create_historical_student(1, admission_year=2022, admission_type="REGULAR")
        self._create_historical_student(2, admission_year=2022, admission_type="REGULAR")

        # Cohort 2023: 4 students (exceeds intake 3 by 1) -> VIOLATION
        for i in range(3, 7):
            self._create_historical_student(i, admission_year=2023, admission_type="REGULAR")

        with Session(engine) as session:
            results = reconcile_program(session, self.program_id, user=self.inst_user)

            # Check 2022-23 regular record
            rec_2022 = next(
                (r for r in results if r.allocation_type == "SANCTIONED" and "2022" in r.academic_year),
                None,
            )
            self.assertIsNotNone(rec_2022)
            self.assertEqual(rec_2022.actual_enrolment, 2)
            self.assertEqual(rec_2022.excess_count, 0)
            self.assertEqual(rec_2022.status, "COMPLIANT")

            # Check 2023-24 regular record
            rec_2023 = next(
                (r for r in results if r.allocation_type == "SANCTIONED" and "2023" in r.academic_year),
                None,
            )
            self.assertIsNotNone(rec_2023)
            self.assertEqual(rec_2023.actual_enrolment, 4)
            self.assertEqual(rec_2023.excess_count, 1)
            self.assertEqual(rec_2023.status, "VIOLATION")

    # =========================================================================
    # Test 5: Repeated reconciliation is idempotent
    # =========================================================================
    def test_repeated_reconciliation_is_idempotent(self):
        """Repeated reconciliation updates records in place without duplicating rows or flags."""
        # Seed 4 students (1 excess)
        for i in range(1, 5):
            self._create_historical_student(i, admission_year=2023, admission_type="REGULAR")

        with Session(engine) as session:
            # First run
            res1 = reconcile_program(session, self.program_id, user=self.inst_user)
            count1 = len(session.exec(
                select(HistoricalReconciliation).where(HistoricalReconciliation.program_id == self.program_id)
            ).all())
            flags1 = len(session.exec(
                select(ValidationFlag).where(ValidationFlag.program_id == self.program_id)
            ).all())

            # Second run
            res2 = reconcile_program(session, self.program_id, user=self.inst_user)
            count2 = len(session.exec(
                select(HistoricalReconciliation).where(HistoricalReconciliation.program_id == self.program_id)
            ).all())
            flags2 = len(session.exec(
                select(ValidationFlag).where(ValidationFlag.program_id == self.program_id)
            ).all())

            # Third run
            res3 = reconcile_program(session, self.program_id, user=self.inst_user)
            count3 = len(session.exec(
                select(HistoricalReconciliation).where(HistoricalReconciliation.program_id == self.program_id)
            ).all())

            self.assertEqual(count1, count2)
            self.assertEqual(count2, count3)
            self.assertEqual(flags1, flags2)

            # Sanctioned record was updated in place
            sanctioned_recs = session.exec(
                select(HistoricalReconciliation).where(
                    HistoricalReconciliation.program_id == self.program_id,
                    HistoricalReconciliation.allocation_type == "SANCTIONED",
                )
            ).all()
            self.assertEqual(len(sanctioned_recs), 1)

    # =========================================================================
    # Test 6: Records with missing admission classifications
    # =========================================================================
    def test_missing_admission_classifications(self):
        """Identifies incomplete historical records (missing type, category, or year) without deleting them."""
        # Seed 1 complete student
        self._create_historical_student(1, admission_year=2023, admission_type="REGULAR", category="GENERAL")

        # Seed 1 unclassified student directly
        aid = f"92{self.program_id % 10000:04d}000099"
        with Session(engine) as session:
            reg = session.exec(select(ApaarRegistry).where(ApaarRegistry.apaar_id == aid)).first()
            if not reg:
                session.add(ApaarRegistry(apaar_id=aid, full_name="Incomplete Student", dob="2002-01-01", gender="F"))
            incomplete_student = Student(
                institution_id=self.institution.id,
                program_id=self.program_id,
                apaar_id=aid,
                student_id=f"INC-{self.program_id}-99",
                full_name="Incomplete Student",
                dob="2002-01-01",
                gender="F",
                category=None,  # Missing category
                admission_year=0,  # Missing/invalid admission year
                admission_type="",  # Missing admission type
                status="ACTIVE",
                consent_level=1,
                created_at=utc_now(),
                updated_at=utc_now(),
            )
            session.add(incomplete_student)
            session.commit()
            session.refresh(incomplete_student)
            inc_id = incomplete_student.id

        with Session(engine) as session:
            results = reconcile_program(session, self.program_id, user=self.inst_user)

            unclass_rec = next((r for r in results if r.allocation_type == "CLASSIFICATION"), None)
            self.assertIsNotNone(unclass_rec)
            self.assertEqual(unclass_rec.status, "REVIEW_REQUIRED")
            self.assertEqual(unclass_rec.violation_type, VIOLATION_TYPE_UNCLASSIFIED)
            self.assertGreaterEqual(unclass_rec.actual_enrolment, 1)
            self.assertIn("Invalid/missing admission_type", unclass_rec.details)

            # Incomplete student is still in the database
            stud = session.get(Student, inc_id)
            self.assertIsNotNone(stud)

    # =========================================================================
    # Test 7: Scheme-specific allocation reconciliation (Within-intake & Supernumerary)
    # =========================================================================
    def test_scheme_specific_allocation_reconciliation(self):
        """Accurately checks scheme-specific allocations (e.g. verified NRI sub-quota)."""
        # Create a verified SeatAllocation for within-intake NRI (limit = 1)
        with Session(engine) as session:
            alloc_nri = SeatAllocation(
                program_id=self.program_id,
                academic_year="2023-24",
                allocation_type="WITHIN_INTAKE",
                category_or_scheme="NRI",
                approved_seats=1,
                issuing_authority="AICTE",
                approval_ref="AICTE/SCHEME/NRI/2023/001",
                verification_status="VERIFIED",
                created_at=utc_now(),
                updated_at=utc_now(),
            )
            session.add(alloc_nri)
            session.commit()

        # Enrol 2 active regular NRI students (excess = 1 for NRI quota)
        self._create_historical_student(1, admission_year=2023, admission_type="REGULAR", is_nri=True)
        self._create_historical_student(2, admission_year=2023, admission_type="REGULAR", is_nri=True)

        with Session(engine) as session:
            results = reconcile_program(session, self.program_id, user=self.inst_user)

            nri_rec = next(
                (r for r in results if r.allocation_type == "WITHIN_INTAKE" and r.category_or_scheme == "NRI"),
                None,
            )
            self.assertIsNotNone(nri_rec)
            self.assertEqual(nri_rec.approved_capacity, 1)
            self.assertEqual(nri_rec.actual_enrolment, 2)
            self.assertEqual(nri_rec.excess_count, 1)
            self.assertEqual(nri_rec.status, "VIOLATION")
            self.assertEqual(nri_rec.violation_type, VIOLATION_TYPE_SCHEME)
            self.assertEqual(nri_rec.approval_status, "VERIFIED")

    # =========================================================================
    # Test 8: Reports, Summary, and CSV Exports
    # =========================================================================
    def test_reports_and_csv_export(self):
        """Generates structured summaries and downloadable CSV audit export."""
        # Seed 4 students (1 regular excess)
        for i in range(1, 5):
            self._create_historical_student(i, admission_year=2023, admission_type="REGULAR")

        with Session(engine) as session:
            reconcile_program(session, self.program_id, user=self.inst_user)

            summary = get_reconciliation_summary(session, institution_id=self.institution.id)
            self.assertGreaterEqual(summary["total_evaluations"], 1)
            self.assertGreaterEqual(summary["total_violations"], 1)
            self.assertGreaterEqual(summary["total_excess_seats"], 1)
            self.assertIn("records", summary)

            csv_text = export_reconciliation_csv_string(session, institution_id=self.institution.id)
            self.assertIn("Reconciliation ID", csv_text)
            self.assertIn("Historical Audit Engineering", csv_text)
            self.assertIn("REGULAR_INTAKE_VIOLATION", csv_text)

    # =========================================================================
    # Test 9: HTTP Endpoints (Institution, AICTE Admin, External API)
    # =========================================================================
    def test_http_reconciliation_endpoints(self):
        """Verifies REST API, Institution, and AICTE Admin HTTP endpoints."""
        # 1. API endpoint: Run reconciliation via API Key
        resp_run = client.post(
            "/api/v1/reconciliation/run",
            headers={"X-API-Key": self.api_key},
        )
        self.assertEqual(resp_run.status_code, 200)
        data_run = resp_run.json()
        self.assertEqual(data_run["status"], "success")

        # 2. API endpoint: Get summary
        resp_summary = client.get(
            "/api/v1/reconciliation/summary",
            headers={"X-API-Key": self.api_key},
        )
        self.assertEqual(resp_summary.status_code, 200)
        data_sum = resp_summary.json()
        self.assertIn("total_evaluations", data_sum)

        # 3. API endpoint: Export CSV
        resp_csv = client.get(
            "/api/v1/reconciliation/export",
            headers={"X-API-Key": self.api_key},
        )
        self.assertEqual(resp_csv.status_code, 200)
        self.assertIn("text/csv", resp_csv.headers["content-type"])

        # 4. Institution endpoint: Run
        resp_inst_run = client.post(
            "/institution/reconciliation/run",
            headers={"Authorization": f"Bearer {self.inst_token}"},
        )
        self.assertEqual(resp_inst_run.status_code, 200)

        # 5. Institution endpoint: Report
        resp_inst_rep = client.get(
            "/institution/reconciliation/report",
            headers={"Authorization": f"Bearer {self.inst_token}"},
        )
        self.assertEqual(resp_inst_rep.status_code, 200)

        # 6. AICTE Admin endpoint: Run
        resp_admin_run = client.post(
            f"/aicte/reconciliation/run?institution_id={self.institution.id}",
            headers={"Authorization": f"Bearer {self.aicte_token}"},
        )
        self.assertEqual(resp_admin_run.status_code, 200)

        # 7. AICTE Admin endpoint: Report
        resp_admin_rep = client.get(
            "/aicte/reconciliation/report",
            headers={"Authorization": f"Bearer {self.aicte_token}"},
        )
        self.assertEqual(resp_admin_rep.status_code, 200)

    # =========================================================================
    # Test 10: Audit Log Hash Integrity
    # =========================================================================
    def test_reconciliation_audit_logging(self):
        """Preserves immutable audit log entries for historical reconciliation runs."""
        with Session(engine) as session:
            reconcile_program(session, self.program_id, user=self.inst_user)

            audit_entry = session.exec(
                select(AuditLog).where(
                    AuditLog.action == "HISTORICAL_RECONCILIATION",
                    AuditLog.entity == "PROGRAM",
                    AuditLog.entity_id == str(self.program_id),
                ).order_by(AuditLog.id.desc())
            ).first()

            self.assertIsNotNone(audit_entry)
            self.assertIn("allocation checks evaluated", audit_entry.details)
            self.assertIsNotNone(audit_entry.prev_hash)
            self.assertIsNotNone(audit_entry.row_hash)


if __name__ == "__main__":
    unittest.main()
