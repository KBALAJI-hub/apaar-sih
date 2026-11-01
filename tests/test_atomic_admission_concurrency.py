"""
Test Suite for Phase 5: Atomic Admission Capacity Enforcement.
Verifies race-condition elimination and database-level consistency across concurrent admissions:
1. Only one seat remains and two requests attempt admission concurrently (exactly 1 succeeds).
2. Several requests compete for the last few seats (e.g. 10 requests for 3 seats -> exactly 3 succeed).
3. Two bulk uploads overlap (total accepted seats across both cannot exceed remaining intake).
4. Two updates compete for the same allocation (withdrawn students reactivating concurrently).
5. A transaction fails after capacity reservation (automatic rollback leaves no orphaned state).
6. Database rollback restores original state (freed seat is immediately claimable by subsequent request).
7. SQLite compatibility: write-serialization and mutex handling against SQLite in-memory/temp database.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import unittest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlmodel import Session, select, SQLModel, create_engine
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database import engine, get_session
from app.models import Institution, Program, Student, User, RegulatoryOverride, SeatAllocation, ApaarRegistry, utc_now
from app.auth import create_access_token
from app.concurrency import atomic_admission_scope
from app.validation import validate_admission_capacity, intake_check

client = TestClient(app, raise_server_exceptions=False)


class TestAtomicAdmissionConcurrency(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with Session(engine) as session:
            # Setup Test Institution
            inst = session.exec(select(Institution).where(Institution.aicte_id == "INST_PHASE5_TEST")).first()
            if not inst:
                inst = Institution(
                    name="Phase 5 Concurrency Institute of Technology",
                    aicte_id="INST_PHASE5_TEST",
                    state="Karnataka",
                    type="Engineering",
                    api_key="phase5-test-api-key-concurrency-atomic",
                )
                session.add(inst)
                session.commit()
                session.refresh(inst)
            cls.inst_id = inst.id
            cls.inst_api_key = inst.api_key

            # Setup Programs
            # Prog 1: Exactly 1 seat capacity (approved_intake = 1)
            p1 = session.exec(
                select(Program).where(Program.institution_id == cls.inst_id, Program.name == "Prog Single Seat")
            ).first()
            if not p1:
                p1 = Program(
                    institution_id=cls.inst_id,
                    name="Prog Single Seat",
                    level="UG",
                    approved_intake=1,
                    supernumerary_cap=0.0,
                    academic_year="2024-25",
                )
                session.add(p1)
                session.commit()
                session.refresh(p1)
            cls.prog_single_id = p1.id

            # Prog 2: Exactly 3 seats capacity (approved_intake = 3)
            p2 = session.exec(
                select(Program).where(Program.institution_id == cls.inst_id, Program.name == "Prog Multi Seat")
            ).first()
            if not p2:
                p2 = Program(
                    institution_id=cls.inst_id,
                    name="Prog Multi Seat",
                    level="UG",
                    approved_intake=3,
                    supernumerary_cap=0.0,
                    academic_year="2024-25",
                )
                session.add(p2)
                session.commit()
                session.refresh(p2)
            cls.prog_multi_id = p2.id

            # Prog 3: Bulk Upload program (approved_intake = 5)
            p3 = session.exec(
                select(Program).where(Program.institution_id == cls.inst_id, Program.name == "Prog Bulk Upload")
            ).first()
            if not p3:
                p3 = Program(
                    institution_id=cls.inst_id,
                    name="Prog Bulk Upload",
                    level="UG",
                    approved_intake=5,
                    supernumerary_cap=0.0,
                    academic_year="2024-25",
                )
                session.add(p3)
                session.commit()
                session.refresh(p3)
            cls.prog_bulk_id = p3.id

            # Prog 4: Update competition program (approved_intake = 1)
            p4 = session.exec(
                select(Program).where(Program.institution_id == cls.inst_id, Program.name == "Prog Update Race")
            ).first()
            if not p4:
                p4 = Program(
                    institution_id=cls.inst_id,
                    name="Prog Update Race",
                    level="UG",
                    approved_intake=1,
                    supernumerary_cap=0.0,
                    academic_year="2024-25",
                )
                session.add(p4)
                session.commit()
                session.refresh(p4)
            cls.prog_update_id = p4.id

            # Setup Institution Portal User
            inst_user = session.exec(select(User).where(User.username == "inst_phase5_test")).first()
            if not inst_user:
                inst_user = User(
                    username="inst_phase5_test",
                    full_name="Phase 5 Institution User",
                    password_hash="testhash",
                    role="INSTITUTION",
                    institution_id=cls.inst_id,
                )
                session.add(inst_user)
                session.commit()
                session.refresh(inst_user)
            cls.inst_user_id = inst_user.id
            cls.inst_token = create_access_token({
                "sub": "inst_phase5_test",
                "role": "INSTITUTION",
                "institution_id": cls.inst_id,
            })

            # Seed Mock ApaarRegistry records for concurrency testing (50 IDs)
            for i in range(1, 51):
                aid = f"50000000{i:04d}"
                reg = session.exec(select(ApaarRegistry).where(ApaarRegistry.apaar_id == aid)).first()
                if not reg:
                    session.add(ApaarRegistry(
                        apaar_id=aid,
                        full_name=f"Concurrent Student {i}",
                        dob="2004-01-01",
                        gender="M",
                    ))
            session.commit()

    def setUp(self):
        """Clean students and allocations for test programs before each test."""
        with Session(engine) as session:
            test_prog_ids = [self.prog_single_id, self.prog_multi_id, self.prog_bulk_id, self.prog_update_id]
            students = session.exec(select(Student).where(Student.program_id.in_(test_prog_ids))).all()
            for s in students:
                session.delete(s)
            session.commit()

    def test_01_one_seat_remaining_two_concurrent_requests(self):
        """
        Test 1: Only one seat remains and two requests attempt admission concurrently.
        Requirement: Exactly one succeeds, the second is rejected / receives 409 conflict. Total active students = 1.
        """
        def send_admission_request(student_idx):
            apaar = f"50000000{student_idx:04d}"
            # Send single student creation request via web form
            resp = client.post(
                "/institution/students/new",
                data={
                    "apaar_id": apaar,
                    "student_id": f"ROLL-CONCUR-{student_idx}",
                    "full_name": f"Concurrent Student {student_idx}",
                    "dob": "2004-01-01",
                    "gender": "M",
                    "category": "GENERAL",
                    "program_id": self.prog_single_id,
                    "admission_year": 2024,
                    "admission_type": "REGULAR",
                    "consent_level": 2,
                },
                cookies={"access_token": self.inst_token},
                follow_redirects=False,
            )
            return resp.status_code, resp.text

        # Run two concurrent admission requests
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(send_admission_request, i) for i in [1, 2]]
            results = [f.result() for f in futures]

        status_codes = [r[0] for r in results]
        
        # In web flow: success redirects 303 to /institution/students; failure returns 400 (Bad Request) or 409 (Conflict)
        successes = [code for code in status_codes if code in (200, 303)]
        failures = [code for code in status_codes if code in (400, 409)]

        self.assertEqual(len(successes), 1, f"Expected exactly 1 success, got {len(successes)}. Statuses: {status_codes}")
        self.assertEqual(len(failures), 1, f"Expected exactly 1 failure, got {len(failures)}. Statuses: {status_codes}")

        with Session(engine) as session:
            count = session.exec(
                select(Student).where(
                    Student.program_id == self.prog_single_id,
                    Student.status == "ACTIVE",
                )
            ).all()
            self.assertEqual(len(count), 1, f"Database must contain exactly 1 active student, found {len(count)}")

    def test_02_several_requests_compete_for_last_seats(self):
        """
        Test 2: Several requests (10 threads) compete for the last few seats (3 seats).
        Requirement: Exactly 3 succeed, 7 fail/blocked. Active students in program == 3.
        """
        def send_api_admission(student_idx):
            apaar = f"50000000{student_idx:04d}"
            # Submit single-item bulk upload via REST API
            payload = [{
                "apaar_id": apaar,
                "student_id": f"ROLL-MULTI-{student_idx}",
                "full_name": f"Concurrent Student {student_idx}",
                "dob": "2004-01-01",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_multi_id,
                "admission_year": 2024,
                "admission_type": "REGULAR",
                "consent_given": True,
            }]
            resp = client.post(
                "/api/v1/students/bulk",
                json=payload,
                headers={"X-API-Key": self.inst_api_key},
            )
            return resp.status_code, resp.json() if resp.status_code == 200 else resp.text

        # Launch 10 concurrent requests for 3 seats
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(send_api_admission, i) for i in range(11, 21)]
            results = [f.result() for f in futures]

        total_accepted = 0
        total_rejected = 0

        for code, body in results:
            if code == 200:
                total_accepted += body.get("accepted_clean", 0)
                total_rejected += body.get("rejected", 0)
            elif code in (400, 409):
                total_rejected += 1

        self.assertEqual(total_accepted, 3, f"Expected exactly 3 accepted students, got {total_accepted}")
        self.assertEqual(total_rejected, 7, f"Expected exactly 7 rejected students, got {total_rejected}")

        with Session(engine) as session:
            count = session.exec(
                select(Student).where(
                    Student.program_id == self.prog_multi_id,
                    Student.status == "ACTIVE",
                )
            ).all()
            self.assertEqual(len(count), 3, f"Total enrolled active students must be exactly 3, found {len(count)}")

    def test_03_two_bulk_uploads_overlap(self):
        """
        Test 3: Two bulk uploads overlap.
        Setup: Program approved intake = 5.
        Bulk Upload A has 4 students. Bulk Upload B has 4 students.
        Total requested = 8 students. Available capacity = 5.
        Requirement: Total accepted across both uploads == 5. Exactly 3 students are rejected. Enrolment == 5.
        """
        def send_batch(start_idx, count):
            batch = []
            for i in range(start_idx, start_idx + count):
                batch.append({
                    "apaar_id": f"50000000{i:04d}",
                    "student_id": f"ROLL-BULK-{i}",
                    "full_name": f"Concurrent Student {i}",
                    "dob": "2004-01-01",
                    "gender": "M",
                    "category": "GENERAL",
                    "program_id": self.prog_bulk_id,
                    "admission_year": 2024,
                    "admission_type": "REGULAR",
                    "consent_given": True,
                })
            resp = client.post(
                "/api/v1/students/bulk",
                json=batch,
                headers={"X-API-Key": self.inst_api_key},
            )
            return resp.status_code, resp.json() if resp.status_code == 200 else resp.text

        # Run two overlapping bulk uploads simultaneously
        with ThreadPoolExecutor(max_workers=2) as executor:
            f1 = executor.submit(send_batch, 21, 4)
            f2 = executor.submit(send_batch, 25, 4)
            res1 = f1.result()
            res2 = f2.result()

        total_accepted = 0
        total_rejected = 0

        for code, body in [res1, res2]:
            if code == 200:
                total_accepted += (body.get("accepted_clean", 0) + body.get("accepted_with_warnings", 0))
                total_rejected += body.get("rejected", 0)
            elif code in (400, 409):
                total_rejected += 4

        self.assertEqual(total_accepted, 5, f"Total accepted across both overlapping bulk batches must equal 5, got {total_accepted}")
        self.assertEqual(total_rejected, 3, f"Total rejected must equal 3, got {total_rejected}")

        with Session(engine) as session:
            count = session.exec(
                select(Student).where(
                    Student.program_id == self.prog_bulk_id,
                    Student.status == "ACTIVE",
                )
            ).all()
            self.assertEqual(len(count), 5, f"Database active count must not exceed 5, found {len(count)}")

    def test_04_two_updates_compete_for_same_allocation(self):
        """
        Test 4: Two updates compete for the same allocation.
        Setup: Program has capacity 1. Student A and Student B exist in INACTIVE status.
        Two concurrent update requests attempt to reactivate Student A and Student B to ACTIVE.
        Requirement: Only 1 can successfully reactivate. The other is rejected (400) or locked (409).
        """
        with Session(engine) as session:
            s_a = Student(
                apaar_id="500000000031",
                institution_id=self.inst_id,
                program_id=self.prog_update_id,
                student_id="ROLL-UPD-A",
                full_name="Update Student A",
                dob="2004-01-01",
                gender="M",
                category="GENERAL",
                admission_type="REGULAR",
                admission_year=2024,
                status="INACTIVE",
                consent_level=1,
                created_at=utc_now(),
            )
            s_b = Student(
                apaar_id="500000000032",
                institution_id=self.inst_id,
                program_id=self.prog_update_id,
                student_id="ROLL-UPD-B",
                full_name="Update Student B",
                dob="2004-01-01",
                gender="F",
                category="GENERAL",
                admission_type="REGULAR",
                admission_year=2024,
                status="INACTIVE",
                consent_level=1,
                created_at=utc_now(),
            )
            session.add(s_a)
            session.add(s_b)
            session.commit()

        def reactivate_student(apaar):
            resp = client.put(
                f"/api/v1/students/{apaar}",
                json={"status": "ACTIVE"},
                headers={"X-API-Key": self.inst_api_key},
            )
            return resp.status_code, resp.json() if resp.status_code == 200 else resp.text

        with ThreadPoolExecutor(max_workers=2) as executor:
            f1 = executor.submit(reactivate_student, "500000000031")
            f2 = executor.submit(reactivate_student, "500000000032")
            res1 = f1.result()
            res2 = f2.result()

        successes = [r for r in [res1, res2] if r[0] == 200]
        failures = [r for r in [res1, res2] if r[0] in (400, 409)]

        self.assertEqual(len(successes), 1, f"Expected exactly 1 successful reactivation, got {len(successes)}")
        self.assertEqual(len(failures), 1, f"Expected exactly 1 rejected reactivation, got {len(failures)}")

        with Session(engine) as session:
            active_students = session.exec(
                select(Student).where(
                    Student.program_id == self.prog_update_id,
                    Student.status == "ACTIVE",
                )
            ).all()
            self.assertEqual(len(active_students), 1, f"Must have exactly 1 active student, found {len(active_students)}")

    def test_05_transaction_fails_after_capacity_reservation_and_rolls_back(self):
        """
        Test 5: A transaction fails after capacity reservation.
        Requirement: The entire transaction rolls back cleanly, no student record is saved,
        and no seat remains consumed.
        """
        with Session(engine) as session:
            try:
                with atomic_admission_scope(session, program_ids=[self.prog_single_id]):
                    cap = validate_admission_capacity(
                        session=session,
                        program_id=self.prog_single_id,
                        admission_type="REGULAR",
                        target_status="ACTIVE",
                        admission_year=2024,
                        category="GENERAL",
                        is_nri=False,
                        is_foreign_national=False,
                    )
                    self.assertTrue(cap.allowed, "Capacity reservation should succeed initially")

                    # Stage student insertion
                    st = Student(
                        apaar_id="500000000041",
                        institution_id=self.inst_id,
                        program_id=self.prog_single_id,
                        student_id="ROLL-FAIL-TEST",
                        full_name="Failed Tx Student",
                        dob="2004-01-01",
                        gender="M",
                        category="GENERAL",
                        admission_type="REGULAR",
                        admission_year=2024,
                        status="ACTIVE",
                        consent_level=1,
                    )
                    session.add(st)
                    session.flush()

                    # Simulate unexpected crash/failure after reservation and flush
                    raise RuntimeError("Simulated mid-transaction failure")

            except RuntimeError:
                pass  # Handled by scope rollback

            # Verify that database was rolled back completely
            student_in_db = session.exec(
                select(Student).where(Student.apaar_id == "500000000041")
            ).first()
            self.assertIsNone(student_in_db, "Student record must NOT exist after transaction failure rollback")

            active_count = session.exec(
                select(Student).where(
                    Student.program_id == self.prog_single_id,
                    Student.status == "ACTIVE",
                )
            ).all()
            self.assertEqual(len(active_count), 0, "No seat must be consumed after failure rollback")

    def test_06_database_rollback_restores_original_state(self):
        """
        Test 6: Database rollback restores original state.
        Requirement: After a transaction rollback in Test 5, subsequent admission requests can
        successfully claim the available seat.
        """
        # Ensure 0 active students in prog_single
        with Session(engine) as session:
            active_count = session.exec(
                select(Student).where(
                    Student.program_id == self.prog_single_id,
                    Student.status == "ACTIVE",
                )
            ).all()
            self.assertEqual(len(active_count), 0)

        # Send legitimate admission request
        resp = client.post(
            "/institution/students/new",
            data={
                "apaar_id": "500000000042",
                "student_id": "ROLL-RESTORE-TEST",
                "full_name": "Restored Seat Student",
                "dob": "2004-01-01",
                "gender": "M",
                "category": "GENERAL",
                "program_id": self.prog_single_id,
                "admission_year": 2024,
                "admission_type": "REGULAR",
                "consent_level": 2,
            },
            cookies={"access_token": self.inst_token},
            follow_redirects=False,
        )
        self.assertIn(resp.status_code, (200, 303), f"Subsequent admission should succeed after rollback, got {resp.status_code}")

        with Session(engine) as session:
            stu = session.exec(
                select(Student).where(Student.apaar_id == "500000000042")
            ).first()
            self.assertIsNotNone(stu, "Student must be successfully saved")
            self.assertEqual(stu.status, "ACTIVE")

    def test_07_sqlite_backend_write_serialization_concurrency(self):
        """
        Test 7: SQLite write-serialization and thread mutex concurrency.
        Runs concurrent requests against SQLite backend to verify cross-platform locking consistency.
        """
        # Create an in-memory SQLite database
        sqlite_engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        SQLModel.metadata.create_all(sqlite_engine)

        # Setup test data in SQLite
        with Session(sqlite_engine) as session:
            inst = Institution(
                name="SQLite Test Institute",
                aicte_id="SQLITE_INST",
                state="Goa",
                type="Polytechnic",
                api_key="sqlite-key",
            )
            session.add(inst)
            session.commit()
            session.refresh(inst)

            prog = Program(
                institution_id=inst.id,
                name="SQLite Concurrency Prog",
                level="Diploma",
                approved_intake=2,  # Exactly 2 seats
                supernumerary_cap=0.0,
                academic_year="2024-25",
            )
            session.add(prog)
            session.commit()
            session.refresh(prog)

            prog_id = prog.id

        def attempt_sqlite_admission(idx):
            with Session(sqlite_engine) as session:
                try:
                    with atomic_admission_scope(session, program_ids=[prog_id]):
                        cap = validate_admission_capacity(
                            session=session,
                            program_id=prog_id,
                            admission_type="REGULAR",
                            target_status="ACTIVE",
                            admission_year=2024,
                            category="GENERAL",
                            is_nri=False,
                            is_foreign_national=False,
                        )
                        if not cap.allowed:
                            session.rollback()
                            return False, cap.reason

                        stu = Student(
                            apaar_id=f"60000000{idx:04d}",
                            institution_id=1,
                            program_id=prog_id,
                            student_id=f"SQLITE-ROLL-{idx}",
                            full_name=f"SQLite Student {idx}",
                            dob="2004-01-01",
                            gender="M",
                            category="GENERAL",
                            admission_type="REGULAR",
                            admission_year=2024,
                            status="ACTIVE",
                            consent_level=1,
                        )
                        session.add(stu)
                        session.commit()
                        return True, "SUCCESS"
                except Exception as e:
                    session.rollback()
                    return False, str(e)

        # 6 concurrent threads competing for 2 seats in SQLite
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [executor.submit(attempt_sqlite_admission, i) for i in range(1, 7)]
            results = [f.result() for f in futures]

        successes = [r for r in results if r[0] is True]
        failures = [r for r in results if r[0] is False]

        self.assertEqual(len(successes), 2, f"SQLite must allow exactly 2 admissions, got {len(successes)}")
        self.assertEqual(len(failures), 4, f"SQLite must reject exactly 4 admissions, got {len(failures)}")

        with Session(sqlite_engine) as session:
            count = session.exec(select(Student).where(Student.status == "ACTIVE")).all()
            self.assertEqual(len(count), 2, f"SQLite database must contain exactly 2 active records, found {len(count)}")


if __name__ == "__main__":
    unittest.main()

