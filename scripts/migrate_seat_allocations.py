"""
Database Migration Script for Phase 3: Regulatory Seat Allocations.
SIH PS 26263 - APAAR Verify

Purpose:
Migrates existing Program and Student records to the approval-backed seat allocation data model:
1. Base Sanctioned Intake:
   - For every Program, creates a SANCTIONED SeatAllocation matching program.approved_intake.
   - Status: VERIFIED, Issuing Authority: AICTE.
   - Approval Ref: AICTE-EOA-MIGRATED-PROG-{id}.
2. Supernumerary Quotas:
   - If program.supernumerary_cap > 0, creates a baseline SUPERNUMERARY SeatAllocation.
   - Status: DRAFT (Unverified).
   - Approval Ref: PENDING_REGULATORY_EVIDENCE.
   - Strictly does NOT invent regulatory approval letters; treats allocations as unverified until formal evidence is supplied.
3. Student Reconciliation:
   - Links existing active students to the created SANCTIONED or DRAFT allocation.
4. Idempotent:
   - Safe to run multiple times without duplicating allocations.
"""

import sys
import os
from pathlib import Path

# Ensure app is in python path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from sqlmodel import Session, select, func
from app.database import engine, create_db_and_tables
from app.models import Program, Student, SeatAllocation
from app.allocation import migrate_program_to_allocations, get_program_allocations


def run_migration(batch_size: int = 500, limit: int = None):
    print("=" * 70)
    print("Starting Regulatory Seat Allocation Migration (Phase 3)")
    print("=" * 70)

    # 1. Ensure schema tables exist
    create_db_and_tables()

    with Session(engine) as session:
        query = select(Program)
        if limit:
            query = query.limit(limit)
        programs = session.exec(query).all()
        total_programs = len(programs)
        print(f"Total programs to inspect for allocation migration: {total_programs}")

        sanc_created = 0
        super_created = 0
        skipped = 0

        for idx, prog in enumerate(programs, 1):
            created = migrate_program_to_allocations(session, prog, commit=False)
            for c in created:
                if c.allocation_type == "SANCTIONED":
                    sanc_created += 1
                elif c.allocation_type == "SUPERNUMERARY":
                    super_created += 1
            if not created:
                skipped += 1

            if idx % batch_size == 0 or idx == total_programs:
                session.commit()
                print(f"Processed {idx}/{total_programs} programs (SANCTIONED: {sanc_created}, SUPERNUMERARY (DRAFT): {super_created})...")

        # Reconcile existing students to allocations
        print("\nReconciling active student records with migrated allocations...")
        students = session.exec(select(Student).where(Student.allocation_id == None)).all()
        reconciled_students = 0

        for stu in students:
            prog_allocs = get_program_allocations(session, stu.program_id, str(stu.admission_year) if stu.admission_year else None)
            if not prog_allocs:
                prog = session.get(Program, stu.program_id)
                if prog:
                    prog_allocs = get_program_allocations(session, prog.id, prog.academic_year)

            if prog_allocs:
                # Match regular vs supernumerary
                target_type = str(stu.admission_type or "REGULAR").upper()
                matched = next((a for a in prog_allocs if a.allocation_type == target_type), None)
                if not matched and target_type == "REGULAR":
                    matched = next((a for a in prog_allocs if a.allocation_type == "SANCTIONED"), None)

                if matched:
                    stu.allocation_id = matched.id
                    session.add(stu)
                    reconciled_students += 1

        session.commit()
        print(f"Student reconciliation completed: {reconciled_students} student records linked to allocations.")

        print("\n" + "=" * 70)
        print("Migration Summary:")
        print(f"  • Verified Sanctioned Allocations Created: {sanc_created}")
        print(f"  • Draft Supernumerary Allocations Created (Unverified): {super_created}")
        print(f"  • Programs Already Having Allocations (Skipped): {skipped}")
        print(f"  • Total Students Reconciled to Allocations: {reconciled_students}")
        print("=" * 70)


if __name__ == "__main__":
    # Test on a small batch first if run standalone
    run_migration(batch_size=100, limit=50)

