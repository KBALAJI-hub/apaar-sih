"""
Database Seed Script for APAAR Verify.
Generates deterministic demo data with fixed seeds:
- 1 AICTE Admin, 5 Institutions, 1 Verifier, 5 Student Users
- 800+ ApaarRegistry rows, 500+ Student rows
- Planted problems for SIH PS 26263 validation & anomaly rules
"""

from datetime import datetime, timezone
import random
from faker import Faker
from sqlmodel import Session, select

from app.auth import hash_password
from app.database import engine, get_session, reset_db
from app.models import (
    AnomalyAlert,
    ApaarRegistry,
    Institution,
    Program,
    Setting,
    Student,
    User,
    ValidationFlag,
    utc_now,
)

# Set deterministic random seeds
random.seed(42)
fake = Faker("en_IN")
Faker.seed(42)


def generate_apaar_id(seq: int) -> str:
    """Generate deterministic 12-digit ASCII APAAR ID."""
    return f"{100000000000 + seq}"


def seed_database():
    print("=" * 65)
    print("  APAAR Verify - Database Seeder (SIH PS 26263)")
    print("=" * 65)

    # 1. Reset tables cleanly
    print("[1/6] Dropping and recreating tables...")
    reset_db()

    with Session(engine) as session:
        # 2. Seed Default Settings
        print("[2/6] Seeding system settings...")
        settings = [
            Setting(key="intake_warn_threshold", value="0.90"),
            Setting(key="intake_block_threshold", value="1.00"),
            Setting(key="nri_outlier_threshold", value="0.25"),
            Setting(key="yoy_surge_threshold", value="2.00"),
            Setting(key="supernumerary_cap_default", value="0.10"),
        ]
        for s in settings:
            session.add(s)
        session.commit()

        # 3. Seed Institutions and Program Quotas
        print("[3/6] Seeding 5 institutions & academic programs...")
        inst_configs = [
            {
                "aicte_id": "AICTE-ENG-001",
                "name": "Delhi Technological Institute",
                "state": "Delhi",
                "type": "Engineering",
                "api_key": "api-key-inst1-secret",
                "username": "inst1",
                "programs": [
                    ("B.Tech Computer Science and Engineering", "UG", 120),
                    ("B.Tech Electronics and Communication", "UG", 120),
                    ("B.Tech Mechanical Engineering", "UG", 60),
                ],
            },
            {
                "aicte_id": "AICTE-MGT-002",
                "name": "Maharashtra Institute of Technology",
                "state": "Maharashtra",
                "type": "Management",
                "api_key": "api-key-inst2-secret",
                "username": "inst2",
                "programs": [
                    ("Master of Business Administration", "PG", 120),
                    ("Executive MBA", "PG", 60),
                ],
            },
            {
                "aicte_id": "AICTE-PHARM-003",
                "name": "Karnataka College of Pharmacy",
                "state": "Karnataka",
                "type": "Pharmacy",
                "api_key": "api-key-inst3-secret",
                "username": "inst3",
                "programs": [
                    ("Bachelor of Pharmacy", "UG", 60),
                    ("Master of Pharmacy (Pharmaceutics)", "PG", 60),
                ],
            },
            {
                "aicte_id": "AICTE-PGDM-004",
                "name": "Tamil Nadu Institute of Management",
                "state": "Tamil Nadu",
                "type": "PGDM",
                "api_key": "api-key-inst4-secret",
                "username": "inst4",
                "programs": [
                    ("Post Graduate Diploma in Management", "PG", 180),
                    ("PGDM Business Analytics", "PG", 60),
                ],
            },
            {
                "aicte_id": "AICTE-POLY-005",
                "name": "Gujarat Polytechnic College",
                "state": "Gujarat",
                "type": "Polytechnic",
                "api_key": "api-key-inst5-secret",
                "username": "inst5",
                "programs": [
                    ("Diploma in Civil Engineering", "Diploma", 60),
                    ("Diploma in Electrical Engineering", "Diploma", 60),
                ],
            },
        ]

        institutions = []
        programs_by_inst = {}

        for cfg in inst_configs:
            inst = Institution(
                aicte_id=cfg["aicte_id"],
                name=cfg["name"],
                state=cfg["state"],
                type=cfg["type"],
                api_key=cfg["api_key"],
            )
            session.add(inst)
            session.commit()
            session.refresh(inst)
            institutions.append(inst)

            # Create institution login user
            user = User(
                username=cfg["username"],
                password_hash=hash_password("Inst@123"),
                role="INSTITUTION",
                institution_id=inst.id,
                full_name=f"{cfg['name']} Registrar",
            )
            session.add(user)

            # Create programs for academic years 2023-24 and 2024-25
            programs_by_inst[inst.id] = []
            for pname, plevel, pintake in cfg["programs"]:
                for year in ["2023-24", "2024-25"]:
                    prog = Program(
                        institution_id=inst.id,
                        name=pname,
                        level=plevel,
                        academic_year=year,
                        approved_intake=pintake,
                        supernumerary_cap=0.10,
                    )
                    session.add(prog)
                    session.commit()
                    session.refresh(prog)
                    programs_by_inst[inst.id].append(prog)

        # Create AICTE Admin & Verifier users
        aicte_admin = User(
            username="aicte_admin",
            password_hash=hash_password("Admin@123"),
            role="AICTE_ADMIN",
            full_name="AICTE Chief Administrator",
        )
        session.add(aicte_admin)

        verifier = User(
            username="employer1",
            password_hash=hash_password("Verify@123"),
            role="VERIFIER",
            full_name="TCS Campus Recruitment Verifier",
        )
        session.add(verifier)
        session.commit()

        # 4. Seed Mock ApaarRegistry (~850 records)
        print("[4/6] Seeding ~850 central ApaarRegistry records...")
        registry_records = []
        for seq in range(1, 851):
            apaar_id = generate_apaar_id(seq)
            gender = random.choice(["M", "F"])
            name = fake.name()
            # Age between 18 and 23
            birth_year = random.randint(2001, 2006)
            birth_month = random.randint(1, 12)
            birth_day = random.randint(1, 28)
            dob = f"{birth_year:04d}-{birth_month:02d}-{birth_day:02d}"

            registry_records.append(
                ApaarRegistry(
                    apaar_id=apaar_id,
                    full_name=name,
                    dob=dob,
                    gender=gender,
                )
            )

        session.bulk_save_objects(registry_records)
        session.commit()

        # 5. Seed ~500 Student Records with Planted Problems
        print("[5/6] Seeding ~500 student records with planted anomalies...")
        students = []
        categories = ["GENERAL", "OBC", "SC", "ST", "EWS"]

        # Track APAAR usage
        curr_apaar_idx = 1

        # Seed students for each institution
        for inst_idx, inst in enumerate(institutions):
            inst_programs = programs_by_inst[inst.id]

            # Institution 2: YoY Surge (inst_idx == 1)
            # Few students in 2023-24, 3x surge in 2024-25
            for prog in inst_programs:
                if inst_idx == 1:
                    target_count = 15 if prog.academic_year == "2023-24" else 55
                elif inst_idx == 2 and "Bachelor of Pharmacy" in prog.name and prog.academic_year == "2024-25":
                    # Institution 3: 135% intake exceeded planted problem
                    target_count = int(prog.approved_intake * 1.35)  # 81 students on 60 intake
                else:
                    target_count = random.randint(35, min(50, prog.approved_intake))

                for s_num in range(target_count):
                    apaar_id = generate_apaar_id(curr_apaar_idx)
                    curr_apaar_idx += 1

                    # Look up registry person
                    reg_person = registry_records[(curr_apaar_idx - 2) % len(registry_records)]
                    full_name = reg_person.full_name
                    dob = reg_person.dob
                    gender = reg_person.gender

                    # Consent distribution: 40% Tier 2, 30% Tier 1, 30% Tier 0
                    consent_dice = random.random()
                    consent_level = 2 if consent_dice < 0.40 else (1 if consent_dice < 0.70 else 0)

                    # Planted anomaly: Institution 4 has ~40% NRI share (inst_idx == 3)
                    is_nri = (random.random() < 0.40) if inst_idx == 3 else (random.random() < 0.05)
                    admission_type = "SUPERNUMERARY" if is_nri and random.random() < 0.5 else "REGULAR"

                    stu = Student(
                        apaar_id=apaar_id,
                        institution_id=inst.id,
                        program_id=prog.id,
                        student_id=f"{inst.aicte_id[:8]}-{prog.academic_year[:4]}-{s_num + 1:03d}",
                        full_name=full_name,
                        dob=dob,
                        gender=gender,
                        category=random.choice(categories),
                        admission_type=admission_type,
                        is_nri=is_nri,
                        oci_status=False,
                        is_foreign_national=False,
                        nationality="Indian",
                        admission_year=int(prog.academic_year[:4]),
                        mode="FULL_TIME",
                        status="ACTIVE",
                        consent_level=consent_level,
                        consent_timestamp=utc_now() if consent_level > 0 else None,
                        created_at=utc_now(),
                    )
                    students.append(stu)

        # Plant specific test anomalies into student dataset:
        # A) 3 duplicate APAAR IDs inside institution 1
        for i in range(3):
            dup_target = students[i]
            students.append(
                Student(
                    apaar_id=dup_target.apaar_id,  # Duplicate APAAR inside inst 1
                    institution_id=institutions[0].id,
                    program_id=programs_by_inst[institutions[0].id][0].id,
                    student_id=f"DTI-DUP-{i + 1:02d}",
                    full_name=dup_target.full_name,
                    dob=dup_target.dob,
                    gender=dup_target.gender,
                    category=dup_target.category,
                    admission_type="REGULAR",
                    is_nri=False,
                    oci_status=False,
                    is_foreign_national=False,
                    nationality="Indian",
                    admission_year=2024,
                    mode="FULL_TIME",
                    status="ACTIVE",
                    consent_level=2,
                    consent_timestamp=utc_now(),
                )
            )

        # B) 4 cross-institution duplicate APAAR IDs (enrolled at inst1 AND inst2)
        for i in range(4):
            source_stu = students[10 + i]
            students.append(
                Student(
                    apaar_id=source_stu.apaar_id,  # Same APAAR active at inst 2
                    institution_id=institutions[1].id,
                    program_id=programs_by_inst[institutions[1].id][0].id,
                    student_id=f"MIT-CROSS-{i + 1:02d}",
                    full_name=source_stu.full_name,
                    dob=source_stu.dob,
                    gender=source_stu.gender,
                    category=source_stu.category,
                    admission_type="REGULAR",
                    is_nri=False,
                    oci_status=False,
                    is_foreign_national=False,
                    nationality="Indian",
                    admission_year=2024,
                    mode="FULL_TIME",  # Simultaneous full-time enrolment
                    status="ACTIVE",
                    consent_level=2,
                    consent_timestamp=utc_now(),
                )
            )

        # C) 5 APAAR IDs missing from the registry
        for i in range(5):
            missing_apaar = f"99988877700{i}"  # Excluded from registry
            students.append(
                Student(
                    apaar_id=missing_apaar,
                    institution_id=institutions[0].id,
                    program_id=programs_by_inst[institutions[0].id][0].id,
                    student_id=f"DTI-NOREG-{i + 1:02d}",
                    full_name=fake.name(),
                    dob="2004-04-10",
                    gender="M",
                    category="GENERAL",
                    admission_type="REGULAR",
                    is_nri=False,
                    oci_status=False,
                    is_foreign_national=False,
                    nationality="Indian",
                    admission_year=2024,
                    mode="FULL_TIME",
                    status="ACTIVE",
                    consent_level=1,
                    consent_timestamp=utc_now(),
                )
            )

        # D) 5 Name or DOB mismatches vs registry
        for i in range(5):
            target_reg = registry_records[50 + i]
            students.append(
                Student(
                    apaar_id=target_reg.apaar_id,
                    institution_id=institutions[0].id,
                    program_id=programs_by_inst[institutions[0].id][0].id,
                    student_id=f"DTI-MISMATCH-{i + 1:02d}",
                    full_name="Mismatched " + target_reg.full_name.split()[0],  # Altered name
                    dob="1999-01-01",  # Altered DOB
                    gender=target_reg.gender,
                    category="GENERAL",
                    admission_type="REGULAR",
                    is_nri=False,
                    oci_status=False,
                    is_foreign_national=False,
                    nationality="Indian",
                    admission_year=2024,
                    mode="FULL_TIME",
                    status="ACTIVE",
                    consent_level=1,
                    consent_timestamp=utc_now(),
                )
            )

        # E) Foreign national rows with nationality India
        for i in range(3):
            students.append(
                Student(
                    apaar_id=generate_apaar_id(curr_apaar_idx + i),
                    institution_id=institutions[0].id,
                    program_id=programs_by_inst[institutions[0].id][0].id,
                    student_id=f"DTI-FNIND-{i + 1:02d}",
                    full_name=fake.name(),
                    dob="2004-07-15",
                    gender="F",
                    category="GENERAL",
                    admission_type="REGULAR",
                    is_nri=False,
                    oci_status=False,
                    is_foreign_national=True,  # Inconsistency
                    nationality="Indian",      # Inconsistency
                    admission_year=2024,
                    mode="FULL_TIME",
                    status="ACTIVE",
                    consent_level=1,
                    consent_timestamp=utc_now(),
                )
            )

        # F) Cluster of students sharing one identical DOB (Suspicious Cluster A4)
        cluster_dob = "2004-05-15"
        for i in range(12):
            students.append(
                Student(
                    apaar_id=generate_apaar_id(curr_apaar_idx + 10 + i),
                    institution_id=institutions[2].id,
                    program_id=programs_by_inst[institutions[2].id][0].id,
                    student_id=f"KCP-CLUSTER-{i + 1:02d}",
                    full_name=fake.name(),
                    dob=cluster_dob,  # Identical DOB cluster
                    gender="M",
                    category="OBC",
                    admission_type="REGULAR",
                    is_nri=False,
                    oci_status=False,
                    is_foreign_national=False,
                    nationality="Indian",
                    admission_year=2024,
                    mode="FULL_TIME",
                    status="ACTIVE",
                    consent_level=1,
                    consent_timestamp=utc_now(),
                )
            )

        # Save all students
        session.bulk_save_objects(students)
        session.commit()

        # 6. Seed 5 Student Login Users linked to APAAR IDs
        print("[6/6] Creating 5 student user accounts linked to APAAR IDs...")
        student_users = []
        for i in range(1, 6):
            linked_stu = students[i * 10]
            student_users.append(
                User(
                    username=f"student{i}",
                    password_hash=hash_password("Student@123"),
                    role="STUDENT",
                    institution_id=linked_stu.institution_id,
                    apaar_id=linked_stu.apaar_id,
                    full_name=linked_stu.full_name,
                )
            )
        for su in student_users:
            session.add(su)
        session.commit()

    # Print summary credentials
    print("\n" + "=" * 65)
    print("  SEEDING COMPLETE - DEMO CREDENTIALS")
    print("=" * 65)
    print("  Role            Username       Password      Notes")
    print("  -------------------------------------------------------------")
    print("  AICTE_ADMIN     aicte_admin    Admin@123     Central AICTE Regulator")
    print("  INSTITUTION     inst1          Inst@123      Delhi Tech (Engineering)")
    print("  INSTITUTION     inst2          Inst@123      Maharashtra Tech (YoY Surge)")
    print("  INSTITUTION     inst3          Inst@123      Karnataka Pharm (135% Intake)")
    print("  INSTITUTION     inst4          Inst@123      TN Institute (40% NRI Share)")
    print("  INSTITUTION     inst5          Inst@123      Gujarat Poly (Polytechnic)")
    print("  VERIFIER        employer1      Verify@123    TCS Campus Recruiter")
    print("  STUDENT         student1..5    Student@123   OTP: 123456 (Linked APAAR)")
    print("=" * 65)
    print(f"  Summary: 5 Institutions | ~850 Registry | {len(students)} Students")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    seed_database()
