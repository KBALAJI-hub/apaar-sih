"""
Generate verified, realistic sample CSVs for APAAR Verify (SIH PS 26263).
Aligns perfectly with ApaarRegistry, Institution 1 (Delhi Technological Institute) approved programs,
and active enrolments in Institution 2.

Produces:
1. good_upload.csv: 25 rows, ALL PASS CLEANLY (100% valid APAARs from registry, matching name/DOB, valid programs).
2. bad_upload.csv: 30 rows, mixed realistic scenario:
   - 10 rows: PASS CLEAN
   - 10 rows: ACCEPTED WITH WARNINGS (R3 name fuzzy mismatch, R4 duplicate, R8 inconsistency, R10 uncaptured consent, R12 duplicate roll no)
   - 10 rows: REJECTED (R1 malformed 11-digit APAAR, R2 missing from registry, R9 missing mandatory DOB/name, R11 unapproved program)
3. cross_dup.csv: 4 rows, testing cross-institution duplicate R5:
   - Uses valid inst1 program and valid active APAARs from inst2 so they get ACCEPTED WITH R5 WARNING and appear on the AICTE Evidence Panel!
"""

import csv
import os
from sqlmodel import Session, select
from app.database import fallback_engine, engine
from app.models import ApaarRegistry, Institution, Program, Student

def generate():
    # Use fallback_engine (apaar.db) or engine
    db_engine = fallback_engine
    with Session(db_engine) as session:
        # 1. Fetch free ApaarRegistry rows (not currently enrolled in Student)
        all_reg = session.exec(select(ApaarRegistry)).all()
        all_stus = session.exec(select(Student)).all()
        enrolled_apaars = {s.apaar_id for s in all_stus}
        
        free_regs = [r for r in all_reg if r.apaar_id not in enrolled_apaars]
        print(f"Available free registry entries: {len(free_regs)}")
        
        # 2. Get inst1 approved programs
        inst1_progs = session.exec(select(Program).where(Program.institution_id == 1)).all()
        p_names = list({p.name for p in inst1_progs})
        print(f"Inst1 approved programs: {p_names}")
        
        # 3. Get inst2 active students for cross-dup
        inst2_stus = session.exec(
            select(Student).where(Student.institution_id == 2, Student.status == "ACTIVE", Student.mode == "FULL_TIME")
        ).all()
        print(f"Inst2 active full-time students: {len(inst2_stus)}")
        
        headers = [
            "apaar_id",
            "student_id",
            "full_name",
            "dob",
            "gender",
            "category",
            "program_name",
            "admission_year",
            "admission_type",
            "is_nri",
            "oci_status",
            "is_foreign_national",
            "nationality",
            "mode",
            "consent_given"
        ]
        
        os.makedirs("sample_data", exist_ok=True)
        
        # -------------------------------------------------------------
        # FILE 1: good_upload.csv (25 clean rows -> ALL PASS)
        # -------------------------------------------------------------
        good_rows = []
        for i in range(25):
            r = free_regs[i]
            prog = p_names[i % len(p_names)]
            good_rows.append([
                r.apaar_id,
                f"DTI-2024-{101 + i}",
                r.full_name,
                r.dob,
                r.gender,
                "GENERAL" if i % 2 == 0 else "OBC",
                prog,
                2024,
                "REGULAR",
                "False",
                "False",
                "False",
                "Indian",
                "FULL_TIME",
                "True"
            ])
            
        with open("sample_data/good_upload.csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(good_rows)
        print("Generated sample_data/good_upload.csv (25 clean rows)")
        
        # -------------------------------------------------------------
        # FILE 2: bad_upload.csv (Mixed test case: Clean, Flagged, Rejected)
        # -------------------------------------------------------------
        # 10 Clean rows (from index 25 to 34 of free_regs)
        bad_rows = []
        for i in range(10):
            r = free_regs[25 + i]
            prog = p_names[i % len(p_names)]
            bad_rows.append([
                r.apaar_id,
                f"DTI-2024-{201 + i}",
                r.full_name,
                r.dob,
                r.gender,
                "GENERAL",
                prog,
                2024,
                "REGULAR",
                "False",
                "False",
                "False",
                "Indian",
                "FULL_TIME",
                "True"
            ])
            
        # 10 Flagged rows (Accepted with warnings)
        # Warning 1: R3 Name fuzzy mismatch (add middle initial)
        r_f1 = free_regs[35]
        bad_rows.append([
            r_f1.apaar_id, "DTI-2024-301", r_f1.full_name + " Kumar", r_f1.dob, r_f1.gender,
            "OBC", p_names[0], 2024, "REGULAR", "False", "False", "False", "Indian", "FULL_TIME", "True"
        ])
        r_f2 = free_regs[36]
        bad_rows.append([
            r_f2.apaar_id, "DTI-2024-302", r_f2.full_name + " Singh", r_f2.dob, r_f2.gender,
            "GENERAL", p_names[1], 2024, "REGULAR", "False", "False", "False", "Indian", "FULL_TIME", "True"
        ])
        # Warning 2: R4 Duplicate APAAR inside institution (use an APAAR already enrolled in inst1)
        inst1_stu = session.exec(select(Student).where(Student.institution_id == 1)).first()
        bad_rows.append([
            inst1_stu.apaar_id, "DTI-2024-303", inst1_stu.full_name, inst1_stu.dob, inst1_stu.gender,
            "GENERAL", p_names[0], 2024, "REGULAR", "False", "False", "False", "Indian", "FULL_TIME", "True"
        ])
        # Warning 3: R8 Logical inconsistency: is_foreign_national=True with nationality=India
        r_f3 = free_regs[37]
        bad_rows.append([
            r_f3.apaar_id, "DTI-2024-304", r_f3.full_name, r_f3.dob, r_f3.gender,
            "GENERAL", p_names[0], 2024, "REGULAR", "False", "False", "True", "India", "FULL_TIME", "True"
        ])
        # Warning 4: R8 Logical inconsistency: is_nri=True and is_foreign_national=True
        r_f4 = free_regs[38]
        bad_rows.append([
            r_f4.apaar_id, "DTI-2024-305", r_f4.full_name, r_f4.dob, r_f4.gender,
            "GENERAL", p_names[1], 2024, "REGULAR", "True", "False", "True", "American", "FULL_TIME", "True"
        ])
        # Warning 5: R10 Consent not given
        r_f5 = free_regs[39]
        bad_rows.append([
            r_f5.apaar_id, "DTI-2024-306", r_f5.full_name, r_f5.dob, r_f5.gender,
            "EWS", p_names[2 % len(p_names)], 2024, "REGULAR", "False", "False", "False", "Indian", "FULL_TIME", "False"
        ])
        r_f6 = free_regs[40]
        bad_rows.append([
            r_f6.apaar_id, "DTI-2024-307", r_f6.full_name, r_f6.dob, r_f6.gender,
            "SC", p_names[0], 2024, "REGULAR", "False", "False", "False", "Indian", "FULL_TIME", "False"
        ])
        # Warning 6: R12 Duplicate roll no
        r_f7 = free_regs[41]
        bad_rows.append([
            r_f7.apaar_id, "DTI-2024-201", r_f7.full_name, r_f7.dob, r_f7.gender,
            "GENERAL", p_names[1], 2024, "REGULAR", "False", "False", "False", "Indian", "FULL_TIME", "True"
        ])
        r_f8 = free_regs[42]
        bad_rows.append([
            r_f8.apaar_id, "DTI-2024-309", r_f8.full_name, r_f8.dob, r_f8.gender,
            "OBC", p_names[2 % len(p_names)], 2024, "REGULAR", "False", "False", "False", "Indian", "False", "True"
        ])
        r_f9 = free_regs[43]
        bad_rows.append([
            r_f9.apaar_id, "DTI-2024-310", r_f9.full_name, r_f9.dob, r_f9.gender,
            "ST", p_names[0], 2024, "REGULAR", "False", "False", "False", "Indian", "FULL_TIME", "False"
        ])
        
        # 10 Fatal Rejections (Rejected rows reported in error CSV)
        # R1: Missing APAAR
        bad_rows.append([
            "", "DTI-2024-401", "Missing APAAR Student", "2004-05-10", "M",
            "GENERAL", p_names[0], 2024, "REGULAR", "False", "False", "False", "Indian", "FULL_TIME", "True"
        ])
        # R1: 11-digit APAAR
        bad_rows.append([
            "12345678901", "DTI-2024-402", "Short APAAR Student", "2004-06-12", "F",
            "OBC", p_names[1], 2024, "REGULAR", "False", "False", "False", "Indian", "FULL_TIME", "True"
        ])
        # R1: Non-numeric APAAR
        bad_rows.append([
            "1000000000AB", "DTI-2024-403", "Alpha APAAR Student", "2004-07-14", "M",
            "SC", p_names[0], 2024, "REGULAR", "False", "False", "False", "Indian", "FULL_TIME", "True"
        ])
        # R2: APAAR not in central registry
        bad_rows.append([
            "999999999991", "DTI-2024-404", "Ghost Student One", "2003-08-15", "M",
            "GENERAL", p_names[0], 2024, "REGULAR", "False", "False", "False", "Indian", "FULL_TIME", "True"
        ])
        bad_rows.append([
            "999999999992", "DTI-2024-405", "Ghost Student Two", "2003-09-16", "F",
            "EWS", p_names[1], 2024, "REGULAR", "False", "False", "False", "Indian", "FULL_TIME", "True"
        ])
        # R9: Mandatory Name Missing
        r_m1 = free_regs[44]
        bad_rows.append([
            r_m1.apaar_id, "DTI-2024-406", "", r_m1.dob, r_m1.gender,
            "GENERAL", p_names[0], 2024, "REGULAR", "False", "False", "False", "Indian", "FULL_TIME", "True"
        ])
        # R9: Mandatory DOB Missing
        r_m2 = free_regs[45]
        bad_rows.append([
            r_m2.apaar_id, "DTI-2024-407", r_m2.full_name, "", r_m2.gender,
            "GENERAL", p_names[1], 2024, "REGULAR", "False", "False", "False", "Indian", "FULL_TIME", "True"
        ])
        # R9: Malformed DOB (not YYYY-MM-DD)
        r_m3 = free_regs[46]
        bad_rows.append([
            r_m3.apaar_id, "DTI-2024-408", r_m3.full_name, "15/08/2004", r_m3.gender,
            "GENERAL", p_names[0], 2024, "REGULAR", "False", "False", "False", "Indian", "FULL_TIME", "True"
        ])
        # R11: Unknown Program not registered for inst1
        r_m4 = free_regs[47]
        bad_rows.append([
            r_m4.apaar_id, "DTI-2024-409", r_m4.full_name, r_m4.dob, r_m4.gender,
            "GENERAL", "Master of Aeronautical Engineering", 2024, "REGULAR", "False", "False", "False", "Indian", "FULL_TIME", "True"
        ])
        r_m5 = free_regs[48]
        bad_rows.append([
            r_m5.apaar_id, "DTI-2024-410", r_m5.full_name, r_m5.dob, r_m5.gender,
            "GENERAL", "Bachelor of Dental Surgery", 2024, "REGULAR", "False", "False", "False", "Indian", "FULL_TIME", "True"
        ])
        
        with open("sample_data/bad_upload.csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(bad_rows)
        print("Generated sample_data/bad_upload.csv (30 rows: 10 clean, 10 flagged, 10 rejected)")
        
        # -------------------------------------------------------------
        # FILE 3: cross_dup.csv (4 rows -> R5 Cross-Institution Duplicates)
        # -------------------------------------------------------------
        cross_rows = []
        for i in range(min(4, len(inst2_stus))):
            s2 = inst2_stus[i]
            # Use Inst1's approved program so R11 does NOT reject it!
            cross_rows.append([
                s2.apaar_id,
                f"DTI-XFER-2024-{10 + i}",
                s2.full_name,
                s2.dob,
                s2.gender,
                s2.category or "GENERAL",
                p_names[0],  # B.Tech Computer Science and Engineering
                2024,
                "REGULAR",
                "False",
                "False",
                "False",
                "Indian",
                "FULL_TIME",
                "True"
            ])
            
        with open("sample_data/cross_dup.csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(cross_rows)
        print("Generated sample_data/cross_dup.csv (4 cross-institution duplicate rows)")

if __name__ == "__main__":
    generate()
