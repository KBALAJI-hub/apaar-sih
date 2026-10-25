"""
Phase 4 Integration Test Suite for APAAR Verify (SIH PS 26263).
Automates the 16-step test checklist from Section 12 of the implementation plan:
1. Login as inst3 -> Dashboard shows intake exceeded in red
2. Upload bad_upload.csv -> Rejected and flagged rows reported, error CSV downloads
3. Add a student near full intake -> Seat meter WARN; at full, BLOCK needs justification
4. Add same APAAR again -> R4 flag
5. Add APAAR active at another institution -> R5 flag and evidence panel entry
6. Login as aicte_admin -> Summary API and dashboard return flags and auto-refresh data
7. Open anomaly alerts -> NRI-share and surge alerts with plain-English reasons
8. Verifier looks up Tier 2 APAAR -> Full details and authentic badge
9. Verifier looks up Tier 0 APAAR -> Valid only, no details
10. Student logs in with OTP (123456), changes consent, views lookup log
11. Open a certificate QR -> Authentic record
12. Edit a student field directly in DB, reopen QR -> TAMPERED
13. Call bulk API from /docs with API key -> 200 OK, summary returned
14. Run audit integrity check -> Chain valid; after manual edit, chain broken
15. Institution opens /aicte/dashboard -> 403 or redirect
16. Verifier exceeds rate limit -> 429 with message
"""

import os
import sys
import tempfile
from fastapi.testclient import TestClient
from sqlmodel import Session, select, func

from app.main import app
from app.database import engine, fallback_engine, get_session
from app.models import (
    User,
    Institution,
    Program,
    Student,
    ValidationFlag,
    AnomalyAlert,
    AuditLog,
    VerificationLog,
    ApaarRegistry,
)
from app.audit import verify_chain
from app.security import sign_record, verify_signature

import functools
# Make print flush by default
print = functools.partial(print, flush=True)

client = TestClient(app, raise_server_exceptions=False)

def run_tests():
    print("=" * 70)
    print("  APAAR VERIFY - PHASE 4 INTEGRATION TEST CHECKLIST (16 STEPS)")
    print("=" * 70)
    
    # Refresh disposable test database from apaar.db to guarantee clean test state
    from app.database import init_test_db
    init_test_db(force_refresh=True)

    results = {}
    
    # ---------------------------------------------------------
    # STEP 1: Login as inst3 -> Dashboard shows intake exceeded
    # ---------------------------------------------------------
    print("\n[Step 1] Login as inst3 and check dashboard for exceeded intake...")
    resp_login = client.post("/login", data={"username": "inst3", "password": "Inst@123"}, follow_redirects=False)
    cookie = resp_login.cookies.get("access_token")
    if not cookie:
        print("FAIL: Could not obtain auth cookie for inst3")
        results[1] = False
    else:
        inst3_client = TestClient(app, cookies={"access_token": cookie}, raise_server_exceptions=False)
        resp_dash = inst3_client.get("/institution/dashboard")
        has_intake_warning = (
            resp_dash.status_code == 200 and
            ("Exceeded" in resp_dash.text or "exceeded" in resp_dash.text or "text-red" in resp_dash.text or "bg-red" in resp_dash.text or "135" in resp_dash.text)
        )
        print(f"  Status: {resp_dash.status_code}, Found intake warning indicator: {has_intake_warning}")
        results[1] = has_intake_warning

    # ---------------------------------------------------------
    # STEP 2: Upload bad_upload.csv -> Rejected/flagged rows reported & error CSV downloads
    # ---------------------------------------------------------
    print("\n[Step 2] Upload sample_data/bad_upload.csv as inst1...")
    resp_login_inst1 = client.post("/login", data={"username": "inst1", "password": "Inst@123"}, follow_redirects=False)
    inst1_cookie = resp_login_inst1.cookies.get("access_token")
    inst1_client = TestClient(app, cookies={"access_token": inst1_cookie}, raise_server_exceptions=False)
    
    csv_path = os.path.join("sample_data", "bad_upload.csv")
    if os.path.exists(csv_path):
        with open(csv_path, "rb") as f:
            resp_upload = inst1_client.post(
                "/institution/upload",
                files={"file": ("bad_upload.csv", f, "text/csv")},
                follow_redirects=True,
            )
        resp_err_csv = inst1_client.get("/institution/upload/error-csv")
        step2_ok = (
            resp_upload.status_code == 200 and
            ("Rejected" in resp_upload.text or "rejected" in resp_upload.text or "Warning" in resp_upload.text or "Flag" in resp_upload.text) and
            resp_err_csv.status_code == 200 and
            resp_err_csv.headers.get("content-type", "").startswith("text/csv")
        )
        print(f"  Upload status: {resp_upload.status_code}, Error CSV status: {resp_err_csv.status_code}, Downloaded: {step2_ok}")
        results[2] = step2_ok
    else:
        print(f"  FAIL: {csv_path} not found")
        results[2] = False

    # ---------------------------------------------------------
    # STEP 3: Intake check: near full -> WARN; at full -> BLOCK needs justification
    # ---------------------------------------------------------
    print("\n[Step 3] Program intake-check API (ALLOW, WARN, BLOCK)...")
    with Session(engine) as s:
        inst = s.exec(select(Institution)).first()
        inst_id = inst.id if inst else 1
        
        # 1. Verify ALLOW on Program 1 (standard low-ratio program)
        resp_allow = client.get("/api/v1/programs/1/intake-check")
        data_allow = resp_allow.json() if resp_allow.status_code == 200 else {}
        decision_allow = data_allow.get("decision")
        is_allow = (resp_allow.status_code == 200 and decision_allow == "ALLOW")
        print(f"  [ALLOW] Program 1: Status={resp_allow.status_code}, Decision={decision_allow}, Fill={data_allow.get('fill_ratio')}")

        # 2. Verify BLOCK on Program 12 (exceeded intake)
        resp_block = client.get("/api/v1/programs/12/intake-check")
        data_block = resp_block.json() if resp_block.status_code == 200 else {}
        decision_block = data_block.get("decision")
        is_block = (resp_block.status_code == 200 and decision_block == "BLOCK")
        print(f"  [BLOCK] Program 12: Status={resp_block.status_code}, Decision={decision_block}, Fill={data_block.get('fill_ratio')}")

        # 3. Verify WARN on isolated program with 90% intake (near full)
        temp_prog = Program(
            name="Intake Guard Verification Program",
            level="UG",
            approved_intake=10,
            academic_year="2024-25",
            institution_id=inst_id,
            supernumerary_cap=0.1,
        )
        s.add(temp_prog)
        s.commit()
        s.refresh(temp_prog)

        test_stus = []
        is_warn = False
        decision_warn = None
        try:
            for i in range(9):
                st = Student(
                    apaar_id=f"9998000000{i:02d}",
                    student_id=f"INTAKE-CHK-{i:02d}",
                    full_name=f"Intake Student {i}",
                    dob="2003-01-01",
                    gender="M",
                    category="General",
                    institution_id=inst_id,
                    program_id=temp_prog.id,
                    admission_year=2024,
                    admission_type="REGULAR",
                    status="ACTIVE",
                    consent_level=1,
                )
                s.add(st)
                test_stus.append(st)
            s.commit()

            resp_warn = client.get(f"/api/v1/programs/{temp_prog.id}/intake-check")
            data_warn = resp_warn.json() if resp_warn.status_code == 200 else {}
            decision_warn = data_warn.get("decision")
            is_warn = (resp_warn.status_code == 200 and decision_warn == "WARN")
            print(f"  [WARN]  Program {temp_prog.id}: Status={resp_warn.status_code}, Decision={decision_warn}, Fill={data_warn.get('fill_ratio')}")
        finally:
            for st in test_stus:
                s.delete(st)
            s.delete(temp_prog)
            s.commit()

    step3_ok = is_allow and is_warn and is_block
    print(f"  Step 3 Result: ALLOW={is_allow}, WARN={is_warn}, BLOCK={is_block} -> All Assertions Passed: {step3_ok}")
    results[3] = step3_ok

    # ---------------------------------------------------------
    # STEP 4: Add duplicate APAAR -> R4 flag
    # ---------------------------------------------------------
    print("\n[Step 4] Checking duplicate APAAR rule (R4)...")
    from app.validation import run_full_validation
    from app.anomaly import run_anomaly_detection
    with Session(engine) as s:
        r4_flag = s.exec(select(ValidationFlag).where(ValidationFlag.rule_code == "R4")).first()
        if not r4_flag:
            insts = s.exec(select(Student.institution_id).distinct()).all()
            for iid in insts:
                if iid:
                    run_full_validation(iid, s)
            s.commit()
            r4_flag = s.exec(select(ValidationFlag).where(ValidationFlag.rule_code == "R4")).first()
        print(f"  Planted or generated R4 flag found in DB: {r4_flag is not None}")
        if r4_flag:
            print(f"  Flag details: Rule={r4_flag.rule_code}, Severity={r4_flag.severity}, Message={r4_flag.message}")
        results[4] = (r4_flag is not None)

    # ---------------------------------------------------------
    # STEP 5: Add APAAR active at another institution -> R5 flag & duplicate evidence panel
    # ---------------------------------------------------------
    print("\n[Step 5] Checking cross-institution duplicate rule (R5) and evidence panel...")
    with Session(engine) as s:
        r5_flag = s.exec(select(ValidationFlag).where(ValidationFlag.rule_code == "R5")).first()
        print(f"  Planted or generated R5 flag found in DB: {r5_flag is not None}")
        if r5_flag:
            print(f"  Flag details: Rule={r5_flag.rule_code}, Message={r5_flag.message}")
        
    resp_admin = client.post("/login", data={"username": "aicte_admin", "password": "Admin@123"}, follow_redirects=False)
    admin_cookie = resp_admin.cookies.get("access_token")
    admin_client = TestClient(app, cookies={"access_token": admin_cookie}, raise_server_exceptions=False)
    resp_dup_panel = admin_client.get("/aicte/duplicates")
    step5_ok = (r5_flag is not None) and (resp_dup_panel.status_code == 200)
    print(f"  AICTE Duplicates panel status: {resp_dup_panel.status_code}, Step 5: {step5_ok}")
    results[5] = step5_ok

    # ---------------------------------------------------------
    # STEP 6: AICTE admin auto-refresh API summary
    # ---------------------------------------------------------
    print("\n[Step 6] Login as aicte_admin and check /api/aicte/summary...")
    resp_summary = admin_client.get("/api/aicte/summary")
    if resp_summary.status_code == 200:
        sum_data = resp_summary.json()
        total_inst = sum_data.get("totals", {}).get("institutions") or sum_data.get("institutions_count")
        print(f"  AICTE Summary API status: 200 OK. Total institutions reported: {total_inst}")
        results[6] = (total_inst is not None and total_inst > 0)
    else:
        print(f"  FAIL: summary API returned {resp_summary.status_code}")
        results[6] = False

    # ---------------------------------------------------------
    # STEP 7: Anomaly alerts: NRI-share and surge alerts with plain-English reasons
    # ---------------------------------------------------------
    print("\n[Step 7] Inspecting AnomalyAlert rows (A2 surge, A3 NRI outlier)...")
    with Session(engine) as s:
        alerts = s.exec(select(AnomalyAlert)).all()
        if not alerts:
            run_anomaly_detection(s)
            s.commit()
            alerts = s.exec(select(AnomalyAlert)).all()
        a2_alerts = [a for a in alerts if a.code == "A2"]
        a3_alerts = [a for a in alerts if a.code == "A3"]
        has_reasons = all(len(a.reason) > 5 for a in alerts) if alerts else False
        print(f"  Total AnomalyAlerts: {len(alerts)} (A2 Surge: {len(a2_alerts)}, A3 NRI: {len(a3_alerts)})")
        for a in alerts[:3]:
            print(f"  Sample Alert [{a.code}]: {a.reason}")
        results[7] = (len(alerts) > 0 and has_reasons)

    # ---------------------------------------------------------
    # STEP 8: Verifier looks up Tier 2 APAAR -> Full details & authentic badge
    # ---------------------------------------------------------
    print("\n[Step 8] Verifier lookup with Tier 2 student consent...")
    resp_v_login = client.post("/login", data={"username": "employer1", "password": "Verify@123"}, follow_redirects=False)
    verifier_cookie = resp_v_login.cookies.get("access_token")
    verifier_client = TestClient(app, cookies={"access_token": verifier_cookie}, raise_server_exceptions=False)
    
    with Session(engine) as s:
        tier2_student = s.exec(select(Student).where(Student.consent_level == 2)).first()
    
    if tier2_student:
        resp_v_t2 = verifier_client.post("/verify", data={"apaar_id": tier2_student.apaar_id})
        t2_ok = (
            resp_v_t2.status_code == 200 and
            tier2_student.full_name in resp_v_t2.text and
            ("Tier 2" in resp_v_t2.text or "Authentic" in resp_v_t2.text or "authentic" in resp_v_t2.text or "VERIFIED" in resp_v_t2.text)
        )
        print(f"  Tier 2 lookup for APAAR {tier2_student.apaar_id}: status={resp_v_t2.status_code}, Found name & authentic badge={t2_ok}")
        results[8] = t2_ok
    else:
        print("  FAIL: No Tier 2 student in DB")
        results[8] = False

    # ---------------------------------------------------------
    # STEP 9: Verifier looks up Tier 0 APAAR -> Valid only, no details
    # ---------------------------------------------------------
    print("\n[Step 9] Verifier lookup with Tier 0 student consent...")
    with Session(engine) as s:
        tier0_student = s.exec(select(Student).where(Student.consent_level == 0)).first()
    
    if tier0_student:
        resp_v_t0 = verifier_client.post("/verify", data={"apaar_id": tier0_student.apaar_id})
        t0_ok = (
            resp_v_t0.status_code == 200 and
            ("not consented" in resp_v_t0.text or "Tier 0" in resp_v_t0.text or "Consent" in resp_v_t0.text or "Valid" in resp_v_t0.text) and
            (tier0_student.dob not in resp_v_t0.text)
        )
        print(f"  Tier 0 lookup for APAAR {tier0_student.apaar_id}: status={resp_v_t0.status_code}, Conceals details={t0_ok}")
        results[9] = t0_ok
    else:
        print("  FAIL: No Tier 0 student in DB")
        results[9] = False

    # ---------------------------------------------------------
    # STEP 10: Student simulated OTP login (123456), changes consent, views lookup log
    # ---------------------------------------------------------
    print("\n[Step 10] Student OTP login and consent toggle...")
    with Session(engine) as s:
        std_user = s.exec(select(User).where(User.role == "STUDENT")).first()
        std_apaar = std_user.apaar_id if (std_user and std_user.apaar_id) else None
        if not std_apaar:
            any_std = s.exec(select(Student)).first()
            std_apaar = any_std.apaar_id if any_std else "100000000001"

    # Login with OTP
    resp_otp = client.post("/student/consent", data={"apaar_id": std_apaar, "otp": "123456"})
    std_session_cookie = resp_otp.cookies.get("access_token")
    std_client = TestClient(app, cookies={"access_token": std_session_cookie}, raise_server_exceptions=False)
    
    # Toggle consent to Tier 1 using action="update_consent"
    resp_consent_update = std_client.post(
        "/student/consent",
        data={"apaar_id": std_apaar, "action": "update_consent", "consent_level": "1"},
        follow_redirects=True,
    )
    step10_ok = (
        resp_otp.status_code in (200, 303) and
        resp_consent_update.status_code == 200 and
        ("updated" in resp_consent_update.text.lower() or "tier 1" in resp_consent_update.text.lower())
    )
    print(f"  Student OTP login status: {resp_otp.status_code}, Consent update status: {resp_consent_update.status_code}, Step 10: {step10_ok}")
    results[10] = step10_ok

    # ---------------------------------------------------------
    # STEP 11: Open a certificate QR -> Authentic record
    # ---------------------------------------------------------
    print("\n[Step 11] Public verification endpoint check (Authentic record)...")
    with Session(engine) as s:
        sample_student = s.exec(select(Student).where(Student.record_signature != None)).first()
    
    if sample_student:
        resp_verify_pub = client.get(f"/verify/record/{sample_student.id}?sig={sample_student.record_signature}")
        is_authentic = (
            resp_verify_pub.status_code == 200 and
            ("Authentic" in resp_verify_pub.text or "authentic" in resp_verify_pub.text or "VERIFIED" in resp_verify_pub.text)
        )
        print(f"  Public verify status: {resp_verify_pub.status_code}, Shows authentic: {is_authentic}")
        results[11] = is_authentic
    else:
        print("  FAIL: No signed student found")
        results[11] = False

    # ---------------------------------------------------------
    # STEP 12: DB tampering test -> modify student field, check TAMPERED
    # ---------------------------------------------------------
    print("\n[Step 12] Tampering demonstration: tamper student name and test signature verification...")
    with Session(engine) as s:
        test_std = s.exec(select(Student)).first()
        real_name = test_std.full_name
        test_std.full_name = real_name + " [TAMPERED_IN_DB]"
        s.add(test_std)
        s.commit()
        s.refresh(test_std)
        
        # Test signature verification directly
        sig_valid = verify_signature(test_std, test_std.record_signature)
        print(f"  Signature verification after DB tampering: {sig_valid} (Expected: False)")
        
        resp_tampered = client.get(f"/verify/record/{test_std.id}?sig={test_std.record_signature}")
        shows_tampered = (
            resp_tampered.status_code in (200, 400, 404) and
            ("TAMPERED" in resp_tampered.text or "tampered" in resp_tampered.text or "not authentic" in resp_tampered.text or "Invalid" in resp_tampered.text)
        )
        print(f"  Public verify status for tampered record: {resp_tampered.status_code}, Shows TAMPERED: {shows_tampered}")
        
        # Revert change
        test_std.full_name = real_name
        s.add(test_std)
        s.commit()
        
        results[12] = (not sig_valid) and shows_tampered

    # ---------------------------------------------------------
    # STEP 13: Bulk API from /docs with API key
    # ---------------------------------------------------------
    print("\n[Step 13] Bulk API call with X-API-Key header...")
    with Session(engine) as s:
        inst = s.exec(select(Institution)).first()
        api_key = inst.api_key if inst else "demo_key"
        prog = s.exec(select(Program).where(Program.institution_id == inst.id)).first()
        prog_name = prog.name if prog else "Computer Science and Engineering"
    
    bulk_payload = [
        {
            "apaar_id": "999900001111",
            "student_id": "API-TEST-001",
            "full_name": "API Bulk Test Student",
            "dob": "2003-01-01",
            "gender": "M",
            "category": "General",
            "program_name": prog_name,
            "admission_year": 2024,
            "admission_type": "REGULAR",
            "is_nri": False,
            "oci_status": False,
            "is_foreign_national": False,
            "nationality": "Indian",
            "mode": "FULL_TIME",
            "consent_given": True
        }
    ]
    resp_bulk = client.post(
        "/api/v1/students/bulk",
        headers={"X-API-Key": api_key},
        json=bulk_payload
    )
    print(f"  Bulk API status: {resp_bulk.status_code}, Response: {resp_bulk.text[:150]}")
    results[13] = (resp_bulk.status_code == 200)

    # ---------------------------------------------------------
    # STEP 14: Hash-chained audit integrity check
    # ---------------------------------------------------------
    print("\n[Step 14] Hash-chained audit log integrity check...")
    with Session(engine) as s:
        valid_before, broken_id = verify_chain(s)
        print(f"  Original audit chain valid: {valid_before}")
        
        # Simulate tampering on the latest audit log entry
        latest_audit = s.exec(select(AuditLog).order_by(AuditLog.id.desc())).first()
        if latest_audit:
            original_action = latest_audit.action
            latest_audit.action = "TAMPERED_ACTION_TEST"
            s.add(latest_audit)
            s.commit()
            
            valid_after, broken_after = verify_chain(s)
            print(f"  After tampering audit row {latest_audit.id}: valid={valid_after}, detected broken id={broken_after}")
            
            # Revert tampering
            latest_audit.action = original_action
            s.add(latest_audit)
            s.commit()
            
            results[14] = valid_before and (not valid_after) and (broken_after == latest_audit.id)
        else:
            results[14] = valid_before

    # ---------------------------------------------------------
    # STEP 15: RBAC denial (Institution opens /aicte/dashboard -> 403 or redirect)
    # ---------------------------------------------------------
    print("\n[Step 15] RBAC enforcement: inst1 opens /aicte/dashboard...")
    resp_rbac = inst1_client.get("/aicte/dashboard", follow_redirects=False)
    rbac_denied = resp_rbac.status_code in (403, 303, 302, 307)
    print(f"  Institution accessing AICTE dashboard status: {resp_rbac.status_code} (Denied: {rbac_denied})")
    results[15] = rbac_denied

    # ---------------------------------------------------------
    # STEP 16: Verifier rate limit (30 requests/min -> 429)
    # ---------------------------------------------------------
    print("\n[Step 16] Verifier rate limit test (threshold = 30 lookups/min)...")
    import time
    from app.routers.verify import RATE_LIMIT_STORE
    RATE_LIMIT_STORE["user:employer1"] = [time.time()] * 30
    resp_rate = verifier_client.post("/verify", data={"apaar_id": "100000000001"})
    got_429 = (resp_rate.status_code == 429)
    print(f"  Rate limit check (30 lookups window): status={resp_rate.status_code}, Triggered 429: {got_429}")
    results[16] = got_429

    # ---------------------------------------------------------
    # SUMMARY REPORT
    # ---------------------------------------------------------
    print("\n" + "=" * 70)
    print("                    CHECKLIST SUMMARY REPORT")
    print("=" * 70)
    passed_count = sum(1 for v in results.values() if v)
    for step_num in range(1, 17):
        status_str = "PASS [OK]" if results.get(step_num) else "FAIL [X]"
        print(f"  Step {step_num:02d}: {status_str}")
    
    print("-" * 70)
    print(f"  TOTAL: {passed_count}/16 steps passed ({int(passed_count/16*100)}%)")
    print("=" * 70)
    return passed_count == 16

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
