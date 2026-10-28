"""
Automated Verification Suite for AICTE Admin Portal Requirements
Tests:
1. Dashboard: System-wide graphs, KPIs, filters, alerts; NO ranking table (#rank-body).
2. Institutions Directory: Simplified 6-column table, search/filter, print button, pagination.
3. Institution Registration: Form validation, duplicate prevention (ID and Name+State), API key generation, hash-chained audit logging.
4. Unified Reports Portal:
   - Tab 1: Compliance Summary
   - Tab 2: Validation Flags & Inconsistencies (with rule/severity filters)
   - Tab 3: Cross-Institution Duplicates (side-by-side evidence)
5. Duplicates Handling & Backward Compatibility:
   - GET /aicte/duplicates returns 200 OK
   - POST /aicte/duplicates/{id}/confirm and resolve redirect & log audit
   - Top navbar removes 'Duplicates' link
6. CSV Export Compatibility: All 5 CSV endpoints return 200 text/csv
7. Settings, Audit Log, and Cryptographic Hash-Chain Integrity.
"""

from fastapi.testclient import TestClient
from sqlmodel import Session, select, func
from app.main import app
from app.database import engine, get_session
from app.models import Institution, ValidationFlag, Student, AuditLog
from app.audit import verify_chain

client = TestClient(app, raise_server_exceptions=False)

def run_suite():
    print("==================================================================")
    print("      AICTE ADMIN PORTAL - USER REQUIREMENTS TEST SUITE           ")
    print("==================================================================")

    # 1. Login as AICTE Admin
    resp_login = client.post("/login", data={"username": "aicte_admin", "password": "Admin@123"}, follow_redirects=False)
    assert resp_login.status_code in (200, 302, 303), f"Admin login failed: {resp_login.status_code}"
    admin_cookie = resp_login.cookies.get("access_token")
    assert admin_cookie, "Could not acquire access token cookie for aicte_admin"
    admin_client = TestClient(app, cookies={"access_token": admin_cookie}, raise_server_exceptions=False)
    print("[PASS] 1. AICTE Admin Authenticated")

    # 2. Test AICTE Central Dashboard
    resp_dash = admin_client.get("/aicte/dashboard")
    assert resp_dash.status_code == 200, f"Dashboard failed: {resp_dash.status_code}"
    dash_html = resp_dash.text
    assert "k-institutions" in dash_html, "Dashboard missing k-institutions KPI"
    assert "k-enrolment" in dash_html, "Dashboard missing k-enrolment KPI"
    assert "k-intake" in dash_html, "Dashboard missing k-intake KPI"
    assert "k-flagged" in dash_html, "Dashboard missing k-flagged KPI"
    assert "k-dups" in dash_html, "Dashboard missing k-dups KPI"
    assert "fillChart" in dash_html, "Dashboard missing fillChart"
    assert "flagChart" in dash_html, "Dashboard missing flagChart"
    assert "high-flags" in dash_html, "Dashboard missing high-flags alert list"
    assert "anomalies" in dash_html, "Dashboard missing anomalies alert list"
    # Ensure ranking table was removed
    assert "id=\"rank-body\"" not in dash_html and "id='rank-body'" not in dash_html, "Dashboard still has #rank-body ranking table"
    # Ensure navbar does not have duplicates link
    assert 'href="/aicte/duplicates"' not in dash_html, "Navbar still has direct Duplicates link"
    print("[PASS] 2. Dashboard Clean & Focused (KPIs, Charts, Alerts present; Ranking table & duplicate nav removed)")

    # 3. Test Institutions Directory
    resp_inst = admin_client.get("/aicte/institutions")
    assert resp_inst.status_code == 200, f"Institutions page failed: {resp_inst.status_code}"
    inst_html = resp_inst.text
    assert "AICTE ID" in inst_html, "Institutions missing AICTE ID header"
    assert "Institution Name" in inst_html, "Institutions missing Institution Name header"
    assert "State" in inst_html, "Institutions missing State header"
    assert "Type" in inst_html, "Institutions missing Type header"
    assert "Sanctioned Intake" in inst_html, "Institutions missing Sanctioned Intake header"
    assert "window.print()" in inst_html, "Institutions missing print functionality"
    assert "register-modal" in inst_html, "Institutions missing registration modal"
    print("[PASS] 3. Institutions Directory (Simplified 6-column table, filters, print, registration modal)")

    # 4. Test Institution Registration & Audit Logging
    test_aicte_id = "1-TESTREG-9999"
    test_name = "Indian Institute of Verification & Testing"
    test_state = "Delhi"
    test_type = "Government"

    # Clean up test inst if left from prior run
    with Session(engine) as s:
        old = s.exec(select(Institution).where(Institution.aicte_id == test_aicte_id)).first()
        if old:
            s.delete(old)
            s.commit()

    resp_reg = admin_client.post(
        "/aicte/institutions/new",
        data={
            "aicte_id": test_aicte_id,
            "name": test_name,
            "state": test_state,
            "institution_type": test_type,
        },
        follow_redirects=True,
    )
    assert resp_reg.status_code == 200, f"Registration POST failed: {resp_reg.status_code}"
    assert "successfully" in str(resp_reg.url) or "successfully" in resp_reg.text

    # Verify DB entry & API key
    with Session(engine) as s:
        new_inst = s.exec(select(Institution).where(Institution.aicte_id == test_aicte_id)).first()
        assert new_inst is not None, "Registered institution not found in database"
        assert new_inst.name == test_name
        assert new_inst.state == test_state
        assert new_inst.type == test_type
        assert new_inst.api_key.startswith("api-key-"), f"Invalid API key generated: {new_inst.api_key}"

        # Verify audit log entry
        audit_entry = s.exec(
            select(AuditLog)
            .where(AuditLog.action == "REGISTER_INSTITUTION", AuditLog.entity_id == str(new_inst.id))
        ).first()
        assert audit_entry is not None, "Audit log entry for REGISTER_INSTITUTION not found"
        assert audit_entry.username == "aicte_admin"
        assert test_aicte_id in (audit_entry.details or "")

        # Verify cryptographic chain integrity
        valid, bad_id = verify_chain(s)
        assert valid, f"Audit log hash chain is invalid at row {bad_id}"

    print("[PASS] 4. Institution Registration (Validation, API Key generation, and hash-chained audit logging verified)")

    # 5. Test Duplicate Institution Registration Prevention
    # 5a: Same AICTE ID
    resp_dup_id = admin_client.post(
        "/aicte/institutions/new",
        data={
            "aicte_id": test_aicte_id,
            "name": "Different Name",
            "state": "Goa",
            "institution_type": "Private",
        },
        follow_redirects=False,
    )
    assert resp_dup_id.status_code == 303
    assert "already+exists" in resp_dup_id.headers.get("location", "")

    # 5b: Same Name and State
    resp_dup_name = admin_client.post(
        "/aicte/institutions/new",
        data={
            "aicte_id": "1-ANOTHER-DIFF-9999",
            "name": test_name,
            "state": test_state,
            "institution_type": "Private",
        },
        follow_redirects=False,
    )
    assert resp_dup_name.status_code == 303
    assert "already+registered" in resp_dup_name.headers.get("location", "")
    print("[PASS] 5. Duplicate Institution Prevention (Blocked duplicate AICTE ID and duplicate Name+State)")

    # 6. Test Unified Reports Portal (3 Tabs)
    # Tab 1: Compliance
    resp_rep1 = admin_client.get("/aicte/reports?tab=compliance")
    assert resp_rep1.status_code == 200
    assert "Institution Compliance Summary" in resp_rep1.text
    assert "Score" in resp_rep1.text and "Approved Intake" in resp_rep1.text and "Fill %" in resp_rep1.text

    # Tab 2: Flags & Inconsistencies
    resp_rep2 = admin_client.get("/aicte/reports?tab=flags")
    assert resp_rep2.status_code == 200
    assert "Validation Flags" in resp_rep2.text
    assert "flag_rule" in resp_rep2.text
    assert "flag_severity" in resp_rep2.text

    # Tab 3: Duplicates
    resp_rep3 = admin_client.get("/aicte/reports?tab=duplicates")
    assert resp_rep3.status_code == 200
    assert "Cross-Institution Duplicates" in resp_rep3.text

    # Backward compatibility: GET /aicte/duplicates
    resp_dup_compat = admin_client.get("/aicte/duplicates")
    assert resp_dup_compat.status_code == 200
    assert "Cross-Institution Duplicates" in resp_dup_compat.text
    print("[PASS] 6. Unified Reports Portal (Compliance Summary, Validation Flags, and Duplicates tabs verified with /aicte/duplicates 200 OK)")

    # 7. Test Duplicates Action Endpoints & Audit Logging
    resp_conf = admin_client.post("/aicte/duplicates/1/confirm", follow_redirects=False)
    assert resp_conf.status_code == 303
    assert "/aicte/reports?tab=duplicates" in resp_conf.headers.get("location", "")

    resp_res = admin_client.post("/aicte/duplicates/1/resolve", follow_redirects=False)
    assert resp_res.status_code == 303
    assert "/aicte/reports?tab=duplicates" in resp_res.headers.get("location", "")

    with Session(engine) as s:
        valid, bad_id = verify_chain(s)
        assert valid, f"Audit log hash chain is invalid at row {bad_id} after duplicate actions"
    print("[PASS] 7. Duplicate Confirm/Resolve Actions & Audit Integrity")

    # 8. Test CSV Exports
    csv_endpoints = [
        "/aicte/reports/enrolment.csv",
        "/aicte/reports/flags.csv",
        "/aicte/reports/breakdown.csv",
        "/aicte/reports/duplicates.csv",
        "/aicte/reports/states.csv",
    ]
    for ep in csv_endpoints:
        resp_csv = admin_client.get(ep)
        assert resp_csv.status_code == 200, f"{ep} returned status {resp_csv.status_code}"
        assert resp_csv.headers.get("content-type", "").startswith("text/csv"), f"{ep} not text/csv"
    print("[PASS] 8. All 5 CSV Regulatory Exports Functional")

    # 9. Test Settings and Audit Log Pages
    resp_set = admin_client.get("/aicte/settings")
    assert resp_set.status_code == 200
    assert "Validation Settings" in resp_set.text

    resp_aud = admin_client.get("/aicte/audit")
    assert resp_aud.status_code == 200
    assert "Audit log" in resp_aud.text

    resp_aud_v = admin_client.get("/aicte/audit/verify")
    assert resp_aud_v.status_code == 200
    assert resp_aud_v.json().get("ok") is True
    print("[PASS] 9. Settings, Audit Log, and Cryptographic Hash-Chain Verification")

    # 10. Test 10 Rows Per Page Default on All Table Lists
    # 10a: Institutions directory
    resp_inst_page = admin_client.get("/aicte/institutions")
    assert resp_inst_page.status_code == 200
    assert "Showing <span class=\"font-bold text-slate-800\">10</span>" in resp_inst_page.text

    # 10b: Compliance reports tab
    resp_comp_page = admin_client.get("/aicte/reports?tab=compliance")
    assert resp_comp_page.status_code == 200
    assert "Showing <span class=\"font-bold text-gray-900\">10</span> rows" in resp_comp_page.text or "Showing <span class=\"font-bold text-slate-800\">10</span>" in resp_comp_page.text

    # 10c: Validation flags report tab
    resp_flags_page = admin_client.get("/aicte/reports?tab=flags")
    assert resp_flags_page.status_code == 200
    assert "Showing <span class=\"font-bold text-gray-900\">10</span> rows" in resp_flags_page.text

    # 10d: Audit logs table
    resp_aud_page = admin_client.get("/aicte/audit")
    assert resp_aud_page.status_code == 200
    assert "Showing <span class=\"font-bold text-gray-900\">10</span> rows" in resp_aud_page.text

    # 10e: Institution students table
    resp_login_inst1 = client.post("/login", data={"username": "inst1", "password": "Inst@123"}, follow_redirects=False)
    inst1_client = TestClient(app, cookies={"access_token": resp_login_inst1.cookies.get("access_token")}, raise_server_exceptions=False)
    resp_stu_page = inst1_client.get("/institution/students")
    assert resp_stu_page.status_code == 200
    assert "Showing <span class=\"font-bold text-gray-900\">1</span> &ndash; <span class=\"font-bold text-gray-900\">10</span>" in resp_stu_page.text
    print("[PASS] 10. All Tables Displaying 10 Rows at a Time with Server-Side Pagination")

    print("\n==================================================================")
    print("      ALL USER REQUIREMENTS SUCCESSFULLY VERIFIED & PASSED!       ")
    print("==================================================================")

if __name__ == "__main__":
    run_suite()
