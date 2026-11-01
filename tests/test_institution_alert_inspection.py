"""
Automated Verification Suite for Institution Dashboard Alert Inspection & Resolution
"""

import os
os.environ["TESTING"] = "1"

from fastapi.testclient import TestClient
from sqlmodel import Session, select, func
from app.main import app
from app.database import engine
from app.models import Institution, Program, Student, User, ValidationFlag, AuditLog
from app.auth import create_access_token
from app.audit import verify_chain

client = TestClient(app, raise_server_exceptions=True)

def test_alert_inspection_suite():
    print("==================================================================")
    print("      INSTITUTION ALERT INSPECTION & RESOLUTION TEST SUITE        ")
    print("==================================================================")

    with Session(engine) as session:
        user_inst1 = session.exec(select(User).where(User.username == "inst1")).first()
        assert user_inst1 is not None, "User inst1 not found in database"
        inst_id = user_inst1.institution_id
        student = session.exec(select(Student).where(Student.institution_id == inst_id)).first()
        program = session.exec(select(Program).where(Program.institution_id == inst_id)).first()

        # Ensure a test validation flag exists for testing inspection
        test_flag = session.exec(
            select(ValidationFlag)
            .where(ValidationFlag.institution_id == inst_id, ValidationFlag.status == "OPEN")
        ).first()

        if not test_flag:
            test_flag = ValidationFlag(
                institution_id=inst_id,
                program_id=program.id if program else None,
                student_id=student.id if student else None,
                rule_code="R12",
                severity="HIGH",
                message="Duplicate institutional roll number identified across active student enrollments.",
                recommended_action="Verify institutional roll number against student registrar ledger and update.",
                status="OPEN",
            )
            session.add(test_flag)
            session.commit()
            session.refresh(test_flag)

        test_flag_id = test_flag.id
        test_student_id = test_flag.student_id

        # Generate tokens
        inst1_token = create_access_token({
            "sub": user_inst1.username,
            "role": user_inst1.role,
            "institution_id": user_inst1.institution_id,
        })

        user_inst2 = session.exec(select(User).where(User.username == "inst2")).first()
        inst2_token = create_access_token({
            "sub": user_inst2.username,
            "role": user_inst2.role,
            "institution_id": user_inst2.institution_id,
        }) if user_inst2 else ""

    print("[PASS] 1. Institution Auth Token Generated")

    # 2. Test Institution Dashboard Alert Display and Modal
    resp_dash = client.get("/institution/dashboard", cookies={"access_token": inst1_token})
    assert resp_dash.status_code == 200, f"Dashboard failed: {resp_dash.status_code}"
    dash_html = resp_dash.text
    assert "Validation Alerts" in dash_html, "Dashboard missing Validation Alerts card"
    assert "Inspect Record" in dash_html, "Dashboard missing 'Inspect Record' button"
    assert "id=\"inspect-modal\"" in dash_html, "Dashboard missing #inspect-modal dialog"
    assert "openInspectModal" in dash_html, "Dashboard missing openInspectModal JS function"
    assert f"/institution/alerts/{test_flag_id}/inspect" in dash_html, "Dashboard missing inspection fallback link"
    print("[PASS] 2. Dashboard correctly renders Validation Alerts, Inspect buttons, and #inspect-modal")

    # 3. Test Dedicated Alert Inspection Page (GET /institution/alerts/{id}/inspect)
    resp_inspect = client.get(f"/institution/alerts/{test_flag_id}/inspect", cookies={"access_token": inst1_token})
    assert resp_inspect.status_code == 200, f"Inspect page failed: {resp_inspect.status_code}"
    inspect_html = resp_inspect.text
    assert "Validation Finding" in inspect_html, "Inspect page missing validation finding section"
    assert "AICTE Corrective Action Required" in inspect_html, "Inspect page missing recommended action"
    assert "Back to Dashboard" in inspect_html, "Inspect page missing Back to Dashboard link"
    assert "Mark as Resolved" in inspect_html, "Inspect page missing Mark as Resolved button"
    if test_student_id:
        assert "Inspected Student Record" in inspect_html, "Inspect page missing student record box"
        assert f"/institution/students/{test_student_id}/edit" in inspect_html, "Inspect page missing Edit Record link"
    print("[PASS] 3. Dedicated Inspection Page renders comprehensive diagnostic and record details")

    # 4. Test JSON Inspection API (GET /institution/alerts/{id}/inspect?json_mode=1)
    resp_json = client.get(f"/institution/alerts/{test_flag_id}/inspect?json_mode=1", cookies={"access_token": inst1_token})
    assert resp_json.status_code == 200
    data = resp_json.json()
    assert data["flag_id"] == test_flag_id
    assert data["rule_code"] == test_flag.rule_code
    assert data["severity"] == test_flag.severity
    assert "recommended_action" in data
    if test_student_id:
        assert data["student"] is not None
        assert "apaar_id" in data["student"]
        assert "student_id" in data["student"]
    print("[PASS] 4. JSON Inspection API returns structured alert and student payload")

    # 5. Test Student Directory Highlighting & Deep-Linking
    if test_student_id:
        with Session(engine) as session:
            stu_record = session.get(Student, test_student_id)
            roll_no = stu_record.student_id

        resp_students = client.get(
            f"/institution/students?student_pk={test_student_id}&q={roll_no}",
            cookies={"access_token": inst1_token},
        )
        assert resp_students.status_code == 200
        stu_html = resp_students.text
        assert f"id=\"student-row-{test_student_id}\"" in stu_html, "Student row missing anchor ID"
        assert "Inspected" in stu_html, "Student row missing 'Inspected' highlight badge"
        assert "scrollIntoView" in stu_html, "Student directory missing auto-scroll to inspected record"
        print("[PASS] 5. Student Directory successfully filters, highlights, and scrolls to inspected record")

    # 6. Test Alert Resolution Endpoint (POST /institution/alerts/{id}/resolve)
    resp_resolve = client.post(
        f"/institution/alerts/{test_flag_id}/resolve",
        headers={"Accept": "application/json"},
        cookies={"access_token": inst1_token},
    )
    assert resp_resolve.status_code == 200
    res_data = resp_resolve.json()
    assert res_data.get("ok") is True

    # Verify database status and hash-chained audit log
    with Session(engine) as session:
        flag_in_db = session.get(ValidationFlag, test_flag_id)
        assert flag_in_db.status == "RESOLVED", "Flag was not updated to RESOLVED in database"

        audit_entry = session.exec(
            select(AuditLog)
            .where(AuditLog.action == "RESOLVE_FLAG", AuditLog.entity_id == str(test_flag_id))
        ).first()
        assert audit_entry is not None, "Missing RESOLVE_FLAG audit log entry"
        assert audit_entry.username == "inst1"

        valid, bad_id = verify_chain(session)
        assert valid, f"Audit log cryptographic chain invalid at row {bad_id}"
    print("[PASS] 6. Alert successfully resolved with immutable audit trail and valid cryptographic chain")

    # 7. Test Security & Cross-Institution Access Isolation
    anon_resp = client.get(f"/institution/alerts/{test_flag_id}/inspect", follow_redirects=False)
    assert anon_resp.status_code in (302, 303, 401, 403), f"Anonymous access not redirected/blocked: {anon_resp.status_code}"

    if inst2_token:
        resp_cross_inspect = client.get(
            f"/institution/alerts/{test_flag_id}/inspect",
            cookies={"access_token": inst2_token},
        )
        assert resp_cross_inspect.status_code == 404, f"Cross-institution inspect permitted! Status: {resp_cross_inspect.status_code}"
        resp_cross_resolve = client.post(
            f"/institution/alerts/{test_flag_id}/resolve",
            cookies={"access_token": inst2_token},
        )
        assert resp_cross_resolve.status_code == 404, f"Cross-institution resolve permitted! Status: {resp_cross_resolve.status_code}"
        print("[PASS] 7. Strict multi-tenant isolation enforced against cross-institution inspection & resolution")

    print("\n==================================================================")
    print("      ALL ALERT INSPECTION TESTS SUCCESSFULLY PASSED!             ")
    print("==================================================================")

if __name__ == "__main__":
    test_alert_inspection_suite()
