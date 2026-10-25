"""
Public & Third-Party Verification Router for APAAR Verify (SIH PS 26263).
Implements:
1. Student login flow at /student/consent (simulated DigiLocker OTP, consent tiers 0/1/2, 'Who looked me up' list).
2. Verifier portal at /verify (tiered result display: No record, Tier 0, Tier 1, Tier 2, 30 req/min rate limit).
3. Public cryptographic verification at /verify/record/{student_id} and QR code generation.
4. AICTE Ed25519 root public key discovery at /.well-known/aicte-public-key.pem.
"""

from collections import defaultdict
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select

from app.audit import log_action
from app.auth import get_current_user, require_role, create_access_token
from app.database import get_session
from app.models import Institution, Program, Student, User, VerificationLog, utc_now
from app.security import (
    get_public_key_pem,
    make_qr_png,
    sign_record,
    verify_signature,
)

router = APIRouter(tags=["Verify"])

# Templates reference
BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# ---------------------------------------------------------------------------
# In-Memory Rate Limiter: 30 lookups per minute per verifier
# ---------------------------------------------------------------------------
RATE_LIMIT_STORE: Dict[str, List[float]] = defaultdict(list)
RATE_LIMIT_MAX = 30
RATE_LIMIT_WINDOW_SECONDS = 60.0


def is_rate_limited(verifier_key: str) -> bool:
    """Check and record lookup timestamps in 60-second sliding window."""
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    timestamps = [ts for ts in RATE_LIMIT_STORE[verifier_key] if ts > cutoff]
    if len(timestamps) >= RATE_LIMIT_MAX:
        RATE_LIMIT_STORE[verifier_key] = timestamps
        return True
    timestamps.append(now)
    RATE_LIMIT_STORE[verifier_key] = timestamps
    return False


def get_verifier_identifier(request: Request, user: Optional[User]) -> Tuple[Optional[int], str]:
    """Resolve verifier user ID and unique tracking key (username or client IP)."""
    if user:
        return user.id, f"user:{user.username}"
    client_ip = request.client.host if request.client else "127.0.0.1"
    return None, f"ip:{client_ip}"


def get_effective_consent_tier(consent_level: Any) -> int:
    """
    Safely resolves consent tier enforcing:
    - Tier 0: Authenticity/status only. No student identity or institutional/program details.
    - Tier 1: Institution, AICTE ID, program, admission year, and enrollment status. Mask personal identity fields.
    - Tier 2: Full details only when explicitly authorized by valid student consent.

    Any unknown, missing, malformed, or out-of-range consent value strictly fails closed to Tier 0.
    """
    if consent_level is None:
        return 0
    try:
        tier_int = int(consent_level)
    except (ValueError, TypeError):
        return 0
    if tier_int in (1, 2):
        return tier_int
    return 0


# ---------------------------------------------------------------------------
# 1. Public AICTE Root Public Key Discovery
# ---------------------------------------------------------------------------
@router.get("/.well-known/aicte-public-key.pem", response_class=Response)
def get_aicte_public_key():
    """Export root AICTE Ed25519 public key in PEM SubjectPublicKeyInfo format."""
    pem_bytes = get_public_key_pem()
    return Response(content=pem_bytes, media_type="application/x-pem-file")


# ---------------------------------------------------------------------------
# 2. Student DigiLocker Consent Flow (/student/consent)
# ---------------------------------------------------------------------------
@router.get("/student/consent", response_class=HTMLResponse)
def student_consent_page(
    request: Request,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    """
    Render student consent portal:
    - If student is logged in via session cookie, show their profile & consent settings directly.
    - Otherwise, show the simulated DigiLocker OTP login form.
    """
    student = None
    lookups: List[VerificationLog] = []

    if user and user.role == "STUDENT" and user.apaar_id:
        student = session.exec(select(Student).where(Student.apaar_id == user.apaar_id)).first()
        if student:
            lookups = session.exec(
                select(VerificationLog)
                .where(VerificationLog.apaar_id == student.apaar_id)
                .order_by(VerificationLog.id.desc())
            ).all()

    return templates.TemplateResponse(
        request=request,
        name="student_consent.html",
        context={
            "student": student,
            "lookups": lookups,
            "role": user.role if user else None,
            "error": None,
            "success": None,
        },
    )


@router.post("/student/consent", response_class=HTMLResponse)
def handle_student_consent(
    request: Request,
    action: str = Form("login"),
    apaar_id: str = Form(...),
    otp: Optional[str] = Form(None),
    consent_level: Optional[str] = Form(None),
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    """
    Process Student Consent actions:
    1. 'login': Verify APAAR ID and demo simulated DigiLocker OTP (123456).
    2. 'update_consent': Set consent level (0, 1, or 2) and record audit trail.
    """
    clean_apaar = apaar_id.strip()
    student = session.exec(select(Student).where(Student.apaar_id == clean_apaar)).first()

    # Step A: Authentication via simulated DigiLocker OTP
    if action == "login":
        if not otp or otp.strip() != "123456":
            return templates.TemplateResponse(
                request=request,
                name="student_consent.html",
                context={
                    "student": None,
                    "apaar_id": clean_apaar,
                    "error": "Invalid OTP. Please enter the simulated DigiLocker OTP: 123456",
                    "role": user.role if user else None,
                },
                status_code=400,
            )

        if not student:
            return templates.TemplateResponse(
                request=request,
                name="student_consent.html",
                context={
                    "student": None,
                    "apaar_id": clean_apaar,
                    "error": f"No student record found matching APAAR ID '{clean_apaar}' in the AICTE registry.",
                    "role": user.role if user else None,
                },
                status_code=404,
            )

        lookups = session.exec(
            select(VerificationLog)
            .where(VerificationLog.apaar_id == student.apaar_id)
            .order_by(VerificationLog.id.desc())
        ).all()

        token = create_access_token({"sub": f"student:{student.apaar_id}", "role": "STUDENT", "apaar_id": student.apaar_id})
        resp = templates.TemplateResponse(
            request=request,
            name="student_consent.html",
            context={
                "student": student,
                "lookups": lookups,
                "role": "STUDENT",
                "success": "DigiLocker identity authenticated successfully.",
            },
        )
        resp.set_cookie(
            key="access_token",
            value=token,
            httponly=True,
            samesite="lax",
        )
        return resp

    # Step B: Update Consent Level (0, 1, or 2)
    elif action == "update_consent":
        if not student:
            return templates.TemplateResponse(
                request=request,
                name="student_consent.html",
                context={
                    "student": None,
                    "error": "Student record not found.",
                    "role": user.role if user else None,
                },
                status_code=404,
            )

        if consent_level is None or not str(consent_level).strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid consent tier. Allowed tiers are 0 (Authenticity only), 1 (Directory only), or 2 (Full record).",
            )
        try:
            new_level = int(consent_level)
            if new_level not in (0, 1, 2):
                raise ValueError("Out of range")
        except (ValueError, TypeError):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid consent tier. Allowed tiers are 0 (Authenticity only), 1 (Directory only), or 2 (Full record).",
            )

        student.consent_level = new_level
        student.consent_timestamp = utc_now() if new_level > 0 else None
        student.updated_at = utc_now()
        # Re-sign record with Ed25519
        student.record_signature = sign_record(student, session)
        session.add(student)
        session.commit()
        session.refresh(student)

        # Log audit entry
        log_action(
            session=session,
            user=user or {"id": None, "username": f"student:{student.apaar_id}"},
            action="CONSENT_UPDATE",
            entity="STUDENT",
            entity_id=str(student.id),
            details=f"Student {student.full_name} updated DigiLocker consent preference to Tier {new_level}",
        )

        lookups = session.exec(
            select(VerificationLog)
            .where(VerificationLog.apaar_id == student.apaar_id)
            .order_by(VerificationLog.id.desc())
        ).all()

        return templates.TemplateResponse(
            request=request,
            name="student_consent.html",
            context={
                "student": student,
                "lookups": lookups,
                "role": user.role if user else None,
                "success": f"DigiLocker consent preferences updated successfully to Tier {new_level}.",
            },
        )

    return RedirectResponse(url="/student/consent", status_code=status.HTTP_303_SEE_OTHER)


# ---------------------------------------------------------------------------
# 3. Verifier Portal (/verify) with Tiered Disclosure & Rate Limiting
# ---------------------------------------------------------------------------
@router.get("/verify", response_class=HTMLResponse)
def verifier_portal_get(
    request: Request,
    apaar_id: Optional[str] = None,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    """Render empty verifier portal or process query string lookup."""
    if apaar_id:
        return process_verifier_lookup(request, apaar_id, session, user)

    return templates.TemplateResponse(
        request=request,
        name="verifier_portal.html",
        context={"role": user.role if user else None, "result_ready": False},
    )


@router.post("/verify", response_class=HTMLResponse)
def verifier_portal_post(
    request: Request,
    apaar_id: str = Form(...),
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    """Handle verifier form submission with rate limiting and tiered disclosure."""
    return process_verifier_lookup(request, apaar_id, session, user)


def process_verifier_lookup(
    request: Request,
    apaar_id: str,
    session: Session,
    user: Optional[User],
) -> Response:
    """
    Execute tiered verifier lookup:
    - Enforces 30 lookups per minute rate limit per verifier.
    - Tier -1 (Not Found): shows 'No record'
    - Tier 0: shows 'APAAR valid, student has not consented to share details'
    - Tier 1: shows institution, program, admission year and status
    - Tier 2: shows full record + authenticity badge + QR code
    - Records VerificationLog and AuditLog for each lookup.
    """
    verifier_id, verifier_key = get_verifier_identifier(request, user)

    # 1. Rate Limit Check (30 lookups per minute)
    if is_rate_limited(verifier_key):
        return templates.TemplateResponse(
            request=request,
            name="verifier_portal.html",
            context={
                "role": user.role if user else None,
                "error": "Rate limit exceeded: You have reached the maximum of 30 lookups per minute. Please wait a moment before trying again.",
                "searched_apaar": apaar_id,
                "result_ready": False,
            },
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    clean_apaar = apaar_id.strip()

    # 2. Student Lookup
    student = session.exec(select(Student).where(Student.apaar_id == clean_apaar)).first()

    institution = None
    program = None

    if not student:
        tier = -1
        result_status = "NOT_FOUND"
    else:
        effective_tier = get_effective_consent_tier(student.consent_level)
        tier = effective_tier
        result_status = "NO_CONSENT" if tier == 0 else "VALID"
        if tier >= 1:
            institution = session.get(Institution, student.institution_id)
            program = session.get(Program, student.program_id)

    # 3. Log to VerificationLog
    vlog = VerificationLog(
        verifier_id=verifier_id,
        apaar_id=clean_apaar,
        tier_shown=max(0, tier) if tier >= 0 else 0,
        result=result_status,
        timestamp=utc_now(),
    )
    session.add(vlog)
    session.commit()

    # 4. Hash-chained Audit Log entry
    log_action(
        session=session,
        user=user or {"id": verifier_id, "username": verifier_key},
        action="VERIFIER_LOOKUP",
        entity="STUDENT",
        entity_id=str(student.id) if student else clean_apaar,
        details=f"Verifier lookup for APAAR {clean_apaar}: Result={result_status}, Tier={tier}",
    )

    return templates.TemplateResponse(
        request=request,
        name="verifier_portal.html",
        context={
            "role": user.role if user else None,
            "result_ready": True,
            "searched_apaar": clean_apaar,
            "tier": tier,
            "student": student if tier >= 1 else None,
            "institution": institution if tier >= 1 else None,
            "program": program if tier >= 1 else None,
            "result_status": result_status,
        },
    )


# ---------------------------------------------------------------------------
# 4. Public Certificate Page (/verify/record/{student_id}) & QR
# ---------------------------------------------------------------------------
@router.get("/verify/record/{student_id}", response_class=HTMLResponse)
def verify_public_record(
    student_id: str,
    request: Request,
    sig: Optional[str] = None,
    session: Session = Depends(get_session),
):
    """
    Public record verification page:
    - Resolves student by institutional roll ID, integer PK, or 12-digit APAAR ID.
    - Strictly requires presented URL Ed25519 digital signature (?sig=...).
      Missing, empty, malformed, or invalid signatures fail verification.
    - Recomputes canonical record and checks Ed25519 signature. Never regenerates signatures during verification.
    - Strictly enforces student consent tiers (Tier 0, 1, 2):
        * Tier 0: Valid/authentic cryptographic status only; student identity and institutional details withheld.
        * Tier 1: Directory verification (institution, program, year, status); personal details withheld.
        * Tier 2: Full details permitted by student.
    - Unknown, missing, malformed, or out-of-range stored consent strictly fails closed to Tier 0.
    - Tampered or unverified records disclose zero student details.
    - Displays 'Authentic record' or 'TAMPERED or not found' with minimal permitted info.
    - Logs audit trail to VerificationLog.
    """
    student = session.exec(select(Student).where(Student.student_id == student_id)).first()
    if not student and student_id.isdigit():
        student = session.get(Student, int(student_id))
    if not student:
        student = session.exec(select(Student).where(Student.apaar_id == student_id)).first()

    is_authentic = False
    institution = None
    program = None
    failure_message = None

    if not student:
        failure_message = f"No student record found matching identifier '{student_id}' in the AICTE national registry."
    elif not sig or not sig.strip():
        is_authentic = False
        failure_message = "No Ed25519 cryptographic signature provided. Public verification requires a valid '?sig=' parameter."
    else:
        is_authentic = verify_signature(student, sig.strip(), session=session)
        if not is_authentic:
            failure_message = "The Ed25519 cryptographic signature failed validation. The record content may have been altered or forged."

    if is_authentic and student:
        tier = get_effective_consent_tier(student.consent_level)
        if tier >= 1:
            institution = session.get(Institution, student.institution_id)
            program = session.get(Program, student.program_id)
    else:
        tier = 0

    vlog = VerificationLog(
        verifier_id=None,
        apaar_id=student.apaar_id if student else student_id,
        tier_shown=tier if is_authentic else 0,
        result="VALID" if is_authentic else "TAMPERED",
        timestamp=utc_now(),
    )
    session.add(vlog)
    session.commit()

    return templates.TemplateResponse(
        request=request,
        name="verify_record.html",
        context={
            "is_authentic": is_authentic,
            "tier": tier,
            "student": student if (is_authentic and tier >= 1) else None,
            "institution": institution if (is_authentic and tier >= 1) else None,
            "program": program if (is_authentic and tier >= 1) else None,
            "requested_id": student_id,
            "failure_message": failure_message,
        },
    )


@router.get("/verify/record/{student_id}/qr", response_class=Response)
def get_student_qr_code(
    student_id: str,
    request: Request,
    session: Session = Depends(get_session),
):
    """Generate and return PNG QR code linking to student's verification page without regenerating signatures."""
    student = session.exec(select(Student).where(Student.student_id == student_id)).first()
    if not student and student_id.isdigit():
        student = session.get(Student, int(student_id))
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")

    sig = student.record_signature or ""
    base_url = str(request.base_url).rstrip("/")
    verification_url = f"{base_url}/verify/record/{student.student_id}?sig={sig}"
    qr_png = make_qr_png(verification_url)
    return Response(content=qr_png, media_type="image/png")


# ---------------------------------------------------------------------------
# 5. Student Dashboard & Certificate Views (SIH PS 26263 D3, D4, Req 10)
# ---------------------------------------------------------------------------
@router.get("/student/dashboard", response_class=HTMLResponse)
def student_dashboard(
    request: Request,
    user: User = Depends(require_role("STUDENT")),
    session: Session = Depends(get_session),
):
    """
    Dedicated Student Dashboard:
    - Displays verified academic profile & APAAR credentials.
    - Displays live Ed25519 tamper-evident signature badge & QR verification code.
    - Quick consent level selector (Tier 0 / Tier 1 / Tier 2) with immediate save.
    - 'Who looked me up' real-time transparency audit trail from VerificationLog.
    - One-click access to official printable certificate.
    """
    student = None
    if user.apaar_id:
        student = session.exec(select(Student).where(Student.apaar_id == user.apaar_id)).first()
    if not student and user.username:
        student = session.exec(select(Student).where(Student.student_id == user.username)).first()
    if not student:
        # Fallback to first student in db if demo user
        student = session.exec(select(Student)).first()

    institution = None
    program = None
    is_signature_valid = False
    lookups: List[VerificationLog] = []

    if student:
        institution = session.get(Institution, student.institution_id)
        program = session.get(Program, student.program_id)

        # Ensure Ed25519 signature is generated and up to date
        if not student.record_signature:
            student.record_signature = sign_record(student, session)
            session.add(student)
            session.commit()

        is_signature_valid = verify_signature(student, student.record_signature, session=session)

        # Fetch who looked me up
        lookups = session.exec(
            select(VerificationLog)
            .where(VerificationLog.apaar_id == student.apaar_id)
            .order_by(VerificationLog.id.desc())
        ).all()

    base_url = str(request.base_url).rstrip("/")
    verify_url = f"{base_url}/verify/record/{student.student_id}?sig={student.record_signature}" if student else ""
    qr_url = f"{base_url}/verify/record/{student.student_id}/qr" if student else ""

    return templates.TemplateResponse(
        request=request,
        name="student_dashboard.html",
        context={
            "user": user,
            "student": student,
            "institution": institution,
            "program": program,
            "is_signature_valid": is_signature_valid,
            "lookups": lookups,
            "verify_url": verify_url,
            "qr_url": qr_url,
            "role": user.role,
        },
    )


@router.post("/student/dashboard/consent")
def update_student_dashboard_consent(
    request: Request,
    consent_level: Optional[str] = Form(None),
    user: User = Depends(require_role("STUDENT")),
    session: Session = Depends(get_session),
):
    """Update student consent tier directly from the student dashboard."""
    if consent_level is None or not str(consent_level).strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid consent tier. Allowed tiers are 0 (Authenticity only), 1 (Directory only), or 2 (Full record).",
        )
    try:
        tier_int = int(consent_level)
        if tier_int not in (0, 1, 2):
            raise ValueError("Out of range")
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid consent tier. Allowed tiers are 0 (Authenticity only), 1 (Directory only), or 2 (Full record).",
        )

    student = None
    if user.apaar_id:
        student = session.exec(select(Student).where(Student.apaar_id == user.apaar_id)).first()
    if not student and user.username:
        student = session.exec(select(Student).where(Student.student_id == user.username)).first()

    if not student:
        raise HTTPException(status_code=404, detail="Student record not found")

    student.consent_level = tier_int
    student.consent_timestamp = utc_now() if tier_int > 0 else None
    student.updated_at = utc_now()
    student.record_signature = sign_record(student, session)
    session.add(student)

    log_action(
        session=session,
        user=user,
        action="UPDATE_CONSENT",
        entity="STUDENT",
        entity_id=str(student.id),
        details=f"Student {student.apaar_id} updated consent to Tier {tier_int} from dashboard",
    )
    session.commit()

    return RedirectResponse(
        url="/student/dashboard",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/certificate/{student_id}", response_class=HTMLResponse)
def view_certificate(
    student_id: str,
    request: Request,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    """
    Render official printable degree-style certificate with APAAR ID,
    institution details, live QR code, and Ed25519 digital signature snippet.
    """
    student = session.exec(select(Student).where(Student.student_id == student_id)).first()
    if not student and student_id.isdigit():
        student = session.get(Student, int(student_id))
    if not student:
        student = session.exec(select(Student).where(Student.apaar_id == student_id)).first()
    if not student:
        raise HTTPException(status_code=404, detail="Student record not found for certificate generation")

    institution = session.get(Institution, student.institution_id)
    program = session.get(Program, student.program_id)

    sig = student.record_signature or ""

    base_url = str(request.base_url).rstrip("/")
    verify_url = f"{base_url}/verify/record/{student.student_id}?sig={sig}"
    qr_src = f"{base_url}/verify/record/{student.student_id}/qr"

    return templates.TemplateResponse(
        request=request,
        name="certificate.html",
        context={
            "student": student,
            "institution": institution,
            "program": program,
            "signature": sig,
            "verify_url": verify_url,
            "qr_src": qr_src,
            "role": user.role if user else None,
        },
    )
