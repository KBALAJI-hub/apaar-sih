"""
Public & Third-Party Verification Router for APAAR Verify (SIH PS 26263).
Implements:
1. Student login flow at /student/consent (simulated DigiLocker OTP, consent tiers 0/1/2, 'Who looked me up' list).
2. Verifier portal at /verify (tiered result display: No record, Tier 0, Tier 1, Tier 2, 30 req/min rate limit).
3. Authenticated cryptographic verification at /verify/record/{student_id} and QR code generation.
4. AICTE Ed25519 root public key discovery at /.well-known/aicte-public-key.pem.
5. Official degree-style certificate view at /certificate/{student_id} enforcing authentication, authorization, and consent tiers.
"""

from collections import defaultdict
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select

from app.audit import log_action
from app.auth import get_current_user, require_role, create_access_token
from app.authz import (
    can_view_certificate,
    can_verify_student,
    get_effective_consent_tier,
    build_certificate_view,
    build_verification_view,
    VALID_PURPOSES,
)
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

SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
}

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


def validate_csrf_origin(request: Request) -> None:
    """
    Validate incoming Origin header for state-changing requests against trusted request host.
    Rejects malformed, opaque (e.g. 'null'), or cross-origin headers with HTTP 403.
    """
    origin = request.headers.get("origin")
    if not origin:
        return

    origin_str = origin.strip()
    if not origin_str or origin_str.lower() == "null":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Cross-site request forgery detected.",
        )

    try:
        from urllib.parse import urlparse
        parsed_origin = urlparse(origin_str)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Cross-site request forgery detected.",
        )

    if parsed_origin.scheme not in ("http", "https") or not parsed_origin.netloc or not parsed_origin.hostname:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Cross-site request forgery detected.",
        )

    host = request.headers.get("host")
    if not host:
        host = request.url.netloc
    if not host:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Host header required for origin validation.",
        )

    try:
        parsed_host = urlparse("//" + host.strip())
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Invalid host header.",
        )

    if not parsed_host.hostname or parsed_origin.hostname.lower() != parsed_host.hostname.lower():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Cross-site request forgery detected.",
        )

    origin_port = parsed_origin.port or (443 if parsed_origin.scheme == "https" else 80)
    req_scheme = request.url.scheme or "http"
    host_port = parsed_host.port or (443 if req_scheme == "https" else 80)
    if origin_port != host_port:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Cross-site request forgery detected.",
        )


def safe_redirect_login(request: Request) -> RedirectResponse:
    """Generate safe redirect to /login with local 'next' URL."""
    target_path = request.url.path
    if request.url.query:
        target_path += f"?{request.url.query}"
    login_url = "/login"
    if target_path.startswith("/") and not target_path.startswith("//") and target_path != "/login":
        login_url = f"/login?next={quote(target_path, safe='/?=&-_')}"
    return RedirectResponse(url=login_url, status_code=status.HTTP_303_SEE_OTHER)


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

    if user and user.role == "STUDENT":
        if user.apaar_id:
            student = session.exec(select(Student).where(Student.apaar_id == user.apaar_id)).first()
        if not student and user.username:
            if user.username.startswith("student:"):
                auth_apaar = user.username.split(":", 1)[1]
                student = session.exec(select(Student).where(Student.apaar_id == auth_apaar)).first()
            else:
                student = session.exec(select(Student).where(Student.student_id == user.username)).first()
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
        headers=SECURITY_HEADERS,
    )


@router.post("/student/consent", response_class=HTMLResponse)
def handle_student_consent(
    request: Request,
    action: str = Form("login"),
    apaar_id: Optional[str] = Form(None),
    otp: Optional[str] = Form(None),
    consent_level: Optional[str] = Form(None),
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    """
    Process Student Consent actions:
    1. 'login': Verify APAAR ID and demo simulated DigiLocker OTP (123456).
       NOTE: This is simulated DigiLocker authentication for the SIH prototype demo,
       not real DigiLocker identity verification.
    2. 'update_consent': Require valid authenticated student session, resolve target student
       strictly from authenticated identity, validate consent tier, re-sign with Ed25519, and log audit.
    """
    clean_apaar = apaar_id.strip() if apaar_id else ""

    # Step A: Authentication via simulated DigiLocker OTP (Demo Prototype)
    # NOTE: Simulated authentication for SIH prototype demo only (not real DigiLocker identity verification).
    if action == "login":
        if not clean_apaar:
            return templates.TemplateResponse(
                request=request,
                name="student_consent.html",
                context={
                    "student": None,
                    "apaar_id": "",
                    "error": "APAAR ID is required for authentication.",
                    "role": user.role if user else None,
                },
                status_code=400,
                headers=SECURITY_HEADERS,
            )

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
                headers=SECURITY_HEADERS,
            )

        student = session.exec(select(Student).where(Student.apaar_id == clean_apaar)).first()
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
                headers=SECURITY_HEADERS,
            )

        lookups = session.exec(
            select(VerificationLog)
            .where(VerificationLog.apaar_id == student.apaar_id)
            .order_by(VerificationLog.id.desc())
        ).all()

        token = create_access_token({
            "sub": f"student:{student.apaar_id}",
            "role": "STUDENT",
            "apaar_id": student.apaar_id,
            "full_name": student.full_name,
        })
        resp = templates.TemplateResponse(
            request=request,
            name="student_consent.html",
            context={
                "student": student,
                "lookups": lookups,
                "role": "STUDENT",
                "success": "DigiLocker identity authenticated successfully (simulated demo).",
            },
            headers=SECURITY_HEADERS,
        )
        resp.set_cookie(
            key="access_token",
            value=token,
            httponly=True,
            samesite="lax",
            secure=False,
            max_age=60 * 60 * 12,
        )
        return resp

    # Step B: Update Consent Level (0, 1, or 2) - Requires authenticated student session
    elif action == "update_consent":
        # 1. Reject missing, invalid or expired authentication
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required: A valid student session is required to modify consent preferences.",
            )

        # 2. Enforce STUDENT role (reject non-students with 403)
        if user.role != "STUDENT":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: requires role 'STUDENT', got '{user.role}'",
            )

        # 3. Check CSRF via Origin header if provided
        validate_csrf_origin(request)

        # 4. Resolve target student strictly from validated authenticated identity
        student = None
        if user.apaar_id:
            student = session.exec(select(Student).where(Student.apaar_id == user.apaar_id)).first()
        if not student and user.username:
            if user.username.startswith("student:"):
                auth_apaar = user.username.split(":", 1)[1]
                student = session.exec(select(Student).where(Student.apaar_id == auth_apaar)).first()
            else:
                student = session.exec(select(Student).where(Student.student_id == user.username)).first()

        if not student:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Authenticated student record not found in AICTE registry.",
            )

        # 5. Prevent cross-student manipulation: Student A cannot change Student B's consent
        if clean_apaar and clean_apaar != student.apaar_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: You cannot modify consent preferences for another student.",
            )

        # 6. Validate consent tier
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

        # 7. Apply consent update, re-sign record, and log audit atomically
        try:
            student.consent_level = new_level
            student.consent_timestamp = utc_now() if new_level > 0 else None
            student.updated_at = utc_now()
            student.record_signature = sign_record(student, session)
            session.add(student)

            # Record immutable hash-chained audit log in same atomic transaction
            log_action(
                session=session,
                user=user,
                action="CONSENT_UPDATE",
                entity="STUDENT",
                entity_id=str(student.id),
                details=f"Student {student.full_name} updated DigiLocker consent preference to Tier {new_level}",
                commit=False,
            )
            session.commit()
            session.refresh(student)
        except Exception:
            session.rollback()
            raise

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
                "role": user.role,
                "success": f"DigiLocker consent preferences updated successfully to Tier {new_level}.",
            },
            headers=SECURITY_HEADERS,
        )

    return RedirectResponse(url="/student/consent", status_code=status.HTTP_303_SEE_OTHER)


# ---------------------------------------------------------------------------
# 3. Verifier Portal (/verify) with Tiered Disclosure, Purpose & Rate Limiting
# ---------------------------------------------------------------------------
@router.get("/verify", response_class=HTMLResponse)
def verifier_portal_get(
    request: Request,
    apaar_id: Optional[str] = None,
    purpose: Optional[str] = None,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    """
    Render verifier portal for authenticated verifiers (employers), institutions, or AICTE administrators.
    Anonymous visitors are redirected to /login?next=/verify.
    """
    if not user:
        return safe_redirect_login(request)

    if apaar_id:
        return process_verifier_lookup(request, apaar_id, purpose, session, user)

    return templates.TemplateResponse(
        request=request,
        name="verifier_portal.html",
        context={
            "user": user,
            "role": user.role,
            "result_ready": False,
            "purposes": sorted(list(VALID_PURPOSES)),
            "searched_purpose": purpose or "EMPLOYMENT_VERIFICATION",
        },
        headers=SECURITY_HEADERS,
    )


@router.post("/verify", response_class=HTMLResponse)
def verifier_portal_post(
    request: Request,
    apaar_id: str = Form(...),
    purpose: Optional[str] = Form("EMPLOYMENT_VERIFICATION"),
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    """Handle verifier form submission with purpose validation, rate limiting, and tiered disclosure."""
    if not user:
        return safe_redirect_login(request)

    return process_verifier_lookup(request, apaar_id, purpose, session, user)


def process_verifier_lookup(
    request: Request,
    apaar_id: str,
    purpose: Optional[str],
    session: Session,
    user: User,
) -> Response:
    """
    Execute tiered verifier lookup:
    - Enforces authentication and purpose specification.
    - Enforces 30 lookups per minute rate limit per verifier.
    - Tier -1 (Not Found): shows 'No record'
    - Tier 0: shows 'APAAR valid, student has not consented to share details'
    - Tier 1: shows institution, program, admission year and status
    - Tier 2: shows full record + authenticity badge (employers receive sanitized VerificationView without printable cert link)
    - Records VerificationLog and hash-chained AuditLog (both allow and rate-limit/denial).
    """
    verifier_id, verifier_key = get_verifier_identifier(request, user)

    # 1. Rate Limit Check (30 lookups per minute)
    if is_rate_limited(verifier_key):
        log_action(
            session=session,
            user=user,
            action="VERIFIER_LOOKUP_DENIED",
            entity="STUDENT_VERIFICATION",
            entity_id=None,
            details={"reason": "RATE_LIMIT_EXCEEDED", "role": user.role, "outcome": "DENIED"},
        )
        session.commit()
        return templates.TemplateResponse(
            request=request,
            name="verifier_portal.html",
            context={
                "role": user.role,
                "error": "Rate limit exceeded: You have reached the maximum of 30 lookups per minute. Please wait a moment before trying again.",
                "searched_apaar": apaar_id,
                "searched_purpose": purpose,
                "purposes": sorted(list(VALID_PURPOSES)),
                "result_ready": False,
            },
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers=SECURITY_HEADERS,
        )

    clean_apaar = apaar_id.strip()
    clean_purpose = str(purpose or "EMPLOYMENT_VERIFICATION").strip()

    # 2. Purpose Validation
    if user.role == "VERIFIER" and (not clean_purpose or clean_purpose not in VALID_PURPOSES):
        log_action(
            session=session,
            user=user,
            action="VERIFIER_LOOKUP_DENIED",
            entity="STUDENT_VERIFICATION",
            entity_id=None,
            details={"reason": "PURPOSE_REQUIRED", "role": user.role, "outcome": "DENIED"},
        )
        session.commit()
        return templates.TemplateResponse(
            request=request,
            name="verifier_portal.html",
            context={
                "role": user.role,
                "error": "A valid verification purpose from the permitted list is strictly required.",
                "searched_apaar": clean_apaar,
                "searched_purpose": clean_purpose,
                "purposes": sorted(list(VALID_PURPOSES)),
                "result_ready": False,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
            headers=SECURITY_HEADERS,
        )

    # 3. Student Lookup
    student = session.exec(select(Student).where(Student.apaar_id == clean_apaar)).first()
    allowed, reason, code, tier = can_verify_student(user, student, clean_purpose or "REGULATORY_OVERSIGHT")

    if not allowed and code != 200:
        log_action(
            session=session,
            user=user,
            action="VERIFIER_LOOKUP_DENIED",
            entity="STUDENT_VERIFICATION",
            entity_id=str(student.id) if student else None,
            details={"reason": reason, "role": user.role, "outcome": "DENIED"},
        )
        session.commit()
        raise HTTPException(status_code=code, detail="Access denied")

    institution = None
    program = None
    if student and tier >= 1:
        institution = session.get(Institution, student.institution_id)
        program = session.get(Program, student.program_id)

    result_status = "NOT_FOUND" if tier == -1 else ("NO_CONSENT" if tier == 0 else "VALID")

    # Build sanitized view model
    base_url = str(request.base_url).rstrip("/")
    verification_view = build_verification_view(
        student=student,
        institution=institution,
        program=program,
        tier=tier,
        is_authentic=True if student else False,
        result_status=result_status,
        base_url=base_url,
    )

    # 4. Log to VerificationLog
    vlog = VerificationLog(
        verifier_id=verifier_id,
        apaar_id=clean_apaar,
        tier_shown=max(0, tier) if tier >= 0 else 0,
        result=result_status,
        timestamp=utc_now(),
    )
    session.add(vlog)

    # 5. Hash-chained Audit Log entry
    log_action(
        session=session,
        user=user,
        action="VERIFIER_LOOKUP_ALLOWED" if student else "VERIFIER_LOOKUP_NOT_FOUND",
        entity="STUDENT_VERIFICATION",
        entity_id=str(student.id) if student else None,
        details={
            "role": user.role,
            "purpose": clean_purpose or "REGULATORY_OVERSIGHT",
            "tier_shown": tier,
            "result": result_status,
            "outcome": "ALLOWED" if student else "NOT_FOUND",
        },
    )
    session.commit()

    return templates.TemplateResponse(
        request=request,
        name="verifier_portal.html",
        context={
            "user": user,
            "role": user.role,
            "result_ready": True,
            "searched_apaar": clean_apaar,
            "searched_purpose": clean_purpose,
            "purposes": sorted(list(VALID_PURPOSES)),
            "tier": tier,
            "verification": verification_view,
            "student": verification_view if tier >= 1 else None,
            "institution": institution if tier >= 1 else None,
            "program": program if tier >= 1 else None,
            "result_status": result_status,
        },
        headers=SECURITY_HEADERS,
    )


# ---------------------------------------------------------------------------
# 4. Authenticated Record Verification (/verify/record/{student_id}) & QR
# ---------------------------------------------------------------------------
@router.get("/verify/record/{student_id}", response_class=HTMLResponse)
def verify_public_record(
    student_id: str,
    request: Request,
    sig: Optional[str] = None,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    """
    Authenticated record verification page (target of QR codes):
    - Strictly requires authenticated login (VERIFIER, INSTITUTION, AICTE_ADMIN, or owning STUDENT).
    - Anonymous visitors are redirected to /login?next=... (or 401).
    - Resolves student within authorized scope:
        * STUDENT: restricted strictly to own apaar_id.
        * INSTITUTION: restricted strictly to own institution_id.
        * VERIFIER / AICTE_ADMIN: permitted across institutions.
    - Validates presented Ed25519 digital signature (?sig=...).
    - Strictly enforces student consent tiers at request time:
        * Tier 0: Valid/authentic cryptographic status only; student details withheld.
        * Tier 1: Directory verification; personal details withheld.
        * Tier 2: Full authorized details.
    - Emits Cache-Control: no-store and logs audit trail.
    """
    # 1. Enforce Authentication
    if not user:
        log_action(
            session=session,
            user={"id": None, "username": "anonymous"},
            action="VERIFICATION_DENIED",
            entity="STUDENT_VERIFICATION",
            entity_id=None,
            details={"reason": "UNAUTHENTICATED", "outcome": "DENIED"},
        )
        session.commit()
        accept = request.headers.get("accept", "")
        if "text/html" in accept or not request.url.path.startswith("/api"):
            return safe_redirect_login(request)
        raise HTTPException(status_code=401, detail="Authentication required")

    # 2. Scope Student Resolution
    student = None
    if user.role == "STUDENT":
        if user.apaar_id:
            student = session.exec(select(Student).where(Student.apaar_id == user.apaar_id)).first()
            if not student or (student.student_id != student_id and str(student.id) != student_id and student.apaar_id != student_id):
                log_action(
                    session=session,
                    user=user,
                    action="VERIFICATION_DENIED",
                    entity="STUDENT_VERIFICATION",
                    entity_id=None,
                    details={"reason": "NOT_OWN_RECORD", "role": "STUDENT", "outcome": "DENIED"},
                )
                session.commit()
                raise HTTPException(status_code=404, detail="Student record not found")
    elif user.role == "INSTITUTION":
        if user.institution_id:
            student = session.exec(
                select(Student).where(Student.student_id == student_id, Student.institution_id == user.institution_id)
            ).first()
            if not student and student_id.isdigit():
                student = session.exec(
                    select(Student).where(Student.id == int(student_id), Student.institution_id == user.institution_id)
                ).first()
            if not student:
                student = session.exec(
                    select(Student).where(Student.apaar_id == student_id, Student.institution_id == user.institution_id)
                ).first()
            if not student:
                log_action(
                    session=session,
                    user=user,
                    action="VERIFICATION_DENIED",
                    entity="STUDENT_VERIFICATION",
                    entity_id=None,
                    details={"reason": "CROSS_INSTITUTION_OR_NOT_FOUND", "role": "INSTITUTION", "outcome": "DENIED"},
                )
                session.commit()
                raise HTTPException(status_code=404, detail="Student record not found")
    else:
        # AICTE_ADMIN or VERIFIER
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
        failure_message = "No Ed25519 cryptographic signature provided. Verification requires a valid '?sig=' parameter."
    else:
        is_authentic = verify_signature(student, sig.strip(), session=session)
        if not is_authentic:
            failure_message = "The Ed25519 cryptographic signature failed validation. The record content may have been altered or forged."

    # 3. Determine Effective Tier
    if is_authentic and student:
        if user.role == "VERIFIER":
            tier = get_effective_consent_tier(student.consent_level)
        else:
            tier = 2  # Owning student, institution, or AICTE admin
        if tier >= 1:
            institution = session.get(Institution, student.institution_id)
            program = session.get(Program, student.program_id)
    else:
        tier = 0

    # 4. Build Sanitized View
    base_url = str(request.base_url).rstrip("/")
    result_status = "VALID" if is_authentic else "TAMPERED"
    verification_view = build_verification_view(
        student=student,
        institution=institution,
        program=program,
        tier=tier,
        is_authentic=is_authentic,
        result_status=result_status,
        failure_message=failure_message,
        base_url=base_url,
    )

    # 5. Log Verification and Hash-Chained Audit Trail
    vlog = VerificationLog(
        verifier_id=user.id,
        apaar_id=student.apaar_id if student else student_id,
        tier_shown=tier if is_authentic else 0,
        result=result_status,
        timestamp=utc_now(),
    )
    session.add(vlog)

    log_action(
        session=session,
        user=user,
        action="VERIFICATION_ALLOWED" if is_authentic else "VERIFICATION_TAMPERED",
        entity="STUDENT_VERIFICATION",
        entity_id=str(student.id) if student else None,
        details={
            "role": user.role,
            "outcome": result_status,
            "tier_shown": tier,
        },
    )
    session.commit()

    return templates.TemplateResponse(
        request=request,
        name="verify_record.html",
        context={
            "verification": verification_view,
            "is_authentic": is_authentic,
            "tier": tier,
            "student": verification_view if (is_authentic and tier >= 1) else None,
            "institution": institution if (is_authentic and tier >= 1) else None,
            "program": program if (is_authentic and tier >= 1) else None,
            "requested_id": student_id,
            "failure_message": failure_message,
            "role": user.role,
        },
        headers=SECURITY_HEADERS,
    )


@router.get("/verify/record/{student_id}/qr", response_class=Response)
def get_student_qr_code(
    student_id: str,
    request: Request,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    """
    Generate and return PNG QR code for authorized stakeholders:
    - Strictly forbids anonymous visitors and third-party employers (VERIFIER).
    - Requires owning STUDENT, matching INSTITUTION, or AICTE_ADMIN.
    """
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    if user.role == "VERIFIER":
        raise HTTPException(status_code=403, detail="Forbidden: Verifiers cannot access raw QR generation endpoints")

    student = None
    if user.role == "STUDENT":
        if user.apaar_id:
            student = session.exec(select(Student).where(Student.apaar_id == user.apaar_id)).first()
            if not student or (student.student_id != student_id and str(student.id) != student_id and student.apaar_id != student_id):
                raise HTTPException(status_code=404, detail="Student not found")
    elif user.role == "INSTITUTION":
        if user.institution_id:
            student = session.exec(
                select(Student).where(Student.student_id == student_id, Student.institution_id == user.institution_id)
            ).first()
            if not student and student_id.isdigit():
                student = session.exec(
                    select(Student).where(Student.id == int(student_id), Student.institution_id == user.institution_id)
                ).first()
            if not student:
                student = session.exec(
                    select(Student).where(Student.apaar_id == student_id, Student.institution_id == user.institution_id)
                ).first()
            if not student:
                raise HTTPException(status_code=404, detail="Student not found")
    else:
        # AICTE_ADMIN
        student = session.exec(select(Student).where(Student.student_id == student_id)).first()
        if not student and student_id.isdigit():
            student = session.get(Student, int(student_id))
        if not student:
            student = session.exec(select(Student).where(Student.apaar_id == student_id)).first()

    if not student:
        raise HTTPException(status_code=404, detail="Student not found")

    sig = student.record_signature or ""
    base_url = str(request.base_url).rstrip("/")
    verification_url = f"{base_url}/verify/record/{student.student_id}?sig={sig}"
    qr_png = make_qr_png(verification_url)
    return Response(content=qr_png, media_type="image/png", headers=SECURITY_HEADERS)


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
        if user.username.startswith("student:"):
            auth_apaar = user.username.split(":", 1)[1]
            student = session.exec(select(Student).where(Student.apaar_id == auth_apaar)).first()
        else:
            student = session.exec(select(Student).where(Student.student_id == user.username)).first()
    if not student:
        student = session.exec(select(Student)).first()

    institution = None
    program = None
    is_signature_valid = False
    lookups: List[VerificationLog] = []

    if student:
        institution = session.get(Institution, student.institution_id)
        program = session.get(Program, student.program_id)

        if not student.record_signature:
            student.record_signature = sign_record(student, session)
            session.add(student)
            session.commit()

        is_signature_valid = verify_signature(student, student.record_signature, session=session)

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
        headers=SECURITY_HEADERS,
    )


@router.post("/student/dashboard/consent")
def update_student_dashboard_consent(
    request: Request,
    consent_level: Optional[str] = Form(None),
    user: Optional[User] = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Update student consent tier directly from the student dashboard."""
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required: A valid student session is required to modify consent preferences.",
        )
    if user.role != "STUDENT":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: requires role 'STUDENT', got '{user.role}'",
        )

    # CSRF check via Origin header if present
    validate_csrf_origin(request)

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
        if user.username.startswith("student:"):
            auth_apaar = user.username.split(":", 1)[1]
            student = session.exec(select(Student).where(Student.apaar_id == auth_apaar)).first()
        else:
            student = session.exec(select(Student).where(Student.student_id == user.username)).first()

    if not student:
        raise HTTPException(status_code=404, detail="Student record not found")

    try:
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
            commit=False,
        )
        session.commit()
    except Exception:
        session.rollback()
        raise

    return RedirectResponse(
        url="/student/dashboard",
        status_code=status.HTTP_303_SEE_OTHER,
    )


# ---------------------------------------------------------------------------
# 6. Official Printable Certificate (/certificate/{student_id})
# ---------------------------------------------------------------------------
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
    Strictly enforces:
    - Authentication required (anonymous users redirected to login or 401).
    - Authorization check (STUDENT own record, INSTITUTION own students, AICTE_ADMIN regulatory oversight).
    - VERIFIER (employer) strictly forbidden with HTTP 403.
    - Sanitized CertificateView guarantees zero ORM model leakage.
    - Uniform 404 for unauthorized student access (prevents IDOR and enumeration).
    - Cache-Control: no-store and hash-chained audit logging of allow/deny.
    """
    # 1. Enforce Authentication
    if not user:
        log_action(
            session=session,
            user={"id": None, "username": "anonymous"},
            action="CERTIFICATE_VIEW_DENIED",
            entity="STUDENT_CERTIFICATE",
            entity_id=None,
            details={"reason": "UNAUTHENTICATED", "outcome": "DENIED"},
        )
        session.commit()
        accept = request.headers.get("accept", "")
        if "text/html" in accept or not request.url.path.startswith("/api"):
            return safe_redirect_login(request)
        raise HTTPException(status_code=401, detail="Authentication required")

    # 2. Enforce Role: Employers forbidden
    if user.role == "VERIFIER":
        log_action(
            session=session,
            user=user,
            action="CERTIFICATE_VIEW_DENIED",
            entity="STUDENT_CERTIFICATE",
            entity_id=None,
            details={"reason": "FORBIDDEN_ROLE", "role": user.role, "outcome": "DENIED"},
        )
        session.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Verifiers are restricted to verification workflows only",
        )

    # 3. Resolve Student within Caller's Authorized Scope
    student = None
    if user.role == "STUDENT":
        if user.apaar_id:
            student = session.exec(select(Student).where(Student.apaar_id == user.apaar_id)).first()
            if not student or (student.student_id != student_id and str(student.id) != student_id and student.apaar_id != student_id):
                log_action(
                    session=session,
                    user=user,
                    action="CERTIFICATE_VIEW_DENIED",
                    entity="STUDENT_CERTIFICATE",
                    entity_id=None,
                    details={"reason": "NOT_OWN_RECORD", "role": "STUDENT", "outcome": "DENIED"},
                )
                session.commit()
                raise HTTPException(status_code=404, detail="Student record not found")
    elif user.role == "INSTITUTION":
        if user.institution_id:
            student = session.exec(
                select(Student).where(Student.student_id == student_id, Student.institution_id == user.institution_id)
            ).first()
            if not student and student_id.isdigit():
                student = session.exec(
                    select(Student).where(Student.id == int(student_id), Student.institution_id == user.institution_id)
                ).first()
            if not student:
                student = session.exec(
                    select(Student).where(Student.apaar_id == student_id, Student.institution_id == user.institution_id)
                ).first()
            if not student:
                log_action(
                    session=session,
                    user=user,
                    action="CERTIFICATE_VIEW_DENIED",
                    entity="STUDENT_CERTIFICATE",
                    entity_id=None,
                    details={"reason": "CROSS_INSTITUTION_OR_NOT_FOUND", "role": "INSTITUTION", "outcome": "DENIED"},
                )
                session.commit()
                raise HTTPException(status_code=404, detail="Student record not found")
    else:
        # AICTE_ADMIN
        student = session.exec(select(Student).where(Student.student_id == student_id)).first()
        if not student and student_id.isdigit():
            student = session.get(Student, int(student_id))
        if not student:
            student = session.exec(select(Student).where(Student.apaar_id == student_id)).first()
        if not student:
            log_action(
                session=session,
                user=user,
                action="CERTIFICATE_VIEW_DENIED",
                entity="STUDENT_CERTIFICATE",
                entity_id=None,
                details={"reason": "NOT_FOUND", "role": "AICTE_ADMIN", "outcome": "DENIED"},
            )
            session.commit()
            raise HTTPException(status_code=404, detail="Student record not found")

    # 4. Central Authorization Policy Check
    allowed, reason, code = can_view_certificate(user, student)
    if not allowed:
        log_action(
            session=session,
            user=user,
            action="CERTIFICATE_VIEW_DENIED",
            entity="STUDENT_CERTIFICATE",
            entity_id=str(student.id) if student else None,
            details={"reason": reason, "role": user.role, "outcome": "DENIED"},
        )
        session.commit()
        raise HTTPException(
            status_code=code,
            detail="Student record not found" if code == 404 else "Access forbidden",
        )

    institution = session.get(Institution, student.institution_id)
    program = session.get(Program, student.program_id)

    if not institution or not program:
        raise HTTPException(status_code=404, detail="Institutional configuration not found")

    sig = student.record_signature or ""
    base_url = str(request.base_url).rstrip("/")
    verify_url = f"{base_url}/verify/record/{student.student_id}?sig={sig}"
    qr_src = f"{base_url}/verify/record/{student.student_id}/qr"

    # 5. Build Sanitized CertificateView
    certificate_view = build_certificate_view(
        student=student,
        institution=institution,
        program=program,
        verify_url=verify_url,
        qr_src=qr_src,
        signature=sig,
    )

    # 6. Log Allowed Access
    log_action(
        session=session,
        user=user,
        action="CERTIFICATE_VIEW_ALLOWED",
        entity="STUDENT_CERTIFICATE",
        entity_id=str(student.id),
        details={
            "role": user.role,
            "purpose": "REGULATORY_OVERSIGHT" if user.role == "AICTE_ADMIN" else "CERTIFICATE_VIEW",
            "outcome": "ALLOWED",
        },
    )
    session.commit()

    return templates.TemplateResponse(
        request=request,
        name="certificate.html",
        context={
            "certificate": certificate_view,
            "student": certificate_view,
            "institution": institution,
            "program": program,
            "signature": sig,
            "verify_url": verify_url,
            "qr_src": qr_src,
            "role": user.role,
        },
        headers=SECURITY_HEADERS,
    )
