"""
Cryptographic Security & Verification Engine for APAAR Verify (SIH PS 26263).
Implements Ed25519 digital signatures, canonical record serialization,
root key management, and QR code generation.
"""

import base64
import io
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import qrcode
from sqlmodel import Session
from app.database import get_db_session

# Default private key file path
DEFAULT_KEY_FILENAME = "aicte_ed25519_private.pem"


def get_private_key_path() -> Path:
    """Resolve Ed25519 private key path from environment or .env file."""
    # 1. Environment variable
    key_env = os.getenv("ED25519_PRIVATE_KEY_PATH")
    if key_env:
        return Path(key_env).resolve()

    # 2. Check .env file if present
    env_file = Path(".env")
    if env_file.exists():
        try:
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("ED25519_PRIVATE_KEY_PATH="):
                        val = line.split("=", 1)[1].strip().strip('"').strip("'")
                        if val:
                            return Path(val).resolve()
        except Exception:
            pass

    return Path(DEFAULT_KEY_FILENAME).resolve()


def load_or_generate_private_key() -> ed25519.Ed25519PrivateKey:
    """
    Generate or load an Ed25519 private key from the designated path.
    Creates and persists a new key and updates .env if missing on first run.
    """
    key_path = get_private_key_path()

    if key_path.exists():
        with open(key_path, "rb") as f:
            key_data = f.read()
        return serialization.load_pem_private_key(key_data, password=None)

    # First run: Generate a new Ed25519 private key
    key_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = ed25519.Ed25519PrivateKey.generate()
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(key_path, "wb") as f:
        f.write(pem_bytes)

    # Ensure .env persists the private key path
    env_file = Path(".env")
    if not env_file.exists():
        with open(env_file, "w", encoding="utf-8") as f:
            f.write(f"ED25519_PRIVATE_KEY_PATH={key_path.name}\n")
    else:
        with open(env_file, "r", encoding="utf-8") as f:
            content = f.read()
        if "ED25519_PRIVATE_KEY_PATH" not in content:
            with open(env_file, "a", encoding="utf-8") as f:
                f.write(f"\nED25519_PRIVATE_KEY_PATH={key_path.name}\n")

    return private_key


# Cache in-memory root keys
_PRIVATE_KEY: Optional[ed25519.Ed25519PrivateKey] = None


def get_private_key() -> ed25519.Ed25519PrivateKey:
    """Retrieve cached Ed25519 private key."""
    global _PRIVATE_KEY
    if _PRIVATE_KEY is None:
        _PRIVATE_KEY = load_or_generate_private_key()
    return _PRIVATE_KEY


def get_public_key() -> ed25519.Ed25519PublicKey:
    """Retrieve corresponding Ed25519 public key."""
    return get_private_key().public_key()


def get_public_key_pem() -> bytes:
    """Export root AICTE Ed25519 public key in standard PEM SubjectPublicKeyInfo format."""
    return get_public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def build_canonical_record(student: Any, session: Optional[Session] = None) -> str:
    """
    Construct canonical JSON (sorted keys, no spaces) of:
    apaar_id, student_id, institution aicte_id, program name, admission_year, status, full_name, and dob.
    """
    from app.database import engine
    from app.models import Institution, Program

    if isinstance(student, dict):
        apaar_id = str(student.get("apaar_id") or "").strip()
        student_id = str(student.get("student_id") or "").strip()
        full_name = str(student.get("full_name") or "").strip()
        dob = str(student.get("dob") or "").strip()
        admission_year = int(student.get("admission_year") or 2024)
        status = str(student.get("status") or "ACTIVE").strip()
        aicte_id = str(student.get("aicte_id") or "").strip()
        program_name = str(student.get("program_name") or "").strip()
        institution_id = student.get("institution_id")
        program_id = student.get("program_id")
    else:
        apaar_id = str(getattr(student, "apaar_id", "") or "").strip()
        student_id = str(getattr(student, "student_id", "") or "").strip()
        full_name = str(getattr(student, "full_name", "") or "").strip()
        dob = str(getattr(student, "dob", "") or "").strip()
        admission_year = int(getattr(student, "admission_year", 2024) or 2024)
        status = str(getattr(student, "status", "ACTIVE") or "ACTIVE").strip()
        aicte_id = str(getattr(student, "aicte_id", "") or "").strip()
        program_name = str(getattr(student, "program_name", "") or "").strip()
        institution_id = getattr(student, "institution_id", None)
        program_id = getattr(student, "program_id", None)

    # Resolve institution aicte_id if not directly set
    if not aicte_id and institution_id:
        if session:
            inst = session.get(Institution, institution_id)
            aicte_id = inst.aicte_id if inst else ""
        else:
            with get_db_session() as s:
                inst = s.get(Institution, institution_id)
                aicte_id = inst.aicte_id if inst else ""

    # Resolve program title if not directly set
    if not program_name and program_id:
        if session:
            prog = session.get(Program, program_id)
            program_name = prog.name if prog else ""
        else:
            with get_db_session() as s:
                prog = s.get(Program, program_id)
                program_name = prog.name if prog else ""

    payload = {
        "admission_year": admission_year,
        "aicte_id": aicte_id,
        "apaar_id": apaar_id,
        "dob": dob,
        "full_name": full_name,
        "program_name": program_name,
        "status": status,
        "student_id": student_id,
    }

    # Deterministic canonical serialization (alphabetical keys, no whitespace)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def sign_record(student: Any, session: Optional[Session] = None) -> str:
    """
    Generate an Ed25519 digital signature over the student's canonical record.
    Returns base64url encoded signature and assigns it to student.record_signature.
    """
    canonical_json = build_canonical_record(student, session=session)
    priv_key = get_private_key()
    raw_sig = priv_key.sign(canonical_json.encode("utf-8"))
    sig_b64url = base64.urlsafe_b64encode(raw_sig).decode("utf-8").rstrip("=")

    if hasattr(student, "record_signature"):
        student.record_signature = sig_b64url

    return sig_b64url


def verify_signature(
    student: Any,
    sig: Optional[str] = None,
    session: Optional[Session] = None,
) -> bool:
    """
    Recompute canonical representation of student and verify against the given signature
    (or student.record_signature) using the AICTE Ed25519 public key.
    """
    signature_str = sig or getattr(student, "record_signature", None)
    if not signature_str or not isinstance(signature_str, str):
        return False

    canonical_json = build_canonical_record(student, session=session)
    pub_key = get_public_key()

    # Re-apply padding if missing
    padded_sig = signature_str + "=" * (-len(signature_str) % 4)
    try:
        raw_sig = base64.urlsafe_b64decode(padded_sig.encode("utf-8"))
        pub_key.verify(raw_sig, canonical_json.encode("utf-8"))
        return True
    except Exception:
        return False


def make_qr_png(url: str) -> bytes:
    """
    Generate a high-contrast black-and-white QR code PNG image for a verification URL.
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
