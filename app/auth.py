"""
Authentication and Role-Based Access Control (RBAC) for APAAR Verify.
Implements bcrypt password hashing, python-jose JWT, cookie management, and RBAC dependencies.
"""

from datetime import datetime, timedelta
import os
from typing import Any, List, Optional
import bcrypt
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from jose import jwt
from pathlib import Path
from sqlmodel import Session, select

from app.database import get_session
from app.models import User
from app.audit import log_action

# Router for authentication endpoints
router = APIRouter(tags=["Authentication"])

# JWT Configuration
SECRET_KEY = os.getenv("JWT_SECRET", "apaar-verify-sih-2024-secret-key-salt")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12  # 12 hours

# Role-specific post-login redirect targets
ROLE_REDIRECTS = {
    "AICTE_ADMIN": "/aicte/dashboard",
    "INSTITUTION": "/institution/dashboard",
    "VERIFIER": "/verify",
    "STUDENT": "/student/consent",
}

# Templates directory reference
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def hash_password(password: str) -> str:
    """Hash a plain text password using bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against its stored bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Generate a signed JWT token containing subject and role claims."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT access token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except Exception:
        return None


def get_current_user(
    request: Request,
    session: Session = Depends(get_session),
) -> Optional[User]:
    """
    Dependency that reads JWT from the access_token HttpOnly cookie,
    validates the token, and returns the User model from the database.
    """
    token = request.cookies.get("access_token")
    if not token:
        return None

    payload = decode_access_token(token)
    if not payload:
        return None

    username = payload.get("sub")
    if not username:
        return None

    statement = select(User).where(User.username == username)
    user = session.exec(statement).first()
    return user


def require_role(*roles: str):
    """
    Dependency factory that checks if the logged-in user possesses one of the required roles.
    Redirects unauthenticated browser requests to /login, returns 401 for API requests.
    Returns 403 if the role does not match.
    """
    def role_checker(
        request: Request,
        user: Optional[User] = Depends(get_current_user),
    ) -> User:
        if not user:
            # If requesting from browser (HTML request) or non-API route, redirect to /login
            accept = request.headers.get("accept", "")
            is_api = request.url.path.startswith("/api")
            if "text/html" in accept or not is_api:
                raise HTTPException(
                    status_code=status.HTTP_303_SEE_OTHER,
                    headers={"Location": "/login"},
                )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: requires role in {roles}, got '{user.role}'",
            )
        return user

    return role_checker


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    """Render the login form."""
    return templates.TemplateResponse(request=request, name="login.html")


@router.post("/login")
async def login(
    request: Request,
    session: Session = Depends(get_session),
):
    """
    Authenticate user, set HttpOnly SameSite=Lax cookie, and redirect based on role:
    AICTE_ADMIN -> /aicte/dashboard
    INSTITUTION -> /institution/dashboard
    VERIFIER    -> /verify
    STUDENT     -> /student/consent
    """
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        body = await request.json()
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", ""))
        is_json = True
    else:
        form = await request.form()
        username = str(form.get("username", "")).strip()
        password = str(form.get("password", ""))
        is_json = False

    statement = select(User).where(User.username == username)
    user = session.exec(statement).first()

    if not user or not verify_password(password, user.password_hash):
        if is_json:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
            )
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Invalid username or password", "username": username},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Create JWT with username and role
    token = create_access_token(data={"sub": user.username, "role": user.role})

    # Record login in hash-chained audit log
    log_action(
        session=session,
        user=user,
        action="LOGIN",
        entity="USER",
        entity_id=user.id,
        details=f"User '{user.username}' logged in with role '{user.role}'",
    )

    # Role-based redirect
    redirect_url = ROLE_REDIRECTS.get(user.role, "/")

    if is_json:
        response = JSONResponse(
            content={"status": "ok", "role": user.role, "redirect_url": redirect_url}
        )
    else:
        response = RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)

    # Set HttpOnly SameSite=Lax cookie
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=60 * 60 * 12,
    )
    return response


@router.get("/logout")
def logout(
    request: Request,
    session: Session = Depends(get_session),
):
    """Clear the access_token cookie, record audit event, and redirect to login."""
    user = get_current_user(request, session)
    if user:
        log_action(
            session=session,
            user=user,
            action="LOGOUT",
            entity="USER",
            entity_id=user.id,
            details=f"User '{user.username}' logged out",
        )

    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(key="access_token")
    return response
