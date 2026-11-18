"""
User Authentication & Session Management Routes
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

Provides secure session authentication, HttpOnly cookies, CSRF tokens,
profile updates, and user management.
"""

import uuid
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, EmailStr
from fastapi import APIRouter, HTTPException, Depends, Request, Response, status

from backend.app.config import settings
from backend.app.core.user_auth import (
    auth_service,
    get_current_user,
    get_current_user_optional,
    require_role,
    hash_password,
    verify_password,
    _hash_token,
    SESSION_COOKIE_NAME,
    CSRF_COOKIE_NAME,
    REMEMBER_ME_DAYS,
    DEFAULT_SESSION_HOURS
)
from backend.app.database.repository import repo

router = APIRouter(prefix="/api/auth", tags=["User Authentication & Sessions"])


# ==============================================================================
# PYDANTIC SCHEMAS
# ==============================================================================

class InitialSetupRequest(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str
    remember_me: Optional[bool] = False
    password: str
    remember_me: Optional[bool] = False


class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str
    role: Optional[str] = "investigator"


class UpdateProfileRequest(BaseModel):
    email: Optional[str] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None


# ==============================================================================
# SETUP WIZARD & AUTHENTICATION ENDPOINTS
# ==============================================================================

@router.get("/setup-status")
def get_setup_status():
    """
    Returns whether initial administrator setup is required.
    Reports setup_required=True only on fresh installations with 0 provisioned users.
    """
    return {
        "setup_required": auth_service.is_setup_required(),
        "deployment_mode": getattr(settings, "DEPLOYMENT_MODE", "workstation")
    }


@router.post("/initial-setup")
def initial_setup(payload: InitialSetupRequest, request: Request, response: Response):
    """
    Provisions the initial primary administrator account during first-time setup.
    Allowed ONLY when zero users exist in the platform.
    Never accepts or uses a hardcoded or universal default password.
    """
    if repo.count_users() > 0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Initial administrator setup has already been completed. Please sign in."
        )

    username = payload.username.strip().lower()
    email = payload.email.strip().lower()
    password = payload.password

    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters long.")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long.")

    user_id = str(uuid.uuid4())
    h_b64, salt = hash_password(password)

    user = repo.create_user(
        user_id=user_id,
        username=username,
        email=email,
        password_hash=h_b64,
        salt=salt,
        role="admin"
    )

    # Migrate any legacy credentials to the newly created admin account
    repo.migrate_legacy_credentials_to_user(user_id)

    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Unknown")

    raw_token, session_record, csrf_token = auth_service.create_session(
        user_id=user["id"],
        user_agent=user_agent,
        ip_address=client_ip,
        remember_me=False
    )

    max_age_seconds = DEFAULT_SESSION_HOURS * 3600
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=max_age_seconds,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        path="/"
    )
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=max_age_seconds,
        httponly=False,
        samesite="lax",
        secure=request.url.scheme == "https",
        path="/"
    )

    return {
        "status": "success",
        "message": f"Administrator '{user['username']}' configured successfully.",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"]
        },
        "csrf_token": csrf_token,
        "token": raw_token
    }


@router.post("/login")
def login(payload: LoginRequest, request: Request, response: Response):
    """
    Authenticates user credentials using Argon2id, generates an ephemeral session,
    and sets secure HttpOnly session and CSRF cookies.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Unknown")

    user = auth_service.authenticate_user(
        username_or_email=payload.username,
        password=payload.password,
        user_agent=user_agent,
        ip_address=client_ip
    )

    raw_token, session_record, csrf_token = auth_service.create_session(
        user_id=user["id"],
        user_agent=user_agent,
        ip_address=client_ip,
        remember_me=bool(payload.remember_me)
    )

    # Cookie lifetime
    max_age_seconds = (REMEMBER_ME_DAYS * 86400) if payload.remember_me else (DEFAULT_SESSION_HOURS * 3600)

    # Set HttpOnly Session Cookie
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=max_age_seconds,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        path="/"
    )

    # Set CSRF Token Cookie (Readable by JS for X-CSRF-Token headers)
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=max_age_seconds,
        httponly=False,
        samesite="lax",
        secure=request.url.scheme == "https",
        path="/"
    )

    return {
        "status": "success",
        "message": f"Welcome back, {user['username']}.",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"]
        },
        "csrf_token": csrf_token,
        "token": raw_token
    }


@router.post("/logout")
def logout(request: Request, response: Response):
    """
    Terminates the active session and clears authentication cookies.
    """
    token = request.cookies.get(SESSION_COOKIE_NAME)
    auth_header = request.headers.get("authorization")
    if not token and auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()

    if token:
        auth_service.revoke_session(token)

    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")
    response.delete_cookie(key=CSRF_COOKIE_NAME, path="/")

    return {
        "status": "success",
        "message": "Signed out successfully."
    }


@router.get("/me")
async def get_current_user_profile(user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """
    Returns the currently authenticated user identity and capabilities.
    """
    if not user:
        return {
            "authenticated": False,
            "user": None
        }

    return {
        "authenticated": True,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "is_active": user["is_active"],
            "auth_method": user.get("auth_method", "session")
        }
    }


@router.put("/profile")
def update_profile(
    payload: UpdateProfileRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Updates the authenticated user's email address or password.
    When a password is changed, all other active sessions for this user are invalidated.
    """
    user_id = current_user["id"]
    db_user = repo.get_user_by_id(user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found.")

    if payload.email and payload.email != db_user["email"]:
        # Check uniqueness
        existing = repo.get_user_by_email(payload.email)
        if existing and existing["id"] != user_id:
            raise HTTPException(status_code=400, detail="Email is already in use.")
        from backend.app.database.db import get_db_connection
        conn = get_db_connection()
        conn.execute("UPDATE users SET email = ? WHERE id = ?", (payload.email.strip().lower(), user_id))
        conn.commit()
        conn.close()

    if payload.new_password:
        if not payload.current_password:
            raise HTTPException(status_code=400, detail="Current password is required to set a new password.")
        if not verify_password(payload.current_password, db_user["password_hash"], db_user["salt"]):
            raise HTTPException(status_code=401, detail="Current password incorrect.")
        if len(payload.new_password) < 8:
            raise HTTPException(status_code=400, detail="New password must be at least 8 characters long.")

        h_b64, salt = hash_password(payload.new_password)
        repo.update_user_password(user_id, h_b64, salt)

        # Invalidate all other active sessions for this user except current session
        token = request.cookies.get(SESSION_COOKIE_NAME)
        auth_header = request.headers.get("authorization")
        if not token and auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        current_sess_id = _hash_token(token) if token else None
        repo.delete_user_sessions_by_user_id(user_id, except_session_id=current_sess_id)

    return {
        "status": "success",
        "message": "User profile updated successfully."
    }


# ==============================================================================
# USER MANAGEMENT (ADMIN ONLY)
# ==============================================================================

@router.get("/users")
def list_system_users(admin: Dict[str, Any] = Depends(require_role(["admin"]))):
    """Lists all registered workbench users (Administrator access required)."""
    return repo.list_users()


@router.post("/users")
def create_system_user(
    payload: CreateUserRequest,
    admin: Dict[str, Any] = Depends(require_role(["admin"]))
):
    """Provisions a new investigator or administrator account."""
    import uuid

    if repo.get_user_by_username(payload.username):
        raise HTTPException(status_code=400, detail=f"Username '{payload.username}' is already taken.")
    if repo.get_user_by_email(payload.email):
        raise HTTPException(status_code=400, detail=f"Email '{payload.email}' is already registered.")
    if len(payload.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long.")

    valid_roles = ("admin", "investigator", "viewer")
    role = payload.role if payload.role in valid_roles else "investigator"

    user_id = str(uuid.uuid4())
    h_b64, salt = hash_password(payload.password)
    user = repo.create_user(
        user_id=user_id,
        username=payload.username,
        email=payload.email,
        password_hash=h_b64,
        salt=salt,
        role=role
    )

    return {
        "status": "success",
        "message": f"User '{user['username']}' provisioned successfully.",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"]
        }
    }


@router.delete("/users/{target_user_id}")
def delete_system_user(
    target_user_id: str,
    admin: Dict[str, Any] = Depends(require_role(["admin"]))
):
    """Deletes an investigator account (Cannot delete self)."""
    if target_user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own active administrator account.")

    deleted = repo.delete_user(target_user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="User not found.")

    return {
        "status": "success",
        "message": "User account permanently removed."
    }

