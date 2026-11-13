import hashlib
import hmac
import logging
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from ..api.dependencies import SessionLocal
from ..core.config import settings
from ..models.sql_models import AuthSession, AuthUser

logger = logging.getLogger(__name__)

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 64
_EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_PUBLIC_PATHS = {
    "/",
    "/health",
    "/auth/login",
    "/auth/session",
    "/auth/logout",
    "/auth/forgot-password",
    "/auth/reset-password",
    "/openapi.json",
    "/docs",
    "/redoc",
}
_PUBLIC_DASHBOARD_READ_PATHS = {
    "/wazuh/alerts",
    "/wazuh/agents",
    "/wazuh/status",
    "/api/incidents",
    "/ai/anomalies",
    "/api/simulations/lab-status",
}


def normalize_email(value: str) -> str:
    return value.strip().casefold()


def valid_email(value: str) -> bool:
    return bool(_EMAIL_PATTERN.fullmatch(normalize_email(value)))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    password_hash = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
        maxmem=64 * 1024 * 1024,
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${password_hash.hex()}"


def verify_password(password: str, encoded_hash: str) -> bool:
    try:
        algorithm, n_value, r_value, p_value, salt_hex, hash_hex = encoded_hash.split("$", 5)
        if algorithm != "scrypt":
            return False
        expected = bytes.fromhex(hash_hex)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n_value),
            r=int(r_value),
            p=int(p_value),
            dklen=len(expected),
            maxmem=64 * 1024 * 1024,
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, MemoryError):
        return False


def hash_opaque_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def ensure_initial_admin(db: Session) -> Optional[AuthUser]:
    email = normalize_email(settings.admin_email)
    if not valid_email(email) or not _valid_scrypt_hash(settings.admin_password_hash):
        logger.warning("Initial admin bootstrap skipped: valid ADMIN_EMAIL and ADMIN_PASSWORD_HASH are required.")
        return None

    user = db.query(AuthUser).filter(AuthUser.email == email).first()
    if user:
        return user

    user = AuthUser(email=email, password_hash=settings.admin_password_hash)
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info("Initial admin account provisioned from environment configuration.")
    return user


def _valid_scrypt_hash(encoded_hash: str) -> bool:
    try:
        algorithm, n_value, r_value, p_value, salt_hex, hash_hex = encoded_hash.split("$", 5)
        return (
            algorithm == "scrypt"
            and int(n_value) == _SCRYPT_N
            and int(r_value) == _SCRYPT_R
            and int(p_value) == _SCRYPT_P
            and len(bytes.fromhex(salt_hex)) == 16
            and len(bytes.fromhex(hash_hex)) == _SCRYPT_DKLEN
        )
    except (ValueError, TypeError):
        return False


def create_session(db: Session, user: AuthUser) -> tuple[str, AuthSession]:
    raw_token = secrets.token_urlsafe(32)
    session = AuthSession(
        user_id=user.id,
        token_hash=hash_opaque_token(raw_token),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=settings.auth_session_ttl_minutes),
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return raw_token, session


def get_session_user(db: Session, raw_token: Optional[str]) -> Optional[AuthUser]:
    if not raw_token:
        return None
    session = (
        db.query(AuthSession)
        .filter(
            AuthSession.token_hash == hash_opaque_token(raw_token),
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > datetime.now(timezone.utc),
        )
        .first()
    )
    if not session:
        return None
    return db.query(AuthUser).filter(AuthUser.id == session.user_id).first()


def revoke_session(db: Session, raw_token: Optional[str]) -> None:
    if not raw_token:
        return
    session = (
        db.query(AuthSession)
        .filter(AuthSession.token_hash == hash_opaque_token(raw_token), AuthSession.revoked_at.is_(None))
        .first()
    )
    if session:
        session.revoked_at = datetime.now(timezone.utc)
        db.commit()


async def require_application_session(request: Request, call_next):
    if request.method == "OPTIONS" or request.url.path in _PUBLIC_PATHS:
        return await call_next(request)
    if request.method == "GET" and request.url.path in _PUBLIC_DASHBOARD_READ_PATHS:
        return await call_next(request)

    with SessionLocal() as db:
        user = get_session_user(db, request.cookies.get("soc_session"))
        if not user:
            return JSONResponse(status_code=401, content={"detail": "Not authenticated"})
        request.state.auth_user_email = user.email
    return await call_next(request)