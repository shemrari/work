import asyncio
import html
import logging
import secrets
import smtplib
import ssl
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...api import dependencies
from ...core.config import settings
from ...models.sql_models import AuthSession, AuthUser, PasswordResetToken
from ...services.auth_security import (
    create_session,
    get_session_user,
    hash_opaque_token,
    hash_password,
    normalize_email,
    revoke_session,
    valid_email,
    verify_password,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["authentication"])
SESSION_COOKIE_NAME = "soc_session"
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=128)


class ForgotPasswordRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=20, max_length=256)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)


def _smtp_is_configured() -> bool:
    sender = settings.smtp_from or settings.smtp_username
    return bool(settings.smtp_host and sender and settings.smtp_username and settings.smtp_password)


def _send_password_reset_email(recipient: str, reset_url: str) -> None:
    sender = settings.smtp_from or settings.smtp_username
    if not _smtp_is_configured():
        raise RuntimeError("SMTP is not configured")

    expiration = settings.password_reset_ttl_minutes
    escaped_url = html.escape(reset_url, quote=True)
    message = EmailMessage()
    message["Subject"] = "Industrial Cybersecurity SOC — Password Reset"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        "Hello,\n\n"
        "A password reset was requested for your Industrial Cybersecurity SOC account.\n"
        f"Use this single-use link within {expiration} minutes:\n{reset_url}\n\n"
        "If you did not request this reset, you can ignore this email. Your password will not change.\n"
    )
    message.add_alternative(
        "<html><body style='margin:0;background:#f4f7fa;font-family:Arial,sans-serif;color:#26394e'>"
        "<main style='max-width:560px;margin:32px auto;padding:28px;background:#fff;border:1px solid #e1e8ef;border-radius:8px'>"
        "<p style='color:#147eaa;font-size:12px;font-weight:bold'>INDUSTRIAL CYBERSECURITY SOC</p>"
        "<h1 style='font-size:22px'>Password reset</h1>"
        "<p>Hello,</p><p>A password reset was requested for your account.</p>"
        f"<p><a href=\"{escaped_url}\" style='display:inline-block;padding:12px 18px;background:#147eaa;color:#fff;text-decoration:none;border-radius:5px'>Reset password</a></p>"
        f"<p>This single-use link expires in {expiration} minutes.</p>"
        "<p style='color:#68798d;font-size:13px'>If you did not request this reset, ignore this message. Your password will not change.</p>"
        "</main></body></html>",
        subtype="html",
    )

    if settings.smtp_use_ssl:
        with smtplib.SMTP_SSL(
            settings.smtp_host,
            settings.smtp_port,
            timeout=settings.smtp_timeout_seconds,
            context=ssl.create_default_context(),
        ) as smtp:
            smtp.login(settings.smtp_username, settings.smtp_password)
            smtp.send_message(message)
        return

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=settings.smtp_timeout_seconds) as smtp:
        smtp.ehlo()
        if settings.smtp_starttls:
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
        smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(message)


@router.post("/login")
def login(
    body: LoginRequest,
    response: Response,
    db: Session = Depends(dependencies.get_db),
):
    email = normalize_email(body.username)
    user = db.query(AuthUser).filter(AuthUser.email == email).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Nom d’utilisateur ou mot de passe incorrect.")

    raw_token, _ = create_session(db, user)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=settings.auth_session_ttl_minutes * 60,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite="lax",
        path="/",
    )
    return {"authenticated": True, "email": user.email}


@router.get("/session")
def read_session(
    request: Request,
    db: Session = Depends(dependencies.get_db),
):
    user = get_session_user(db, request.cookies.get(SESSION_COOKIE_NAME))
    if not user:
        return {"authenticated": False, "email": None}
    return {"authenticated": True, "email": user.email}


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(dependencies.get_db),
):
    revoke_session(db, request.cookies.get(SESSION_COOKIE_NAME))
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite="lax",
    )
    return {"authenticated": False}


@router.post("/forgot-password")
async def forgot_password(
    body: ForgotPasswordRequest,
    db: Session = Depends(dependencies.get_db),
):
    email = normalize_email(body.email)
    if not valid_email(email):
        raise HTTPException(status_code=422, detail="Adresse email invalide.")

    user = db.query(AuthUser).filter(AuthUser.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Veuillez contacter l’administrateur.")
    if not _smtp_is_configured():
        logger.error("Password recovery requested but SMTP configuration is incomplete.")
        raise HTTPException(status_code=503, detail="Le service de réinitialisation est indisponible. Contactez l’administrateur.")

    raw_token = secrets.token_urlsafe(32)
    reset_row = PasswordResetToken(
        user_id=user.id,
        token_hash=hash_opaque_token(raw_token),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=settings.password_reset_ttl_minutes),
    )
    now = datetime.now(timezone.utc)
    old_tokens = (
        db.query(PasswordResetToken)
        .filter(PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None))
        .all()
    )
    for old_token in old_tokens:
        old_token.used_at = now
    db.add(reset_row)
    db.commit()

    reset_url = f"{settings.frontend_base_url}/reset-password?{urlencode({'token': raw_token})}"
    try:
        await asyncio.to_thread(_send_password_reset_email, user.email, reset_url)
    except Exception as error:
        reset_row.used_at = datetime.now(timezone.utc)
        db.commit()
        logger.error("Password reset email delivery failed (%s).", type(error).__name__)
        raise HTTPException(status_code=503, detail="L’envoi du lien a échoué. Contactez l’administrateur.") from None

    return {"message": "Un lien de réinitialisation a été envoyé à l’adresse configurée."}


@router.post("/reset-password")
def reset_password(
    body: ResetPasswordRequest,
    response: Response,
    db: Session = Depends(dependencies.get_db),
):
    if len(body.new_password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(status_code=422, detail=f"Le mot de passe doit contenir au moins {MIN_PASSWORD_LENGTH} caractères.")

    now = datetime.now(timezone.utc)
    reset_row = (
        db.query(PasswordResetToken)
        .filter(
            PasswordResetToken.token_hash == hash_opaque_token(body.token),
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
        .first()
    )
    if not reset_row:
        raise HTTPException(status_code=400, detail="Ce lien est invalide ou a expiré. Demandez un nouveau lien.")

    user = db.query(AuthUser).filter(AuthUser.id == reset_row.user_id).first()
    if not user:
        reset_row.used_at = now
        db.commit()
        raise HTTPException(status_code=400, detail="Ce lien est invalide ou a expiré. Demandez un nouveau lien.")

    user.password_hash = hash_password(body.new_password)
    reset_row.used_at = now
    other_tokens = (
        db.query(PasswordResetToken)
        .filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.id != reset_row.id,
            PasswordResetToken.used_at.is_(None),
        )
        .all()
    )
    for other_token in other_tokens:
        other_token.used_at = now
    sessions = (
        db.query(AuthSession)
        .filter(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None))
        .all()
    )
    for session in sessions:
        session.revoked_at = now
    db.commit()

    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite="lax",
    )
    return {"message": "Votre mot de passe a été modifié avec succès."}