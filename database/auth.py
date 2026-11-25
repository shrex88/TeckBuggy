"""SQLite-backed authentication helpers for SENTINEL AI."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import secrets
from typing import Any, Optional

from sqlalchemy import func, or_, select

from config import DATABASE_URL
from database.database import get_db_url, get_session, init_db
from database.models import AuditLog, Finding, Report, Scan, UserAccount


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format_dt(dt: Optional[datetime]) -> str:
    return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "—"


def _user_profile_dict(account: UserAccount) -> dict[str, Any]:
    return {
        "id": account.id,
        "username": account.username,
        "email": account.email,
        "full_name": account.full_name,
        "role": account.role,
        "created_at": _format_dt(account.created_at),
        "last_login_at": _format_dt(account.last_login_at),
        "login_count": int(account.login_count or 0),
    }


class AuthError(ValueError):
    """Raised when registration or authentication fails validation."""


def hash_password(password: str, salt: Optional[str] = None) -> str:
    """Hash a password with a per-user random salt using PBKDF2-HMAC-SHA256."""
    actual_salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        actual_salt.encode("utf-8"),
        120_000,
    ).hex()
    return f"{actual_salt}${digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a stored salted PBKDF2 hash."""
    if "$" not in stored_hash:
        return False
    salt, expected_hex = stored_hash.split("$", 1)
    candidate_hex = hash_password(password, salt=salt).split("$", 1)[1]
    return hmac.compare_digest(candidate_hex, expected_hex)


def ensure_default_admin(database_url: Optional[str] = None) -> None:
    """Seed a default analyst account if no user accounts exist yet."""
    resolved_url = get_db_url(database_url)
    init_db(resolved_url)
    with get_session(resolved_url) as session:
        count = session.scalar(select(func.count(UserAccount.id))) or 0
        if count == 0:
            session.add(
                UserAccount(
                    username="admin",
                    email="admin@sentinel.ai",
                    full_name="Lead Security Analyst",
                    role="Security Admin",
                    password_hash=hash_password("Sentinel@2026"),
                )
            )


def register_user(
    username: str,
    email: str,
    password: str,
    full_name: str = "",
    database_url: Optional[str] = None,
) -> dict[str, Any]:
    """Register a new SENTINEL AI user account in SQLite."""
    clean_user = username.strip().lower()
    clean_email = email.strip().lower()
    clean_name = full_name.strip() or clean_user

    if len(clean_user) < 3:
        raise AuthError("Username must be at least 3 characters.")
    if "@" not in clean_email or "." not in clean_email:
        raise AuthError("Please enter a valid email address.")
    if len(password) < 6:
        raise AuthError("Password must be at least 6 characters.")

    resolved_url = get_db_url(database_url)
    init_db(resolved_url)
    with get_session(resolved_url) as session:
        existing = session.scalar(
            select(UserAccount).where(
                or_(UserAccount.username == clean_user, UserAccount.email == clean_email)
            )
        )
        if existing is not None:
            raise AuthError("An account with that username or email already exists.")

        now = _utc_now()
        account = UserAccount(
            username=clean_user,
            email=clean_email,
            full_name=clean_name,
            role="Security Analyst",
            password_hash=hash_password(password),
            last_login_at=now,
            login_count=1,
        )
        session.add(account)
        session.flush()
        session.add(
            AuditLog(
                user_id=account.id,
                event_type="USER_REGISTERED",
                actor=account.username,
                status="success",
                details=f"Account created for {account.email}",
            )
        )
        return _user_profile_dict(account)


def authenticate_user(
    identifier: str,
    password: str,
    database_url: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """Authenticate a user by username or email, update login telemetry, and return profile."""
    clean_id = identifier.strip().lower()
    if not clean_id or not password:
        return None

    resolved_url = get_db_url(database_url)
    init_db(resolved_url)
    with get_session(resolved_url) as session:
        account = session.scalar(
            select(UserAccount).where(
                or_(UserAccount.username == clean_id, UserAccount.email == clean_id)
            )
        )
        if account is None or not verify_password(password, account.password_hash):
            return None
        account.last_login_at = _utc_now()
        account.login_count = int(account.login_count or 0) + 1
        session.add(
            AuditLog(
                user_id=account.id,
                event_type="USER_LOGIN",
                actor=account.username,
                status="success",
                details=f"Authenticated workspace session (login #{account.login_count})",
            )
        )
        session.flush()
        return _user_profile_dict(account)


def get_user_account_summary(
    user_id: int,
    database_url: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """Return real-time account metadata and scanned test statistics for a user."""
    resolved_url = get_db_url(database_url)
    init_db(resolved_url)
    with get_session(resolved_url) as session:
        account = session.get(UserAccount, user_id)
        if account is None:
            return None

        total_scans = session.scalar(
            select(func.count(Scan.id)).where(Scan.user_id == user_id)
        ) or 0
        total_findings = session.scalar(
            select(func.count(Finding.id)).join(Scan).where(Scan.user_id == user_id)
        ) or 0
        total_reports = session.scalar(
            select(func.count(Report.id)).join(Scan).where(Scan.user_id == user_id)
        ) or 0
        recent_scans = list(
            session.scalars(
                select(Scan)
                .where(Scan.user_id == user_id)
                .order_by(Scan.scan_date.desc(), Scan.id.desc())
                .limit(5)
            ).all()
        )
        summary = _user_profile_dict(account)
        summary.update(
            {
                "total_scans": int(total_scans),
                "total_findings": int(total_findings),
                "total_reports": int(total_reports),
                "recent_targets": [s.target_url for s in recent_scans],
            }
        )
        return summary
