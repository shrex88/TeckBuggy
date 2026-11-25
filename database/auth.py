"""SQLite-backed authentication helpers for SENTINEL AI."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any, Optional

from sqlalchemy import func, or_, select

from config import DATABASE_URL
from database.database import get_session, init_db
from database.models import UserAccount


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


def ensure_default_admin(database_url: str = DATABASE_URL) -> None:
    """Seed a default analyst account if no user accounts exist yet."""
    init_db(database_url)
    with get_session(database_url) as session:
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
    database_url: str = DATABASE_URL,
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

    init_db(database_url)
    with get_session(database_url) as session:
        existing = session.scalar(
            select(UserAccount).where(
                or_(UserAccount.username == clean_user, UserAccount.email == clean_email)
            )
        )
        if existing is not None:
            raise AuthError("An account with that username or email already exists.")

        account = UserAccount(
            username=clean_user,
            email=clean_email,
            full_name=clean_name,
            role="Security Analyst",
            password_hash=hash_password(password),
        )
        session.add(account)
        session.flush()
        return {
            "id": account.id,
            "username": account.username,
            "email": account.email,
            "full_name": account.full_name,
            "role": account.role,
        }


def authenticate_user(
    identifier: str,
    password: str,
    database_url: str = DATABASE_URL,
) -> Optional[dict[str, Any]]:
    """Authenticate a user by username or email and return their profile dict."""
    clean_id = identifier.strip().lower()
    if not clean_id or not password:
        return None

    init_db(database_url)
    with get_session(database_url) as session:
        account = session.scalar(
            select(UserAccount).where(
                or_(UserAccount.username == clean_id, UserAccount.email == clean_id)
            )
        )
        if account is None or not verify_password(password, account.password_hash):
            return None
        return {
            "id": account.id,
            "username": account.username,
            "email": account.email,
            "full_name": account.full_name,
            "role": account.role,
        }
