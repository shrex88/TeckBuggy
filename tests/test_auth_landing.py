"""Tests for SENTINEL AI landing page & SQLite-backed authentication."""

from __future__ import annotations

from pathlib import Path

import pytest

from database import (
    AuthError,
    authenticate_user,
    ensure_default_admin,
    register_user,
    reset_engine,
)


@pytest.fixture()
def auth_db_url(tmp_path: Path) -> str:
    reset_engine()
    url = f"sqlite:///{(tmp_path / 'auth_test.db').as_posix()}"
    yield url
    reset_engine()


def test_default_admin_seed_and_authenticate(auth_db_url: str) -> None:
    ensure_default_admin(auth_db_url)

    by_email = authenticate_user("admin@sentinel.ai", "Sentinel@2026", auth_db_url)
    assert by_email is not None
    assert by_email["username"] == "admin"

    by_user = authenticate_user("admin", "Sentinel@2026", auth_db_url)
    assert by_user is not None

    bad = authenticate_user("admin@sentinel.ai", "wrongpass", auth_db_url)
    assert bad is None


def test_register_user_and_duplicate_rejection(auth_db_url: str) -> None:
    created = register_user(
        username="analyst1",
        email="analyst1@sentinel.ai",
        password="StrongPassword123",
        full_name="Analyst One",
        database_url=auth_db_url,
    )
    assert created["username"] == "analyst1"
    assert created["full_name"] == "Analyst One"

    authed = authenticate_user("analyst1@sentinel.ai", "StrongPassword123", auth_db_url)
    assert authed is not None

    with pytest.raises(AuthError):
        register_user(
            username="analyst1",
            email="other@sentinel.ai",
            password="StrongPassword123",
            database_url=auth_db_url,
        )

    with pytest.raises(AuthError):
        register_user(
            username="ab",
            email="invalid",
            password="123",
            database_url=auth_db_url,
        )
