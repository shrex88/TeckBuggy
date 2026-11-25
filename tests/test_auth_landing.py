"""Tests for SENTINEL AI landing page & SQLite-backed authentication."""

from __future__ import annotations

from pathlib import Path

import pytest

from database import (
    AuthError,
    Scan,
    authenticate_user,
    ensure_default_admin,
    get_dashboard_snapshot,
    get_session,
    register_user,
    reset_engine,
    reset_scan_workspace_data,
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


def test_reset_scan_workspace_data_preserves_users(auth_db_url: str) -> None:
    ensure_default_admin(auth_db_url)
    with get_session(auth_db_url) as session:
        session.add(
            Scan(
                target_url="http://127.0.0.1:8000/",
                security_score=60.0,
                total_findings=3,
                status="completed",
            )
        )

    assert get_dashboard_snapshot(auth_db_url)["has_scans"] is True
    reset_scan_workspace_data(auth_db_url)

    snap = get_dashboard_snapshot(auth_db_url)
    assert snap["has_scans"] is False
    assert snap["total_scans"] == 0
    assert authenticate_user("admin@sentinel.ai", "Sentinel@2026", auth_db_url) is not None


def test_settings_reset_button_clears_workspace(auth_db_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    from streamlit.testing.v1 import AppTest
    import config
    import database.database as db_mod

    monkeypatch.setenv("SENTINEL_DATABASE_URL", auth_db_url)
    monkeypatch.setattr(config, "DATABASE_URL", auth_db_url)
    monkeypatch.setattr(db_mod, "DATABASE_URL", auth_db_url)

    app_path = Path(__file__).resolve().parent.parent / "app.py"
    at = AppTest.from_file(app_path, default_timeout=15)
    at.run()
    at.text_input(key="login_identifier").set_value("admin@sentinel.ai")
    at.text_input(key="login_password").set_value("Sentinel@2026")
    [b for b in at.button if b.label == "Sign In to Workspace"][0].click().run()
    assert not at.exception

    with get_session(auth_db_url) as session:
        session.add(
            Scan(
                target_url="http://127.0.0.1:8000/",
                security_score=75.0,
                total_findings=2,
                status="completed",
            )
        )
    assert get_dashboard_snapshot(auth_db_url)["total_scans"] == 1

    [b for b in at.sidebar.button if b.key == "nav_settings"][0].click().run()
    reset_btn = [b for b in at.button if b.key == "btn_reset_workspace_data"]
    assert len(reset_btn) == 1
    reset_btn[0].click().run()
    assert not at.exception
    assert get_dashboard_snapshot(auth_db_url)["total_scans"] == 0
