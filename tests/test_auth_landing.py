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
    init_db,
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
    import database.auth as auth_mod

    monkeypatch.setenv("SENTINEL_DATABASE_URL", auth_db_url)
    monkeypatch.setattr(config, "DATABASE_URL", auth_db_url)
    monkeypatch.setattr(db_mod, "DATABASE_URL", auth_db_url)
    monkeypatch.setattr(auth_mod, "DATABASE_URL", auth_db_url)
    reset_engine()
    init_db(auth_db_url)
    ensure_default_admin(auth_db_url)

    app_path = Path(__file__).resolve().parent.parent / "app.py"
    at = AppTest.from_file(app_path, default_timeout=30)
    at.run()
    at.text_input(key="login_identifier").set_value("admin@sentinel.ai")
    at.text_input(key="login_password").set_value("Sentinel@2026")
    [b for b in at.button if b.label == "Sign In to Workspace"][0].click().run()
    assert not at.exception

    with get_session(auth_db_url) as session:
        session.add(
            Scan(
                user_id=1,
                target_url="http://127.0.0.1:8000/",
                security_score=75.0,
                total_findings=2,
                status="completed",
            )
        )
    assert get_dashboard_snapshot(auth_db_url, user_id=1)["total_scans"] == 1

    [b for b in at.sidebar.button if b.key == "nav_settings"][0].click().run()
    reset_btn = [b for b in at.button if b.key == "btn_reset_workspace_data"]
    assert len(reset_btn) == 1
    reset_btn[0].click().run()
    assert not at.exception
    assert get_dashboard_snapshot(auth_db_url, user_id=1)["total_scans"] == 0


def test_realtime_login_telemetry_and_user_account_summary(auth_db_url: str) -> None:
    from database import get_user_account_summary, save_scan_results

    created = register_user(
        username="telemetry_user",
        email="telemetry@sentinel.ai",
        password="StrongPassword123",
        full_name="Telemetry Analyst",
        database_url=auth_db_url,
    )
    assert created["login_count"] == 1
    assert created["created_at"] != "—"
    assert created["last_login_at"] != "—"

    logged_in = authenticate_user("telemetry@sentinel.ai", "StrongPassword123", auth_db_url)
    assert logged_in is not None
    assert logged_in["login_count"] == 2

    save_scan_results(
        target_url="https://example.com",
        security_score=88.0,
        findings_data=[],
        user_id=created["id"],
        database_url=auth_db_url,
    )
    summary = get_user_account_summary(created["id"], database_url=auth_db_url)
    assert summary is not None
    assert summary["login_count"] == 2
    assert summary["total_scans"] == 1
    assert summary["recent_targets"] == ["https://example.com"]
