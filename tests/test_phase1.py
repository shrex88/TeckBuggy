"""Phase 1 verification tests for database, demo lab, and dashboard snapshot."""

from __future__ import annotations

from pathlib import Path

import pytest

from database import (
    Finding,
    Report,
    Scan,
    get_dashboard_snapshot,
    get_session,
    init_db,
    reset_engine,
)
from tests.conftest import create_test_low_sec_app as create_demo_app


@pytest.fixture()
def temp_db_url(tmp_path: Path) -> str:
    reset_engine()
    db_file = tmp_path / "test_sentinel.db"
    url = f"sqlite:///{db_file.as_posix()}"
    yield url
    reset_engine()


def test_database_initialization_and_empty_snapshot(temp_db_url: str) -> None:
    init_db(temp_db_url)
    snapshot = get_dashboard_snapshot(temp_db_url)
    assert snapshot["has_scans"] is False
    assert snapshot["total_scans"] == 0
    assert snapshot["total_vulnerabilities"] == 0
    assert snapshot["overall_security_score"] is None
    assert snapshot["priority_findings"] == []


def test_database_relationships_and_persistence(temp_db_url: str) -> None:
    init_db(temp_db_url)
    with get_session(temp_db_url) as session:
        scan = Scan(
            target_url="http://127.0.0.1:5050",
            security_score=72.0,
            total_findings=1,
            status="completed",
        )
        finding = Finding(
            rule_id="HDR-001",
            target_path="/",
            title="Missing Content-Security-Policy Header",
            severity="High",
            risk_score=7.5,
            evidence="CSP header absent in response",
            owasp_category="A05:2021 - Security Misconfiguration",
            remediation="Add Content-Security-Policy header.",
            finding_status="open",
        )
        report = Report(report_path="data/reports/sample.html")
        scan.findings.append(finding)
        scan.reports.append(report)
        session.add(scan)

    snapshot = get_dashboard_snapshot(temp_db_url)
    assert snapshot["has_scans"] is True
    assert snapshot["total_scans"] == 1
    assert snapshot["total_vulnerabilities"] == 1
    assert snapshot["high_findings"] == 1
    assert snapshot["overall_security_score"] == 72.0
    assert snapshot["total_reports"] == 1


def test_demo_lab_configurable_vulnerabilities() -> None:
    lab = create_demo_app()
    client = lab.test_client()

    # Default insecure state
    home_resp = client.get("/")
    assert home_resp.status_code == 200
    assert "Content-Security-Policy" not in home_resp.headers

    cookie_resp = client.get("/session-test")
    assert cookie_resp.status_code == 200
    set_cookie = cookie_resp.headers.get("Set-Cookie", "")
    assert "sentinel_demo_session=" in set_cookie
    assert "HttpOnly" not in set_cookie

    cfg_resp = client.get("/config.json")
    assert cfg_resp.status_code == 200
    assert cfg_resp.get_json()["warning"] == "SYNTHETIC_TEST_DATA_ONLY"

    # Toggle hardened mode
    toggle_resp = client.post(
        "/lab/settings",
        json={
            "missing_security_headers": False,
            "insecure_cookie_flags": False,
            "expose_config_endpoint": False,
        },
    )
    assert toggle_resp.status_code == 200

    hardened_home = client.get("/")
    assert "Content-Security-Policy" in hardened_home.headers
    assert hardened_home.headers["X-Frame-Options"] == "DENY"

    hardened_cookie = client.get("/session-test").headers.get("Set-Cookie", "")
    assert "HttpOnly" in hardened_cookie

    hidden_cfg = client.get("/config.json")
    assert hidden_cfg.status_code == 404


def test_streamlit_navigation_and_empty_state(temp_db_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    from streamlit.testing.v1 import AppTest
    import config
    import database.database as db_mod

    monkeypatch.setenv("SENTINEL_DATABASE_URL", temp_db_url)
    monkeypatch.setattr(config, "DATABASE_URL", temp_db_url)
    monkeypatch.setattr(db_mod, "DATABASE_URL", temp_db_url)
    app_path = Path(__file__).resolve().parent.parent / "app.py"
    at = AppTest.from_file(app_path, default_timeout=15)
    at.run()
    assert not at.exception

    # Empty state CTA button exists when DB has no scans; otherwise navigate via sidebar
    cta = [b for b in at.button if b.key == "cta_first_scan"]
    if cta:
        cta[0].click().run()
        assert not at.exception
        assert at.session_state["active_page"] == "new_scan"

    # Verify all 16 sidebar navigation buttons work cleanly without exceptions
    nav_keys = [
        "nav_overview",
        "nav_new_scan",
        "nav_security_benchmark",
        "nav_vulnerabilities",
        "nav_ai_intelligence",
        "nav_ai_copilot",
        "nav_digital_twin",
        "nav_remediation_confidence",
        "nav_approval_centre",
        "nav_remediation_history",
        "nav_security_proof",
        "nav_regression_guard",
        "nav_learning_mode",
        "nav_scan_history",
        "nav_reports",
        "nav_settings",
    ]
    for key in nav_keys:
        btn = [b for b in at.sidebar.button if b.key == key]
        assert len(btn) == 1, f"Missing sidebar button {key}"
        btn[0].click().run()
        assert not at.exception, f"Exception on navigation to {key}: {at.exception}"

