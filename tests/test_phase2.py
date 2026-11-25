"""Phase 2 comprehensive tests for scanners, OWASP 2025 mapping, AI risk engine, and DB integration."""

from __future__ import annotations

import socket
import ssl
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from werkzeug.serving import make_server

from database import get_dashboard_snapshot, get_findings, init_db, reset_engine
from demo_lab.app import create_demo_app
from intelligence import (
    OWASP_A02_MISCONFIG,
    OWASP_A04_CRYPTO,
    OWASP_A07_AUTH,
    assess_finding_risk,
    classify_risk_level,
    map_finding_to_owasp,
)
from scanner import (
    StandardFinding,
    TargetValidationError,
    analyze_headers,
    analyze_set_cookie_headers,
    inspect_tls_endpoint,
    run_security_scan,
    validate_target_url,
)
from scanner.target_validator import safe_fetch


@pytest.fixture()
def temp_db_url(tmp_path: Path) -> str:
    reset_engine()
    db_file = tmp_path / "test_phase2.db"
    url = f"sqlite:///{db_file.as_posix()}"
    init_db(url)
    yield url
    reset_engine()


@pytest.fixture()
def live_demo_lab() -> str:
    """Start the Phase 1 Flask SENTINEL LAB on an ephemeral localhost port for real HTTP tests."""
    app = create_demo_app()
    server = make_server("127.0.0.1", 0, app)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=3)


def test_authorised_target_validation() -> None:
    v1 = validate_target_url("http://127.0.0.1:5050")
    assert v1.hostname == "127.0.0.1"
    assert v1.port == 5050

    v2 = validate_target_url("http://localhost:8080/app")
    assert v2.hostname == "localhost"
    assert v2.base_path == "/app"

    v3 = validate_target_url("http://[::1]:5050")
    assert v3.hostname == "::1"

    # Allowlisted local Docker test service with mocked private bridge IP
    docker_resolver = lambda host, port: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("172.18.0.5", port))]
    v4 = validate_target_url(
        "http://demo-lab:5050",
        allowed_docker_hosts=("demo-lab",),
        resolver=docker_resolver,
    )
    assert v4.hostname == "demo-lab"
    assert v4.resolved_ip == "172.18.0.5"


def test_external_target_and_dns_rebinding_blocking() -> None:
    blocked_targets = [
        "https://example.com",
        "http://8.8.8.8",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "http://user:pass@127.0.0.1:5050",
    ]
    for url in blocked_targets:
        with pytest.raises(TargetValidationError):
            validate_target_url(url)

    # DNS rebinding simulation: localhost resolving to a public IP must be blocked
    evil_resolver = lambda host, port: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
    with pytest.raises(TargetValidationError, match="DNS rebinding blocked"):
        validate_target_url("http://localhost:5050", resolver=evil_resolver)


def test_redirect_validation_blocks_external_redirects() -> None:
    mock_session = MagicMock()
    redirect_resp = MagicMock()
    redirect_resp.is_redirect = True
    redirect_resp.is_permanent_redirect = False
    redirect_resp.headers = {"Location": "https://evil.example.com/steal"}
    redirect_resp.iter_content.return_value = []
    mock_session.request.return_value = redirect_resp

    with pytest.raises(TargetValidationError, match="not authorised"):
        safe_fetch("http://127.0.0.1:5050/", session=mock_session)


def test_header_detection_and_csp_frame_ancestors() -> None:
    # Missing all headers on HTTPS
    findings = analyze_headers({}, scheme="https", target_path="/")
    rule_ids = {f.rule_id for f in findings}
    assert {"HDR-001", "HDR-002", "HDR-003", "HDR-004", "HDR-005", "HDR-006"} == rule_ids

    # CSP with frame-ancestors 'none' satisfies clickjacking protection (HDR-003 absent)
    findings_with_csp = analyze_headers(
        {
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        },
        scheme="http",
        target_path="/",
    )
    assert findings_with_csp == []


def test_cookie_detection_never_exposes_values() -> None:
    secret_value = "SUPER_SECRET_RAW_TOKEN_XYZ_999"
    headers = [f"sentinel_demo_session={secret_value}; Path=/"]
    findings = analyze_set_cookie_headers(headers, scheme="https", target_path="/session-test")

    assert len(findings) == 3
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {"COOKIE-001", "COOKIE-002", "COOKIE-003"}

    for f in findings:
        assert secret_value not in f.evidence
        assert secret_value not in f.description
        assert secret_value not in f.remediation_reference
        assert f.metadata["is_session_cookie"] is True


def test_tls_checks_strict_verification() -> None:
    with patch("scanner.tls_scanner.socket.create_connection") as mock_conn:
        mock_sock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        with patch("scanner.tls_scanner.ssl.create_default_context") as mock_ctx_fn:
            mock_ctx = MagicMock()
            mock_ctx_fn.return_value = mock_ctx
            mock_ctx.wrap_socket.side_effect = ssl.SSLCertVerificationError("self-signed certificate")

            findings = inspect_tls_endpoint("127.0.0.1", 8443)
            assert mock_ctx.check_hostname is True
            assert mock_ctx.verify_mode == ssl.CERT_REQUIRED
            assert len(findings) == 1
            assert findings[0].rule_id == "TLS-004"


def test_owasp_2025_mapping() -> None:
    hdr = StandardFinding(
        rule_id="HDR-001",
        title="Missing CSP",
        category="Security Headers",
        severity="High",
        target_path="/",
        evidence="Missing",
        description="Missing CSP",
        remediation_reference="Add CSP",
    )
    assert map_finding_to_owasp(hdr) == OWASP_A02_MISCONFIG

    tls = StandardFinding(
        rule_id="TLS-004",
        title="Untrusted Cert",
        category="TLS / Transport Security",
        severity="High",
        target_path="/",
        evidence="Untrusted",
        description="Untrusted",
        remediation_reference="Fix cert",
    )
    assert map_finding_to_owasp(tls) == OWASP_A04_CRYPTO

    sess_cookie = StandardFinding(
        rule_id="COOKIE-001",
        title="Missing HttpOnly",
        category="Cookie Security",
        severity="High",
        target_path="/session-test",
        evidence="Missing",
        description="Missing",
        remediation_reference="Add HttpOnly",
        metadata={"is_session_cookie": True},
    )
    assert map_finding_to_owasp(sess_cookie) == OWASP_A07_AUTH


def test_risk_score_calculation_and_profiles() -> None:
    finding = StandardFinding(
        rule_id="FILE-002",
        title="Exposed Config",
        category="Exposed Files & Endpoints",
        severity="High",
        target_path="/config.json",
        evidence="200 OK",
        description="Exposed",
        remediation_reference="Restrict",
        confidence=95.0,
        exposure=95.0,
        exploitability=65.0,
    )
    fintech = assess_finding_risk(finding, application_profile="Fintech / Payment Application")
    general = assess_finding_risk(finding, application_profile="General Web Application")

    # Exact formula check for General Web Application (Data Sensitivity = 50):
    # (80*0.30) + (95*0.25) + (50*0.20) + (65*0.15) + (95*0.10) = 24 + 23.75 + 10 + 9.75 + 9.5 = 77.0
    assert general.risk_score == 77.0
    assert general.risk_category == "High"
    assert fintech.risk_score > general.risk_score
    assert "assumption" in fintech.explanation.lower()

    assert classify_risk_level(92.0) == "Critical"
    assert classify_risk_level(75.0) == "High"
    assert classify_risk_level(50.0) == "Medium"
    assert classify_risk_level(20.0) == "Low"


def test_end_to_end_scan_against_live_demo_lab_and_db(
    live_demo_lab: str, temp_db_url: str
) -> None:
    result = run_security_scan(
        target_url=live_demo_lab,
        application_profile="Customer Portal",
        database_url=temp_db_url,
    )
    assert result.scan_id >= 1
    assert result.total_findings > 0

    rule_ids = {f.rule_id for f in result.findings}
    # Demo lab defaults: missing headers + insecure cookie on /session-test + exposed /config.json + HTTP TLS-000
    assert "HDR-001" in rule_ids
    assert "COOKIE-001" in rule_ids
    assert "FILE-002" in rule_ids
    assert "TLS-000" in rule_ids

    # Ensure synthetic secret from /config.json or cookie value was never stored
    stored_findings = get_findings(scan_id=result.scan_id, database_url=temp_db_url)
    assert len(stored_findings) == result.total_findings
    for sf in stored_findings:
        assert "SYNTHETIC_DEMO_KEY_NOT_REAL_0000" not in sf["evidence"]
        assert "synthetic-session-token-0001" not in sf["evidence"]

    snapshot = get_dashboard_snapshot(temp_db_url)
    assert snapshot["has_scans"] is True
    assert snapshot["total_scans"] == 1
    assert snapshot["total_vulnerabilities"] == result.total_findings
    assert snapshot["overall_security_score"] == result.security_score
