"""Phase 3 end-to-end tests: Remediation, Security Proof, PDF Reports, and Live Demo Workflow."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
import requests
from werkzeug.serving import make_server

from database import (
    get_all_reports,
    get_all_scans,
    get_findings,
    init_db,
    reset_engine,
    save_scan_results,
)
from tests.conftest import create_test_low_sec_app as create_demo_app
from intelligence import SecurityProofError, compare_scans
from remediation import SUPPORTED_FRAMEWORKS, generate_remediation_playbook
from reporting import generate_pdf_report
from scanner import run_security_scan


@pytest.fixture()
def temp_db_url(tmp_path: Path) -> str:
    reset_engine()
    db_file = tmp_path / "test_phase3.db"
    url = f"sqlite:///{db_file.as_posix()}"
    init_db(url)
    yield url
    reset_engine()


@pytest.fixture()
def live_demo_lab() -> str:
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


def test_smart_remediation_engine_all_frameworks() -> None:
    sample_finding = {
        "rule_id": "HDR-001",
        "title": "Missing Content-Security-Policy Header",
        "severity": "High",
        "risk_score": 78.5,
        "target_path": "/",
        "evidence": "CSP header omitted.",
    }
    playbook = generate_remediation_playbook(sample_finding)
    assert playbook.finding_title == "Missing Content-Security-Policy Header"
    assert playbook.severity == "High"
    assert playbook.risk_score == 78.5
    assert "Content-Security-Policy" in playbook.corrected_config
    for fw in SUPPORTED_FRAMEWORKS:
        assert fw in playbook.snippets
        assert len(playbook.snippets[fw]) > 10


def test_security_proof_rejects_incomplete_scans(temp_db_url: str) -> None:
    s1 = save_scan_results(
        target_url="http://127.0.0.1:5050/",
        security_score=60.0,
        findings_data=[],
        status="completed",
        database_url=temp_db_url,
    )
    s2 = save_scan_results(
        target_url="http://127.0.0.1:5050/",
        security_score=0.0,
        findings_data=[],
        status="failed",
        database_url=temp_db_url,
    )
    with pytest.raises(SecurityProofError, match="completed"):
        compare_scans(s1, s2, database_url=temp_db_url)


def test_full_end_to_end_hackathon_demonstration(
    live_demo_lab: str, temp_db_url: str, tmp_path: Path
) -> None:
    """Execute Steps 1-10: AUTHORISE -> SCAN -> DETECT -> PRIORITISE -> FIX -> RESCAN -> VERIFY -> PDF."""
    # Step 1-5: Initial scan against intentionally misconfigured local Flask lab
    baseline = run_security_scan(
        target_url=live_demo_lab,
        application_profile="Fintech / Payment Application",
        database_url=temp_db_url,
    )
    assert baseline.total_findings > 0
    baseline_findings = get_findings(scan_id=baseline.scan_id, database_url=temp_db_url)
    assert all(f["finding_status"] == "open" for f in baseline_findings)

    # Step 6: Generate remediation playbook for a detected finding
    playbook = generate_remediation_playbook(baseline_findings[0])
    assert "Flask" in playbook.snippets

    # Step 7: Developer manually applies fixes to SENTINEL LAB via /lab/settings
    resp = requests.post(
        f"{live_demo_lab}/lab/settings",
        json={
            "missing_security_headers": False,
            "insecure_cookie_flags": False,
            "expose_config_endpoint": False,
        },
        timeout=5,
    )
    assert resp.status_code == 200

    # Step 8: Run follow-up scan
    followup = run_security_scan(
        target_url=live_demo_lab,
        application_profile="Fintech / Payment Application",
        database_url=temp_db_url,
    )
    assert followup.security_score > baseline.security_score

    # Step 9: Run Security Proof comparison & verify resolution in SQLite
    proof = compare_scans(
        baseline.scan_id,
        followup.scan_id,
        mark_verified_resolved=True,
        database_url=temp_db_url,
    )
    assert proof.updated_security_score > proof.original_security_score
    assert len(proof.fixed_vulnerabilities) >= 6
    assert proof.risk_reduction > 0
    assert proof.percentage_improvement > 0

    # Verify baseline fixed findings are now marked 'resolved' in SQLite
    updated_baseline = get_findings(scan_id=baseline.scan_id, database_url=temp_db_url)
    resolved_count = sum(1 for f in updated_baseline if f["finding_status"] == "resolved")
    assert resolved_count == len(proof.fixed_vulnerabilities)

    # Verify Scan History includes both scans and critical_findings count
    scans = get_all_scans(database_url=temp_db_url)
    assert len(scans) == 2
    assert "critical_findings" in scans[0]

    # Step 10: Generate PDF Report & verify SQLite Report registry
    pdf_path = generate_pdf_report(
        baseline.scan_id,
        output_dir=tmp_path / "reports",
        database_url=temp_db_url,
    )
    assert pdf_path.exists()
    assert pdf_path.read_bytes().startswith(b"%PDF-")

    reports = get_all_reports(database_url=temp_db_url)
    assert len(reports) == 1
    assert reports[0]["scan_id"] == baseline.scan_id
