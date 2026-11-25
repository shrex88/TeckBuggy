"""Tests for AI Remediation Confidence Engine and Integrated Workflow."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from database import get_findings, init_db, reset_engine, save_scan_results
from database.models import RemediationProposal
from intelligence import (
    evaluate_remediation_proposal,
    generate_ai_remediation_proposal,
    list_confidence_outcomes,
)
from remediation import (
    apply_approved_remediation,
    set_proposal_decision,
    verify_remediation_proposal,
)
from scanner import run_security_scan
from tests.conftest import (
    create_test_high_sec_app as create_high_security_app,
    create_test_low_sec_app as create_demo_app,
)


@pytest.fixture()
def temp_db_url(tmp_path: Path) -> str:
    reset_engine()
    db_file = tmp_path / "test_master.db"
    url = f"sqlite:///{db_file.as_posix()}"
    init_db(url)
    yield url
    reset_engine()


@pytest.fixture()
def two_live_apps() -> tuple[str, str]:
    high_app = create_high_security_app()
    low_app = create_demo_app()
    high_srv = make_server("127.0.0.1", 0, high_app)
    low_srv = make_server("127.0.0.1", 0, low_app)
    high_url = f"http://127.0.0.1:{high_srv.server_port}"
    low_url = f"http://127.0.0.1:{low_srv.server_port}"

    t1 = threading.Thread(target=high_srv.serve_forever, daemon=True)
    t2 = threading.Thread(target=low_srv.serve_forever, daemon=True)
    t1.start()
    t2.start()
    try:
        yield high_url, low_url
    finally:
        high_srv.shutdown()
        low_srv.shutdown()
        t1.join(timeout=3)
        t2.join(timeout=3)


def test_remediation_confidence_engine_and_missing_evidence(temp_db_url: str) -> None:
    from database import get_session

    s1 = save_scan_results(
        target_url="http://127.0.0.1:5050/",
        security_score=65.0,
        findings_data=[
            {
                "rule_id": "HDR-001",
                "target_path": "/",
                "title": "Missing CSP",
                "severity": "High",
                "risk_score": 74.5,
                "evidence": "HTTP response for '/' omitted Content-Security-Policy header.",
                "owasp_category": "A02:2025 - Security Misconfiguration",
                "remediation": "Add CSP",
            }
        ],
        database_url=temp_db_url,
    )
    f_good = get_findings(scan_id=s1, database_url=temp_db_url)[0]
    p_good = generate_ai_remediation_proposal(
        f_good, framework="Flask", use_gemini=False, database_url=temp_db_url
    )
    ev_good = evaluate_remediation_proposal(p_good["id"], database_url=temp_db_url)
    assert ev_good.confidence_level == "High Confidence"
    assert ev_good.verification_status == "Not Verified"

    s2 = save_scan_results(
        target_url="http://127.0.0.1:5050/",
        security_score=65.0,
        findings_data=[
            {
                "rule_id": "HDR-001",
                "target_path": "/",
                "title": "Missing CSP",
                "severity": "High",
                "risk_score": 74.5,
                "evidence": "",
                "owasp_category": "A02:2025 - Security Misconfiguration",
                "remediation": "Add CSP",
            }
        ],
        database_url=temp_db_url,
    )
    f_no_ev = get_findings(scan_id=s2, database_url=temp_db_url)[0]
    p_no_ev = generate_ai_remediation_proposal(
        f_no_ev, framework="Flask", use_gemini=False, database_url=temp_db_url
    )
    ev_no_ev = evaluate_remediation_proposal(p_no_ev["id"], database_url=temp_db_url)
    assert ev_no_ev.confidence_level == "Insufficient Evidence"

    with get_session(temp_db_url) as session:
        prop_row = session.get(RemediationProposal, p_good["id"])
        assert prop_row is not None
        prop_row.corrected_config = "Content-Security-Policy: script-src 'unsafe-inline' *"
    ev_bad_csp = evaluate_remediation_proposal(p_good["id"], database_url=temp_db_url)
    assert ev_bad_csp.confidence_score < ev_good.confidence_score


def test_full_integrated_workflow_detect_to_verify_and_confidence_outcome(
    two_live_apps: tuple[str, str], temp_db_url: str
) -> None:
    _, low_url = two_live_apps

    scan = run_security_scan(low_url, database_url=temp_db_url)
    csp_finding = next(
        f for f in get_findings(scan_id=scan.scan_id, database_url=temp_db_url)
        if f["rule_id"] == "HDR-001"
    )

    proposal = generate_ai_remediation_proposal(
        csp_finding, framework="Flask", use_gemini=False, database_url=temp_db_url
    )
    evaluate_remediation_proposal(proposal["id"], database_url=temp_db_url)
    set_proposal_decision(proposal["id"], decision="Approved", database_url=temp_db_url)

    apply_approved_remediation(proposal["id"], target_url=low_url, database_url=temp_db_url)
    ver = verify_remediation_proposal(proposal["id"], target_url=low_url, database_url=temp_db_url)
    assert ver["verified"] is True

    outcomes = list_confidence_outcomes(database_url=temp_db_url)
    assert len(outcomes) == 1
    assert outcomes[0]["actual_resolved"] is True
