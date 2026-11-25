"""Comprehensive integration tests for SENTINEL AI Enterprise Features."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from config import REMEDIATION_API_TOKEN
from database import get_audit_logs, get_findings, init_db, reset_engine, save_scan_results
from demo_lab.app import create_demo_app
from demo_lab.high_security_app import create_high_security_app
from intelligence import (
    evaluate_security_regression,
    generate_ai_remediation_proposal,
    run_security_benchmark,
    validate_gemini_proposal_payload,
)
from remediation import (
    RemediationValidationError,
    apply_approved_remediation,
    list_backups,
    rollback_configuration,
    set_proposal_decision,
    validate_remediation_request,
    verify_remediation_proposal,
)
from reporting import generate_pdf_report
from scanner import run_security_scan


@pytest.fixture()
def temp_db_url(tmp_path: Path) -> str:
    reset_engine()
    db_file = tmp_path / "test_enterprise.db"
    url = f"sqlite:///{db_file.as_posix()}"
    init_db(url)
    yield url
    reset_engine()


@pytest.fixture()
def two_local_apps(monkeypatch: pytest.MonkeyPatch) -> tuple[str, str]:
    """Launch both Application A (High-Security) and Application B (Low-Security) on ephemeral ports."""
    high_app = create_high_security_app()
    low_app = create_demo_app()

    high_srv = make_server("127.0.0.1", 0, high_app)
    low_srv = make_server("127.0.0.1", 0, low_app)

    high_url = f"http://127.0.0.1:{high_srv.server_port}"
    low_url = f"http://127.0.0.1:{low_srv.server_port}"

    # Point config/validator URLs to the ephemeral test ports
    import config
    import remediation.fix_validator as fv

    monkeypatch.setattr(config, "HIGH_SECURITY_APP_URL", high_url)
    monkeypatch.setattr(config, "LOW_SECURITY_APP_URL", low_url)
    monkeypatch.setattr(fv, "HIGH_SECURITY_APP_URL", high_url)
    monkeypatch.setattr(fv, "LOW_SECURITY_APP_URL", low_url)

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


def test_gemini_payload_validation_and_fallback(temp_db_url: str) -> None:
    # Reject untrusted / unknown action_id
    bad_payload = {
        "technical_explanation": "x",
        "potential_security_impact": "y",
        "root_cause": "z",
        "recommended_correction": "c",
        "corrected_configuration": "cfg",
        "secure_code_example": "code",
        "verification_instructions": "v",
        "remediation_priority": "High",
        "action_id": "EXECUTE_ARBITRARY_SHELL",
    }
    assert validate_gemini_proposal_payload(bad_payload) is None

    # Accept valid allowlisted payload
    good_payload = {**bad_payload, "action_id": "ENABLE_CSP"}
    validated = validate_gemini_proposal_payload(good_payload)
    assert validated is not None
    assert validated["action_id"] == "ENABLE_CSP"

    # Fallback works without Gemini API key
    scan_id = save_scan_results(
        target_url="http://127.0.0.1:5050/",
        security_score=60.0,
        findings_data=[
            {
                "rule_id": "HDR-001",
                "target_path": "/",
                "title": "Missing CSP",
                "severity": "High",
                "risk_score": 74.5,
                "evidence": "Missing",
                "owasp_category": "A02:2025 - Security Misconfiguration",
                "remediation": "Add CSP",
            }
        ],
        database_url=temp_db_url,
    )
    finding = get_findings(scan_id=scan_id, database_url=temp_db_url)[0]
    prop = generate_ai_remediation_proposal(
        finding, framework="Flask", use_gemini=False, database_url=temp_db_url
    )
    assert prop["source"] == "rule_based_fallback"
    assert prop["action_id"] == "ENABLE_CSP"
    assert prop["approval_status"] == "Pending Review"


def test_remediation_governance_and_high_security_protection(two_local_apps: tuple[str, str]) -> None:
    high_url, low_url = two_local_apps

    # High-Security App A must never be a remediation target
    with pytest.raises(RemediationValidationError, match="read-only"):
        validate_remediation_request(
            target_url=high_url,
            action_id="ENABLE_CSP",
            approval_status="Approved",
        )

    # Pending/Rejected proposals must not execute
    with pytest.raises(RemediationValidationError, match="Pending Review"):
        validate_remediation_request(
            target_url=low_url,
            action_id="ENABLE_CSP",
            approval_status="Pending Review",
        )

    # Unknown action rejected
    with pytest.raises(RemediationValidationError, match="ALLOWLISTED_ACTIONS"):
        validate_remediation_request(
            target_url=low_url,
            action_id="DROP_DATABASE",
            approval_status="Approved",
        )

    # Flask API rejects arbitrary code/shell keys & missing token
    lab = create_demo_app()
    client = lab.test_client()
    assert client.get("/api/remediation/status").status_code == 401
    bad_apply = client.post(
        "/api/remediation/apply",
        json={"action_id": "ENABLE_CSP", "developer_approved": True, "command": "rm -rf /"},
        headers={"X-Sentinel-Approval-Token": REMEDIATION_API_TOKEN},
    )
    assert bad_apply.status_code == 400


def test_benchmark_apply_verify_rollback_regression_and_pdf(
    two_local_apps: tuple[str, str], temp_db_url: str, tmp_path: Path
) -> None:
    high_url, low_url = two_local_apps

    # 1. Security Benchmark compares App A (High-Sec) vs App B (Low-Sec)
    bench = run_security_benchmark(
        high_sec_url=high_url,
        low_sec_url=low_url,
        application_profile="Fintech / Payment Application",
        database_url=temp_db_url,
    )
    assert bench.high_sec_score > bench.low_sec_score
    assert len(bench.control_matrix) >= 10

    # 2. Pick a Low-Security finding (HDR-001 Missing CSP) and generate proposal
    low_findings = get_findings(scan_id=bench.low_sec_scan_id, database_url=temp_db_url)
    csp_finding = next(f for f in low_findings if f["rule_id"] == "HDR-001")
    proposal = generate_ai_remediation_proposal(
        csp_finding, framework="Flask", use_gemini=False, database_url=temp_db_url
    )

    # 3. Developer approves and applies fix to Low-Security App B
    set_proposal_decision(proposal["id"], decision="Approved", database_url=temp_db_url)
    apply_res = apply_approved_remediation(
        proposal["id"], target_url=low_url, database_url=temp_db_url
    )
    assert apply_res["approval_status"] == "Verification Pending"
    backup_uid = apply_res["backup_uid"]
    assert len(list_backups(database_url=temp_db_url)) == 1

    # 4. Verify fix via fresh scan
    ver_res = verify_remediation_proposal(
        proposal["id"], target_url=low_url, database_url=temp_db_url
    )
    assert ver_res["verified"] is True
    assert ver_res["approval_status"] == "Verified"

    # 5. Rollback restores original setting and triggers Regression Guard on next scan
    rb_res = rollback_configuration(backup_uid, database_url=temp_db_url)
    assert rb_res["restored_verified"] is True

    post_rb_scan = run_security_scan(
        low_url, application_profile="Fintech / Payment Application", database_url=temp_db_url
    )
    reg_report = evaluate_security_regression(
        bench.low_sec_scan_id, post_rb_scan.scan_id, database_url=temp_db_url
    )
    assert len(reg_report.returning_fixed_vulnerabilities) >= 1
    assert reg_report.alerts_generated >= 1

    # 6. Audit logs & 16-section PDF report
    assert len(get_audit_logs(database_url=temp_db_url)) >= 4
    pdf_path = generate_pdf_report(
        ver_res["followup_scan_id"],
        output_dir=tmp_path / "reports",
        database_url=temp_db_url,
    )
    assert pdf_path.exists()
    assert pdf_path.read_bytes().startswith(b"%PDF-")
