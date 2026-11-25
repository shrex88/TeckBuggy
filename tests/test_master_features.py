"""Tests for Security Digital Twin, AI Remediation Confidence Engine, and Security Learning Mode."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
import requests
from werkzeug.serving import make_server

from database import get_findings, init_db, reset_engine, save_scan_results
from database.models import RemediationProposal
from demo_lab.app import create_demo_app
from demo_lab.high_security_app import create_high_security_app
from digital_twin import (
    RECOMMENDED_CSP,
    get_simulation_details,
    list_simulations,
    run_digital_twin_simulation,
    simulate_cookie_policy,
    simulate_csp_policy,
)
from intelligence import (
    evaluate_remediation_proposal,
    generate_ai_remediation_proposal,
    list_confidence_outcomes,
)
from learning import (
    ask_security_tutor,
    get_learning_dashboard_state,
    get_lesson,
    mark_lesson_completed,
    set_learning_level,
    submit_quiz_attempt,
    verify_practical_challenge,
)
from remediation import (
    apply_approved_remediation,
    set_proposal_decision,
    verify_remediation_proposal,
)
from scanner import TargetValidationError, run_security_scan


@pytest.fixture()
def temp_db_url(tmp_path: Path) -> str:
    reset_engine()
    db_file = tmp_path / "test_master.db"
    url = f"sqlite:///{db_file.as_posix()}"
    init_db(url)
    yield url
    reset_engine()


@pytest.fixture()
def two_live_apps(monkeypatch: pytest.MonkeyPatch) -> tuple[str, str]:
    high_app = create_high_security_app()
    low_app = create_demo_app()
    high_srv = make_server("127.0.0.1", 0, high_app)
    low_srv = make_server("127.0.0.1", 0, low_app)
    high_url = f"http://127.0.0.1:{high_srv.server_port}"
    low_url = f"http://127.0.0.1:{low_srv.server_port}"

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


def test_digital_twin_simulations_and_isolation(
    two_live_apps: tuple[str, str], temp_db_url: str
) -> None:
    high_url, low_url = two_live_apps
    run_security_scan(high_url, database_url=temp_db_url)
    run_security_scan(low_url, database_url=temp_db_url)

    # Low-security combined simulation with HTTP Secure cookie -> CONDITIONAL due to HTTP
    sim_low = run_digital_twin_simulation(
        target_url=low_url,
        app_label="Low Security",
        simulation_mode="Both (CSP + Cookies)",
        proposed_csp=RECOMMENDED_CSP,
        enable_secure_cookie=True,
        enable_httponly_cookie=True,
        samesite="Lax",
        enable_additional_headers=True,
        database_url=temp_db_url,
    )
    assert sim_low.evaluation.projected_score > sim_low.evaluation.baseline_score
    assert sim_low.evaluation.classification == "CONDITIONAL"
    assert any("HTTPS" in w.warning_title for w in sim_low.evaluation.compatibility_warnings)

    # Verify original live Low-Security app was NOT modified by simulation
    live_resp = requests.get(f"{low_url}/", timeout=5)
    assert "Content-Security-Policy" not in live_resp.headers

    # High-security simulation
    sim_high = run_digital_twin_simulation(
        target_url=high_url,
        app_label="High Security",
        simulation_mode="CSP Only",
        database_url=temp_db_url,
    )
    assert sim_high.evaluation.baseline_score >= 90.0

    # Invalid CSP detection
    bad_csp = simulate_csp_policy("script-src 'unsafe-inline' *")
    assert len(bad_csp.unsafe_directives) >= 2
    empty_csp = simulate_csp_policy("")
    assert empty_csp.valid_syntax is False

    # Cookie simulator HTTP vs HTTPS
    c_http = simulate_cookie_policy(scheme="http", enable_secure=True)
    assert c_http.https_compatible is False
    assert c_http.classification == "CONDITIONAL"

    # History & details
    sims = list_simulations(database_url=temp_db_url)
    assert len(sims) == 2
    assert get_simulation_details(sim_low.simulation_id, database_url=temp_db_url) is not None


def test_remediation_confidence_engine_and_missing_evidence(temp_db_url: str) -> None:
    from database import get_session

    # 1. Scan with complete evidence -> High Confidence
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

    # 2. Missing evidence -> Insufficient Evidence
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

    # 3. Invalid CSP proposal lowers score
    with get_session(temp_db_url) as session:
        prop_row = session.get(RemediationProposal, p_good["id"])
        assert prop_row is not None
        prop_row.corrected_config = "Content-Security-Policy: script-src 'unsafe-inline' *"
    ev_bad_csp = evaluate_remediation_proposal(p_good["id"], database_url=temp_db_url)
    assert ev_bad_csp.confidence_score < ev_good.confidence_score


def test_learning_mode_lessons_quizzes_tutor_and_challenges(
    two_live_apps: tuple[str, str], temp_db_url: str
) -> None:
    _, low_url = two_live_apps

    # Levels
    for lvl in ("BEGINNER", "INTERMEDIATE", "ADVANCED"):
        lesson = get_lesson("HDR-001", learning_level=lvl)
        assert lesson.learning_level == lvl
        assert "Flask" in lesson.framework_implementations

    set_learning_level("INTERMEDIATE", database_url=temp_db_url)
    assert mark_lesson_completed("HDR-001", "INTERMEDIATE", database_url=temp_db_url) is True

    # Quiz scoring & badge
    from learning import QUIZ_BANK

    perfect_answers = {q.qid: q.correct_answer for q in QUIZ_BANK}
    q_res = submit_quiz_attempt(answers=perfect_answers, database_url=temp_db_url)
    assert q_res["score"] == q_res["total"]

    # Tutor (deterministic when Gemini disabled/mocked or live)
    reply = ask_security_tutor(
        question="Why is HttpOnly important?",
        learning_level="BEGINNER",
        rule_id="COOKIE-001",
        database_url=temp_db_url,
    )
    assert len(reply["answer"]) > 20

    # Local target restriction on challenge
    with pytest.raises(TargetValidationError):
        verify_practical_challenge(
            challenge_id="CHAL-CSP",
            baseline_scan_id=1,
            target_url="https://example.com",
            database_url=temp_db_url,
        )

    state = get_learning_dashboard_state(database_url=temp_db_url)
    assert state["learning_level"] == "INTERMEDIATE"
    assert state["points"] >= 15
    assert any(b["badge_id"] == "OWASP_EXPLORER" for b in state["achievements"])


def test_full_integrated_workflow_detect_to_verify_and_confidence_outcome(
    two_live_apps: tuple[str, str], temp_db_url: str
) -> None:
    _, low_url = two_live_apps

    # DETECT
    scan = run_security_scan(low_url, database_url=temp_db_url)
    csp_finding = next(
        f for f in get_findings(scan_id=scan.scan_id, database_url=temp_db_url)
        if f["rule_id"] == "HDR-001"
    )

    # LEARN & SIMULATE
    get_lesson("HDR-001", learning_level="BEGINNER")
    sim = run_digital_twin_simulation(
        target_url=low_url,
        simulation_mode="CSP Only",
        application_profile="General Web Application",
        database_url=temp_db_url,
    )
    assert sim.evaluation.projected_score > sim.evaluation.baseline_score

    # EVALUATE & APPROVE
    proposal = generate_ai_remediation_proposal(
        csp_finding, framework="Flask", use_gemini=False, database_url=temp_db_url
    )
    evaluate_remediation_proposal(proposal["id"], database_url=temp_db_url)
    set_proposal_decision(proposal["id"], decision="Approved", database_url=temp_db_url)

    # REMEDIATE -> RESCAN -> VERIFY
    apply_approved_remediation(proposal["id"], target_url=low_url, database_url=temp_db_url)
    ver = verify_remediation_proposal(proposal["id"], target_url=low_url, database_url=temp_db_url)
    assert ver["verified"] is True

    # Confidence outcome recorded automatically from Security Proof
    outcomes = list_confidence_outcomes(database_url=temp_db_url)
    assert len(outcomes) == 1
    assert outcomes[0]["actual_resolved"] is True
