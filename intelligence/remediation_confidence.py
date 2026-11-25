"""AI Remediation Confidence Engine for SENTINEL AI (Feature Two).

Independently evaluates technical correctness, application safety, and
verification status of remediation proposals using deterministic validation
and documented weighted scoring—never trusting AI output blindly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select

from config import ALLOWLISTED_ACTIONS, DATABASE_URL
from database.database import get_session, init_db, log_audit_event
from database.models import (
    ConfidenceFactor,
    ConfidenceOutcome,
    Finding,
    RegressionWarning,
    RemediationEvaluation,
    RemediationProposal,
    Scan,
    ValidationResult,
)
from intelligence.ai_remediation import RULE_TO_ACTION_ID
from remediation.fix_validator import run_deterministic_proposal_validation
from remediation.regression_analyzer import RegressionItem, analyze_proposal_regressions

CONFIDENCE_WEIGHTS: dict[str, float] = {
    "Finding-to-Fix Relevance": 0.20,
    "Technical Correctness": 0.20,
    "Configuration Validity": 0.15,
    "Framework Compatibility": 0.15,
    "Expected Security Improvement": 0.10,
    "Regression Safety": 0.10,
    "Evidence Completeness": 0.10,
}


@dataclass(frozen=True)
class ConfidenceAssessment:
    """Three-part independent assessment of a remediation proposal."""

    evaluation_id: int
    proposal_id: int
    confidence_score: float
    confidence_level: str
    application_safety: str
    verification_status: str
    factors: list[dict[str, Any]]
    validation_checks: list[dict[str, object]]
    regression_warnings: list[RegressionItem]
    explanation: str


def classify_confidence_level(score: float, *, evidence_score: float) -> str:
    """Classify confidence level; missing evidence prevents High Confidence."""
    if evidence_score < 50.0:
        return "Insufficient Evidence"
    if score >= 80.0:
        return "High Confidence"
    if score >= 55.0:
        return "Moderate Confidence"
    return "Low Confidence"


def evaluate_remediation_proposal(
    proposal_id: int,
    *,
    database_url: str = DATABASE_URL,
) -> ConfidenceAssessment:
    """Evaluate a persisted RemediationProposal independently and store results in SQLite."""
    init_db(database_url)
    with get_session(database_url) as session:
        proposal = session.get(RemediationProposal, proposal_id)
        if proposal is None:
            raise ValueError(f"Proposal #{proposal_id} not found.")
        finding = session.get(Finding, proposal.finding_id)
        scan = session.get(Scan, finding.scan_id) if finding else None

        rule_id = (finding.rule_id if finding else "").upper()
        evidence_text = (finding.evidence if finding else "") or ""
        target_scheme = urlparse(scan.target_url).scheme if scan else "http"
        approval_status = proposal.approval_status
        action_id = proposal.action_id
        corrected_cfg = proposal.corrected_config
        framework = proposal.framework
        code_snippet = proposal.secure_code_example
        finding_severity = finding.severity if finding else "Medium"

    # 1. Deterministic technical validation
    val_checks = run_deterministic_proposal_validation(
        rule_id=rule_id,
        action_id=action_id,
        corrected_config=corrected_cfg,
        framework=framework,
        code_snippet=code_snippet,
    )
    passed_val = sum(1 for c in val_checks if c["passed"])
    total_val = max(1, len(val_checks))

    # 2. Deterministic regression analysis
    regressions = analyze_proposal_regressions(
        rule_id=rule_id,
        action_id=action_id,
        corrected_config=corrected_cfg,
        target_scheme=target_scheme,
    )

    # 3. Compute normalized 0-100 factors
    expected_action = RULE_TO_ACTION_ID.get(rule_id)
    relevance = 100.0 if (expected_action and expected_action == action_id) else (
        65.0 if action_id in ALLOWLISTED_ACTIONS else 20.0
    )

    tech_correctness = round((passed_val / total_val) * 100.0, 1)
    syntax_check = val_checks[1] if len(val_checks) > 1 else {"passed": True}
    config_validity = 95.0 if syntax_check["passed"] else 30.0

    fw_check = val_checks[2] if len(val_checks) > 2 else {"passed": True}
    fw_compat = 95.0 if fw_check["passed"] else 45.0

    sev_improvement_map = {"Critical": 95.0, "High": 85.0, "Medium": 70.0, "Low": 55.0}
    expected_improvement = sev_improvement_map.get(finding_severity, 65.0)
    if not syntax_check["passed"]:
        expected_improvement = 25.0

    high_reg = sum(1 for r in regressions if r.likelihood == "High")
    med_reg = sum(1 for r in regressions if r.likelihood == "Medium")
    regression_safety = max(20.0, 95.0 - (high_reg * 35.0) - (med_reg * 15.0))

    evidence_completeness = 95.0 if len(evidence_text.strip()) >= 20 else 35.0

    raw_scores = {
        "Finding-to-Fix Relevance": relevance,
        "Technical Correctness": tech_correctness,
        "Configuration Validity": config_validity,
        "Framework Compatibility": fw_compat,
        "Expected Security Improvement": expected_improvement,
        "Regression Safety": regression_safety,
        "Evidence Completeness": evidence_completeness,
    }

    factors_list: list[dict[str, Any]] = []
    total_score = 0.0
    for name, weight in CONFIDENCE_WEIGHTS.items():
        r_score = max(0.0, min(100.0, float(raw_scores[name])))
        w_score = round(r_score * weight, 2)
        total_score += w_score
        factors_list.append(
            {
                "factor_name": name,
                "raw_score": r_score,
                "weight": weight,
                "weighted_score": w_score,
            }
        )

    total_score = round(max(0.0, min(100.0, total_score)), 1)
    conf_level = classify_confidence_level(total_score, evidence_score=evidence_completeness)

    if high_reg > 0 or not syntax_check["passed"]:
        app_safety = "Caution (Conditional)"
    elif med_reg > 0:
        app_safety = "Conditional"
    else:
        app_safety = "Safe"

    if approval_status == "Verified":
        verif_status = "Verified (Confirmed by Follow-Up Scan)"
    elif approval_status == "Verification Pending":
        verif_status = "Verification Pending (Rescan Required)"
    else:
        verif_status = "Not Verified"

    explanation = (
        f"Remediation Confidence: {total_score:.1f}/100 ({conf_level}) based on deterministic "
        f"validation ({passed_val}/{total_val} checks passed), evidence completeness ({evidence_completeness:.0f}/100), "
        f"and {len(regressions)} regression check(s). Application Safety: {app_safety}. "
        f"Verification Status: {verif_status}."
    )

    with get_session(database_url) as session:
        ev = RemediationEvaluation(
            proposal_id=proposal_id,
            confidence_score=total_score,
            confidence_level=conf_level,
            application_safety=app_safety,
            verification_status=verif_status,
            explanation=explanation,
        )
        session.add(ev)
        session.flush()
        eval_id = int(ev.id)

        for fl in factors_list:
            session.add(
                ConfidenceFactor(
                    evaluation_id=eval_id,
                    factor_name=fl["factor_name"],
                    raw_score=fl["raw_score"],
                    weight=fl["weight"],
                    weighted_score=fl["weighted_score"],
                )
            )
        for vc in val_checks:
            session.add(
                ValidationResult(
                    evaluation_id=eval_id,
                    check_name=str(vc["check_name"]),
                    passed=1 if vc["passed"] else 0,
                    details=str(vc["details"]),
                )
            )
        for rw in regressions:
            session.add(
                RegressionWarning(
                    evaluation_id=eval_id,
                    risk_description=rw.risk_description,
                    potential_impact=rw.potential_impact,
                    likelihood=rw.likelihood,
                    required_testing=rw.required_testing,
                    recommended_action=rw.recommended_action,
                )
            )

    log_audit_event(
        event_type="CONFIDENCE_EVALUATED",
        action_id=action_id,
        status=conf_level,
        details=explanation,
        database_url=database_url,
    )

    return ConfidenceAssessment(
        evaluation_id=eval_id,
        proposal_id=proposal_id,
        confidence_score=total_score,
        confidence_level=conf_level,
        application_safety=app_safety,
        verification_status=verif_status,
        factors=factors_list,
        validation_checks=val_checks,
        regression_warnings=regressions,
        explanation=explanation,
    )


def record_confidence_outcome(
    *,
    evaluation_id: int,
    followup_scan_id: int,
    actual_resolved: bool,
    regression_occurred: bool = False,
    evidence_summary: str = "",
    database_url: str = DATABASE_URL,
) -> int:
    """Link predicted confidence to actual Security Proof follow-up scan results."""
    init_db(database_url)
    with get_session(database_url) as session:
        ev = session.get(RemediationEvaluation, evaluation_id)
        if ev is None:
            raise ValueError(f"Evaluation #{evaluation_id} not found.")
        outcome = ConfidenceOutcome(
            evaluation_id=evaluation_id,
            followup_scan_id=followup_scan_id,
            predicted_confidence=ev.confidence_score,
            actual_resolved=1 if actual_resolved else 0,
            regression_occurred=1 if regression_occurred else 0,
            evidence_summary=evidence_summary,
        )
        session.add(outcome)
        session.flush()
        return int(outcome.id)


def list_confidence_outcomes(database_url: str = DATABASE_URL) -> list[dict[str, Any]]:
    """Return tracked confidence-vs-actual outcome records."""
    init_db(database_url)
    with get_session(database_url) as session:
        rows = list(
            session.scalars(
                select(ConfidenceOutcome).order_by(ConfidenceOutcome.recorded_at.desc())
            ).all()
        )
        return [
            {
                "id": o.id,
                "evaluation_id": o.evaluation_id,
                "followup_scan_id": o.followup_scan_id,
                "predicted_confidence": o.predicted_confidence,
                "actual_resolved": bool(o.actual_resolved),
                "regression_occurred": bool(o.regression_occurred),
                "evidence_summary": o.evidence_summary,
                "recorded_at": o.recorded_at.strftime("%Y-%m-%d %H:%M UTC") if o.recorded_at else "—",
            }
            for o in rows
        ]
