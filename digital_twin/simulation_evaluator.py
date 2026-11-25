"""Simulation Evaluator using existing scanner rules and risk engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from digital_twin.compatibility_checker import CompatibilityWarning
from digital_twin.configuration_snapshot import VirtualSnapshot
from digital_twin.cookie_simulator import CookieSimulationResult
from digital_twin.csp_simulator import CspSimulationResult
from intelligence.owasp_mapper import map_finding_to_owasp
from intelligence.risk_engine import assess_finding_risk, compute_overall_security_score
from scanner.cookie_scanner import analyze_set_cookie_headers
from scanner.header_scanner import analyze_headers
from scanner.models import StandardFinding


@dataclass(frozen=True)
class EvaluatedSimulation:
    """Evaluated Digital Twin simulation metrics and classification."""

    baseline_score: float
    projected_score: float
    expected_risk_reduction: float
    classification: str
    passed_checks: int
    failed_checks: int
    remaining_findings: list[dict[str, Any]]
    compatibility_warnings: list[CompatibilityWarning]


def evaluate_virtual_configuration(
    *,
    snapshot: VirtualSnapshot,
    simulated_headers: dict[str, str],
    simulated_set_cookies: list[str],
    csp_result: CspSimulationResult | None,
    cookie_result: CookieSimulationResult | None,
    compatibility_warnings: list[CompatibilityWarning],
    application_profile: str = "Fintech / Payment Application",
) -> EvaluatedSimulation:
    """Re-run real scanner rules + risk engine on the virtual configuration."""
    virtual_findings: list[StandardFinding] = []

    # 1. Re-run real header scanner rules
    hdr_findings = analyze_headers(simulated_headers, scheme=snapshot.scheme, target_path="/")
    virtual_findings.extend(hdr_findings)

    # 2. Re-run real cookie scanner rules
    cookie_findings = analyze_set_cookie_headers(
        simulated_set_cookies, scheme=snapshot.scheme, target_path="/session-test"
    )
    virtual_findings.extend(cookie_findings)

    # 3. Preserve non-simulated findings (TLS & exposed files) from snapshot
    for f in snapshot.findings:
        rid = str(f["rule_id"])
        if rid.startswith("TLS-") or rid.startswith("FILE-"):
            virtual_findings.append(
                StandardFinding(
                    rule_id=rid,
                    title=str(f["title"]),
                    category="TLS / Transport Security" if rid.startswith("TLS-") else "Exposed Files & Endpoints",
                    severity=str(f["severity"]),
                    target_path=str(f["target_path"]),
                    evidence="Preserved from baseline scan snapshot.",
                    description=str(f["title"]),
                    remediation_reference="Apply corresponding hardening control.",
                    owasp_mapping=str(f["owasp_category"]),
                )
            )

    assessments = []
    remaining_dicts: list[dict[str, Any]] = []
    for vf in virtual_findings:
        if not vf.owasp_mapping:
            vf.owasp_mapping = map_finding_to_owasp(vf)
        assessment = assess_finding_risk(vf, application_profile=application_profile)
        assessments.append(assessment)
        remaining_dicts.append(
            {
                "rule_id": vf.rule_id,
                "title": vf.title,
                "severity": vf.severity,
                "risk_score": assessment.risk_score,
                "status": "Remaining",
            }
        )

    projected_score = compute_overall_security_score(assessments)
    baseline_risk = sum(float(f["risk_score"]) for f in snapshot.findings)
    projected_risk = sum(a.risk_score for a in assessments)
    risk_reduction = round(baseline_risk - projected_risk, 2)

    total_evaluated_controls = 9  # 6 headers + 3 cookie controls
    failed_simulated = len(hdr_findings) + len(cookie_findings)
    passed_simulated = max(0, total_evaluated_controls - failed_simulated)

    # Determine classification honestly
    has_blocking_compat = any(w.severity == "High" for w in compatibility_warnings)
    if csp_result is not None and (not csp_result.valid_syntax or csp_result.report_only):
        classification = "NOT RESOLVED" if not csp_result.valid_syntax else "CONDITIONAL"
    elif has_blocking_compat or (cookie_result is not None and not cookie_result.https_compatible):
        classification = "CONDITIONAL"
    elif len(remaining_dicts) < len(snapshot.findings):
        classification = "SIMULATED PASS"
    else:
        classification = "NOT RESOLVED"

    return EvaluatedSimulation(
        baseline_score=snapshot.baseline_score,
        projected_score=projected_score,
        expected_risk_reduction=risk_reduction,
        classification=classification,
        passed_checks=passed_simulated,
        failed_checks=failed_simulated,
        remaining_findings=remaining_dicts,
        compatibility_warnings=compatibility_warnings,
    )
