"""Explainable AI Risk Intelligence Engine for SENTINEL AI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from config import APPLICATION_PROFILES

if TYPE_CHECKING:
    from scanner.models import StandardFinding

SEVERITY_BASE_SCORES: dict[str, float] = {
    "Critical": 95.0,
    "High": 80.0,
    "Medium": 55.0,
    "Low": 25.0,
    "Info": 10.0,
}

FACTOR_WEIGHTS: dict[str, float] = {
    "severity": 0.30,
    "exposure": 0.25,
    "data_sensitivity": 0.20,
    "exploitability": 0.15,
    "confidence": 0.10,
}


@dataclass(frozen=True)
class RiskAssessment:
    """Explainable risk score breakdown for a single finding."""

    risk_score: float
    risk_category: str
    application_profile: str
    factor_breakdown: dict[str, float]
    weighted_contributions: dict[str, float]
    explanation: str
    remediation_priority: str
    fintech_impact: dict[str, str]


def _clamp_0_100(value: float) -> float:
    return max(0.0, min(100.0, float(value)))


def classify_risk_level(score: float) -> str:
    """Classify a 0-100 risk score into Critical, High, Medium, or Low."""
    rounded = round(score)
    if rounded >= 90:
        return "Critical"
    if rounded >= 70:
        return "High"
    if rounded >= 40:
        return "Medium"
    return "Low"


def _priority_for_category(risk_category: str) -> str:
    if risk_category == "Critical":
        return "P0 — Immediate (Remediate within 24 hours)"
    if risk_category == "High":
        return "P1 — Urgent (Remediate within current sprint)"
    if risk_category == "Medium":
        return "P2 — Scheduled (Plan in upcoming release)"
    return "P3 — Advisory (Harden during routine maintenance)"


def assess_finding_risk(
    finding: StandardFinding,
    *,
    application_profile: str = "General Web Application",
) -> RiskAssessment:
    """Compute a transparent, rule-based weighted risk score for a finding."""
    profile_meta: dict[str, Any] = APPLICATION_PROFILES.get(
        application_profile,
        APPLICATION_PROFILES["General Web Application"],
    )
    resolved_profile = (
        application_profile
        if application_profile in APPLICATION_PROFILES
        else "General Web Application"
    )

    severity_score = _clamp_0_100(SEVERITY_BASE_SCORES.get(finding.severity, 25.0))
    exposure_score = _clamp_0_100(finding.exposure)
    data_sensitivity_score = _clamp_0_100(float(profile_meta["data_sensitivity"]))
    exploitability_score = _clamp_0_100(finding.exploitability)
    confidence_score = _clamp_0_100(finding.confidence)

    factor_breakdown = {
        "severity": severity_score,
        "exposure": exposure_score,
        "data_sensitivity": data_sensitivity_score,
        "exploitability": exploitability_score,
        "confidence": confidence_score,
    }

    weighted_contributions = {
        k: round(factor_breakdown[k] * FACTOR_WEIGHTS[k], 2)
        for k in FACTOR_WEIGHTS
    }

    total_score = round(_clamp_0_100(sum(weighted_contributions.values())), 2)
    risk_category = classify_risk_level(total_score)
    priority = _priority_for_category(risk_category)

    explanation = (
        f"Score {total_score:.1f}/100 ({risk_category}) computed from Severity "
        f"({severity_score:.0f}×0.30={weighted_contributions['severity']:.1f}), "
        f"Exposure ({exposure_score:.0f}×0.25={weighted_contributions['exposure']:.1f}), "
        f"Data Sensitivity ({data_sensitivity_score:.0f}×0.20={weighted_contributions['data_sensitivity']:.1f} "
        f"under '{resolved_profile}' assumption), "
        f"Exploitability ({exploitability_score:.0f}×0.15={weighted_contributions['exploitability']:.1f}), "
        f"and Confidence ({confidence_score:.0f}×0.10={weighted_contributions['confidence']:.1f}). "
        f"{profile_meta['assumption']}"
    )

    fintech_impact = build_fintech_impact_analysis(finding, resolved_profile)

    return RiskAssessment(
        risk_score=total_score,
        risk_category=risk_category,
        application_profile=resolved_profile,
        factor_breakdown=factor_breakdown,
        weighted_contributions=weighted_contributions,
        explanation=explanation,
        remediation_priority=priority,
        fintech_impact=fintech_impact,
    )


def build_fintech_impact_analysis(
    finding: "StandardFinding",
    application_profile: str,
) -> dict[str, str]:
    """Generate contextual Fintech & web application impact notes without claiming unverified breaches."""
    rid = (finding.rule_id or "").upper()
    is_fintech = application_profile == "Fintech / Payment Application"
    prefix = "High-sensitivity payment context: " if is_fintech else f"{application_profile} context: "

    if rid.startswith("COOKIE-"):
        sessions = f"{prefix}Weak cookie flags increase exposure of authenticated customer sessions to XSS or CSRF."
    elif rid == "HDR-001":
        sessions = f"{prefix}Absent CSP increases script-injection risk against active customer sessions."
    else:
        sessions = f"{prefix}Indirect session impact depending on client-side execution controls."

    if rid.startswith("TLS-") or rid in {"HDR-002", "COOKIE-002"}:
        payment = f"{prefix}Transport or cookie encryption gaps weaken protection of payment-flow requests."
    elif rid.startswith("FILE-"):
        payment = f"{prefix}Exposed configuration endpoints may reveal topology or synthetic/test parameters."
    else:
        payment = f"{prefix}Hardening defense-in-depth reduces payment-interface attack surface."

    confidentiality = (
        f"{prefix}Potential confidentiality exposure if sensitive metadata or tokens are transmitted without strict controls (configured assumption, not proof of data breach)."
    )
    configuration = f"Direct configuration gap detected at '{finding.target_path}' ({finding.rule_id})."
    availability = "Low direct availability impact; primarily a confidentiality/integrity hardening issue."

    return {
        "Customer Sessions": sessions,
        "Payment Application Security": payment,
        "Data Confidentiality": confidentiality,
        "Application Configuration": configuration,
        "Application Availability": availability,
    }


def compute_overall_security_score(assessments: list[RiskAssessment]) -> float:
    """Compute an overall 0-100 security posture score from finding risk assessments."""
    if not assessments:
        return 100.0
    penalty = 0.0
    for a in assessments:
        if a.risk_category == "Critical":
            penalty += 18.0
        elif a.risk_category == "High":
            penalty += 10.0
        elif a.risk_category == "Medium":
            penalty += 5.0
        else:
            penalty += 2.0
    return round(max(0.0, 100.0 - penalty), 1)
