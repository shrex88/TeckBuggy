"""End-to-end defensive scan orchestrator for SENTINEL AI (Phase 2)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import requests

from config import DATABASE_URL
from database.database import save_scan_results
from intelligence.owasp_mapper import map_finding_to_owasp
from intelligence.risk_engine import (
    RiskAssessment,
    assess_finding_risk,
    compute_overall_security_score,
)
from scanner.cookie_scanner import scan_cookies
from scanner.exposed_file_scanner import scan_exposed_files
from scanner.header_scanner import scan_headers
from scanner.models import StandardFinding
from scanner.target_validator import ALLOWED_LOCAL_HOSTS, ValidatedTarget, validate_target_url
from scanner.tls_scanner import scan_tls

ProgressCallback = Callable[[float, str], None]


@dataclass
class ScanExecutionResult:
    """Result summary returned after a completed scan is persisted."""

    scan_id: int
    target_url: str
    application_profile: str
    security_score: float
    total_findings: int
    findings: list[StandardFinding]
    assessments: list[RiskAssessment]


def run_security_scan(
    target_url: str,
    *,
    application_profile: str = "General Web Application",
    user_id: int | None = None,
    allow_public: bool | None = None,
    database_url: str = DATABASE_URL,
    session: requests.Session | None = None,
    progress_callback: ProgressCallback | None = None,
) -> ScanExecutionResult:
    """Validate target, run all defensive scanners, score findings, and persist."""

    def _notify(pct: float, msg: str) -> None:
        if progress_callback is not None:
            progress_callback(pct, msg)

    _notify(0.10, "Validating target URL and SSRF policy...")
    validated: ValidatedTarget = validate_target_url(target_url, allow_public=allow_public)

    http_session = session or requests.Session()
    all_findings: list[StandardFinding] = []

    is_streamlit_self_port = validated.hostname in ALLOWED_LOCAL_HOSTS and validated.port == 8501

    _notify(0.25, "Inspecting HTTP security headers...")
    if not is_streamlit_self_port:
        header_findings, _ = scan_headers(
            validated.normalized_url, session=http_session, validated=validated, allow_public=allow_public
        )
        all_findings.extend(header_findings)

    _notify(0.45, "Analysing cookie security flags...")
    cookie_findings = scan_cookies(
        validated.normalized_url, session=http_session, validated=validated, allow_public=allow_public
    )
    all_findings.extend(cookie_findings)

    _notify(0.65, "Inspecting TLS & transport security...")
    tls_findings = scan_tls(validated.normalized_url, validated=validated, allow_public=allow_public)
    all_findings.extend(tls_findings)

    _notify(0.80, "Checking predefined exposed configuration paths...")
    file_findings = scan_exposed_files(
        validated.normalized_url, session=http_session, validated=validated, allow_public=allow_public
    )
    all_findings.extend(file_findings)

    _notify(0.90, "Mapping OWASP Top 10:2025 & computing AI risk scores...")
    assessments: list[RiskAssessment] = []
    db_finding_payloads: list[dict[str, object]] = []

    for finding in all_findings:
        finding.owasp_mapping = map_finding_to_owasp(finding)
        assessment = assess_finding_risk(
            finding, application_profile=application_profile
        )
        assessments.append(assessment)
        finding.metadata["risk_assessment"] = {
            "risk_score": assessment.risk_score,
            "risk_category": assessment.risk_category,
            "application_profile": assessment.application_profile,
            "factor_breakdown": assessment.factor_breakdown,
            "weighted_contributions": assessment.weighted_contributions,
            "explanation": assessment.explanation,
            "remediation_priority": assessment.remediation_priority,
        }
        db_finding_payloads.append(
            {
                "rule_id": finding.rule_id,
                "target_path": finding.target_path,
                "title": finding.title,
                "severity": finding.severity,
                "risk_score": assessment.risk_score,
                "evidence": f"{finding.evidence}\n\n[AI Risk Intelligence]\n{assessment.explanation}",
                "owasp_category": finding.owasp_mapping,
                "remediation": (
                    f"[{assessment.remediation_priority}] {finding.remediation_reference}"
                ),
                "finding_status": "open",
            }
        )

    security_score = compute_overall_security_score(assessments)

    _notify(0.95, "Persisting scan and findings to SQLite...")
    scan_id = save_scan_results(
        target_url=validated.normalized_url,
        security_score=security_score,
        findings_data=db_finding_payloads,
        user_id=user_id,
        status="completed",
        database_url=database_url,
    )

    _notify(1.0, "Scan completed successfully.")
    return ScanExecutionResult(
        scan_id=scan_id,
        target_url=validated.normalized_url,
        application_profile=application_profile,
        security_score=security_score,
        total_findings=len(all_findings),
        findings=all_findings,
        assessments=assessments,
    )
