"""Security Proof Engine for SENTINEL AI (Phase 3).

Performs before-and-after scan comparison using stable (rule_id, target_path)
matching and only marks findings resolved when verified by a subsequent completed scan.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select

from config import DATABASE_URL
from database.database import get_session, init_db
from database.models import Finding, Scan


class SecurityProofError(ValueError):
    """Raised when a before-and-after scan comparison cannot be performed safely."""


@dataclass(frozen=True)
class SecurityProofResult:
    """Verified before-and-after security comparison result."""

    baseline_scan_id: int
    followup_scan_id: int
    target_url: str
    original_security_score: float
    updated_security_score: float
    fixed_vulnerabilities: list[dict[str, Any]]
    remaining_vulnerabilities: list[dict[str, Any]]
    newly_discovered_vulnerabilities: list[dict[str, Any]]
    baseline_total_risk: float
    followup_total_risk: float
    risk_reduction: float
    percentage_improvement: float


def _finding_key(finding: Finding) -> tuple[str, str]:
    """Stable matching key combining rule_id and normalized target_path."""
    return (
        (finding.rule_id or "").strip().upper(),
        (finding.target_path or "/").strip(),
    )


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "rule_id": finding.rule_id,
        "target_path": finding.target_path,
        "title": finding.title,
        "severity": finding.severity,
        "risk_score": float(finding.risk_score or 0.0),
        "owasp_category": finding.owasp_category,
        "finding_status": finding.finding_status,
    }


def compare_scans(
    baseline_scan_id: int,
    followup_scan_id: int,
    *,
    mark_verified_resolved: bool = True,
    database_url: str = DATABASE_URL,
) -> SecurityProofResult:
    """Compare a baseline scan against a follow-up scan and verify resolved findings."""
    if baseline_scan_id == followup_scan_id:
        raise SecurityProofError("Select two different scans to run Security Proof comparison.")

    init_db(database_url)
    with get_session(database_url) as session:
        baseline = session.get(Scan, baseline_scan_id)
        followup = session.get(Scan, followup_scan_id)

        if baseline is None or followup is None:
            raise SecurityProofError("One or both selected scans could not be found in SQLite.")

        if baseline.status != "completed" or followup.status != "completed":
            raise SecurityProofError(
                f"Both scans must have status 'completed' (got baseline='{baseline.status}', "
                f"follow-up='{followup.status}'). Incomplete or failed scans cannot verify fixes."
            )

        if baseline.target_url.rstrip("/") != followup.target_url.rstrip("/"):
            raise SecurityProofError(
                "Scans must target the same application URL to produce a valid Security Proof comparison."
            )

        baseline_findings = list(
            session.scalars(select(Finding).where(Finding.scan_id == baseline_scan_id)).all()
        )
        followup_findings = list(
            session.scalars(select(Finding).where(Finding.scan_id == followup_scan_id)).all()
        )

        baseline_map: dict[tuple[str, str], Finding] = {
            _finding_key(f): f for f in baseline_findings
        }
        followup_map: dict[tuple[str, str], Finding] = {
            _finding_key(f): f for f in followup_findings
        }

        fixed: list[dict[str, Any]] = []
        remaining: list[dict[str, Any]] = []
        newly_discovered: list[dict[str, Any]] = []

        for key, b_finding in baseline_map.items():
            if key not in followup_map:
                if mark_verified_resolved:
                    b_finding.finding_status = "resolved"
                fixed.append(_finding_to_dict(b_finding))
            else:
                remaining.append(_finding_to_dict(followup_map[key]))

        for key, f_finding in followup_map.items():
            if key not in baseline_map:
                newly_discovered.append(_finding_to_dict(f_finding))

        baseline_risk = round(sum(float(f.risk_score or 0.0) for f in baseline_findings), 2)
        followup_risk = round(sum(float(f.risk_score or 0.0) for f in followup_findings), 2)
        risk_reduction = round(baseline_risk - followup_risk, 2)

        if baseline_risk > 0:
            pct_improvement = round((risk_reduction / baseline_risk) * 100.0, 1)
        else:
            pct_improvement = 0.0

        return SecurityProofResult(
            baseline_scan_id=baseline_scan_id,
            followup_scan_id=followup_scan_id,
            target_url=followup.target_url,
            original_security_score=float(baseline.security_score or 0.0),
            updated_security_score=float(followup.security_score or 0.0),
            fixed_vulnerabilities=fixed,
            remaining_vulnerabilities=remaining,
            newly_discovered_vulnerabilities=newly_discovered,
            baseline_total_risk=baseline_risk,
            followup_total_risk=followup_risk,
            risk_reduction=risk_reduction,
            percentage_improvement=pct_improvement,
        )
