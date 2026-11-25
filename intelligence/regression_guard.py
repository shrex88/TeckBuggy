"""Security Regression Guard for SENTINEL AI (Unique Feature 9).

Compares a previously verified scan against a later scan of the same authorised
local target to detect returning vulnerabilities, score drops, and control drift.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select

from config import DATABASE_URL
from database.database import get_session, init_db, log_audit_event, save_regression_alert
from database.models import Finding, Scan


class RegressionGuardError(ValueError):
    """Raised when a regression check cannot be performed safely."""


@dataclass(frozen=True)
class RegressionReport:
    """Result of comparing a verified baseline scan against a later scan."""

    baseline_scan_id: int
    latest_scan_id: int
    target_url: str
    score_delta: float
    returning_fixed_vulnerabilities: list[dict[str, Any]]
    newly_introduced_vulnerabilities: list[dict[str, Any]]
    header_regressions: list[str]
    cookie_regressions: list[str]
    exposed_file_regressions: list[str]
    alerts_generated: int


def _key(f: Finding) -> tuple[str, str]:
    return ((f.rule_id or "").strip().upper(), (f.target_path or "/").strip())


def evaluate_security_regression(
    baseline_scan_id: int,
    latest_scan_id: int,
    *,
    database_url: str = DATABASE_URL,
) -> RegressionReport:
    """Detect regressions between an earlier verified scan and a newer scan."""
    if baseline_scan_id == latest_scan_id:
        raise RegressionGuardError("Select two different scans to evaluate regression.")

    init_db(database_url)
    with get_session(database_url) as session:
        baseline = session.get(Scan, baseline_scan_id)
        latest = session.get(Scan, latest_scan_id)

        if baseline is None or latest is None:
            raise RegressionGuardError("Selected scans were not found in SQLite.")
        if baseline.status != "completed" or latest.status != "completed":
            raise RegressionGuardError("Both scans must have status 'completed'.")
        if baseline.target_url.rstrip("/") != latest.target_url.rstrip("/"):
            raise RegressionGuardError("Scans must belong to the same authorised target URL.")

        base_findings = list(
            session.scalars(select(Finding).where(Finding.scan_id == baseline_scan_id)).all()
        )
        latest_findings = list(
            session.scalars(select(Finding).where(Finding.scan_id == latest_scan_id)).all()
        )

        # Any finding from baseline that was marked 'resolved' OR absent in a prior verified state
        base_map = {_key(f): f for f in base_findings}
        latest_map = {_key(f): f for f in latest_findings}

        returning: list[dict[str, Any]] = []
        newly_introduced: list[dict[str, Any]] = []
        header_regs: list[str] = []
        cookie_regs: list[str] = []
        file_regs: list[str] = []

        for k, lf in latest_map.items():
            bf = base_map.get(k)
            is_returning = bf is not None and (bf.finding_status or "").lower() == "resolved"
            is_new = bf is None
            if is_returning:
                returning.append(
                    {
                        "rule_id": lf.rule_id,
                        "title": lf.title,
                        "target_path": lf.target_path,
                        "severity": lf.severity,
                    }
                )
            elif is_new:
                newly_introduced.append(
                    {
                        "rule_id": lf.rule_id,
                        "title": lf.title,
                        "target_path": lf.target_path,
                        "severity": lf.severity,
                    }
                )

            if is_returning or is_new:
                rid = (lf.rule_id or "").upper()
                if rid.startswith("HDR-"):
                    header_regs.append(f"{lf.rule_id}: {lf.title}")
                elif rid.startswith("COOKIE-"):
                    cookie_regs.append(f"{lf.rule_id}: {lf.title}")
                elif rid.startswith("FILE-"):
                    file_regs.append(f"{lf.rule_id}: {lf.title}")

        score_delta = round(
            float(latest.security_score or 0.0) - float(baseline.security_score or 0.0), 1
        )
        target_url = latest.target_url

    alerts_count = 0
    if returning:
        save_regression_alert(
            baseline_scan_id=baseline_scan_id,
            latest_scan_id=latest_scan_id,
            target_url=target_url,
            alert_type="REGRESSED_VERIFIED_CONTROLS",
            severity="High",
            details=f"{len(returning)} previously resolved finding(s) returned.",
            database_url=database_url,
        )
        alerts_count += 1

    if score_delta < 0:
        save_regression_alert(
            baseline_scan_id=baseline_scan_id,
            latest_scan_id=latest_scan_id,
            target_url=target_url,
            alert_type="SECURITY_SCORE_DETERIORATION",
            severity="High" if score_delta <= -15 else "Medium",
            details=f"Security score dropped by {abs(score_delta):.1f} points.",
            database_url=database_url,
        )
        alerts_count += 1

    if newly_introduced:
        save_regression_alert(
            baseline_scan_id=baseline_scan_id,
            latest_scan_id=latest_scan_id,
            target_url=target_url,
            alert_type="NEW_MISCONFIGURATION_DETECTED",
            severity="Medium",
            details=f"{len(newly_introduced)} new misconfiguration(s) detected.",
            database_url=database_url,
        )
        alerts_count += 1

    log_audit_event(
        event_type="REGRESSION_GUARD_CHECK",
        target_url=target_url,
        status="alert" if alerts_count > 0 else "clean",
        details=(
            f"Compared scan #{baseline_scan_id} -> #{latest_scan_id}: "
            f"returning={len(returning)}, new={len(newly_introduced)}, score_delta={score_delta:+.1f}"
        ),
        database_url=database_url,
    )

    return RegressionReport(
        baseline_scan_id=baseline_scan_id,
        latest_scan_id=latest_scan_id,
        target_url=target_url,
        score_delta=score_delta,
        returning_fixed_vulnerabilities=returning,
        newly_introduced_vulnerabilities=newly_introduced,
        header_regressions=header_regs,
        cookie_regressions=cookie_regs,
        exposed_file_regressions=file_regs,
        alerts_generated=alerts_count,
    )
