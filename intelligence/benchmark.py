"""SENTINEL Security Benchmark Engine (Unique Feature 1).

Compares Application A (High-Security Reference) and Application B (Low-Security Demo Lab)
using genuine scanner results—never assuming either passes or fails automatically.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from config import DATABASE_URL
from database.database import log_audit_event, save_benchmark_run
from scanner.orchestrator import ScanExecutionResult, run_security_scan

SECURITY_CONTROLS: list[tuple[str, str, str]] = [
    ("HDR-001", "Content-Security-Policy", "Security Headers"),
    ("HDR-002", "Strict-Transport-Security (HTTPS)", "Security Headers"),
    ("HDR-003", "Clickjacking Protection (XFO / CSP)", "Security Headers"),
    ("HDR-004", "X-Content-Type-Options (nosniff)", "Security Headers"),
    ("HDR-005", "Referrer-Policy", "Security Headers"),
    ("HDR-006", "Permissions-Policy", "Security Headers"),
    ("COOKIE-001", "Cookie HttpOnly Flag", "Cookie Security"),
    ("COOKIE-002", "Cookie Secure Flag", "Cookie Security"),
    ("COOKIE-003", "Cookie SameSite Attribute", "Cookie Security"),
    ("TLS-000", "Encrypted HTTPS Transport", "TLS / Transport"),
    ("FILE-001", "Protected /.env Endpoint", "Exposed Files"),
    ("FILE-002", "Protected /config.json Endpoint", "Exposed Files"),
    ("FILE-003", "Protected /backup.zip Endpoint", "Exposed Files"),
    ("FILE-004", "Protected /phpinfo.php Endpoint", "Exposed Files"),
    ("FILE-005", "Protected /server-status Endpoint", "Exposed Files"),
]


@dataclass(frozen=True)
class BenchmarkComparison:
    """Side-by-side Security Benchmark comparison result."""

    benchmark_id: int
    high_sec_url: str
    low_sec_url: str
    high_sec_scan_id: int
    low_sec_scan_id: int
    high_sec_score: float
    low_sec_score: float
    high_sec_severity_counts: dict[str, int]
    low_sec_severity_counts: dict[str, int]
    control_matrix: list[dict[str, str]]
    high_sec_error: str | None = None
    low_sec_error: str | None = None


def _count_severities(result: ScanExecutionResult | None) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    if result is None:
        return counts
    for f in result.findings:
        sev = f.severity if f.severity in counts else "Info"
        counts[sev] += 1
    return counts


def _control_status(
    rule_id: str,
    result: ScanExecutionResult | None,
    error_msg: str | None,
    target_url: str,
) -> str:
    if error_msg or result is None:
        return "Scan Error"
    if rule_id == "HDR-002" and target_url.startswith("http://"):
        return "Not Applicable"
    failed_rules = {f.rule_id for f in result.findings}
    if rule_id in failed_rules:
        return "Failed"
    return "Passed"


def run_security_benchmark(
    *,
    high_sec_url: str,
    low_sec_url: str,
    application_profile: str = "Fintech / Payment Application",
    database_url: str = DATABASE_URL,
) -> BenchmarkComparison:
    """Execute genuine scans on both local targets and persist a side-by-side benchmark."""
    high_res: ScanExecutionResult | None = None
    low_res: ScanExecutionResult | None = None
    high_err: str | None = None
    low_err: str | None = None

    try:
        high_res = run_security_scan(
            high_sec_url,
            application_profile=application_profile,
            database_url=database_url,
        )
    except Exception as exc:
        high_err = str(exc)

    try:
        low_res = run_security_scan(
            low_sec_url,
            application_profile=application_profile,
            database_url=database_url,
        )
    except Exception as exc:
        low_err = str(exc)

    matrix: list[dict[str, str]] = []
    for rule_id, control_name, domain in SECURITY_CONTROLS:
        matrix.append(
            {
                "Rule ID": rule_id,
                "Domain": domain,
                "Security Control": control_name,
                "Application A (High-Security)": _control_status(
                    rule_id, high_res, high_err, high_sec_url
                ),
                "Application B (Low-Security)": _control_status(
                    rule_id, low_res, low_err, low_sec_url
                ),
            }
        )

    high_score = high_res.security_score if high_res else 0.0
    low_score = low_res.security_score if low_res else 0.0
    high_sev = _count_severities(high_res)
    low_sev = _count_severities(low_res)

    summary_payload = {
        "high_sec_url": high_sec_url,
        "low_sec_url": low_sec_url,
        "high_sec_score": high_score,
        "low_sec_score": low_score,
        "high_sec_severity_counts": high_sev,
        "low_sec_severity_counts": low_sev,
        "control_matrix": matrix,
        "high_sec_error": high_err,
        "low_sec_error": low_err,
    }

    bench_id = save_benchmark_run(
        high_sec_scan_id=high_res.scan_id if high_res else 0,
        low_sec_scan_id=low_res.scan_id if low_res else 0,
        high_sec_score=high_score,
        low_sec_score=low_score,
        summary_json=json.dumps(summary_payload),
        database_url=database_url,
    )

    log_audit_event(
        event_type="BENCHMARK_EXECUTED",
        target_url=f"{high_sec_url} vs {low_sec_url}",
        status="completed" if not (high_err or low_err) else "partial_error",
        details=(
            f"Benchmark #{bench_id}: High-Sec Score={high_score}, "
            f"Low-Sec Score={low_score}."
        ),
        database_url=database_url,
    )

    return BenchmarkComparison(
        benchmark_id=bench_id,
        high_sec_url=high_sec_url,
        low_sec_url=low_sec_url,
        high_sec_scan_id=high_res.scan_id if high_res else 0,
        low_sec_scan_id=low_res.scan_id if low_res else 0,
        high_sec_score=high_score,
        low_sec_score=low_score,
        high_sec_severity_counts=high_sev,
        low_sec_severity_counts=low_sev,
        control_matrix=matrix,
        high_sec_error=high_err,
        low_sec_error=low_err,
    )
