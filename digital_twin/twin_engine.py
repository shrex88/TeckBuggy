"""High-level orchestrator for SENTINEL AI Security Digital Twin."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from config import DATABASE_URL
from database.database import log_audit_event
from digital_twin.compatibility_checker import check_compatibility
from digital_twin.configuration_snapshot import VirtualSnapshot, create_virtual_snapshot
from digital_twin.cookie_simulator import CookieSimulationResult, simulate_cookie_policy
from digital_twin.csp_simulator import RECOMMENDED_CSP, CspSimulationResult, simulate_csp_policy
from digital_twin.simulation_evaluator import EvaluatedSimulation, evaluate_virtual_configuration
from digital_twin.simulation_history import save_simulation_history


@dataclass(frozen=True)
class DigitalTwinRunResult:
    """Complete result returned by running a Digital Twin What-If simulation."""

    simulation_id: int
    snapshot: VirtualSnapshot
    simulation_mode: str
    csp_result: CspSimulationResult | None
    cookie_result: CookieSimulationResult | None
    evaluation: EvaluatedSimulation
    proposed_changes: list[tuple[str, str, str]]


def run_digital_twin_simulation(
    *,
    target_url: str,
    app_label: str = "Authorised Local App",
    simulation_mode: str = "Both (CSP + Cookies)",
    proposed_csp: str = RECOMMENDED_CSP,
    csp_report_only: bool = False,
    enable_secure_cookie: bool = True,
    enable_httponly_cookie: bool = True,
    samesite: str = "Lax",
    enable_additional_headers: bool = False,
    application_profile: str = "Fintech / Payment Application",
    database_url: str = DATABASE_URL,
) -> DigitalTwinRunResult:
    """Execute an isolated What-If simulation without modifying the live application."""
    snapshot = create_virtual_snapshot(
        target_url, app_label=app_label, database_url=database_url
    )

    sim_headers = dict(snapshot.headers)
    sim_cookies: list[str] = []
    proposed_changes: list[tuple[str, str, str]] = []

    csp_res: CspSimulationResult | None = None
    cookie_res: CookieSimulationResult | None = None

    include_csp = simulation_mode in {"CSP Only", "Both (CSP + Cookies)", "Custom"}
    include_cookies = simulation_mode in {"Cookies Only", "Both (CSP + Cookies)", "Custom"}

    if include_csp:
        existing_csp = snapshot.headers.get("Content-Security-Policy")
        csp_res = simulate_csp_policy(
            proposed_csp, existing_csp=existing_csp, report_only=csp_report_only
        )
        if csp_res.valid_syntax and not csp_res.report_only:
            sim_headers["Content-Security-Policy"] = csp_res.policy_value
        proposed_changes.append(
            (
                csp_res.header_name,
                existing_csp or "Missing",
                csp_res.policy_value,
            )
        )

    if enable_additional_headers:
        for hdr, val in (
            ("X-Frame-Options", "DENY"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            ("Permissions-Policy", "geolocation=(), microphone=(), camera=()"),
        ):
            if hdr not in sim_headers:
                proposed_changes.append((hdr, "Missing", val))
                sim_headers[hdr] = val

    if include_cookies:
        base_cookie = snapshot.cookies_meta[0] if snapshot.cookies_meta else {}
        orig_cookie_desc = (
            f"HttpOnly={base_cookie.get('httponly', False)}, "
            f"Secure={base_cookie.get('secure', False)}, "
            f"SameSite={base_cookie.get('samesite') or 'Unset'}"
        )
        cookie_res = simulate_cookie_policy(
            cookie_name=str(base_cookie.get("name", "sentinel_session_cookie")),
            scheme=snapshot.scheme,
            enable_secure=enable_secure_cookie,
            enable_httponly=enable_httponly_cookie,
            samesite=samesite,
        )
        sim_cookies.append(cookie_res.simulated_set_cookie_header)
        proposed_changes.append(
            (
                "Session Cookie Policy",
                orig_cookie_desc,
                cookie_res.simulated_set_cookie_header,
            )
        )
    else:
        for cm in snapshot.cookies_meta:
            parts = [f"{cm.get('name', 'session')}=<REDACTED>"]
            if cm.get("httponly"):
                parts.append("HttpOnly")
            if cm.get("secure"):
                parts.append("Secure")
            if cm.get("samesite"):
                parts.append(f"SameSite={cm['samesite']}")
            sim_cookies.append("; ".join(parts))

    warnings = check_compatibility(
        scheme=snapshot.scheme,
        csp_result=csp_res,
        cookie_result=cookie_res,
    )

    evaluation = evaluate_virtual_configuration(
        snapshot=snapshot,
        simulated_headers=sim_headers,
        simulated_set_cookies=sim_cookies,
        csp_result=csp_res,
        cookie_result=cookie_res,
        compatibility_warnings=warnings,
        application_profile=application_profile,
    )

    summary = (
        f"Mode={simulation_mode} | Baseline={evaluation.baseline_score:.1f} -> "
        f"Projected={evaluation.projected_score:.1f} | {evaluation.classification}"
    )

    sim_id = save_simulation_history(
        snapshot_id=snapshot.snapshot_id,
        target_url=snapshot.target_url,
        simulation_mode=simulation_mode,
        baseline_score=evaluation.baseline_score,
        projected_score=evaluation.projected_score,
        classification=evaluation.classification,
        passed_checks=evaluation.passed_checks,
        failed_checks=evaluation.failed_checks,
        summary_text=summary,
        proposed_changes=proposed_changes,
        remaining_findings=evaluation.remaining_findings,
        compatibility_warnings=[
            {
                "domain": w.domain,
                "severity": w.severity,
                "warning_title": w.warning_title,
                "explanation": w.explanation,
            }
            for w in warnings
        ],
        database_url=database_url,
    )

    log_audit_event(
        event_type="DIGITAL_TWIN_SIMULATION",
        target_url=snapshot.target_url,
        status=evaluation.classification,
        details=summary,
        database_url=database_url,
    )

    return DigitalTwinRunResult(
        simulation_id=sim_id,
        snapshot=snapshot,
        simulation_mode=simulation_mode,
        csp_result=csp_res,
        cookie_result=cookie_res,
        evaluation=evaluation,
        proposed_changes=proposed_changes,
    )
