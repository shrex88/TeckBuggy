"""HTTP Security Header Scanner for SENTINEL AI."""

from __future__ import annotations

import re
from typing import Any

import requests

from scanner.models import StandardFinding
from scanner.target_validator import ValidatedTarget, safe_fetch, validate_target_url


def _has_csp_frame_ancestors(csp_value: str | None) -> bool:
    """Return True if a Content-Security-Policy header defines a non-wildcard frame-ancestors directive."""
    if not csp_value:
        return False
    match = re.search(r"(?:^|;)\s*frame-ancestors\s+([^;]+)", csp_value, flags=re.IGNORECASE)
    if not match:
        return False
    directive_val = match.group(1).strip()
    return bool(directive_val) and directive_val != "*"


def _make_header_finding(
    *,
    rule_id: str,
    header_name: str,
    current_value: str | None,
    expected_value: str,
    severity: str,
    title: str,
    description: str,
    evidence: str,
    recommended_fix: str,
    target_path: str,
    exposure: float = 80.0,
    exploitability: float = 50.0,
) -> StandardFinding:
    return StandardFinding(
        rule_id=rule_id,
        title=title,
        category="Security Headers",
        severity=severity,
        target_path=target_path,
        evidence=evidence,
        description=description,
        remediation_reference=recommended_fix,
        confidence=95.0,
        exposure=exposure,
        exploitability=exploitability,
        metadata={
            "finding_id": rule_id,
            "header_name": header_name,
            "current_value": current_value if current_value is not None else "Missing",
            "expected_value": expected_value,
            "severity": severity,
            "description": description,
            "technical_evidence": evidence,
            "recommended_fix": recommended_fix,
        },
    )


def analyze_headers(
    headers: dict[str, str],
    *,
    scheme: str,
    target_path: str = "/",
) -> list[StandardFinding]:
    """Analyse HTTP response headers for missing or misconfigured security headers."""
    normalized = {k.lower(): v for k, v in headers.items()}
    findings: list[StandardFinding] = []

    csp = normalized.get("content-security-policy")
    if not csp:
        findings.append(
            _make_header_finding(
                rule_id="HDR-001",
                header_name="Content-Security-Policy",
                current_value=None,
                expected_value="default-src 'self'; frame-ancestors 'none'; object-src 'none'",
                severity="High",
                title="Missing Content-Security-Policy Header",
                description=(
                    "The application does not send a Content-Security-Policy (CSP) header, "
                    "increasing exposure to Cross-Site Scripting (XSS) and unauthorized resource loading."
                ),
                evidence=f"HTTP response for '{target_path}' omitted the Content-Security-Policy header.",
                recommended_fix=(
                    "Configure a strict Content-Security-Policy header restricting script-src, "
                    "object-src, and frame-ancestors."
                ),
                target_path=target_path,
                exposure=85.0,
                exploitability=65.0,
            )
        )

    if scheme.lower() == "https":
        hsts = normalized.get("strict-transport-security")
        if not hsts or "max-age=" not in hsts.lower():
            findings.append(
                _make_header_finding(
                    rule_id="HDR-002",
                    header_name="Strict-Transport-Security",
                    current_value=hsts,
                    expected_value="max-age=31536000; includeSubDomains",
                    severity="High",
                    title="Missing or Weak Strict-Transport-Security (HSTS) Header",
                    description=(
                        "HTTPS responses without HSTS allow protocol downgrade and SSL-stripping "
                        "risks on subsequent client connections."
                    ),
                    evidence=(
                        f"HTTPS response for '{target_path}' returned "
                        f"Strict-Transport-Security={hsts!r}."
                    ),
                    recommended_fix=(
                        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
                        "to all HTTPS responses."
                    ),
                    target_path=target_path,
                    exposure=80.0,
                    exploitability=55.0,
                )
            )

    xfo = normalized.get("x-frame-options")
    if not xfo and not _has_csp_frame_ancestors(csp):
        findings.append(
            _make_header_finding(
                rule_id="HDR-003",
                header_name="X-Frame-Options",
                current_value=None,
                expected_value="DENY (or CSP frame-ancestors 'none'/'self')",
                severity="Medium",
                title="Missing Clickjacking Protection (X-Frame-Options / CSP frame-ancestors)",
                description=(
                    "Neither X-Frame-Options nor a restrictive CSP frame-ancestors directive is set, "
                    "allowing the page to be embedded in third-party iframes."
                ),
                evidence=(
                    f"Response for '{target_path}' lacks X-Frame-Options and CSP frame-ancestors."
                ),
                recommended_fix=(
                    "Set 'X-Frame-Options: DENY' (or 'SAMEORIGIN') and define "
                    "'frame-ancestors' in Content-Security-Policy."
                ),
                target_path=target_path,
                exposure=75.0,
                exploitability=50.0,
            )
        )

    xcto = normalized.get("x-content-type-options")
    if not xcto or xcto.strip().lower() != "nosniff":
        findings.append(
            _make_header_finding(
                rule_id="HDR-004",
                header_name="X-Content-Type-Options",
                current_value=xcto,
                expected_value="nosniff",
                severity="Medium",
                title="Missing or Invalid X-Content-Type-Options Header",
                description=(
                    "Without 'X-Content-Type-Options: nosniff', browsers may MIME-sniff responses "
                    "away from the declared Content-Type."
                ),
                evidence=f"Response for '{target_path}' returned X-Content-Type-Options={xcto!r}.",
                recommended_fix="Set 'X-Content-Type-Options: nosniff' on all HTTP responses.",
                target_path=target_path,
                exposure=75.0,
                exploitability=45.0,
            )
        )

    ref_policy = normalized.get("referrer-policy")
    if not ref_policy:
        findings.append(
            _make_header_finding(
                rule_id="HDR-005",
                header_name="Referrer-Policy",
                current_value=None,
                expected_value="strict-origin-when-cross-origin",
                severity="Low",
                title="Missing Referrer-Policy Header",
                description=(
                    "No Referrer-Policy header was returned, which may leak full URLs or query "
                    "parameters in the Referer header during cross-origin navigation."
                ),
                evidence=f"HTTP response for '{target_path}' omitted Referrer-Policy.",
                recommended_fix="Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                target_path=target_path,
                exposure=65.0,
                exploitability=30.0,
            )
        )

    perm_policy = normalized.get("permissions-policy")
    if not perm_policy:
        findings.append(
            _make_header_finding(
                rule_id="HDR-006",
                header_name="Permissions-Policy",
                current_value=None,
                expected_value="geolocation=(), microphone=(), camera=()",
                severity="Low",
                title="Missing Permissions-Policy Header",
                description=(
                    "Permissions-Policy is absent, leaving browser feature access (camera, "
                    "microphone, geolocation) unrestricted by response policy."
                ),
                evidence=f"HTTP response for '{target_path}' omitted Permissions-Policy.",
                recommended_fix=(
                    "Add a restrictive 'Permissions-Policy' header disabling unused browser APIs."
                ),
                target_path=target_path,
                exposure=60.0,
                exploitability=25.0,
            )
        )

    return findings


def scan_headers(
    target_url: str,
    *,
    session: requests.Session | None = None,
    validated: ValidatedTarget | None = None,
) -> tuple[list[StandardFinding], requests.Response]:
    """Fetch an authorised local target and run HTTP security header checks."""
    vt = validated or validate_target_url(target_url)
    resp = safe_fetch(vt.normalized_url, method="GET", session=session)
    findings = analyze_headers(dict(resp.headers), scheme=vt.scheme, target_path=vt.base_path)
    return findings, resp
