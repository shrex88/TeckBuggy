"""Compatibility Checker for Security Digital Twin."""

from __future__ import annotations

from dataclasses import dataclass

from digital_twin.cookie_simulator import CookieSimulationResult
from digital_twin.csp_simulator import CspSimulationResult


@dataclass(frozen=True)
class CompatibilityWarning:
    """Structured compatibility warning produced by simulation."""

    domain: str
    severity: str
    warning_title: str
    explanation: str


def check_compatibility(
    *,
    scheme: str,
    csp_result: CspSimulationResult | None = None,
    cookie_result: CookieSimulationResult | None = None,
) -> list[CompatibilityWarning]:
    """Identify potential application compatibility issues from proposed CSP/cookie changes."""
    warnings: list[CompatibilityWarning] = []

    if csp_result is not None:
        if csp_result.syntax_errors:
            warnings.append(
                CompatibilityWarning(
                    domain="CSP",
                    severity="High",
                    warning_title="Invalid CSP Syntax",
                    explanation="; ".join(csp_result.syntax_errors),
                )
            )
        if csp_result.report_only:
            warnings.append(
                CompatibilityWarning(
                    domain="CSP",
                    severity="Info",
                    warning_title="CSP Report-Only Mode Active",
                    explanation="Content-Security-Policy-Report-Only logs violations without enforcing blocking; security finding remains unresolved until enforced.",
                )
            )
        parsed = csp_result.parsed_directives
        if "script-src" in parsed and "'unsafe-inline'" not in parsed["script-src"]:
            warnings.append(
                CompatibilityWarning(
                    domain="CSP",
                    severity="Medium",
                    warning_title="Inline & External Script Restriction",
                    explanation="Strict script-src blocks inline <script> tags and external CDN scripts unless explicitly allowlisted.",
                )
            )
        if "style-src" in parsed and "'unsafe-inline'" not in parsed["style-src"]:
            warnings.append(
                CompatibilityWarning(
                    domain="CSP",
                    severity="Low",
                    warning_title="Inline & External Stylesheet Restriction",
                    explanation="Strict style-src may block inline style attributes or external CSS CDNs.",
                )
            )
        if "img-src" in parsed or "font-src" in parsed:
            warnings.append(
                CompatibilityWarning(
                    domain="CSP",
                    severity="Low",
                    warning_title="External Image / Font Asset Check",
                    explanation="Verify that external images and web fonts are covered by img-src and font-src.",
                )
            )
        if "frame-ancestors" in parsed and "'none'" in parsed["frame-ancestors"]:
            warnings.append(
                CompatibilityWarning(
                    domain="CSP",
                    severity="Low",
                    warning_title="Iframe Embedding Disabled",
                    explanation="frame-ancestors 'none' prevents any third-party or internal iframe embedding.",
                )
            )

    if cookie_result is not None:
        if cookie_result.secure and scheme.lower() != "https":
            warnings.append(
                CompatibilityWarning(
                    domain="Cookie",
                    severity="High",
                    warning_title="Secure Cookie Requires HTTPS",
                    explanation="Target uses plain HTTP; enabling Secure may prevent browsers from storing or transmitting the session cookie until HTTPS is enabled.",
                )
            )
        if cookie_result.httponly:
            warnings.append(
                CompatibilityWarning(
                    domain="Cookie",
                    severity="Low",
                    warning_title="JavaScript Cookie Access Blocked",
                    explanation="Ensure no frontend JavaScript relies on reading this cookie via document.cookie.",
                )
            )
        if cookie_result.samesite.lower() == "strict":
            warnings.append(
                CompatibilityWarning(
                    domain="Cookie",
                    severity="Medium",
                    warning_title="SameSite=Strict Cross-Site Session Impact",
                    explanation="Users arriving from external links (e.g., OAuth/SSO or payment redirects) may need to re-authenticate.",
                )
            )
        elif cookie_result.samesite.lower() == "none" and not cookie_result.secure:
            warnings.append(
                CompatibilityWarning(
                    domain="Cookie",
                    severity="High",
                    warning_title="SameSite=None Requires Secure",
                    explanation="Modern browsers reject SameSite=None cookies unless Secure=True is also set.",
                )
            )

    return warnings
