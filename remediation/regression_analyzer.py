"""Deterministic Regression & Side-Effect Analyzer for SENTINEL AI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RegressionItem:
    """Structured potential side-effect assessment for a remediation proposal."""

    risk_description: str
    potential_impact: str
    evidence: str
    likelihood: str
    required_testing: str
    recommended_action: str


def analyze_proposal_regressions(
    *,
    rule_id: str,
    action_id: str,
    corrected_config: str,
    target_scheme: str = "http",
) -> list[RegressionItem]:
    """Identify potential side effects without presenting speculative issues as confirmed failures."""
    rid = (rule_id or "").upper()
    aid = (action_id or "").upper()
    cfg_lower = (corrected_config or "").lower()
    items: list[RegressionItem] = []

    if rid == "HDR-001" or aid == "ENABLE_CSP":
        items.append(
            RegressionItem(
                risk_description="External or inline scripts and stylesheets may be blocked by strict CSP directives.",
                potential_impact="Interactive UI widgets, inline event handlers, or third-party CDN assets could fail to execute.",
                evidence=f"Proposed policy '{corrected_config[:120]}' restricts script/style sources.",
                likelihood="Medium" if "'self'" in cfg_lower else "Low",
                required_testing="Load all application pages with browser DevTools Console open to check for CSP violation reports.",
                recommended_action="Preview in Content-Security-Policy-Report-Only mode in the Digital Twin before enforcing.",
            )
        )
        if "frame-ancestors" in cfg_lower:
            items.append(
                RegressionItem(
                    risk_description="Iframe embedding will be restricted by frame-ancestors.",
                    potential_impact="Legitimate portal or payment iframe integrations could be blocked.",
                    evidence="CSP includes frame-ancestors directive.",
                    likelihood="Low",
                    required_testing="Verify any embedded partner or checkout iframes.",
                    recommended_action="Allowlist only trusted origins in frame-ancestors if embedding is required.",
                )
            )

    elif rid == "COOKIE-002" or aid == "ENABLE_SECURE_COOKIE":
        is_http = target_scheme.lower() != "https"
        items.append(
            RegressionItem(
                risk_description="Secure cookies will not be transmitted over plaintext HTTP.",
                potential_impact="User sessions may fail to persist if accessed over http:// instead of https://.",
                evidence=f"Target scheme is '{target_scheme}'.",
                likelihood="High" if is_http else "Low",
                required_testing="Verify login and session persistence over HTTPS.",
                recommended_action="Ensure HTTPS is active before enforcing Secure=True in production.",
            )
        )

    elif rid == "COOKIE-001" or aid == "ENABLE_HTTPONLY_COOKIE":
        items.append(
            RegressionItem(
                risk_description="Client-side JavaScript will no longer be able to read the cookie via document.cookie.",
                potential_impact="Any frontend script reading this cookie directly will receive an empty/missing value.",
                evidence="HttpOnly flag blocks JavaScript cookie access.",
                likelihood="Low",
                required_testing="Test login, logout, and API authentication flows in the browser.",
                recommended_action="Keep session tokens HttpOnly and pass non-sensitive UI state via JSON APIs.",
            )
        )

    elif rid == "COOKIE-003" or aid == "CONFIGURE_SAMESITE":
        items.append(
            RegressionItem(
                risk_description="Cross-site cookie transmission behavior changes under SameSite=Lax/Strict.",
                potential_impact="Cross-origin SSO callbacks or third-party payment POST redirects may omit cookies.",
                evidence="SameSite restricts cross-site cookie attachment.",
                likelihood="Medium" if "strict" in cfg_lower else "Low",
                required_testing="Test external redirect and payment callback flows.",
                recommended_action="Prefer SameSite=Lax for standard web apps unless Strict is specifically required.",
            )
        )

    elif rid.startswith("TLS-") or aid == "ENABLE_TLS_TEST_CONFIGURATION":
        items.append(
            RegressionItem(
                risk_description="Strict TLS 1.2+/certificate validation may reject legacy clients or untrusted self-signed certs.",
                potential_impact="Outdated API consumers or misconfigured reverse proxies may fail TLS handshakes.",
                evidence="TLS hardening enforces modern protocol versions and certificate trust.",
                likelihood="Low",
                required_testing="Verify TLS handshake with curl and supported client browsers.",
                recommended_action="Deploy a valid SAN certificate and support TLS 1.2 and TLS 1.3.",
            )
        )

    elif rid.startswith("FILE-") or aid == "DISABLE_SYNTHETIC_CONFIG_EXPOSURE":
        items.append(
            RegressionItem(
                risk_description="Disabling exposed configuration endpoints returns HTTP 404/403.",
                potential_impact="Any diagnostic script polling /config.json without auth will receive 404.",
                evidence=f"Action {aid} disables unauthenticated access.",
                likelihood="Low",
                required_testing="Verify normal application routes return 200 while /config.json returns 404.",
                recommended_action="Move internal diagnostics behind authenticated admin interfaces.",
            )
        )

    else:
        items.append(
            RegressionItem(
                risk_description="Header or configuration hardening may alter browser/client handling.",
                potential_impact="Minor compatibility impact if legacy clients rely on permissive defaults.",
                evidence=f"Proposed action {aid} for {rid}.",
                likelihood="Low",
                required_testing="Smoke-test primary user journeys after applying.",
                recommended_action="Test in Digital Twin first and keep backup ready for rollback.",
            )
        )

    return items
