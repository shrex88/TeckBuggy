"""Cookie Security Simulator for Security Digital Twin.

Simulates Secure, HttpOnly, and SameSite attributes without ever storing
or exposing actual cookie values.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CookieSimulationResult:
    """Outcome of simulating cookie security attributes."""

    cookie_name: str
    secure: bool
    httponly: bool
    samesite: str
    https_compatible: bool
    classification: str
    explanations: list[str]
    simulated_set_cookie_header: str


def simulate_cookie_policy(
    *,
    cookie_name: str = "sentinel_session_cookie",
    scheme: str = "http",
    enable_secure: bool = True,
    enable_httponly: bool = True,
    samesite: str = "Lax",
) -> CookieSimulationResult:
    """Simulate cookie hardening and evaluate HTTP vs HTTPS & cross-site compatibility."""
    clean_samesite = (samesite or "").strip()
    is_https = scheme.lower() == "https"
    https_compatible = (not enable_secure) or is_https

    explanations: list[str] = []
    if enable_secure:
        if is_https:
            explanations.append("Secure flag enabled on HTTPS: cookie is protected from plaintext network transmission.")
        else:
            explanations.append(
                "Conditional: Secure flag requires HTTPS. On plain http://, browsers may refuse to store/send the cookie."
            )
    else:
        explanations.append("Secure flag disabled: cookie could be sent over unencrypted HTTP.")

    if enable_httponly:
        explanations.append(
            "HttpOnly enabled: protects session cookie from document.cookie JavaScript access (mitigates XSS cookie theft)."
        )
    else:
        explanations.append("HttpOnly disabled: client-side JavaScript can read the cookie.")

    ss_lower = clean_samesite.lower()
    if ss_lower == "strict":
        explanations.append("SameSite=Strict: maximum CSRF defense, but cross-site inbound links will not include the session cookie.")
    elif ss_lower == "lax":
        explanations.append("SameSite=Lax: strong CSRF protection while preserving top-level GET navigation.")
    elif ss_lower == "none":
        explanations.append("SameSite=None: allows cross-site requests; requires Secure=True over HTTPS.")
    else:
        explanations.append("SameSite unset: weaker CSRF protection across browsers.")

    if not https_compatible or (ss_lower == "none" and not enable_secure):
        classification = "CONDITIONAL"
    elif enable_secure and enable_httponly and ss_lower in {"lax", "strict"}:
        classification = "SIMULATED PASS"
    else:
        classification = "NOT RESOLVED"

    flags = [f"{cookie_name}=<REDACTED>", "Path=/"]
    if enable_httponly:
        flags.append("HttpOnly")
    if enable_secure:
        flags.append("Secure")
    if clean_samesite:
        flags.append(f"SameSite={clean_samesite}")

    return CookieSimulationResult(
        cookie_name=cookie_name,
        secure=enable_secure,
        httponly=enable_httponly,
        samesite=clean_samesite or "Unset",
        https_compatible=https_compatible,
        classification=classification,
        explanations=explanations,
        simulated_set_cookie_header="; ".join(flags),
    )
