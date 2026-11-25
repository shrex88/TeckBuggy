"""OWASP Top 10:2025 Mapper for SENTINEL AI."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.models import StandardFinding

OWASP_A02_MISCONFIG = "A02:2025 - Security Misconfiguration"
OWASP_A04_CRYPTO = "A04:2025 - Cryptographic Failures"
OWASP_A07_AUTH = "A07:2025 - Authentication Failures"


def map_finding_to_owasp(finding: StandardFinding) -> str:
    """Map a standardised finding to OWASP Top 10:2025 using rule & context."""
    rule_id = (finding.rule_id or "").upper()
    category = (finding.category or "").lower()
    is_session_cookie = bool(finding.metadata.get("is_session_cookie", False))

    if rule_id == "HDR-002":
        return OWASP_A04_CRYPTO

    if rule_id.startswith("HDR-") or "header" in category:
        return OWASP_A02_MISCONFIG

    if rule_id.startswith("TLS-") or "tls" in category or "transport" in category:
        return OWASP_A04_CRYPTO

    if rule_id == "COOKIE-002":
        return OWASP_A04_CRYPTO

    if rule_id.startswith("COOKIE-") or "cookie" in category:
        if is_session_cookie:
            return OWASP_A07_AUTH
        return OWASP_A02_MISCONFIG

    if rule_id == "FILE-001":
        return OWASP_A04_CRYPTO

    if rule_id.startswith("FILE-") or "exposed" in category:
        return OWASP_A02_MISCONFIG

    return OWASP_A02_MISCONFIG
