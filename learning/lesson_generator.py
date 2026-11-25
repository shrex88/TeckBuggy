"""Personalized Security Lesson Generator for Security Learning Mode."""

from __future__ import annotations

from dataclasses import dataclass

from remediation.fix_generator import generate_remediation_playbook

LEARNING_LEVELS: tuple[str, ...] = ("BEGINNER", "INTERMEDIATE", "ADVANCED")


@dataclass(frozen=True)
class SecurityLesson:
    """Complete 12-part security lesson adapted to a learner's skill level."""

    rule_id: str
    vulnerability_name: str
    severity: str
    owasp_mapping: str
    learning_level: str
    simple_explanation: str
    technical_explanation: str
    root_cause: str
    security_impact: str
    insecure_example: str
    secure_example: str
    framework_implementations: dict[str, str]
    prevention_strategies: list[str]
    verification_steps: str


_LESSON_CATALOGUE: dict[str, dict[str, object]] = {
    "HDR-001": {
        "name": "Missing Content-Security-Policy (CSP)",
        "severity": "High",
        "owasp": "A02:2025 - Security Misconfiguration",
        "simple": "Content-Security-Policy is like a guest list for your webpage—it tells the browser which scripts and styles are allowed to run.",
        "insecure": "# No Content-Security-Policy header sent in HTTP response",
        "secure": "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
        "prevention": [
            "Define an explicit allowlist for script-src, style-src, img-src, and font-src.",
            "Avoid 'unsafe-inline', 'unsafe-eval', and wildcard '*' sources.",
            "Test new policies using Content-Security-Policy-Report-Only before enforcing.",
        ],
    },
    "COOKIE-002": {
        "name": "Missing Secure Cookie Attribute",
        "severity": "High",
        "owasp": "A04:2025 - Cryptographic Failures",
        "simple": "The Secure flag ensures browsers only send a session cookie over encrypted HTTPS connections, never over plain HTTP.",
        "insecure": "Set-Cookie: session_id=<REDACTED>; Path=/",
        "secure": "Set-Cookie: session_id=<REDACTED>; Path=/; Secure; HttpOnly; SameSite=Lax",
        "prevention": [
            "Serve all authenticated applications over HTTPS.",
            "Set SESSION_COOKIE_SECURE = True in framework configuration.",
        ],
    },
    "COOKIE-001": {
        "name": "Missing HttpOnly Cookie Attribute",
        "severity": "High",
        "owasp": "A07:2025 - Authentication Failures",
        "simple": "HttpOnly locks your session cookie so JavaScript code in the browser cannot read or steal it.",
        "insecure": "Set-Cookie: session_id=<REDACTED>; Path=/",
        "secure": "Set-Cookie: session_id=<REDACTED>; Path=/; HttpOnly; Secure; SameSite=Lax",
        "prevention": [
            "Enable HttpOnly on all session and authentication cookies.",
            "Do not store session tokens in localStorage or accessible JS cookies.",
        ],
    },
    "COOKIE-003": {
        "name": "Insecure SameSite Cookie Configuration",
        "severity": "Medium",
        "owasp": "A07:2025 - Authentication Failures",
        "simple": "SameSite controls whether your cookie is sent when a user clicks a link or submits a form from another website.",
        "insecure": "Set-Cookie: session_id=<REDACTED>; Path=/",
        "secure": "Set-Cookie: session_id=<REDACTED>; Path=/; SameSite=Lax; HttpOnly; Secure",
        "prevention": [
            "Default to SameSite=Lax (or SameSite=Strict for sensitive actions).",
            "Pair SameSite with anti-CSRF tokens on state-changing requests.",
        ],
    },
    "HDR-004": {
        "name": "Missing X-Content-Type-Options",
        "severity": "Medium",
        "owasp": "A02:2025 - Security Misconfiguration",
        "simple": "X-Content-Type-Options: nosniff stops browsers from guessing file types and accidentally running text files as scripts.",
        "insecure": "# X-Content-Type-Options omitted",
        "secure": "X-Content-Type-Options: nosniff",
        "prevention": [
            "Send X-Content-Type-Options: nosniff on every HTTP response.",
            "Always set accurate Content-Type headers.",
        ],
    },
    "HDR-005": {
        "name": "Missing Referrer-Policy",
        "severity": "Low",
        "owasp": "A02:2025 - Security Misconfiguration",
        "simple": "Referrer-Policy limits how much of the current page's URL is shared when a user clicks a link to another site.",
        "insecure": "# Referrer-Policy omitted",
        "secure": "Referrer-Policy: strict-origin-when-cross-origin",
        "prevention": ["Configure strict-origin-when-cross-origin or no-referrer globally."],
    },
    "HDR-006": {
        "name": "Missing Permissions-Policy",
        "severity": "Low",
        "owasp": "A02:2025 - Security Misconfiguration",
        "simple": "Permissions-Policy lets your app disable browser features like camera, microphone, and GPS when not needed.",
        "insecure": "# Permissions-Policy omitted",
        "secure": "Permissions-Policy: geolocation=(), microphone=(), camera=()",
        "prevention": ["Explicitly disable unused browser APIs in Permissions-Policy."],
    },
    "TLS-000": {
        "name": "TLS / HTTPS Transport Misconfiguration",
        "severity": "Medium",
        "owasp": "A04:2025 - Cryptographic Failures",
        "simple": "HTTPS/TLS encrypts traffic between the user's browser and your server so attackers on the network cannot read or alter it.",
        "insecure": "http://example.local (unencrypted plaintext transport)",
        "secure": "https://example.local with TLS 1.2 / TLS 1.3 and valid SAN certificate",
        "prevention": [
            "Enforce TLS 1.2 and TLS 1.3 only; disable TLS 1.0/1.1.",
            "Use valid, non-expired certificates with matching Subject Alternative Names.",
        ],
    },
    "FILE-002": {
        "name": "Exposed Configuration Files (/config.json, /.env)",
        "severity": "High",
        "owasp": "A02:2025 - Security Misconfiguration",
        "simple": "Configuration files should never be reachable in a browser—they can reveal internal settings or credentials.",
        "insecure": "GET /config.json -> HTTP 200 OK (publicly accessible)",
        "secure": "GET /config.json -> HTTP 404 Not Found / 403 Forbidden",
        "prevention": [
            "Keep .env and configuration files outside the web root.",
            "Block dotfile and config routes in reverse proxy and application middleware.",
        ],
    },
}


def list_lesson_topics() -> list[dict[str, str]]:
    """Return all available lesson topics."""
    return [
        {
            "rule_id": rid,
            "title": str(meta["name"]),
            "severity": str(meta["severity"]),
            "owasp_mapping": str(meta["owasp"]),
        }
        for rid, meta in _LESSON_CATALOGUE.items()
    ]


def get_lesson(rule_id: str, learning_level: str = "BEGINNER") -> SecurityLesson:
    """Return a structured 12-part lesson tailored to BEGINNER, INTERMEDIATE, or ADVANCED."""
    rid = (rule_id or "HDR-001").upper()
    if rid not in _LESSON_CATALOGUE:
        rid = "FILE-002" if rid.startswith("FILE-") else ("TLS-000" if rid.startswith("TLS-") else "HDR-001")

    level = learning_level.upper() if learning_level.upper() in LEARNING_LEVELS else "BEGINNER"
    meta = _LESSON_CATALOGUE[rid]
    playbook = generate_remediation_playbook(
        {
            "rule_id": rid,
            "title": meta["name"],
            "severity": meta["severity"],
            "risk_score": 75.0,
            "target_path": "/",
        }
    )

    if level == "BEGINNER":
        tech = f"[Beginner Guide] {meta['simple']} Step-by-step: apply the secure configuration below and re-scan."
    elif level == "INTERMEDIATE":
        tech = f"[Intermediate] {playbook.technical_explanation} Follow framework best practices and verify headers/flags."
    else:
        tech = (
            f"[Advanced Architecture] {playbook.technical_explanation} Root cause: missing defense-in-depth middleware; "
            f"validate via deterministic header/attribute assertions and Security Proof regression checks."
        )

    return SecurityLesson(
        rule_id=rid,
        vulnerability_name=str(meta["name"]),
        severity=str(meta["severity"]),
        owasp_mapping=str(meta["owasp"]),
        learning_level=level,
        simple_explanation=str(meta["simple"]),
        technical_explanation=tech,
        root_cause=f"Missing or permissive security control for {rid} in application/server responses.",
        security_impact=playbook.security_impact,
        insecure_example=str(meta["insecure"]),
        secure_example=str(meta["secure"]),
        framework_implementations=playbook.snippets,
        prevention_strategies=list(meta["prevention"]),  # type: ignore[arg-type]
        verification_steps=playbook.verification_instructions,
    )
