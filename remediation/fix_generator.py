"""Smart Remediation Engine for SENTINEL AI (Phase 3).

Generates actionable, framework-specific remediation guidance and configuration
snippets without ever automatically modifying the target application.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

SUPPORTED_FRAMEWORKS: tuple[str, ...] = (
    "Flask",
    "Django",
    "Apache",
    "Nginx",
    "Express",
)


@dataclass(frozen=True)
class RemediationPlaybook:
    """Complete remediation guidance for a single finding."""

    rule_id: str
    finding_title: str
    severity: str
    risk_score: float
    technical_explanation: str
    security_impact: str
    recommended_fix: str
    corrected_config: str
    snippets: dict[str, str]
    verification_instructions: str


_RULE_PLAYBOOKS: dict[str, dict[str, Any]] = {
    "HDR-001": {
        "technical_explanation": (
            "The HTTP response omitted the Content-Security-Policy (CSP) header. "
            "Without CSP, browsers execute inline scripts and load resources from arbitrary origins."
        ),
        "security_impact": (
            "Increases the blast radius of Cross-Site Scripting (XSS) and data injection attacks."
        ),
        "recommended_fix": "Define a strict Content-Security-Policy restricting script, object, and frame sources.",
        "corrected_config": "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
        "snippets": {
            "Flask": (
                "@app.after_request\n"
                "def set_csp(response):\n"
                "    response.headers['Content-Security-Policy'] = \"default-src 'self'; object-src 'none'; frame-ancestors 'none'\"\n"
                "    return response"
            ),
            "Django": (
                "# settings.py (with django-csp)\n"
                "CSP_DEFAULT_SRC = (\"'self'\",)\n"
                "CSP_OBJECT_SRC = (\"'none'\",)\n"
                "CSP_FRAME_ANCESTORS = (\"'none'\",)"
            ),
            "Apache": (
                "Header always set Content-Security-Policy \"default-src 'self'; object-src 'none'; frame-ancestors 'none'\""
            ),
            "Nginx": (
                "add_header Content-Security-Policy \"default-src 'self'; object-src 'none'; frame-ancestors 'none'\" always;"
            ),
            "Express": (
                "const helmet = require('helmet');\n"
                "app.use(helmet.contentSecurityPolicy({\n"
                "  directives: { defaultSrc: [\"'self'\"], objectSrc: [\"'none'\"], frameAncestors: [\"'none'\"] }\n"
                "}));"
            ),
        },
        "verification_instructions": (
            "Inspect response headers via curl -I <target> or re-run SENTINEL AI Security Proof "
            "to confirm Content-Security-Policy is present."
        ),
    },
    "HDR-002": {
        "technical_explanation": "HTTPS response omitted Strict-Transport-Security (HSTS) with a sufficient max-age.",
        "security_impact": "Allows SSL-stripping or accidental plaintext HTTP downgrade on repeat visits.",
        "recommended_fix": "Enable Strict-Transport-Security on all HTTPS responses.",
        "corrected_config": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "snippets": {
            "Flask": "response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'",
            "Django": "SECURE_HSTS_SECONDS = 31536000\nSECURE_HSTS_INCLUDE_SUBDOMAINS = True",
            "Apache": "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"",
            "Nginx": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
            "Express": "app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));",
        },
        "verification_instructions": "Verify Strict-Transport-Security appears on HTTPS responses and re-scan.",
    },
    "HDR-003": {
        "technical_explanation": "Neither X-Frame-Options nor CSP frame-ancestors was returned.",
        "security_impact": "Attackers can embed pages in hidden iframes to perform Clickjacking attacks.",
        "recommended_fix": "Set X-Frame-Options: DENY (or SAMEORIGIN) and CSP frame-ancestors.",
        "corrected_config": "X-Frame-Options: DENY",
        "snippets": {
            "Flask": "response.headers['X-Frame-Options'] = 'DENY'",
            "Django": "X_FRAME_OPTIONS = 'DENY'",
            "Apache": "Header always set X-Frame-Options \"DENY\"",
            "Nginx": "add_header X-Frame-Options \"DENY\" always;",
            "Express": "app.use(helmet.frameguard({ action: 'deny' }));",
        },
        "verification_instructions": "Confirm X-Frame-Options: DENY or CSP frame-ancestors is present on rescan.",
    },
    "HDR-004": {
        "technical_explanation": "X-Content-Type-Options was missing or not set to 'nosniff'.",
        "security_impact": "Browsers may MIME-sniff non-script responses into executable JavaScript or HTML.",
        "recommended_fix": "Return X-Content-Type-Options: nosniff on all responses.",
        "corrected_config": "X-Content-Type-Options: nosniff",
        "snippets": {
            "Flask": "response.headers['X-Content-Type-Options'] = 'nosniff'",
            "Django": "SECURE_CONTENT_TYPE_NOSNIFF = True",
            "Apache": "Header always set X-Content-Type-Options \"nosniff\"",
            "Nginx": "add_header X-Content-Type-Options \"nosniff\" always;",
            "Express": "app.use(helmet.noSniff());",
        },
        "verification_instructions": "Confirm X-Content-Type-Options: nosniff is returned on rescan.",
    },
    "HDR-005": {
        "technical_explanation": "The Referrer-Policy header was omitted from the HTTP response.",
        "security_impact": "Sensitive URL paths or query tokens may leak to external origins via the Referer header.",
        "recommended_fix": "Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer.",
        "corrected_config": "Referrer-Policy: strict-origin-when-cross-origin",
        "snippets": {
            "Flask": "response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'",
            "Django": "SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'",
            "Apache": "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
            "Nginx": "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
            "Express": "app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));",
        },
        "verification_instructions": "Verify Referrer-Policy header is present in response headers and rescan.",
    },
    "HDR-006": {
        "technical_explanation": "The Permissions-Policy header was omitted from the HTTP response.",
        "security_impact": "Leaves powerful browser APIs (geolocation, camera, microphone) unrestricted.",
        "recommended_fix": "Restrict unused browser features using Permissions-Policy.",
        "corrected_config": "Permissions-Policy: geolocation=(), microphone=(), camera=()",
        "snippets": {
            "Flask": "response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'",
            "Django": "# Add middleware setting response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'",
            "Apache": "Header always set Permissions-Policy \"geolocation=(), microphone=(), camera=()\"",
            "Nginx": "add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\" always;",
            "Express": "app.use((req, res, next) => { res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()'); next(); });",
        },
        "verification_instructions": "Confirm Permissions-Policy header is present on rescan.",
    },
    "COOKIE-001": {
        "technical_explanation": "A Set-Cookie header was issued without the HttpOnly attribute.",
        "security_impact": "Client-side scripts (e.g. via XSS) can read the cookie via document.cookie.",
        "recommended_fix": "Enable HttpOnly=True on session and authentication cookies.",
        "corrected_config": "Set-Cookie: <name>=<redacted>; HttpOnly; Secure; SameSite=Lax",
        "snippets": {
            "Flask": "app.config['SESSION_COOKIE_HTTPONLY'] = True\nresp.set_cookie('session_id', val, httponly=True, secure=True, samesite='Lax')",
            "Django": "SESSION_COOKIE_HTTPONLY = True\nCSRF_COOKIE_HTTPONLY = True",
            "Apache": "Header edit Set-Cookie ^(.*)$ $1;HttpOnly",
            "Nginx": "proxy_cookie_flags ~ httponly;",
            "Express": "res.cookie('session_id', val, { httpOnly: true, secure: true, sameSite: 'lax' });",
        },
        "verification_instructions": "Check Set-Cookie header contains HttpOnly and run Security Proof rescan.",
    },
    "COOKIE-002": {
        "technical_explanation": "A Set-Cookie header was issued without the Secure attribute.",
        "security_impact": "The cookie may be transmitted over plaintext HTTP connections.",
        "recommended_fix": "Enable Secure=True on cookies and serve over HTTPS.",
        "corrected_config": "Set-Cookie: <name>=<redacted>; Secure; HttpOnly; SameSite=Lax",
        "snippets": {
            "Flask": "app.config['SESSION_COOKIE_SECURE'] = True\nresp.set_cookie('session_id', val, secure=True, httponly=True, samesite='Lax')",
            "Django": "SESSION_COOKIE_SECURE = True\nCSRF_COOKIE_SECURE = True",
            "Apache": "Header edit Set-Cookie ^(.*)$ $1;Secure",
            "Nginx": "proxy_cookie_flags ~ secure;",
            "Express": "res.cookie('session_id', val, { secure: true, httpOnly: true, sameSite: 'lax' });",
        },
        "verification_instructions": "Verify Set-Cookie contains Secure and re-run SENTINEL AI scan.",
    },
    "COOKIE-003": {
        "technical_explanation": "A Set-Cookie header lacked a restrictive SameSite attribute (Lax or Strict).",
        "security_impact": "Weakens defense-in-depth against Cross-Site Request Forgery (CSRF).",
        "recommended_fix": "Set SameSite=Lax (or Strict) on session cookies.",
        "corrected_config": "Set-Cookie: <name>=<redacted>; SameSite=Lax; HttpOnly; Secure",
        "snippets": {
            "Flask": "app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'\nresp.set_cookie('session_id', val, samesite='Lax')",
            "Django": "SESSION_COOKIE_SAMESITE = 'Lax'",
            "Apache": "Header edit Set-Cookie ^(.*)$ $1;SameSite=Lax",
            "Nginx": "proxy_cookie_flags ~ samesite=lax;",
            "Express": "res.cookie('session_id', val, { sameSite: 'lax', httpOnly: true, secure: true });",
        },
        "verification_instructions": "Confirm SameSite=Lax or Strict is present in Set-Cookie on rescan.",
    },
    "FILE-002": {
        "technical_explanation": "The application configuration endpoint (/config.json) returned HTTP 200 without authentication.",
        "security_impact": "May expose internal settings, feature flags, or synthetic/test keys.",
        "recommended_fix": "Remove /config.json from public routes or enforce authentication and return HTTP 404/403.",
        "corrected_config": "HTTP 404 Not Found or 403 Forbidden for /config.json",
        "snippets": {
            "Flask": "# Remove public route or disable in production config\n@app.route('/config.json')\ndef disabled_config():\n    return {'error': 'Not Found'}, 404",
            "Django": "# Ensure config.json is not served in urls.py or staticfiles",
            "Apache": "<Files \"config.json\">\n    Require all denied\n</Files>",
            "Nginx": "location = /config.json {\n    return 404;\n}",
            "Express": "app.get('/config.json', (req, res) => res.status(404).json({ error: 'Not found' }));",
        },
        "verification_instructions": "Confirm /config.json returns HTTP 404 or 403 and verify with Security Proof rescan.",
    },
}


def generate_remediation_playbook(finding: dict[str, Any]) -> RemediationPlaybook:
    """Build a complete, developer-ready remediation playbook for a stored finding."""
    rule_id = str(finding.get("rule_id", "GENERIC")).upper()
    title = str(finding.get("title", "Security Finding"))
    severity = str(finding.get("severity", "Medium"))
    risk_score = float(finding.get("risk_score", 0.0))

    template = _RULE_PLAYBOOKS.get(rule_id)
    if template is not None:
        return RemediationPlaybook(
            rule_id=rule_id,
            finding_title=title,
            severity=severity,
            risk_score=risk_score,
            technical_explanation=str(template["technical_explanation"]),
            security_impact=str(template["security_impact"]),
            recommended_fix=str(template["recommended_fix"]),
            corrected_config=str(template["corrected_config"]),
            snippets=dict(template["snippets"]),
            verification_instructions=str(template["verification_instructions"]),
        )

    remediation_text = str(
        finding.get("remediation")
        or "Harden the affected component according to OWASP Top 10:2025 best practices."
    )
    target_path = str(finding.get("target_path", "/"))
    return RemediationPlaybook(
        rule_id=rule_id,
        finding_title=title,
        severity=severity,
        risk_score=risk_score,
        technical_explanation=str(finding.get("evidence") or f"Finding detected at {target_path}."),
        security_impact="Increases application attack surface if left unmitigated.",
        recommended_fix=remediation_text,
        corrected_config=f"# Apply hardened configuration for {rule_id} at {target_path}",
        snippets={
            fw: f"# {fw} reference: {remediation_text}" for fw in SUPPORTED_FRAMEWORKS
        },
        verification_instructions="Apply the fix manually and run a Security Proof follow-up scan to verify resolution.",
    )
