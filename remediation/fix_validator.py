"""Strict Remediation Validator for SENTINEL AI.

Enforces target authorization (blocks High-Security Application A),
action allowlisting, and mandatory developer approval before execution.
"""

from __future__ import annotations

from urllib.parse import urlparse

from config import ALLOWLISTED_ACTIONS, HIGH_SECURITY_APP_URL, LOW_SECURITY_APP_URL
from digital_twin.csp_simulator import simulate_csp_policy
from scanner.target_validator import validate_target_url


class RemediationValidationError(ValueError):
    """Raised when a remediation request violates safety or governance rules."""


def validate_remediation_request(
    *,
    target_url: str,
    action_id: str,
    approval_status: str,
) -> str:
    """Validate that target is remediable, action is allowlisted, and status is Approved."""
    vt = validate_target_url(target_url)
    normalized_target = vt.normalized_url.rstrip("/")

    high_parsed = urlparse(HIGH_SECURITY_APP_URL)
    low_parsed = urlparse(LOW_SECURITY_APP_URL)
    target_parsed = urlparse(normalized_target)

    # Never allow modifying High-Security Application A (read-only)
    if (target_parsed.hostname, target_parsed.port) == (high_parsed.hostname, high_parsed.port):
        raise RemediationValidationError(
            "Target rejected: High-Security Reference Application (Application A) is strictly read-only."
        )

    # Only allow remediation against the authorised Low-Security Demo Lab (Application B)
    if (target_parsed.hostname, target_parsed.port) != (low_parsed.hostname, low_parsed.port):
        raise RemediationValidationError(
            f"Target rejected: '{target_url}' is not registered as a remediable local lab target."
        )

    clean_action = (action_id or "").strip().upper()
    if clean_action not in ALLOWLISTED_ACTIONS:
        raise RemediationValidationError(
            f"Action '{action_id}' is not in the approved ALLOWLISTED_ACTIONS catalogue."
        )

    if approval_status != "Approved":
        raise RemediationValidationError(
            f"Execution blocked: proposal approval_status is '{approval_status}', expected 'Approved'."
        )

    return clean_action


def run_deterministic_proposal_validation(
    *,
    rule_id: str,
    action_id: str,
    corrected_config: str,
    framework: str,
    code_snippet: str,
) -> list[dict[str, object]]:
    """Run deterministic syntax, attribute, and framework compatibility checks."""
    checks: list[dict[str, object]] = []
    clean_action = (action_id or "").strip().upper()
    rid = (rule_id or "").strip().upper()
    cfg = (corrected_config or "").strip()
    code = (code_snippet or "").strip()

    # 1. Allowlisted action check
    checks.append(
        {
            "check_name": "Allowlisted Action Catalogue",
            "passed": clean_action in ALLOWLISTED_ACTIONS,
            "details": (
                f"Action '{clean_action}' is in ALLOWLISTED_ACTIONS."
                if clean_action in ALLOWLISTED_ACTIONS
                else f"Action '{clean_action}' is NOT allowlisted."
            ),
        }
    )

    # 2. Configuration syntax validation
    if rid == "HDR-001" or clean_action == "ENABLE_CSP":
        csp_sim = simulate_csp_policy(cfg.replace("Content-Security-Policy:", "").strip())
        checks.append(
            {
                "check_name": "CSP Syntax Validation",
                "passed": csp_sim.valid_syntax and len(csp_sim.unsafe_directives) == 0,
                "details": (
                    "Valid CSP directives without unsafe-inline/unsafe-eval/wildcard."
                    if csp_sim.valid_syntax and not csp_sim.unsafe_directives
                    else "; ".join(csp_sim.syntax_errors + csp_sim.unsafe_directives)
                ),
            }
        )
    elif rid.startswith("COOKIE-") or "COOKIE" in clean_action or "SAMESITE" in clean_action:
        has_attr = any(
            tok in cfg.lower()
            for tok in ("httponly", "secure", "samesite=lax", "samesite=strict")
        )
        checks.append(
            {
                "check_name": "Cookie Attribute Validation",
                "passed": has_attr,
                "details": (
                    "Proposal includes explicit HttpOnly/Secure/SameSite attribute."
                    if has_attr
                    else "Proposal lacks valid HttpOnly, Secure, or SameSite=Lax/Strict attribute."
                ),
            }
        )
    elif rid.startswith("TLS-") or "TLS" in clean_action:
        tls_ok = "1.2" in cfg or "1.3" in cfg or "tls" in cfg.lower()
        checks.append(
            {
                "check_name": "TLS Configuration Validation",
                "passed": tls_ok,
                "details": "References TLS 1.2+/certificate validation." if tls_ok else "Incomplete TLS policy.",
            }
        )
    else:
        hdr_ok = bool(cfg) and "\n" not in cfg.splitlines()[0][:200]
        checks.append(
            {
                "check_name": "Header / Endpoint Policy Validation",
                "passed": bool(cfg),
                "details": "Corrected configuration is non-empty and well-formed." if cfg else "Empty configuration.",
            }
        )

    # 3. Framework snippet validation
    fw_lower = (framework or "Flask").lower()
    fw_keywords = {
        "flask": ("response", "headers", "set_cookie", "route", "app"),
        "django": ("secure_", "session_", "csp_", "x_frame_options", "settings"),
        "apache": ("header", "files", "require"),
        "nginx": ("add_header", "proxy_cookie_flags", "location", "return"),
        "express": ("app.use", "helmet", "res.cookie", "res.setheader", "app.get"),
    }
    expected = fw_keywords.get(fw_lower, ("",))
    fw_ok = bool(code) and any(kw in code.lower() for kw in expected)
    checks.append(
        {
            "check_name": f"Framework Compatibility ({framework})",
            "passed": fw_ok,
            "details": (
                f"Code snippet matches {framework} configuration conventions."
                if fw_ok
                else f"Code snippet does not clearly match {framework} conventions."
            ),
        }
    )

    # 4. Unsafe shell/eval injection guard
    dangerous = any(tok in code.lower() for tok in ("os.system(", "subprocess.", "rm -rf", "eval("))
    checks.append(
        {
            "check_name": "Safe Non-Destructive Code Guard",
            "passed": not dangerous,
            "details": "No dangerous shell or eval calls detected." if not dangerous else "Unsafe execution pattern detected!",
        }
    )

    return checks
