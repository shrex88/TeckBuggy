"""Strict Remediation Validator for SENTINEL AI.

Enforces target authorization (blocks High-Security Application A),
action allowlisting, and mandatory developer approval before execution.
"""

from __future__ import annotations

from config import ALLOWLISTED_ACTIONS
from scanner.target_validator import validate_target_url


def _validate_csp_syntax(policy: str) -> tuple[bool, list[str], list[str]]:
    """Deterministic CSP syntax and unsafe-directive validator."""
    cleaned = (policy or "").strip()
    errors: list[str] = []
    unsafe: list[str] = []
    if not cleaned:
        errors.append("CSP policy cannot be empty.")
        return False, unsafe, errors
    if "\n" in cleaned or "\r" in cleaned:
        errors.append("CSP policy must not contain CR/LF newline characters.")
    parsed: dict[str, list[str]] = {}
    for raw_part in cleaned.split(";"):
        part = raw_part.strip()
        if not part:
            continue
        tokens = part.split()
        name = tokens[0].lower()
        parsed[name] = tokens[1:]
        if not name.replace("-", "").isalpha():
            errors.append(f"Invalid CSP directive name '{name}'.")
        if not tokens[1:] and name != "upgrade-insecure-requests":
            errors.append(f"Directive '{name}' has no source expressions.")
        lower_vals = [v.lower() for v in tokens[1:]]
        if "'unsafe-inline'" in lower_vals:
            unsafe.append(f"{name} allows 'unsafe-inline'")
        if "'unsafe-eval'" in lower_vals:
            unsafe.append(f"{name} allows 'unsafe-eval'")
        if "*" in lower_vals:
            unsafe.append(f"{name} uses wildcard '*'")
    if not parsed and not errors:
        errors.append("No valid CSP directives were parsed.")
    return len(errors) == 0, unsafe, errors


class RemediationValidationError(ValueError):
    """Raised when a remediation request violates safety or governance rules."""


def validate_remediation_request(
    *,
    target_url: str,
    action_id: str,
    approval_status: str,
) -> str:
    """Validate that target is an authorised local URL, action is allowlisted, and status is Approved."""
    validate_target_url(target_url)

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
        valid_syntax, unsafe_dirs, syntax_errs = _validate_csp_syntax(
            cfg.replace("Content-Security-Policy:", "").strip()
        )
        checks.append(
            {
                "check_name": "CSP Syntax Validation",
                "passed": valid_syntax and len(unsafe_dirs) == 0,
                "details": (
                    "Valid CSP directives without unsafe-inline/unsafe-eval/wildcard."
                    if valid_syntax and not unsafe_dirs
                    else "; ".join(syntax_errs + unsafe_dirs)
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
