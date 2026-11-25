"""Content-Security-Policy (CSP) Simulator for Security Digital Twin."""

from __future__ import annotations

from dataclasses import dataclass

RECOMMENDED_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; font-src 'self'; object-src 'none'; "
    "base-uri 'self'; frame-ancestors 'none'"
)

KEY_DIRECTIVES = (
    "default-src",
    "script-src",
    "style-src",
    "img-src",
    "font-src",
    "object-src",
    "base-uri",
    "frame-ancestors",
)


@dataclass(frozen=True)
class CspSimulationResult:
    """Result of parsing, validating, and simulating a CSP policy."""

    valid_syntax: bool
    report_only: bool
    header_name: str
    policy_value: str
    parsed_directives: dict[str, list[str]]
    unsafe_directives: list[str]
    missing_recommended_directives: list[str]
    external_resource_conflicts: list[str]
    syntax_errors: list[str]


def parse_csp(policy: str) -> dict[str, list[str]]:
    """Parse a CSP header string into directive -> token list."""
    directives: dict[str, list[str]] = {}
    for raw_part in (policy or "").split(";"):
        part = raw_part.strip()
        if not part:
            continue
        tokens = part.split()
        name = tokens[0].lower()
        directives[name] = tokens[1:]
    return directives


def simulate_csp_policy(
    proposed_csp: str,
    *,
    existing_csp: str | None = None,
    report_only: bool = False,
) -> CspSimulationResult:
    """Validate CSP syntax, detect unsafe directives, and check resource restrictions."""
    cleaned = (proposed_csp or "").strip()
    syntax_errors: list[str] = []

    if not cleaned:
        syntax_errors.append("CSP policy cannot be empty.")
    if "\n" in cleaned or "\r" in cleaned:
        syntax_errors.append("CSP policy must not contain CR/LF newline characters.")

    parsed = parse_csp(cleaned)
    if not parsed and not syntax_errors:
        syntax_errors.append("No valid CSP directives were parsed.")

    for d_name, vals in parsed.items():
        if not d_name.replace("-", "").isalpha():
            syntax_errors.append(f"Invalid CSP directive name '{d_name}'.")
        if not vals and d_name != "upgrade-insecure-requests":
            syntax_errors.append(f"Directive '{d_name}' has no source expressions.")

    unsafe: list[str] = []
    conflicts: list[str] = []
    for d_name, vals in parsed.items():
        lower_vals = [v.lower() for v in vals]
        if "'unsafe-inline'" in lower_vals:
            unsafe.append(f"{d_name} allows 'unsafe-inline'")
        if "'unsafe-eval'" in lower_vals:
            unsafe.append(f"{d_name} allows 'unsafe-eval'")
        if "*" in lower_vals:
            unsafe.append(f"{d_name} uses wildcard '*'")
        if any(v.startswith("http://") for v in lower_vals):
            conflicts.append(f"{d_name} references insecure http:// external origin")
        if d_name in {"script-src", "style-src", "font-src"} and "'self'" in lower_vals and len(lower_vals) == 1:
            conflicts.append(
                f"{d_name} 'self' will block external CDN scripts/styles/fonts unless explicitly allowlisted."
            )

    if existing_csp and existing_csp.strip() and existing_csp.strip() != cleaned:
        conflicts.append("Existing CSP directives will be merged/updated; verify existing third-party origins.")

    missing = [d for d in KEY_DIRECTIVES if d not in parsed]
    header_name = "Content-Security-Policy-Report-Only" if report_only else "Content-Security-Policy"

    return CspSimulationResult(
        valid_syntax=len(syntax_errors) == 0,
        report_only=report_only,
        header_name=header_name,
        policy_value=cleaned,
        parsed_directives=parsed,
        unsafe_directives=unsafe,
        missing_recommended_directives=missing,
        external_resource_conflicts=conflicts,
        syntax_errors=syntax_errors,
    )
