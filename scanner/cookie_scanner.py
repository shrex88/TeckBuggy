"""Cookie Security Scanner for SENTINEL AI.

Never exposes or stores actual cookie values.
"""

from __future__ import annotations

from typing import Iterable

import requests

from scanner.models import StandardFinding
from scanner.target_validator import ValidatedTarget, safe_fetch, validate_target_url

SESSION_COOKIE_HINTS = (
    "session",
    "sess",
    "sid",
    "auth",
    "token",
    "jwt",
    "jsessionid",
    "phpsessid",
    "csrftoken",
)


def _extract_set_cookie_headers(response: requests.Response) -> list[str]:
    """Extract all Set-Cookie header lines from a requests.Response."""
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        cookies = list(raw_headers.getlist("Set-Cookie"))
        if cookies:
            return cookies
    single = response.headers.get("Set-Cookie")
    return [single] if single else []


def _parse_cookie_attributes(set_cookie_header: str) -> tuple[str, dict[str, str | bool]]:
    """Parse cookie name and security attributes without retaining the cookie value."""
    parts = [p.strip() for p in set_cookie_header.split(";") if p.strip()]
    if not parts:
        return "unknown", {}

    name_part = parts[0]
    cookie_name = name_part.split("=", 1)[0].strip() if "=" in name_part else name_part
    attrs: dict[str, str | bool] = {
        "secure": False,
        "httponly": False,
        "samesite": "",
    }
    for attr in parts[1:]:
        lower = attr.lower()
        if lower == "secure":
            attrs["secure"] = True
        elif lower == "httponly":
            attrs["httponly"] = True
        elif lower.startswith("samesite="):
            attrs["samesite"] = attr.split("=", 1)[1].strip()
    return cookie_name, attrs


def analyze_set_cookie_headers(
    set_cookie_headers: Iterable[str],
    *,
    scheme: str,
    target_path: str = "/",
) -> list[StandardFinding]:
    """Inspect Set-Cookie headers for missing Secure, HttpOnly, and SameSite flags."""
    findings: list[StandardFinding] = []

    for raw_cookie in set_cookie_headers:
        cookie_name, attrs = _parse_cookie_attributes(raw_cookie)
        is_session_cookie = any(hint in cookie_name.lower() for hint in SESSION_COOKIE_HINTS)

        if not attrs.get("httponly", False):
            findings.append(
                StandardFinding(
                    rule_id="COOKIE-001",
                    title=f"Cookie '{cookie_name}' Missing HttpOnly Flag",
                    category="Cookie Security",
                    severity="High" if is_session_cookie else "Medium",
                    target_path=target_path,
                    evidence=(
                        f"Set-Cookie for '{cookie_name}' (value redacted) lacks the HttpOnly attribute."
                    ),
                    description=(
                        "Cookies without the HttpOnly flag can be read via client-side JavaScript "
                        "(document.cookie), increasing impact if XSS occurs."
                    ),
                    remediation_reference=(
                        f"Set HttpOnly=True on cookie '{cookie_name}'."
                    ),
                    confidence=95.0,
                    exposure=80.0,
                    exploitability=65.0 if is_session_cookie else 45.0,
                    metadata={
                        "cookie_name": cookie_name,
                        "is_session_cookie": is_session_cookie,
                        "missing_flag": "HttpOnly",
                    },
                )
            )

        if not attrs.get("secure", False):
            sev = "High" if (is_session_cookie or scheme.lower() == "https") else "Medium"
            findings.append(
                StandardFinding(
                    rule_id="COOKIE-002",
                    title=f"Cookie '{cookie_name}' Missing Secure Flag",
                    category="Cookie Security",
                    severity=sev,
                    target_path=target_path,
                    evidence=(
                        f"Set-Cookie for '{cookie_name}' (value redacted) lacks the Secure attribute."
                    ),
                    description=(
                        "Cookies without the Secure flag may be transmitted over unencrypted HTTP "
                        "connections, exposing session or application state."
                    ),
                    remediation_reference=(
                        f"Set Secure=True on cookie '{cookie_name}' and serve over HTTPS."
                    ),
                    confidence=95.0,
                    exposure=80.0,
                    exploitability=60.0 if is_session_cookie else 45.0,
                    metadata={
                        "cookie_name": cookie_name,
                        "is_session_cookie": is_session_cookie,
                        "missing_flag": "Secure",
                    },
                )
            )

        samesite = str(attrs.get("samesite", "")).strip()
        if not samesite or (samesite.lower() == "none" and not attrs.get("secure", False)):
            findings.append(
                StandardFinding(
                    rule_id="COOKIE-003",
                    title=f"Cookie '{cookie_name}' Missing or Weak SameSite Attribute",
                    category="Cookie Security",
                    severity="Medium" if is_session_cookie else "Low",
                    target_path=target_path,
                    evidence=(
                        f"Set-Cookie for '{cookie_name}' (value redacted) has SameSite={samesite or 'Unset'!r}."
                    ),
                    description=(
                        "Missing or unhardened SameSite cookie attributes weaken defense-in-depth "
                        "against Cross-Site Request Forgery (CSRF)."
                    ),
                    remediation_reference=(
                        f"Set SameSite='Lax' or 'Strict' on cookie '{cookie_name}'."
                    ),
                    confidence=92.0,
                    exposure=75.0,
                    exploitability=50.0 if is_session_cookie else 35.0,
                    metadata={
                        "cookie_name": cookie_name,
                        "is_session_cookie": is_session_cookie,
                        "samesite": samesite or "Unset",
                    },
                )
            )

    return findings


def scan_cookies(
    target_url: str,
    *,
    session: requests.Session | None = None,
    validated: ValidatedTarget | None = None,
    paths: tuple[str, ...] = ("/", "/session-test"),
    allow_public: bool | None = None,
) -> list[StandardFinding]:
    """Scan an authorised local target for insecure cookie configurations."""
    vt = validated or validate_target_url(target_url, allow_public=allow_public)
    findings: list[StandardFinding] = []
    seen_keys: set[tuple[str, str, str]] = set()

    base = vt.normalized_url.rstrip("/")
    for path in paths:
        url = vt.normalized_url if path == "/" else f"{base}{path}"
        try:
            resp = safe_fetch(url, method="GET", session=session, allow_public=allow_public)
        except requests.RequestException:
            continue
        raw_cookies = _extract_set_cookie_headers(resp)
        for finding in analyze_set_cookie_headers(
            raw_cookies, scheme=vt.scheme, target_path=path
        ):
            dedup_key = (
                finding.rule_id,
                str(finding.metadata.get("cookie_name", "")),
                path,
            )
            if dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                findings.append(finding)

    return findings
