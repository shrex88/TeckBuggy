"""Safe Exposed File & Configuration Endpoint Scanner for SENTINEL AI.

Checks only a strictly limited predefined list using HEAD (and limited GET fallback)
without downloading or storing sensitive file contents. Includes soft-404 / SPA
fallback filtering and Content-Type validation to prevent false positives.
"""

from __future__ import annotations

import time
from typing import Iterable

import requests

from config import DEFAULT_REQUEST_TIMEOUT, MAX_REQUESTS_PER_SCAN
from scanner.models import StandardFinding
from scanner.target_validator import ValidatedTarget, validate_target_url

PREDEFINED_EXPOSED_PATHS: tuple[str, ...] = (
    "/.env",
    "/config.json",
    "/backup.zip",
    "/phpinfo.php",
    "/server-status",
)

# Paths that must never be flagged if the server returns an HTML SPA fallback
NON_HTML_SENSITIVE_PATHS: frozenset[str] = frozenset({
    "/.env",
    "/config.json",
    "/backup.zip",
})

PATH_METADATA: dict[str, dict[str, str]] = {
    "/.env": {
        "rule_id": "FILE-001",
        "title": "Exposed Environment Configuration (/.env)",
        "severity": "Critical",
        "remediation": "Block public access to dotfiles and remove .env from web-accessible roots.",
    },
    "/config.json": {
        "rule_id": "FILE-002",
        "title": "Exposed Application Configuration (/config.json)",
        "severity": "High",
        "remediation": "Restrict or remove configuration JSON endpoints from unauthenticated HTTP access.",
    },
    "/backup.zip": {
        "rule_id": "FILE-003",
        "title": "Exposed Backup Archive (/backup.zip)",
        "severity": "Critical",
        "remediation": "Remove archive backups from web roots and store backups in access-controlled storage.",
    },
    "/phpinfo.php": {
        "rule_id": "FILE-004",
        "title": "Exposed Diagnostics Endpoint (/phpinfo.php)",
        "severity": "Medium",
        "remediation": "Remove phpinfo.php and diagnostic scripts from deployed environments.",
    },
    "/server-status": {
        "rule_id": "FILE-005",
        "title": "Exposed Server Status Endpoint (/server-status)",
        "severity": "Medium",
        "remediation": "Restrict /server-status to internal administrative interfaces only.",
    },
}


def _probe_metadata(
    http_session: requests.Session,
    probe_url: str,
) -> tuple[int, str, str] | None:
    """Safely fetch (status_code, content_type, content_length) without buffering body."""
    try:
        resp = http_session.head(
            probe_url,
            timeout=DEFAULT_REQUEST_TIMEOUT,
            allow_redirects=False,
        )
        if resp.status_code in {405, 501}:
            with http_session.get(
                probe_url,
                timeout=DEFAULT_REQUEST_TIMEOUT,
                allow_redirects=False,
                stream=True,
            ) as get_resp:
                return (
                    get_resp.status_code,
                    get_resp.headers.get("Content-Type", "unknown"),
                    get_resp.headers.get("Content-Length", "unknown"),
                )
        return (
            resp.status_code,
            resp.headers.get("Content-Type", "unknown"),
            resp.headers.get("Content-Length", "unknown"),
        )
    except requests.RequestException:
        return None


def _is_html_content_type(content_type: str) -> bool:
    ct = content_type.lower()
    return "text/html" in ct or "application/xhtml+xml" in ct


def scan_exposed_files(
    target_url: str,
    *,
    session: requests.Session | None = None,
    validated: ValidatedTarget | None = None,
    paths: Iterable[str] = PREDEFINED_EXPOSED_PATHS,
    rate_limit_delay: float = 0.05,
) -> list[StandardFinding]:
    """Check the predefined sensitive paths using safe metadata-only requests."""
    vt = validated or validate_target_url(target_url)
    http_session = session or requests.Session()
    findings: list[StandardFinding] = []
    base = vt.normalized_url.rstrip("/")

    # Baseline soft-404 / SPA catch-all detection on a guaranteed-nonexistent path
    baseline_sig: tuple[int, str, str] | None = None
    baseline_url = f"{base}/__sentinel_soft404_probe_9f3a__"
    validate_target_url(baseline_url)
    baseline_probe = _probe_metadata(http_session, baseline_url)
    if baseline_probe is not None and baseline_probe[0] == 200:
        baseline_sig = baseline_probe

    checked = 0
    for path in paths:
        if checked >= MAX_REQUESTS_PER_SCAN:
            break
        if path not in PREDEFINED_EXPOSED_PATHS:
            continue

        checked += 1
        probe_url = f"{base}{path}"
        validate_target_url(probe_url)

        probe_res = _probe_metadata(http_session, probe_url)
        if probe_res is None:
            continue

        status_code, content_type, content_length = probe_res

        if status_code == 200:
            # Filter out SPA catch-all / soft-404 responses
            if baseline_sig is not None and probe_res == baseline_sig:
                continue
            if path in NON_HTML_SENSITIVE_PATHS and _is_html_content_type(content_type):
                continue

            meta = PATH_METADATA[path]
            findings.append(
                StandardFinding(
                    rule_id=meta["rule_id"],
                    title=meta["title"],
                    category="Exposed Files & Endpoints",
                    severity=meta["severity"],
                    target_path=path,
                    evidence=(
                        f"HTTP {status_code} returned for '{path}' "
                        f"(Content-Type: {content_type}, Content-Length: {content_length}). "
                        "Body content was not downloaded or stored."
                    ),
                    description=(
                        f"Sensitive endpoint '{path}' is accessible over HTTP without authorization."
                    ),
                    remediation_reference=meta["remediation"],
                    confidence=95.0,
                    exposure=95.0,
                    exploitability=80.0 if meta["severity"] == "Critical" else 65.0,
                    metadata={
                        "status_code": status_code,
                        "content_type": content_type,
                        "content_length": content_length,
                    },
                )
            )

        if rate_limit_delay > 0:
            time.sleep(rate_limit_delay)

    return findings
