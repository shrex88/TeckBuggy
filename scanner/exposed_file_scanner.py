"""Safe Exposed File & Configuration Endpoint Scanner for SENTINEL AI.

Checks only a strictly limited predefined list using HEAD (and limited GET fallback)
without downloading or storing sensitive file contents.
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

    checked = 0
    for path in paths:
        if checked >= MAX_REQUESTS_PER_SCAN:
            break
        if path not in PREDEFINED_EXPOSED_PATHS:
            continue

        checked += 1
        probe_url = f"{base}{path}"
        validate_target_url(probe_url)

        try:
            resp = http_session.head(
                probe_url,
                timeout=DEFAULT_REQUEST_TIMEOUT,
                allow_redirects=False,
            )
            if resp.status_code in {405, 501}:
                # Limited GET fallback: inspect headers/status only, never buffer body
                with http_session.get(
                    probe_url,
                    timeout=DEFAULT_REQUEST_TIMEOUT,
                    allow_redirects=False,
                    stream=True,
                ) as get_resp:
                    status_code = get_resp.status_code
                    content_type = get_resp.headers.get("Content-Type", "unknown")
                    content_length = get_resp.headers.get("Content-Length", "unknown")
            else:
                status_code = resp.status_code
                content_type = resp.headers.get("Content-Type", "unknown")
                content_length = resp.headers.get("Content-Length", "unknown")
        except requests.RequestException:
            continue

        if status_code == 200:
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
