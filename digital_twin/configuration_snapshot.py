"""Virtual Configuration Snapshot builder for Security Digital Twin.

Retrieves genuine scan & finding observations from SQLite without modifying
the target application or storing any actual cookie values or secrets.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select

from config import DATABASE_URL
from database.database import get_session, init_db
from database.models import ConfigurationSnapshot, Finding, Scan
from scanner.target_validator import validate_target_url


class DigitalTwinSnapshotError(ValueError):
    """Raised when a virtual snapshot cannot be created from scan history."""


@dataclass(frozen=True)
class VirtualSnapshot:
    """Isolated virtual representation of an authorised local application."""

    snapshot_id: int
    scan_id: int
    target_url: str
    app_label: str
    scheme: str
    baseline_score: float
    headers: dict[str, str]
    cookies_meta: list[dict[str, Any]]
    exposed_paths: list[str]
    findings: list[dict[str, Any]]


def create_virtual_snapshot(
    target_url: str,
    *,
    app_label: str = "Authorised Local App",
    database_url: str = DATABASE_URL,
) -> VirtualSnapshot:
    """Create an isolated virtual snapshot from the latest completed scan of target_url."""
    vt = validate_target_url(target_url)
    norm = vt.normalized_url.rstrip("/")

    init_db(database_url)
    with get_session(database_url) as session:
        # Match either with or without trailing slash
        candidates = list(
            session.scalars(
                select(Scan)
                .where(Scan.status == "completed")
                .order_by(Scan.scan_date.desc(), Scan.id.desc())
            ).all()
        )
        latest_scan = next(
            (s for s in candidates if s.target_url.rstrip("/") == norm),
            None,
        )
        if latest_scan is None:
            raise DigitalTwinSnapshotError(
                f"No completed scan found for '{target_url}'. Run a scan first before launching the Digital Twin."
            )

        db_findings = list(
            session.scalars(
                select(Finding).where(Finding.scan_id == latest_scan.id)
            ).all()
        )
        failed_rules = {f.rule_id for f in db_findings}

        # Reconstruct safe virtual header state from actual scanner observations
        headers: dict[str, str] = {}
        if "HDR-001" not in failed_rules:
            headers["Content-Security-Policy"] = "default-src 'self'"
        if vt.scheme == "https" and "HDR-002" not in failed_rules:
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if "HDR-003" not in failed_rules:
            headers["X-Frame-Options"] = "DENY"
        if "HDR-004" not in failed_rules:
            headers["X-Content-Type-Options"] = "nosniff"
        if "HDR-005" not in failed_rules:
            headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if "HDR-006" not in failed_rules:
            headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        # Reconstruct safe cookie attribute metadata (never actual values)
        cookie_findings = [f for f in db_findings if f.rule_id.startswith("COOKIE-")]
        cookies_meta: list[dict[str, Any]] = []
        if cookie_findings:
            cookies_meta.append(
                {
                    "name": "sentinel_session_cookie",
                    "httponly": "COOKIE-001" not in failed_rules,
                    "secure": "COOKIE-002" not in failed_rules,
                    "samesite": "" if "COOKIE-003" in failed_rules else "Lax",
                }
            )
        else:
            cookies_meta.append(
                {
                    "name": "sentinel_session_cookie",
                    "httponly": True,
                    "secure": True,
                    "samesite": "Lax",
                }
            )

        exposed_paths = [
            f.target_path for f in db_findings if f.rule_id.startswith("FILE-")
        ]

        snap_row = ConfigurationSnapshot(
            scan_id=latest_scan.id,
            target_url=latest_scan.target_url,
            app_label=app_label,
            scheme=urlparse(latest_scan.target_url).scheme or "http",
            headers_json=json.dumps(headers),
            cookies_meta_json=json.dumps(cookies_meta),
            exposed_paths_json=json.dumps(exposed_paths),
        )
        session.add(snap_row)
        session.flush()
        snap_id = int(snap_row.id)

        findings_data = [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "risk_score": float(f.risk_score or 0.0),
                "target_path": f.target_path,
                "owasp_category": f.owasp_category,
                "finding_status": f.finding_status,
            }
            for f in db_findings
        ]
        baseline_score = float(latest_scan.security_score or 0.0)
        scan_id = int(latest_scan.id)
        target = latest_scan.target_url

    return VirtualSnapshot(
        snapshot_id=snap_id,
        scan_id=scan_id,
        target_url=target,
        app_label=app_label,
        scheme=vt.scheme,
        baseline_score=baseline_score,
        headers=headers,
        cookies_meta=cookies_meta,
        exposed_paths=exposed_paths,
        findings=findings_data,
    )
