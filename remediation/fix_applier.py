"""Controlled Remediation Applier for SENTINEL AI.

Captures a SQLite ConfigBackup before calling the Low-Security Lab's
token-protected /api/remediation/apply endpoint.
"""

from __future__ import annotations

import uuid
from typing import Any

import requests

from config import ALLOWLISTED_ACTIONS, DATABASE_URL, DEFAULT_REQUEST_TIMEOUT, REMEDIATION_API_TOKEN
from database.database import get_session, init_db, log_audit_event
from database.models import ConfigBackup, RemediationProposal
from remediation.fix_validator import RemediationValidationError, validate_remediation_request


class RemediationApplyError(RuntimeError):
    """Raised when applying an approved remediation fails."""


def apply_approved_remediation(
    proposal_id: int,
    *,
    target_url: str,
    approved_by: str = "developer",
    database_url: str = DATABASE_URL,
    http_session: requests.Session | None = None,
) -> dict[str, Any]:
    """Validate approval, store backup, and apply allowlisted fix to Application B."""
    init_db(database_url)
    with get_session(database_url) as session:
        proposal = session.get(RemediationProposal, proposal_id)
        if proposal is None:
            raise RemediationApplyError(f"Proposal #{proposal_id} not found.")

        action_id = proposal.action_id
        approval_status = proposal.approval_status
        finding_id = proposal.finding_id

    # Enforce strict validation (rejects High-Sec App A, pending/rejected, unknown actions)
    clean_action = validate_remediation_request(
        target_url=target_url,
        action_id=action_id,
        approval_status=approval_status,
    )

    backup_uid = f"bkp-{uuid.uuid4().hex[:12]}"
    base_url = target_url.rstrip("/")
    sess = http_session or requests.Session()
    headers = {"X-Sentinel-Approval-Token": REMEDIATION_API_TOKEN}

    try:
        resp = sess.post(
            f"{base_url}/api/remediation/apply",
            json={
                "action_id": clean_action,
                "developer_approved": True,
                "backup_uid": backup_uid,
                "target_identity": "SENTINEL_LOW_SECURITY_DEMO_LAB",
            },
            headers=headers,
            timeout=DEFAULT_REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise RemediationApplyError(f"Failed to contact local remediation API: {exc}") from exc

    data = resp.json() if resp.headers.get("Content-Type", "").startswith("application/json") else {}
    if resp.status_code == 404:
        log_audit_event(
            event_type="REMEDIATION_ENDPOINT_UNAVAILABLE",
            target_url=base_url,
            actor=approved_by,
            action_id=clean_action,
            status="manual_required",
            details=f"Proposal #{proposal_id}: target {base_url} does not expose /api/remediation/apply (HTTP 404).",
            database_url=database_url,
        )
        raise RemediationApplyError(
            f"Target '{base_url}' does not expose /api/remediation/apply (HTTP 404). "
            "Apply the approved fix manually to your application, then click 'Mark Applied Manually' and 'Verify Fix via Fresh Scan'."
        )
    if resp.status_code != 200:
        err_msg = data.get("error") or f"HTTP {resp.status_code}"
        log_audit_event(
            event_type="REMEDIATION_APPLY_FAILED",
            target_url=base_url,
            actor=approved_by,
            action_id=clean_action,
            status="failed",
            details=f"Proposal #{proposal_id} apply failed: {err_msg}",
            database_url=database_url,
        )
        raise RemediationApplyError(f"Remediation API rejected request: {err_msg}")

    setting_key = str(data.get("setting_key") or ALLOWLISTED_ACTIONS[clean_action]["setting"])
    original_val = str(data.get("original_value"))
    applied_val = str(data.get("applied_value"))

    with get_session(database_url) as session:
        backup = ConfigBackup(
            backup_uid=backup_uid,
            target_url=base_url,
            finding_id=finding_id,
            proposal_id=proposal_id,
            action_id=clean_action,
            setting_key=setting_key,
            original_value=original_val,
            applied_value=applied_val,
            approved_by=approved_by,
        )
        session.add(backup)
        proposal_obj = session.get(RemediationProposal, proposal_id)
        if proposal_obj is not None:
            proposal_obj.approval_status = "Verification Pending"

    log_audit_event(
        event_type="REMEDIATION_APPLIED",
        target_url=base_url,
        actor=approved_by,
        action_id=clean_action,
        status="Verification Pending",
        details=(
            f"Applied {clean_action} on {setting_key} ({original_val} -> {applied_val}); "
            f"backup={backup_uid}. Awaiting fresh Security Proof verification."
        ),
        database_url=database_url,
    )

    return {
        "proposal_id": proposal_id,
        "action_id": clean_action,
        "backup_uid": backup_uid,
        "setting_key": setting_key,
        "original_value": original_val,
        "applied_value": applied_val,
        "approval_status": "Verification Pending",
    }
