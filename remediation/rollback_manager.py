"""Smart Rollback Manager for SENTINEL AI (Unique Feature 6)."""

from __future__ import annotations

from typing import Any

import requests
from sqlalchemy import select

from config import DATABASE_URL, DEFAULT_REQUEST_TIMEOUT, REMEDIATION_API_TOKEN
from database.database import get_session, init_db, log_audit_event
from database.models import ConfigBackup, RemediationProposal, RollbackRecord


class RollbackError(RuntimeError):
    """Raised when a configuration rollback cannot be completed or verified."""


def list_backups(database_url: str = DATABASE_URL) -> list[dict[str, Any]]:
    """Return stored configuration backups newest first."""
    init_db(database_url)
    with get_session(database_url) as session:
        rows = list(
            session.scalars(
                select(ConfigBackup).order_by(ConfigBackup.created_at.desc(), ConfigBackup.id.desc())
            ).all()
        )
        return [
            {
                "id": b.id,
                "backup_uid": b.backup_uid,
                "target_url": b.target_url,
                "finding_id": b.finding_id,
                "proposal_id": b.proposal_id,
                "action_id": b.action_id,
                "setting_key": b.setting_key,
                "original_value": b.original_value,
                "applied_value": b.applied_value,
                "approved_by": b.approved_by,
                "created_at": b.created_at.strftime("%Y-%m-%d %H:%M UTC") if b.created_at else "—",
            }
            for b in rows
        ]


def rollback_configuration(
    backup_uid: str,
    *,
    database_url: str = DATABASE_URL,
    http_session: requests.Session | None = None,
) -> dict[str, Any]:
    """Restore the pre-remediation setting using backup_uid and verify restoration."""
    init_db(database_url)
    with get_session(database_url) as session:
        backup = session.scalar(
            select(ConfigBackup).where(ConfigBackup.backup_uid == backup_uid)
        )
        if backup is None:
            raise RollbackError(f"Backup '{backup_uid}' not found in SQLite.")

        target_url = backup.target_url.rstrip("/")
        setting_key = backup.setting_key
        expected_original = backup.original_value
        action_id = backup.action_id
        proposal_id = backup.proposal_id

    sess = http_session or requests.Session()
    headers = {"X-Sentinel-Approval-Token": REMEDIATION_API_TOKEN}

    try:
        resp = sess.post(
            f"{target_url}/api/remediation/rollback",
            json={"backup_uid": backup_uid},
            headers=headers,
            timeout=DEFAULT_REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise RollbackError(f"Rollback API call failed: {exc}") from exc

    if resp.status_code != 200:
        err = resp.json().get("error", f"HTTP {resp.status_code}") if resp.text else f"HTTP {resp.status_code}"
        raise RollbackError(f"Target refused rollback: {err}")

    # Verify restoration via /api/remediation/status
    verified = False
    try:
        status_resp = sess.get(
            f"{target_url}/api/remediation/status",
            headers=headers,
            timeout=DEFAULT_REQUEST_TIMEOUT,
        )
        if status_resp.status_code == 200:
            lab_settings = status_resp.json().get("lab_settings", {})
            verified = str(lab_settings.get(setting_key)) == expected_original
    except requests.RequestException:
        verified = False

    if not verified:
        raise RollbackError(
            f"Rollback verification failed: '{setting_key}' did not match original '{expected_original}'."
        )

    with get_session(database_url) as session:
        rec = RollbackRecord(
            backup_uid=backup_uid,
            target_url=target_url,
            action_id=action_id,
            restored_verified=1,
            details=f"Restored {setting_key}={expected_original} and verified via /api/remediation/status.",
        )
        session.add(rec)
        proposal = session.get(RemediationProposal, proposal_id)
        if proposal is not None:
            proposal.approval_status = "Rolled Back"

    log_audit_event(
        event_type="REMEDIATION_ROLLED_BACK",
        target_url=target_url,
        action_id=action_id,
        status="Rolled Back",
        details=f"Restored {setting_key}={expected_original} from {backup_uid} (verified={verified}).",
        database_url=database_url,
    )

    return {
        "backup_uid": backup_uid,
        "setting_key": setting_key,
        "restored_value": expected_original,
        "restored_verified": verified,
        "approval_status": "Rolled Back",
    }
