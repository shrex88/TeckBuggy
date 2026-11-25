"""Post-Remediation Verification Engine for SENTINEL AI."""

from __future__ import annotations

from typing import Any

from config import DATABASE_URL
from database.database import get_session, init_db, log_audit_event
from database.models import Finding, RemediationProposal
from intelligence.security_proof import compare_scans
from scanner.orchestrator import run_security_scan


def verify_remediation_proposal(
    proposal_id: int,
    *,
    target_url: str,
    application_profile: str = "Fintech / Payment Application",
    database_url: str = DATABASE_URL,
) -> dict[str, Any]:
    """Run a fresh defensive scan and verify whether the target finding is resolved."""
    init_db(database_url)
    with get_session(database_url) as session:
        proposal = session.get(RemediationProposal, proposal_id)
        if proposal is None:
            raise ValueError(f"Proposal #{proposal_id} not found.")
        finding = session.get(Finding, proposal.finding_id)
        if finding is None:
            raise ValueError(f"Finding #{proposal.finding_id} not found.")

        baseline_scan_id = finding.scan_id
        rule_id = finding.rule_id
        target_path = finding.target_path
        action_id = proposal.action_id

    followup = run_security_scan(
        target_url=target_url,
        application_profile=application_profile,
        database_url=database_url,
    )

    proof = compare_scans(
        baseline_scan_id=baseline_scan_id,
        followup_scan_id=followup.scan_id,
        mark_verified_resolved=True,
        database_url=database_url,
    )

    fixed_keys = {(f["rule_id"], f["target_path"]) for f in proof.fixed_vulnerabilities}
    is_verified = (rule_id, target_path) in fixed_keys
    new_status = "Verified" if is_verified else "Verification Failed"

    with get_session(database_url) as session:
        proposal_obj = session.get(RemediationProposal, proposal_id)
        if proposal_obj is not None:
            proposal_obj.approval_status = new_status

    log_audit_event(
        event_type="REMEDIATION_VERIFIED" if is_verified else "REMEDIATION_VERIFICATION_FAILED",
        target_url=target_url,
        action_id=action_id,
        status=new_status,
        details=(
            f"Proposal #{proposal_id} ({rule_id} at {target_path}) "
            f"checked against follow-up scan #{followup.scan_id}: {new_status}."
        ),
        database_url=database_url,
    )

    return {
        "proposal_id": proposal_id,
        "verified": is_verified,
        "approval_status": new_status,
        "followup_scan_id": followup.scan_id,
        "proof": proof,
    }
