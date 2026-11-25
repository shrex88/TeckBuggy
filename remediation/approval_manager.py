"""Developer Approval Manager for SENTINEL AI."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from config import DATABASE_URL
from database.database import get_session, init_db, log_audit_event
from database.models import ApprovalRecord, Finding, RemediationProposal

VALID_APPROVAL_STATES = frozenset({
    "Pending Review",
    "Approved",
    "Rejected",
    "Modification Requested",
    "Saved for Later",
    "Applied",
    "Verification Pending",
    "Verified",
    "Verification Failed",
    "Rolled Back",
})


class ApprovalError(ValueError):
    """Raised when an invalid approval transition is requested."""


def list_proposals(database_url: str = DATABASE_URL) -> list[dict[str, Any]]:
    """Return all remediation proposals joined with finding context."""
    init_db(database_url)
    with get_session(database_url) as session:
        proposals = list(
            session.scalars(
                select(RemediationProposal).order_by(
                    RemediationProposal.created_at.desc(), RemediationProposal.id.desc()
                )
            ).all()
        )
        results: list[dict[str, Any]] = []
        for p in proposals:
            finding = session.get(Finding, p.finding_id)
            results.append(
                {
                    "id": p.id,
                    "finding_id": p.finding_id,
                    "rule_id": finding.rule_id if finding else "UNKNOWN",
                    "finding_title": finding.title if finding else "Finding",
                    "severity": finding.severity if finding else "Medium",
                    "risk_score": float(finding.risk_score or 0.0) if finding else 0.0,
                    "target_path": finding.target_path if finding else "/",
                    "scan_id": finding.scan_id if finding else 0,
                    "action_id": p.action_id,
                    "source": p.source,
                    "framework": p.framework,
                    "technical_explanation": p.technical_explanation,
                    "security_impact": p.security_impact,
                    "root_cause": p.root_cause,
                    "recommended_correction": p.recommended_correction,
                    "original_config": p.original_config,
                    "corrected_config": p.corrected_config,
                    "secure_code_example": p.secure_code_example,
                    "verification_instructions": p.verification_instructions,
                    "remediation_priority": p.remediation_priority,
                    "approval_status": p.approval_status,
                    "created_at": p.created_at.strftime("%Y-%m-%d %H:%M UTC")
                    if p.created_at
                    else "—",
                }
            )
        return results


def set_proposal_decision(
    proposal_id: int,
    *,
    decision: str,
    reviewer: str = "developer",
    notes: str = "",
    database_url: str = DATABASE_URL,
) -> dict[str, Any]:
    """Record an explicit developer approval, rejection, modification request, or save-for-later decision."""
    allowed_decisions = {"Approved", "Rejected", "Modification Requested", "Saved for Later"}
    if decision not in allowed_decisions:
        raise ApprovalError(f"Decision must be one of {sorted(allowed_decisions)}.")

    init_db(database_url)
    with get_session(database_url) as session:
        proposal = session.get(RemediationProposal, proposal_id)
        if proposal is None:
            raise ApprovalError(f"Proposal #{proposal_id} not found.")

        proposal.approval_status = decision
        record = ApprovalRecord(
            proposal_id=proposal_id,
            decision=decision,
            reviewer=reviewer,
            notes=notes,
        )
        session.add(record)
        action_id = proposal.action_id

    log_audit_event(
        event_type=f"PROPOSAL_{decision.upper()}",
        actor=reviewer,
        action_id=action_id,
        status=decision,
        details=f"Proposal #{proposal_id} marked '{decision}' by {reviewer}. {notes}".strip(),
        database_url=database_url,
    )
    return {"proposal_id": proposal_id, "approval_status": decision, "action_id": action_id}
