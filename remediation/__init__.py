"""Remediation governance, generation, application, rollback, and verification package."""

from remediation.approval_manager import (
    VALID_APPROVAL_STATES,
    ApprovalError,
    list_proposals,
    set_proposal_decision,
)
from remediation.fix_applier import RemediationApplyError, apply_approved_remediation
from remediation.fix_generator import (
    SUPPORTED_FRAMEWORKS,
    RemediationPlaybook,
    generate_remediation_playbook,
)
from remediation.fix_validator import (
    RemediationValidationError,
    run_deterministic_proposal_validation,
    validate_remediation_request,
)
from remediation.regression_analyzer import RegressionItem, analyze_proposal_regressions
from remediation.rollback_manager import RollbackError, list_backups, rollback_configuration
from remediation.verification_engine import verify_remediation_proposal

__all__ = [
    "ApprovalError",
    "RegressionItem",
    "RemediationApplyError",
    "RemediationPlaybook",
    "RemediationValidationError",
    "RollbackError",
    "SUPPORTED_FRAMEWORKS",
    "VALID_APPROVAL_STATES",
    "analyze_proposal_regressions",
    "apply_approved_remediation",
    "generate_remediation_playbook",
    "list_backups",
    "list_proposals",
    "rollback_configuration",
    "run_deterministic_proposal_validation",
    "set_proposal_decision",
    "validate_remediation_request",
    "verify_remediation_proposal",
]
