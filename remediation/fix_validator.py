"""Strict Remediation Validator for SENTINEL AI.

Enforces target authorization (blocks High-Security Application A),
action allowlisting, and mandatory developer approval before execution.
"""

from __future__ import annotations

from urllib.parse import urlparse

from config import ALLOWLISTED_ACTIONS, HIGH_SECURITY_APP_URL, LOW_SECURITY_APP_URL
from scanner.target_validator import validate_target_url


class RemediationValidationError(ValueError):
    """Raised when a remediation request violates safety or governance rules."""


def validate_remediation_request(
    *,
    target_url: str,
    action_id: str,
    approval_status: str,
) -> str:
    """Validate that target is remediable, action is allowlisted, and status is Approved."""
    vt = validate_target_url(target_url)
    normalized_target = vt.normalized_url.rstrip("/")

    high_parsed = urlparse(HIGH_SECURITY_APP_URL)
    low_parsed = urlparse(LOW_SECURITY_APP_URL)
    target_parsed = urlparse(normalized_target)

    # Never allow modifying High-Security Application A (read-only)
    if (target_parsed.hostname, target_parsed.port) == (high_parsed.hostname, high_parsed.port):
        raise RemediationValidationError(
            "Target rejected: High-Security Reference Application (Application A) is strictly read-only."
        )

    # Only allow remediation against the authorised Low-Security Demo Lab (Application B)
    if (target_parsed.hostname, target_parsed.port) != (low_parsed.hostname, low_parsed.port):
        raise RemediationValidationError(
            f"Target rejected: '{target_url}' is not registered as a remediable local lab target."
        )

    clean_action = (action_id or "").strip().upper()
    if clean_action not in ALLOWLISTED_ACTIONS:
        raise RemediationValidationError(
            f"Action '{action_id}' is not in the approved ALLOWLISTED_ACTIONS catalogue."
        )

    if approval_status != "Approved":
        raise RemediationValidationError(
            f"Execution blocked: proposal approval_status is '{approval_status}', expected 'Approved'."
        )

    return clean_action
