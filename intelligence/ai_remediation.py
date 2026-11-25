"""SENTINEL AI Remediation Copilot (Unique Feature 3).

Generates structured remediation proposals via Google Gemini API (treated as
untrusted data and strictly validated), with deterministic rule-based fallback
when Gemini is unavailable.
"""

from __future__ import annotations

import json
from typing import Any

from config import ALLOWLISTED_ACTIONS, DATABASE_URL
from database.database import get_session, init_db, log_audit_event
from database.models import RemediationProposal
from intelligence.gemini_client import is_gemini_configured, request_gemini_json
from remediation.fix_generator import generate_remediation_playbook

REQUIRED_GEMINI_KEYS: tuple[str, ...] = (
    "technical_explanation",
    "potential_security_impact",
    "root_cause",
    "recommended_correction",
    "corrected_configuration",
    "secure_code_example",
    "verification_instructions",
    "remediation_priority",
    "action_id",
)

RULE_TO_ACTION_ID: dict[str, str] = {
    "HDR-001": "ENABLE_CSP",
    "HDR-003": "ENABLE_FRAME_PROTECTION",
    "HDR-004": "ENABLE_NOSNIFF",
    "HDR-005": "ENABLE_REFERRER_POLICY",
    "HDR-006": "ENABLE_PERMISSIONS_POLICY",
    "COOKIE-001": "ENABLE_HTTPONLY_COOKIE",
    "COOKIE-002": "ENABLE_SECURE_COOKIE",
    "COOKIE-003": "CONFIGURE_SAMESITE",
    "FILE-002": "DISABLE_SYNTHETIC_CONFIG_EXPOSURE",
    "TLS-000": "ENABLE_TLS_TEST_CONFIGURATION",
}


def validate_gemini_proposal_payload(payload: Any) -> dict[str, str] | None:
    """Strictly validate untrusted Gemini JSON output against schema and allowlisted actions."""
    if not isinstance(payload, dict):
        return None

    cleaned: dict[str, str] = {}
    for key in REQUIRED_GEMINI_KEYS:
        val = payload.get(key)
        if not isinstance(val, str) or not val.strip():
            return None
        cleaned[key] = val.strip()

    action_id = cleaned["action_id"].upper()
    if action_id not in ALLOWLISTED_ACTIONS:
        return None
    cleaned["action_id"] = action_id
    return cleaned


def _build_gemini_prompt(finding: dict[str, Any], framework: str) -> str:
    context = {
        "finding_id": finding.get("id"),
        "rule_id": finding.get("rule_id"),
        "vulnerability_title": finding.get("title"),
        "severity": finding.get("severity"),
        "technical_evidence": finding.get("evidence"),
        "target_path": finding.get("target_path"),
        "application_framework": framework,
        "owasp_classification": finding.get("owasp_category"),
        "allowlisted_action_ids": sorted(ALLOWLISTED_ACTIONS.keys()),
    }
    return (
        "You are SENTINEL AI Remediation Copilot. Analyse the following web security finding "
        "and return ONLY a JSON object with these exact string keys: "
        f"{list(REQUIRED_GEMINI_KEYS)}. "
        "Choose action_id strictly from allowlisted_action_ids. "
        "Do not output shell commands or destructive scripts.\n\n"
        f"Finding Context:\n{json.dumps(context, indent=2)}"
    )


def generate_ai_remediation_proposal(
    finding: dict[str, Any],
    *,
    framework: str = "Flask",
    use_gemini: bool = True,
    database_url: str = DATABASE_URL,
) -> dict[str, Any]:
    """Generate and persist a validated remediation proposal (Gemini or deterministic fallback)."""
    rule_id = str(finding.get("rule_id", "")).upper()
    default_action_id = RULE_TO_ACTION_ID.get(rule_id, "ENABLE_CSP")
    playbook = generate_remediation_playbook(finding)

    validated_gemini: dict[str, str] | None = None
    if use_gemini and is_gemini_configured():
        raw_resp = request_gemini_json(_build_gemini_prompt(finding, framework))
        validated_gemini = validate_gemini_proposal_payload(raw_resp)

    if validated_gemini is not None:
        source = "gemini_ai"
        action_id = validated_gemini["action_id"]
        tech_exp = validated_gemini["technical_explanation"]
        sec_impact = validated_gemini["potential_security_impact"]
        root_cause = validated_gemini["root_cause"]
        rec_corr = validated_gemini["recommended_correction"]
        corr_cfg = validated_gemini["corrected_configuration"]
        code_ex = validated_gemini["secure_code_example"]
        verif = validated_gemini["verification_instructions"]
        priority = validated_gemini["remediation_priority"]
    else:
        source = "rule_based_fallback"
        action_id = default_action_id
        tech_exp = playbook.technical_explanation
        sec_impact = playbook.security_impact
        root_cause = f"Control {rule_id} is disabled or missing at {finding.get('target_path', '/')}."
        rec_corr = playbook.recommended_fix
        corr_cfg = playbook.corrected_config
        code_ex = playbook.snippets.get(framework, playbook.corrected_config)
        verif = playbook.verification_instructions
        priority = "High" if playbook.risk_score >= 70 else "Medium"

    original_cfg = f"Current state at {finding.get('target_path', '/')}: {finding.get('evidence', 'Misconfigured')[:240]}"

    init_db(database_url)
    with get_session(database_url) as session:
        proposal = RemediationProposal(
            finding_id=int(finding["id"]),
            action_id=action_id,
            source=source,
            framework=framework,
            technical_explanation=tech_exp,
            security_impact=sec_impact,
            root_cause=root_cause,
            recommended_correction=rec_corr,
            original_config=original_cfg,
            corrected_config=corr_cfg,
            secure_code_example=code_ex,
            verification_instructions=verif,
            remediation_priority=priority,
            approval_status="Pending Review",
        )
        session.add(proposal)
        session.flush()
        proposal_id = int(proposal.id)

    log_audit_event(
        event_type="PROPOSAL_GENERATED",
        action_id=action_id,
        status="Pending Review",
        details=f"Generated {source} proposal #{proposal_id} for finding #{finding['id']} ({rule_id}).",
        database_url=database_url,
    )

    return {
        "id": proposal_id,
        "finding_id": int(finding["id"]),
        "action_id": action_id,
        "source": source,
        "framework": framework,
        "technical_explanation": tech_exp,
        "security_impact": sec_impact,
        "root_cause": root_cause,
        "recommended_correction": rec_corr,
        "original_config": original_cfg,
        "corrected_config": corr_cfg,
        "secure_code_example": code_ex,
        "verification_instructions": verif,
        "remediation_priority": priority,
        "approval_status": "Pending Review",
    }
