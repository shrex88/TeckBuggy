"""Hands-On Security Lab Challenge Engine for Security Learning Mode.

Challenges are restricted to authorised local targets and never automatically
modify the application; achievements are awarded only after genuine Security
Proof verification.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from config import DATABASE_URL
from database.database import get_session, init_db
from database.models import PracticalExercise
from intelligence.security_proof import SecurityProofError, compare_scans
from learning.progress_tracker import add_learning_points, award_achievement
from scanner.orchestrator import run_security_scan
from scanner.target_validator import validate_target_url


@dataclass(frozen=True)
class SecurityChallenge:
    """Practical hands-on challenge tied to a scanner rule."""

    challenge_id: str
    title: str
    rule_id: str
    badge_id: str
    badge_name: str
    instructions: list[str]


CHALLENGES: tuple[SecurityChallenge, ...] = (
    SecurityChallenge(
        challenge_id="CHAL-CSP",
        title="Fix Missing CSP Header",
        rule_id="HDR-001",
        badge_id="HEADER_GUARDIAN",
        badge_name="Header Guardian",
        instructions=[
            "1. Scan the Low-Security Application (127.0.0.1:5050).",
            "2. Identify HDR-001 (Missing Content-Security-Policy).",
            "3. Study the HDR-001 lesson and simulate CSP in Security Digital Twin.",
            "4. Manually apply or approve ENABLE_CSP in Developer Approval Centre.",
            "5. Click 'Verify Challenge via Rescan' below to prove resolution.",
        ],
    ),
    SecurityChallenge(
        challenge_id="CHAL-COOKIE",
        title="Harden Session Cookie (HttpOnly)",
        rule_id="COOKIE-001",
        badge_id="COOKIE_PROTECTOR",
        badge_name="Cookie Protector",
        instructions=[
            "1. Scan the Low-Security Application (127.0.0.1:5050).",
            "2. Identify COOKIE-001 (Missing HttpOnly Flag).",
            "3. Study the COOKIE-001 lesson and simulate HttpOnly in Digital Twin.",
            "4. Apply ENABLE_HTTPONLY_COOKIE via Developer Approval Centre.",
            "5. Click 'Verify Challenge via Rescan' below to prove resolution.",
        ],
    ),
    SecurityChallenge(
        challenge_id="CHAL-CONFIG",
        title="Lock Down Exposed Configuration (/config.json)",
        rule_id="FILE-002",
        badge_id="CONFIG_DETECTIVE",
        badge_name="Configuration Detective",
        instructions=[
            "1. Scan the Low-Security Application (127.0.0.1:5050).",
            "2. Identify FILE-002 (Exposed /config.json).",
            "3. Study the FILE-002 lesson.",
            "4. Apply DISABLE_SYNTHETIC_CONFIG_EXPOSURE via Developer Approval Centre.",
            "5. Click 'Verify Challenge via Rescan' below to prove resolution.",
        ],
    ),
)


def verify_practical_challenge(
    *,
    challenge_id: str,
    baseline_scan_id: int,
    target_url: str,
    learner_id: str = "default",
    database_url: str = DATABASE_URL,
) -> dict[str, Any]:
    """Run a fresh scan on an authorised local target and verify challenge completion."""
    validate_target_url(target_url)
    challenge = next((c for c in CHALLENGES if c.challenge_id == challenge_id), None)
    if challenge is None:
        raise ValueError(f"Unknown challenge '{challenge_id}'.")

    followup = run_security_scan(target_url=target_url, database_url=database_url)
    try:
        proof = compare_scans(
            baseline_scan_id=baseline_scan_id,
            followup_scan_id=followup.scan_id,
            mark_verified_resolved=True,
            database_url=database_url,
        )
    except SecurityProofError as exc:
        return {"verified": False, "message": str(exc), "followup_scan_id": followup.scan_id}

    fixed_rules = {f["rule_id"] for f in proof.fixed_vulnerabilities}
    verified = challenge.rule_id in fixed_rules

    if verified:
        init_db(database_url)
        with get_session(database_url) as session:
            session.add(
                PracticalExercise(
                    learner_id=learner_id,
                    challenge_id=challenge.challenge_id,
                    rule_id=challenge.rule_id,
                    target_url=followup.target_url,
                    status="verified",
                    verified_scan_id=followup.scan_id,
                    completed_at=datetime.now(timezone.utc),
                )
            )
        add_learning_points(50, learner_id=learner_id, database_url=database_url)
        award_achievement(
            badge_id=challenge.badge_id,
            badge_name=challenge.badge_name,
            reason=f"Verified resolution of {challenge.rule_id} on Scan #{followup.scan_id}.",
            learner_id=learner_id,
            database_url=database_url,
        )
        return {
            "verified": True,
            "message": f"Challenge '{challenge.title}' verified! Badge '{challenge.badge_name}' awarded.",
            "followup_scan_id": followup.scan_id,
        }

    return {
        "verified": False,
        "message": (
            f"{challenge.rule_id} is still present in Scan #{followup.scan_id}. "
            "Apply the fix first, then re-verify."
        ),
        "followup_scan_id": followup.scan_id,
    }
