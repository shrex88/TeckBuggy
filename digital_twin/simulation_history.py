"""Simulation History persistence and comparison for Security Digital Twin."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from config import DATABASE_URL
from database.database import get_session, init_db
from database.models import (
    CompatibilityResult,
    DigitalTwinSimulation,
    ProposedChange,
    SimulatedFinding,
)


def save_simulation_history(
    *,
    snapshot_id: int,
    target_url: str,
    simulation_mode: str,
    baseline_score: float,
    projected_score: float,
    classification: str,
    passed_checks: int,
    failed_checks: int,
    summary_text: str,
    proposed_changes: list[tuple[str, str, str]],
    remaining_findings: list[dict[str, Any]],
    compatibility_warnings: list[dict[str, str]],
    database_url: str = DATABASE_URL,
) -> int:
    """Persist a Digital Twin simulation and its child records to SQLite."""
    init_db(database_url)
    with get_session(database_url) as session:
        sim = DigitalTwinSimulation(
            snapshot_id=snapshot_id,
            target_url=target_url,
            simulation_mode=simulation_mode,
            baseline_score=baseline_score,
            projected_score=projected_score,
            classification=classification,
            passed_checks=passed_checks,
            failed_checks=failed_checks,
            remaining_count=len(remaining_findings),
            summary_text=summary_text,
        )
        session.add(sim)
        session.flush()
        sim_id = int(sim.id)

        for ctrl, orig, prop in proposed_changes:
            session.add(
                ProposedChange(
                    simulation_id=sim_id,
                    control_name=ctrl,
                    original_value=orig,
                    proposed_value=prop,
                )
            )
        for rf in remaining_findings:
            session.add(
                SimulatedFinding(
                    simulation_id=sim_id,
                    rule_id=str(rf["rule_id"]),
                    title=str(rf["title"]),
                    severity=str(rf["severity"]),
                    status=str(rf.get("status", "Remaining")),
                )
            )
        for cw in compatibility_warnings:
            session.add(
                CompatibilityResult(
                    simulation_id=sim_id,
                    domain=cw["domain"],
                    severity=cw["severity"],
                    warning_title=cw["warning_title"],
                    explanation=cw["explanation"],
                )
            )
        return sim_id


def list_simulations(database_url: str = DATABASE_URL) -> list[dict[str, Any]]:
    """Return all Digital Twin simulations newest first."""
    init_db(database_url)
    with get_session(database_url) as session:
        rows = list(
            session.scalars(
                select(DigitalTwinSimulation).order_by(
                    DigitalTwinSimulation.created_at.desc(), DigitalTwinSimulation.id.desc()
                )
            ).all()
        )
        return [
            {
                "id": s.id,
                "snapshot_id": s.snapshot_id,
                "target_url": s.target_url,
                "simulation_mode": s.simulation_mode,
                "baseline_score": s.baseline_score,
                "projected_score": s.projected_score,
                "classification": s.classification,
                "passed_checks": s.passed_checks,
                "failed_checks": s.failed_checks,
                "remaining_count": s.remaining_count,
                "summary_text": s.summary_text,
                "created_at": s.created_at.strftime("%Y-%m-%d %H:%M UTC") if s.created_at else "—",
            }
            for s in rows
        ]


def get_simulation_details(
    simulation_id: int,
    database_url: str = DATABASE_URL,
) -> dict[str, Any] | None:
    """Retrieve full details for a persisted Digital Twin simulation."""
    init_db(database_url)
    with get_session(database_url) as session:
        sim = session.get(DigitalTwinSimulation, simulation_id)
        if sim is None:
            return None
        changes = list(
            session.scalars(
                select(ProposedChange).where(ProposedChange.simulation_id == simulation_id)
            ).all()
        )
        warnings = list(
            session.scalars(
                select(CompatibilityResult).where(CompatibilityResult.simulation_id == simulation_id)
            ).all()
        )
        return {
            "id": sim.id,
            "target_url": sim.target_url,
            "simulation_mode": sim.simulation_mode,
            "baseline_score": sim.baseline_score,
            "projected_score": sim.projected_score,
            "classification": sim.classification,
            "changes": [
                {
                    "control": c.control_name,
                    "original": c.original_value,
                    "proposed": c.proposed_value,
                }
                for c in changes
            ],
            "warnings": [
                {
                    "domain": w.domain,
                    "severity": w.severity,
                    "warning_title": w.warning_title,
                    "explanation": w.explanation,
                }
                for w in warnings
            ],
        }
