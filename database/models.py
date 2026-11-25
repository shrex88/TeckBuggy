"""SQLAlchemy ORM models for SENTINEL AI."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Base declarative class for all Sentinel AI database models."""

class Scan(Base):
    """Represents a single security assessment run against a target URL."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_url: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    scan_date: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    security_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    total_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="pending")

    findings: Mapped[List["Finding"]] = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    reports: Mapped[List["Report"]] = relationship(
        "Report",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return (
            f"<Scan(id={self.id}, target_url={self.target_url!r}, "
            f"status={self.status!r}, total_findings={self.total_findings})>"
        )

class Finding(Base):
    """Represents a security finding discovered during a scan."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    target_path: Mapped[str] = mapped_column(String(512), nullable=False)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    owasp_category: Mapped[str] = mapped_column(String(128), nullable=False)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    finding_status: Mapped[str] = mapped_column(
        String(64), nullable=False, default="open"
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")

    def __repr__(self) -> str:
        return (
            f"<Finding(id={self.id}, rule_id={self.rule_id!r}, "
            f"severity={self.severity!r}, risk_score={self.risk_score})>"
        )

class Report(Base):
    """Represents a generated security report artifact linked to a scan."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    report_path: Mapped[str] = mapped_column(String(1024), nullable=False)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="reports")

    def __repr__(self) -> str:
        return (
            f"<Report(id={self.id}, scan_id={self.scan_id}, "
            f"report_path={self.report_path!r})>"
        )

class RemediationProposal(Base):
    """Stores AI (Gemini or deterministic fallback) remediation proposals for a finding."""

    __tablename__ = "remediation_proposals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="rule_based")
    framework: Mapped[str] = mapped_column(String(64), nullable=False, default="Flask")
    technical_explanation: Mapped[str] = mapped_column(Text, nullable=False)
    security_impact: Mapped[str] = mapped_column(Text, nullable=False)
    root_cause: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_correction: Mapped[str] = mapped_column(Text, nullable=False)
    original_config: Mapped[str] = mapped_column(Text, nullable=False)
    corrected_config: Mapped[str] = mapped_column(Text, nullable=False)
    secure_code_example: Mapped[str] = mapped_column(Text, nullable=False)
    verification_instructions: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_priority: Mapped[str] = mapped_column(String(64), nullable=False)
    approval_status: Mapped[str] = mapped_column(
        String(64), nullable=False, default="Pending Review", index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )

class ConfigurationSnapshot(Base):
    """Isolated virtual configuration snapshot derived from a genuine scan."""

    __tablename__ = "configuration_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    target_url: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    app_label: Mapped[str] = mapped_column(String(128), nullable=False)
    scheme: Mapped[str] = mapped_column(String(16), nullable=False)
    headers_json: Mapped[str] = mapped_column(Text, nullable=False)
    cookies_meta_json: Mapped[str] = mapped_column(Text, nullable=False)
    exposed_paths_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )

class DigitalTwinSimulation(Base):
    """Stores a What-If Digital Twin simulation run."""

    __tablename__ = "digital_twin_simulations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("configuration_snapshots.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_url: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    simulation_mode: Mapped[str] = mapped_column(String(64), nullable=False)
    baseline_score: Mapped[float] = mapped_column(Float, nullable=False)
    projected_score: Mapped[float] = mapped_column(Float, nullable=False)
    classification: Mapped[str] = mapped_column(String(64), nullable=False)
    passed_checks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_checks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    remaining_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    summary_text: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )

class ProposedChange(Base):
    """Individual proposed configuration change inside a Digital Twin simulation."""

    __tablename__ = "proposed_changes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    simulation_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("digital_twin_simulations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    control_name: Mapped[str] = mapped_column(String(128), nullable=False)
    original_value: Mapped[str] = mapped_column(Text, nullable=False)
    proposed_value: Mapped[str] = mapped_column(Text, nullable=False)

class SimulatedFinding(Base):
    """Remaining or simulated finding evaluated by the Digital Twin."""

    __tablename__ = "simulated_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    simulation_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("digital_twin_simulations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False)

class CompatibilityResult(Base):
    """Compatibility warnings detected during a Digital Twin simulation."""

    __tablename__ = "compatibility_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    simulation_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("digital_twin_simulations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    warning_title: Mapped[str] = mapped_column(String(256), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)

class RemediationEvaluation(Base):
    """Independent confidence & safety evaluation for a remediation proposal."""

    __tablename__ = "remediation_evaluations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    proposal_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("remediation_proposals.id", ondelete="CASCADE"), nullable=False, index=True
    )
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence_level: Mapped[str] = mapped_column(String(64), nullable=False)
    application_safety: Mapped[str] = mapped_column(String(64), nullable=False)
    verification_status: Mapped[str] = mapped_column(String(64), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )

class ConfidenceFactor(Base):
    """Normalized factor score breakdown for a RemediationEvaluation."""

    __tablename__ = "confidence_factors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    evaluation_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("remediation_evaluations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    factor_name: Mapped[str] = mapped_column(String(128), nullable=False)
    raw_score: Mapped[float] = mapped_column(Float, nullable=False)
    weight: Mapped[float] = mapped_column(Float, nullable=False)
    weighted_score: Mapped[float] = mapped_column(Float, nullable=False)

class ValidationResult(Base):
    """Deterministic technical validation checks for a RemediationEvaluation."""

    __tablename__ = "validation_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    evaluation_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("remediation_evaluations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    check_name: Mapped[str] = mapped_column(String(128), nullable=False)
    passed: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    details: Mapped[str] = mapped_column(Text, nullable=False)

class RegressionWarning(Base):
    """Potential side-effect / regression warnings for a RemediationEvaluation."""

    __tablename__ = "regression_warnings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    evaluation_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("remediation_evaluations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    risk_description: Mapped[str] = mapped_column(Text, nullable=False)
    potential_impact: Mapped[str] = mapped_column(Text, nullable=False)
    likelihood: Mapped[str] = mapped_column(String(32), nullable=False)
    required_testing: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_action: Mapped[str] = mapped_column(Text, nullable=False)

class ConfidenceOutcome(Base):
    """Tracks predicted remediation confidence against actual Security Proof outcomes."""

    __tablename__ = "confidence_outcomes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    evaluation_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("remediation_evaluations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    followup_scan_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    predicted_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    actual_resolved: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    regression_occurred: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    evidence_summary: Mapped[str] = mapped_column(Text, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )

class LearningProfile(Base):
    """Developer learning profile, skill level, and points."""

    __tablename__ = "learning_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    learner_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, default="default")
    learning_level: Mapped[str] = mapped_column(String(32), nullable=False, default="BEGINNER")
    points: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )

class Lesson(Base):
    """Catalogued security lesson linked to a scanner rule ID."""

    __tablename__ = "lessons"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    owasp_category: Mapped[str] = mapped_column(String(128), nullable=False)

class LearningProgress(Base):
    """Tracks completed lessons per learner."""

    __tablename__ = "learning_progress"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    learner_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True, default="default")
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    learning_level: Mapped[str] = mapped_column(String(32), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )

class QuizAttempt(Base):
    """Persisted quiz attempt score and topic."""

    __tablename__ = "quiz_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    learner_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True, default="default")
    topic: Mapped[str] = mapped_column(String(128), nullable=False)
    difficulty: Mapped[str] = mapped_column(String(32), nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    total_questions: Mapped[int] = mapped_column(Integer, nullable=False)
    attempted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )

class PracticalExercise(Base):
    """Tracks hands-on local lab exercises verified through Security Proof."""

    __tablename__ = "practical_exercises"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    learner_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True, default="default")
    challenge_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    target_url: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="in_progress")
    verified_scan_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

class Achievement(Base):
    """Earned learning achievements and badges."""

    __tablename__ = "achievements"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    learner_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True, default="default")
    badge_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    badge_name: Mapped[str] = mapped_column(String(128), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    earned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )

class ApprovalRecord(Base):
    """Tracks developer approval, rejection, application, and verification decisions."""

    __tablename__ = "approval_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    proposal_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("remediation_proposals.id", ondelete="CASCADE"), nullable=False, index=True
    )
    decision: Mapped[str] = mapped_column(String(64), nullable=False)
    reviewer: Mapped[str] = mapped_column(String(128), nullable=False, default="developer")
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )

class ConfigBackup(Base):
    """Stores pre-remediation configuration snapshots for safe rollback."""

    __tablename__ = "config_backups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    backup_uid: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    target_url: Mapped[str] = mapped_column(String(512), nullable=False)
    finding_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    proposal_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    action_id: Mapped[str] = mapped_column(String(128), nullable=False)
    setting_key: Mapped[str] = mapped_column(String(128), nullable=False)
    original_value: Mapped[str] = mapped_column(String(256), nullable=False)
    applied_value: Mapped[str] = mapped_column(String(256), nullable=False)
    approved_by: Mapped[str] = mapped_column(String(128), nullable=False, default="developer")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )

class RollbackRecord(Base):
    """Records configuration rollbacks and post-rollback verification state."""

    __tablename__ = "rollback_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    backup_uid: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_url: Mapped[str] = mapped_column(String(512), nullable=False)
    action_id: Mapped[str] = mapped_column(String(128), nullable=False)
    restored_verified: Mapped[bool] = mapped_column(Integer, nullable=False, default=0)
    details: Mapped[str] = mapped_column(Text, nullable=False)
    rolled_back_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )

class BenchmarkRun(Base):
    """Stores side-by-side Security Benchmark runs (Application A vs Application B)."""

    __tablename__ = "benchmark_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    high_sec_scan_id: Mapped[int] = mapped_column(Integer, nullable=False)
    low_sec_scan_id: Mapped[int] = mapped_column(Integer, nullable=False)
    high_sec_score: Mapped[float] = mapped_column(Float, nullable=False)
    low_sec_score: Mapped[float] = mapped_column(Float, nullable=False)
    summary_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )

class RegressionAlert(Base):
    """Stores Security Regression Guard alerts when verified controls regress."""

    __tablename__ = "regression_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    baseline_scan_id: Mapped[int] = mapped_column(Integer, nullable=False)
    latest_scan_id: Mapped[int] = mapped_column(Integer, nullable=False)
    target_url: Mapped[str] = mapped_column(String(512), nullable=False)
    alert_type: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )

class AuditLog(Base):
    """Immutable audit trail for governance, approvals, remediation, and rollbacks."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    target_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False, default="developer")
    action_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )


class UserAccount(Base):
    """Registered user accounts for SENTINEL AI workspace authentication."""

    __tablename__ = "user_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    email: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(128), nullable=False, default="Security Analyst")
    role: Mapped[str] = mapped_column(String(64), nullable=False, default="Security Analyst")
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )

