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
