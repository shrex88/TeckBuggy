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
