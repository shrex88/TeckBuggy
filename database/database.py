"""Database engine, session management, initialization, and query helpers."""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator, Optional

from sqlalchemy import Engine, create_engine, delete, event, func, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

import config
from config import DATA_DIR, DATABASE_URL, REPORTS_DIR
from database.models import (
    ApprovalRecord,
    AuditLog,
    Base,
    BenchmarkRun,
    ConfidenceFactor,
    ConfidenceOutcome,
    ConfigBackup,
    Finding,
    RegressionAlert,
    RegressionWarning,
    RemediationEvaluation,
    RemediationProposal,
    Report,
    RollbackRecord,
    Scan,
    ValidationResult,
)

logger = logging.getLogger(__name__)


class DatabaseError(RuntimeError):
    """Raised when a database initialization or query operation fails."""


def get_db_url(database_url: Optional[str] = None) -> str:
    """Resolve database URL dynamically from argument, env var, or config."""
    if database_url:
        return str(database_url)
    env_url = os.getenv("SENTINEL_DATABASE_URL")
    if env_url:
        return env_url
    return str(getattr(config, "DATABASE_URL", DATABASE_URL))


def _configure_sqlite_pragmas(dbapi_connection: Any, _connection_record: Any) -> None:
    """Enable SQLite foreign key enforcement and WAL mode for reliability."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON;")
    cursor.close()


def create_db_engine(database_url: Optional[str] = None) -> Engine:
    """Create and configure a SQLAlchemy engine."""
    resolved_url = get_db_url(database_url)
    connect_args = {"check_same_thread": False} if resolved_url.startswith("sqlite") else {}
    engine = create_engine(
        resolved_url,
        echo=False,
        future=True,
        connect_args=connect_args,
    )
    if resolved_url.startswith("sqlite"):
        event.listen(engine, "connect", _configure_sqlite_pragmas)
    return engine


_engine: Optional[Engine] = None
_SessionLocal: Optional[sessionmaker[Session]] = None


def get_engine(database_url: Optional[str] = None) -> Engine:
    """Return the singleton SQLAlchemy engine, creating it if needed."""
    global _engine, _SessionLocal
    resolved_url = get_db_url(database_url)
    if _engine is None or str(_engine.url) != resolved_url:
        if _engine is not None:
            try:
                _engine.dispose()
            except Exception:
                pass
        if resolved_url.startswith("sqlite:///"):
            db_file = Path(resolved_url.replace("sqlite:///", "", 1))
            db_file.parent.mkdir(parents=True, exist_ok=True)
        else:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
        _engine = create_db_engine(resolved_url)
        _SessionLocal = sessionmaker(
            bind=_engine,
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
        )
    return _engine


def init_db(database_url: Optional[str] = None) -> Engine:
    """Initialize all database tables safely and ensure additive columns exist."""
    try:
        resolved_url = get_db_url(database_url)
        engine = get_engine(resolved_url)
        Base.metadata.create_all(bind=engine)
        # Additive migrations for existing SQLite databases
        if resolved_url.startswith("sqlite"):
            migrations = (
                "ALTER TABLE scans ADD COLUMN user_id INTEGER REFERENCES user_accounts(id)",
                "ALTER TABLE user_accounts ADD COLUMN last_login_at DATETIME",
                "ALTER TABLE user_accounts ADD COLUMN login_count INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE audit_logs ADD COLUMN user_id INTEGER REFERENCES user_accounts(id)",
            )
            with engine.connect() as conn:
                for stmt in migrations:
                    try:
                        conn.exec_driver_sql(stmt)
                        conn.commit()
                    except Exception:
                        pass
        return engine
    except SQLAlchemyError as exc:
        logger.exception("Failed to initialize database schema.")
        raise DatabaseError(f"Database initialization failed: {exc}") from exc


@contextmanager
def get_session(database_url: Optional[str] = None) -> Generator[Session, None, None]:
    """Provide a transactional SQLAlchemy session with automatic rollback on error."""
    resolved_url = get_db_url(database_url)
    if _SessionLocal is None or _engine is None or str(_engine.url) != resolved_url:
        init_db(resolved_url)
    assert _SessionLocal is not None
    session = _SessionLocal()
    try:
        yield session
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        logger.exception("Database transaction failed; rolled back.")
        raise DatabaseError(f"Database transaction error: {exc}") from exc
    finally:
        session.close()


def reset_engine() -> None:
    """Dispose the cached engine and session factory (primarily for testing)."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None


def get_dashboard_snapshot(
    database_url: Optional[str] = None,
    user_id: int | None = None,
) -> dict[str, Any]:
    """Fetch real scan and finding aggregates from SQLite for the Overview dashboard.

    Returns an empty-state snapshot when no scans have been executed yet.
    """
    resolved_url = get_db_url(database_url)
    init_db(resolved_url)
    with get_session(resolved_url) as session:
        scans_count_stmt = select(func.count(Scan.id))
        if user_id is not None:
            scans_count_stmt = scans_count_stmt.where(Scan.user_id == user_id)
        total_scans = session.scalar(scans_count_stmt) or 0
        if total_scans == 0:
            return {
                "has_scans": False,
                "total_scans": 0,
                "overall_security_score": None,
                "total_vulnerabilities": 0,
                "critical_findings": 0,
                "high_findings": 0,
                "severity_counts": {},
                "owasp_counts": {},
                "recent_scans": [],
                "priority_findings": [],
                "security_alerts": [],
                "total_reports": 0,
            }

        latest_scan_stmt = select(Scan).order_by(Scan.scan_date.desc(), Scan.id.desc())
        recent_scans_stmt = select(Scan).order_by(Scan.scan_date.desc(), Scan.id.desc()).limit(8)
        if user_id is not None:
            latest_scan_stmt = latest_scan_stmt.where(Scan.user_id == user_id)
            recent_scans_stmt = recent_scans_stmt.where(Scan.user_id == user_id)

        latest_scan = session.scalar(latest_scan_stmt.limit(1))
        recent_scans = list(session.scalars(recent_scans_stmt).all())

        findings_stmt = select(Finding).join(Scan).order_by(Finding.risk_score.desc(), Finding.id.desc())
        if user_id is not None:
            findings_stmt = findings_stmt.where(Scan.user_id == user_id)
        all_findings = list(session.scalars(findings_stmt).all())

        reports_stmt = select(func.count(Report.id)).join(Scan)
        if user_id is not None:
            reports_stmt = reports_stmt.where(Scan.user_id == user_id)
        total_reports = session.scalar(reports_stmt) or 0

        severity_counts: dict[str, int] = {}
        owasp_counts: dict[str, int] = {}
        critical_count = 0
        high_count = 0

        for f in all_findings:
            sev = f.severity or "Info"
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            if sev.lower() == "critical":
                critical_count += 1
            elif sev.lower() == "high":
                high_count += 1
            cat = f.owasp_category or "Uncategorized"
            owasp_counts[cat] = owasp_counts.get(cat, 0) + 1

        security_alerts = [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "target_path": f.target_path,
                "risk_score": f.risk_score,
                "status": f.finding_status,
            }
            for f in all_findings
            if (f.severity or "").lower() in {"critical", "high"}
        ][:5]

        return {
            "has_scans": True,
            "total_scans": total_scans,
            "overall_security_score": latest_scan.security_score if latest_scan else None,
            "total_vulnerabilities": len(all_findings),
            "critical_findings": critical_count,
            "high_findings": high_count,
            "severity_counts": severity_counts,
            "owasp_counts": owasp_counts,
            "recent_scans": [
                {
                    "id": s.id,
                    "target_url": s.target_url,
                    "scan_date": s.scan_date.strftime("%Y-%m-%d %H:%M UTC")
                    if s.scan_date
                    else "—",
                    "security_score": s.security_score,
                    "total_findings": s.total_findings,
                    "status": s.status,
                }
                for s in recent_scans
            ],
            "priority_findings": [
                {
                    "id": f.id,
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "target_path": f.target_path,
                    "severity": f.severity,
                    "risk_score": f.risk_score,
                    "owasp_category": f.owasp_category,
                    "finding_status": f.finding_status,
                }
                for f in all_findings[:10]
            ],
            "security_alerts": security_alerts,
            "total_reports": total_reports,
        }


def save_scan_results(
    *,
    target_url: str,
    security_score: float,
    findings_data: list[dict[str, Any]],
    user_id: int | None = None,
    status: str = "completed",
    database_url: Optional[str] = None,
) -> int:
    """Persist a completed scan and its findings to SQLite, returning the new scan ID."""
    resolved_url = get_db_url(database_url)
    init_db(resolved_url)
    with get_session(resolved_url) as session:
        scan = Scan(
            user_id=user_id,
            target_url=target_url,
            security_score=security_score,
            total_findings=len(findings_data),
            status=status,
        )
        for item in findings_data:
            scan.findings.append(
                Finding(
                    rule_id=str(item["rule_id"]),
                    target_path=str(item["target_path"]),
                    title=str(item["title"]),
                    severity=str(item["severity"]),
                    risk_score=float(item["risk_score"]),
                    evidence=str(item.get("evidence", "")),
                    owasp_category=str(item["owasp_category"]),
                    remediation=str(item.get("remediation", "")),
                    finding_status=str(item.get("finding_status", "open")),
                )
            )
        session.add(scan)
        session.flush()
        return int(scan.id)


def get_all_scans(
    database_url: Optional[str] = None,
    user_id: int | None = None,
) -> list[dict[str, Any]]:
    """Return all recorded scans ordered newest first."""
    resolved_url = get_db_url(database_url)
    init_db(resolved_url)
    with get_session(resolved_url) as session:
        stmt = select(Scan).order_by(Scan.scan_date.desc(), Scan.id.desc())
        if user_id is not None:
            stmt = stmt.where(Scan.user_id == user_id)
        scans = list(session.scalars(stmt).all())
        return [
            {
                "id": s.id,
                "user_id": s.user_id,
                "target_url": s.target_url,
                "scan_date": s.scan_date.strftime("%Y-%m-%d %H:%M UTC")
                if s.scan_date
                else "—",
                "security_score": s.security_score,
                "total_findings": s.total_findings,
                "critical_findings": sum(
                    1 for f in s.findings if (f.severity or "").lower() == "critical"
                ),
                "status": s.status,
            }
            for s in scans
        ]


def get_findings(
    *,
    scan_id: int | None = None,
    user_id: int | None = None,
    severity: str | None = None,
    owasp_category: str | None = None,
    database_url: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Query persisted findings with optional filters."""
    resolved_url = get_db_url(database_url)
    init_db(resolved_url)
    with get_session(resolved_url) as session:
        stmt = select(Finding).join(Scan).order_by(Finding.risk_score.desc(), Finding.id.desc())
        if scan_id is not None:
            stmt = stmt.where(Finding.scan_id == scan_id)
        if user_id is not None:
            stmt = stmt.where(Scan.user_id == user_id)
        if severity and severity != "All":
            stmt = stmt.where(Finding.severity == severity)
        if owasp_category and owasp_category != "All":
            stmt = stmt.where(Finding.owasp_category == owasp_category)

        rows = list(session.scalars(stmt).all())
        return [
            {
                "id": f.id,
                "scan_id": f.scan_id,
                "rule_id": f.rule_id,
                "target_path": f.target_path,
                "title": f.title,
                "severity": f.severity,
                "risk_score": f.risk_score,
                "evidence": f.evidence or "",
                "owasp_category": f.owasp_category,
                "remediation": f.remediation or "",
                "finding_status": f.finding_status,
            }
            for f in rows
        ]


def update_finding_status(
    finding_id: int,
    new_status: str,
    database_url: Optional[str] = None,
) -> bool:
    """Update the triage status of a persisted finding."""
    resolved_url = get_db_url(database_url)
    init_db(resolved_url)
    with get_session(resolved_url) as session:
        finding = session.get(Finding, finding_id)
        if finding is None:
            return False
        finding.finding_status = new_status
        return True


def save_report_record(
    *,
    scan_id: int,
    report_path: str,
    database_url: Optional[str] = None,
) -> int:
    """Persist a generated PDF report record linked to a scan."""
    resolved_url = get_db_url(database_url)
    init_db(resolved_url)
    with get_session(resolved_url) as session:
        report = Report(scan_id=scan_id, report_path=report_path)
        session.add(report)
        session.flush()
        return int(report.id)


def get_all_reports(
    database_url: Optional[str] = None,
    user_id: int | None = None,
) -> list[dict[str, Any]]:
    """Return all generated report records ordered newest first."""
    resolved_url = get_db_url(database_url)
    init_db(resolved_url)
    with get_session(resolved_url) as session:
        stmt = select(Report).join(Scan).order_by(Report.generated_at.desc(), Report.id.desc())
        if user_id is not None:
            stmt = stmt.where(Scan.user_id == user_id)
        reports = list(session.scalars(stmt).all())
        return [
            {
                "id": r.id,
                "scan_id": r.scan_id,
                "generated_at": r.generated_at.strftime("%Y-%m-%d %H:%M UTC")
                if r.generated_at
                else "—",
                "report_path": r.report_path,
            }
            for r in reports
        ]


def log_audit_event(
    *,
    event_type: str,
    status: str,
    details: str,
    target_url: str | None = None,
    actor: str = "developer",
    action_id: str | None = None,
    user_id: int | None = None,
    database_url: Optional[str] = None,
) -> int:
    """Append an immutable audit log record to SQLite."""
    resolved_url = get_db_url(database_url)
    init_db(resolved_url)
    with get_session(resolved_url) as session:
        entry = AuditLog(
            user_id=user_id,
            event_type=event_type,
            target_url=target_url,
            actor=actor,
            action_id=action_id,
            status=status,
            details=details,
        )
        session.add(entry)
        session.flush()
        return int(entry.id)


def get_audit_logs(
    *,
    limit: int = 100,
    user_id: int | None = None,
    database_url: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Return recent audit log records newest first."""
    resolved_url = get_db_url(database_url)
    init_db(resolved_url)
    with get_session(resolved_url) as session:
        stmt = select(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        if user_id is not None:
            stmt = stmt.where(or_(AuditLog.user_id == user_id, AuditLog.user_id.is_(None)))
        rows = list(session.scalars(stmt.limit(limit)).all())
        return [
            {
                "id": r.id,
                "event_type": r.event_type,
                "target_url": r.target_url or "—",
                "actor": r.actor,
                "action_id": r.action_id or "—",
                "status": r.status,
                "details": r.details,
                "created_at": r.created_at.strftime("%Y-%m-%d %H:%M UTC") if r.created_at else "—",
            }
            for r in rows
        ]


def save_benchmark_run(
    *,
    high_sec_scan_id: int,
    low_sec_scan_id: int,
    high_sec_score: float,
    low_sec_score: float,
    summary_json: str,
    database_url: str = DATABASE_URL,
) -> int:
    """Persist a Security Benchmark comparison run."""
    init_db(database_url)
    with get_session(database_url) as session:
        run = BenchmarkRun(
            high_sec_scan_id=high_sec_scan_id,
            low_sec_scan_id=low_sec_scan_id,
            high_sec_score=high_sec_score,
            low_sec_score=low_sec_score,
            summary_json=summary_json,
        )
        session.add(run)
        session.flush()
        return int(run.id)


def get_latest_benchmark_run(database_url: str = DATABASE_URL) -> dict[str, Any] | None:
    """Return the most recent persisted Security Benchmark run, if any."""
    init_db(database_url)
    with get_session(database_url) as session:
        run = session.scalar(
            select(BenchmarkRun).order_by(BenchmarkRun.created_at.desc(), BenchmarkRun.id.desc()).limit(1)
        )
        if run is None:
            return None
        return {
            "id": run.id,
            "high_sec_scan_id": run.high_sec_scan_id,
            "low_sec_scan_id": run.low_sec_scan_id,
            "high_sec_score": run.high_sec_score,
            "low_sec_score": run.low_sec_score,
            "summary_json": run.summary_json,
            "created_at": run.created_at.strftime("%Y-%m-%d %H:%M UTC") if run.created_at else "—",
        }


def save_regression_alert(
    *,
    baseline_scan_id: int,
    latest_scan_id: int,
    target_url: str,
    alert_type: str,
    severity: str,
    details: str,
    database_url: str = DATABASE_URL,
) -> int:
    """Persist a Security Regression Guard alert."""
    init_db(database_url)
    with get_session(database_url) as session:
        alert = RegressionAlert(
            baseline_scan_id=baseline_scan_id,
            latest_scan_id=latest_scan_id,
            target_url=target_url,
            alert_type=alert_type,
            severity=severity,
            details=details,
        )
        session.add(alert)
        session.flush()
        return int(alert.id)


def get_regression_alerts(database_url: str = DATABASE_URL) -> list[dict[str, Any]]:
    """Return persisted Security Regression Guard alerts newest first."""
    init_db(database_url)
    with get_session(database_url) as session:
        rows = list(
            session.scalars(
                select(RegressionAlert).order_by(
                    RegressionAlert.detected_at.desc(), RegressionAlert.id.desc()
                )
            ).all()
        )
        return [
            {
                "id": a.id,
                "baseline_scan_id": a.baseline_scan_id,
                "latest_scan_id": a.latest_scan_id,
                "target_url": a.target_url,
                "alert_type": a.alert_type,
                "severity": a.severity,
                "details": a.details,
                "detected_at": a.detected_at.strftime("%Y-%m-%d %H:%M UTC") if a.detected_at else "—",
            }
            for a in rows
        ]


def reset_scan_workspace_data(
    database_url: Optional[str] = None,
    user_id: int | None = None,
) -> None:
    """Clear operational scan, finding, proposal, audit, and report records.

    If user_id is provided, deletes scans belonging to user_id or unassigned (user_id IS NULL)
    to cleanly reset the active user's workspace.
    User accounts (`user_accounts`) are preserved.
    """
    resolved_url = get_db_url(database_url)
    init_db(resolved_url)
    with get_session(resolved_url) as session:
        if user_id is not None:
            user_scans = list(
                session.scalars(
                    select(Scan).where(
                        or_(Scan.user_id == user_id, Scan.user_id.is_(None))
                    )
                ).all()
            )
            deleted_scan_ids = [s.id for s in user_scans]
            for s in user_scans:
                session.delete(s)
            if deleted_scan_ids:
                session.execute(
                    delete(BenchmarkRun).where(
                        or_(
                            BenchmarkRun.high_sec_scan_id.in_(deleted_scan_ids),
                            BenchmarkRun.low_sec_scan_id.in_(deleted_scan_ids),
                        )
                    )
                )
                session.execute(
                    delete(RegressionAlert).where(
                        or_(
                            RegressionAlert.baseline_scan_id.in_(deleted_scan_ids),
                            RegressionAlert.latest_scan_id.in_(deleted_scan_ids),
                        )
                    )
                )
            # Clear orphaned benchmark runs when no scans remain
            remaining_scans = session.scalar(select(func.count(Scan.id))) or 0
            if remaining_scans == 0:
                session.execute(delete(BenchmarkRun))
                session.execute(delete(RegressionAlert))
        else:
            for model in (
                ConfidenceFactor,
                ValidationResult,
                RegressionWarning,
                RemediationEvaluation,
                ConfidenceOutcome,
                ApprovalRecord,
                RollbackRecord,
                ConfigBackup,
                RemediationProposal,
                Finding,
                Report,
                Scan,
                BenchmarkRun,
                RegressionAlert,
                AuditLog,
            ):
                session.execute(delete(model))

    if user_id is None and REPORTS_DIR.exists():
        for pdf_file in REPORTS_DIR.glob("*.pdf"):
            try:
                pdf_file.unlink()
            except OSError:
                logger.warning("Could not remove old report file: %s", pdf_file)
