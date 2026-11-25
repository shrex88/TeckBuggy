"""Database package for SENTINEL AI."""

from database.database import (
    DatabaseError,
    get_all_reports,
    get_all_scans,
    get_dashboard_snapshot,
    get_engine,
    get_findings,
    get_session,
    init_db,
    reset_engine,
    save_report_record,
    save_scan_results,
    update_finding_status,
)
from database.models import Base, Finding, Report, Scan

__all__ = [
    "Base",
    "DatabaseError",
    "Finding",
    "Report",
    "Scan",
    "get_all_reports",
    "get_all_scans",
    "get_dashboard_snapshot",
    "get_engine",
    "get_findings",
    "get_session",
    "init_db",
    "reset_engine",
    "save_report_record",
    "save_scan_results",
    "update_finding_status",
]
