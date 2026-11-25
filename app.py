"""SENTINEL AI — Main Streamlit Application Entrypoint (Phase 1)."""

from __future__ import annotations

import streamlit as st

from components import (
    render_ai_intelligence_page,
    render_coming_soon_page,
    render_new_scan_page,
    render_overview_dashboard,
    render_scan_history_page,
    render_settings_page,
    render_sidebar,
    render_vulnerabilities_page,
)
from config import APP_NAME, APP_TAGLINE, ASSETS_DIR
from database import DatabaseError, get_dashboard_snapshot, init_db

COMING_SOON_MODULES: dict[str, dict[str, object]] = {
    "new_scan": {
        "title": "New Security Scan",
        "phase": "Phase 2",
        "description": "Configure and launch automated web application security assessments against authorised targets.",
        "capabilities": [
            "HTTP security header & TLS posture inspection",
            "Cookie flag & session hardening analysis",
            "Sensitive endpoint & misconfiguration discovery",
            "Real-time scan progress telemetry persisted to SQLite",
        ],
    },
    "vulnerabilities": {
        "title": "Vulnerabilities",
        "phase": "Phase 2",
        "description": "Filterable vulnerability inventory with evidence inspection, OWASP mapping, and triage workflows.",
        "capabilities": [
            "Severity, OWASP Top 10, and status filtering",
            "Raw HTTP evidence & affected endpoint inspection",
            "Finding lifecycle tracking (Open, Mitigated, Accepted Risk)",
        ],
    },
    "ai_intelligence": {
        "title": "AI Risk Intelligence",
        "phase": "Phase 3",
        "description": "AI-driven contextual risk scoring, exploitability correlation, and attack-path prioritisation.",
        "capabilities": [
            "Composite AI risk scoring beyond static CVSS",
            "Chained misconfiguration & exposure correlation",
            "Executive risk narrative generation",
        ],
    },
    "remediation": {
        "title": "Remediation Centre",
        "phase": "Phase 3",
        "description": "Actionable developer-ready remediation playbooks and configuration patches.",
        "capabilities": [
            "Framework-specific header & cookie hardening snippets",
            "Prioritised fix queue ranked by risk reduction",
            "Verification checklist linked to Security Proof",
        ],
    },
    "security_proof": {
        "title": "Security Proof",
        "phase": "Phase 3",
        "description": "Automated post-remediation verification and cryptographic audit trail.",
        "capabilities": [
            "Before/after diff verification against target endpoints",
            "Regression checks for previously resolved findings",
            "Compliance-ready verification evidence",
        ],
    },
    "scan_history": {
        "title": "Scan History",
        "phase": "Phase 2",
        "description": "Historical timeline of executed scans, posture trends, and comparative diffs.",
        "capabilities": [
            "Chronological scan ledger backed by SQLite",
            "Security score trendlines across assessment runs",
            "Target-by-target comparison view",
        ],
    },
    "reports": {
        "title": "Reports",
        "phase": "Phase 3",
        "description": "Exportable executive and technical security assessment reports.",
        "capabilities": [
            "Executive summary & technical appendix generation",
            "Persistent report artifact registry in SQLite",
            "Downloadable HTML / PDF / JSON bundles",
        ],
    },
}


def _load_custom_css() -> None:
    """Inject custom Sentinel AI stylesheet into the Streamlit page."""
    css_path = ASSETS_DIR / "style.css"
    if css_path.exists():
        css_text = css_path.read_text(encoding="utf-8")
        st.markdown(f"<style>{css_text}</style>", unsafe_allow_html=True)


def main() -> None:
    """Configure page, initialize database, and route active navigation view."""
    st.set_page_config(
        page_title=f"{APP_NAME} · {APP_TAGLINE}",
        page_icon="🛡",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    _load_custom_css()

    if "active_page" not in st.session_state:
        st.session_state["active_page"] = "overview"

    try:
        init_db()
        snapshot = get_dashboard_snapshot()
    except DatabaseError as exc:
        st.error(f"Database initialization error: {exc}")
        st.stop()

    selected_page = render_sidebar(
        active_page=st.session_state["active_page"],
        total_scans=snapshot["total_scans"],
    )
    if selected_page != st.session_state["active_page"]:
        st.session_state["active_page"] = selected_page
        st.rerun()

    active = st.session_state["active_page"]
    if active == "overview":
        render_overview_dashboard(snapshot)
    elif active == "new_scan":
        render_new_scan_page()
    elif active == "vulnerabilities":
        render_vulnerabilities_page()
    elif active == "ai_intelligence":
        render_ai_intelligence_page()
    elif active == "scan_history":
        render_scan_history_page()
    elif active == "settings":
        render_settings_page(snapshot)
    elif active in COMING_SOON_MODULES:
        meta = COMING_SOON_MODULES[active]
        render_coming_soon_page(
            title=str(meta["title"]),
            phase=str(meta["phase"]),
            description=str(meta["description"]),
            planned_capabilities=list(meta["capabilities"]),  # type: ignore[arg-type]
        )
    else:
        render_overview_dashboard(snapshot)


if __name__ == "__main__":
    main()
