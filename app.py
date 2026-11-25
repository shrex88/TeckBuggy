"""SENTINEL AI — Main Streamlit Application Entrypoint."""

from __future__ import annotations

import streamlit as st

from components import (
    render_ai_copilot_page,
    render_ai_intelligence_page,
    render_approval_centre_page,
    render_learning_mode_page,
    render_new_scan_page,
    render_overview_dashboard,
    render_regression_guard_page,
    render_remediation_confidence_page,
    render_remediation_history_page,
    render_reports_page,
    render_scan_history_page,
    render_security_benchmark_page,
    render_security_proof_page,
    render_settings_page,
    render_sidebar,
    render_vulnerabilities_page,
)
from config import APP_NAME, APP_TAGLINE, ASSETS_DIR
from database import DatabaseError, get_dashboard_snapshot, init_db


def _load_custom_css() -> None:
    """Inject custom Sentinel AI stylesheet into the Streamlit page."""
    css_path = ASSETS_DIR / "style.css"
    if css_path.exists():
        css_text = css_path.read_text(encoding="utf-8")
        st.markdown(f"<style>{css_text}</style>", unsafe_allow_html=True)


def main() -> None:
    """Configure page, initialize database, and route all 13 navigation views."""
    logo_file = ASSETS_DIR / "logo.png"
    st.set_page_config(
        page_title=f"{APP_NAME} · {APP_TAGLINE}",
        page_icon=str(logo_file) if logo_file.exists() else "🛡",
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

    routes = {
        "overview": lambda: render_overview_dashboard(snapshot),
        "new_scan": render_new_scan_page,
        "security_benchmark": render_security_benchmark_page,
        "vulnerabilities": render_vulnerabilities_page,
        "ai_intelligence": render_ai_intelligence_page,
        "ai_copilot": render_ai_copilot_page,
        "remediation_confidence": render_remediation_confidence_page,
        "approval_centre": render_approval_centre_page,
        "remediation_history": render_remediation_history_page,
        "security_proof": render_security_proof_page,
        "regression_guard": render_regression_guard_page,
        "learning_mode": render_learning_mode_page,
        "scan_history": render_scan_history_page,
        "reports": render_reports_page,
        "settings": lambda: render_settings_page(snapshot),
    }

    handler = routes.get(st.session_state["active_page"], routes["overview"])
    handler()


if __name__ == "__main__":
    main()
