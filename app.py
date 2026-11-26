"""SENTINEL AI — Main Streamlit Application Entrypoint."""

from __future__ import annotations

import socket
import threading

import streamlit as st

from components import (
    render_ai_copilot_page,
    render_ai_intelligence_page,
    render_approval_centre_page,
    render_landing_and_login,
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
from database import DatabaseError, ensure_default_admin, get_dashboard_snapshot, init_db


@st.cache_resource
def _ensure_local_demo_server() -> bool:
    """Start a lightweight built-in Flask demo target on 127.0.0.1:8000 if not already running."""
    try:
        with socket.create_connection(("127.0.0.1", 8000), timeout=0.25):
            return True
    except OSError:
        pass

    try:
        from flask import Flask, make_response
        from werkzeug.serving import make_server

        demo = Flask("sentinel_embedded_demo")

        @demo.route("/", methods=["GET"])
        def _index():
            resp = make_response("<html><body><h1>SENTINEL Local Demo Target</h1></body></html>", 200)
            resp.set_cookie("sentinel_demo_session", "demo-token", httponly=False, secure=False)
            return resp

        @demo.route("/.env", methods=["GET"])
        def _env():
            return make_response("APP_ENV=local_demo\n", 200, {"Content-Type": "text/plain"})

        server = make_server("127.0.0.1", 8000, demo, threaded=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return True
    except Exception:
        return False


_LIGHT_THEME_CSS = """
/* Light Liquid Glassmorphism Theme Overrides */
:root {
    --bg-primary: #f1f5f9;
    --bg-secondary: #ffffff;
    --bg-panel: rgba(255, 255, 255, 0.78);
    --bg-panel-elevated: rgba(255, 255, 255, 0.92);
    --border-glass: rgba(15, 23, 42, 0.10);
    --border-glass-bright: rgba(2, 132, 199, 0.35);
    --border-subtle: rgba(15, 23, 42, 0.12);
    --text-primary: #0f172a;
    --text-secondary: #475569;
    --text-muted: #64748b;
}
html, body, [class*="css"] {
    color: #0f172a !important;
}
.stApp {
    background:
        radial-gradient(ellipse 80% 50% at 20% -10%, rgba(14, 165, 233, 0.18) 0%, transparent 60%),
        radial-gradient(ellipse 60% 40% at 85% 15%, rgba(139, 92, 246, 0.16) 0%, transparent 60%),
        radial-gradient(ellipse 70% 60% at 50% 110%, rgba(236, 72, 153, 0.10) 0%, transparent 70%),
        linear-gradient(180deg, #f0f7ff 0%, #f8fafc 50%, #eef2ff 100%) !important;
}
header[data-testid="stHeader"] {
    background: rgba(255, 255, 255, 0.78) !important;
    border-bottom: 1px solid rgba(15, 23, 42, 0.10) !important;
}
section[data-testid="stSidebar"] {
    background: rgba(248, 250, 252, 0.86) !important;
    border-right: 1px solid rgba(15, 23, 42, 0.10) !important;
    box-shadow: 8px 0 30px rgba(15, 23, 42, 0.08) !important;
}
section[data-testid="stSidebar"] div.stButton > button {
    background: rgba(255, 255, 255, 0.75) !important;
    color: #334155 !important;
    border: 1px solid rgba(15, 23, 42, 0.08) !important;
}
section[data-testid="stSidebar"] div.stButton > button:hover {
    background: rgba(14, 165, 233, 0.14) !important;
    color: #0f172a !important;
}
section[data-testid="stSidebar"] div.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, rgba(14, 165, 233, 0.22), rgba(139, 92, 246, 0.20)) !important;
    color: #0f172a !important;
    border: 1px solid rgba(2, 132, 199, 0.5) !important;
}
.brand-title,
.sentinel-page-title {
    background: linear-gradient(135deg, #0f172a 0%, #0284c7 65%, #7c3aed 100%) !important;
    -webkit-background-clip: text !important;
    -webkit-text-fill-color: transparent !important;
}
.brand-tagline,
.sentinel-page-kicker {
    color: #0284c7 !important;
}
.sentinel-panel,
.metric-card,
.sentinel-table-wrap,
.ai-suggestion-card,
.sidebar-footer-card,
.sidebar-user-card,
.alert-row,
.sentinel-feature-card,
.sentinel-workflow-bar,
.sentinel-login-header,
.sentinel-how-card {
    background: rgba(255, 255, 255, 0.78) !important;
    border: 1px solid rgba(15, 23, 42, 0.10) !important;
    box-shadow: 0 12px 32px rgba(15, 23, 42, 0.08), inset 0 1px 0 rgba(255, 255, 255, 0.9) !important;
    color: #0f172a !important;
}
.panel-title,
.metric-value,
.sentinel-hero-title,
.sentinel-feature-card h4,
.sentinel-wf-step strong,
.sentinel-brand-name,
.sentinel-portal-title,
.sentinel-section-heading {
    color: #0f172a !important;
}
.sentinel-page-subtitle,
.sentinel-hero-sub,
.sentinel-feature-card p,
.sentinel-portal-sub,
.metric-label,
.metric-caption,
.panel-badge {
    color: #475569 !important;
}
.sentinel-glass-table thead th {
    background: rgba(241, 245, 249, 0.92) !important;
    color: #334155 !important;
    border-bottom: 1px solid rgba(15, 23, 42, 0.10) !important;
}
.sentinel-glass-table tbody td {
    color: #0f172a !important;
    border-bottom: 1px solid rgba(15, 23, 42, 0.06) !important;
}
.sentinel-glass-table tbody td[style*="color:#94a3b8"] {
    color: #475569 !important;
}
div.stButton > button[kind="secondary"],
.sentinel-nav-pill {
    background: rgba(255, 255, 255, 0.85) !important;
    color: #0f172a !important;
    border: 1px solid rgba(15, 23, 42, 0.15) !important;
}
div[data-baseweb="input"],
div[data-baseweb="select"] > div {
    background: rgba(255, 255, 255, 0.92) !important;
    border: 1px solid rgba(15, 23, 42, 0.16) !important;
    color: #0f172a !important;
}
div[data-baseweb="input"] input,
div[data-baseweb="select"] span {
    color: #0f172a !important;
}
p, label, .stMarkdown, .stCaption, h1, h2, h3, h4 {
    color: #000000 !important;
}
.js-plotly-plot .xtick text,
.js-plotly-plot .ytick text,
.js-plotly-plot .gtitle,
.js-plotly-plot .xtitle,
.js-plotly-plot .ytitle,
.js-plotly-plot .legendtext,
.js-plotly-plot .annotation-text,
.js-plotly-plot .indicator .numbers,
.js-plotly-plot .indicator .title {
    fill: #000000 !important;
}
code {
    color: #0369a1 !important;
    background: rgba(14, 165, 233, 0.10) !important;
}
.header-pill,
.sentinel-hero-badge {
    background: rgba(14, 165, 233, 0.12) !important;
    color: #0369a1 !important;
    border-color: rgba(2, 132, 199, 0.35) !important;
}
[style*="color:#F8FAFC"], [style*="color:#f8fafc"],
[style*="color:#E2E8F0"], [style*="color:#e2e8f0"],
[style*="color: #F8FAFC"], [style*="color: #f8fafc"] {
    color: #000000 !important;
}
[style*="color:#CBD5E1"], [style*="color:#cbd5e1"],
[style*="color:#94A3B8"], [style*="color:#94a3b8"],
[style*="color: #94A3B8"], [style*="color: #94a3b8"] {
    color: #111827 !important;
}
[style*="color:#00F0FF"], [style*="color:#00f0ff"],
[style*="color: #00F0FF"], [style*="color: #00f0ff"] {
    color: #0284c7 !important;
}
"""


def _load_custom_css() -> None:
    """Inject custom Sentinel AI stylesheet (with dark/light mode support)."""
    css_path = ASSETS_DIR / "style.css"
    css_text = css_path.read_text(encoding="utf-8") if css_path.exists() else ""
    if st.session_state.get("theme_mode", "dark") == "light":
        css_text = f"{css_text}\n{_LIGHT_THEME_CSS}"
    if css_text:
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

    if "theme_mode" not in st.session_state:
        st.session_state["theme_mode"] = "dark"

    _ensure_local_demo_server()
    _load_custom_css()

    if "active_page" not in st.session_state:
        st.session_state["active_page"] = "overview"
    if "auth_user" not in st.session_state:
        st.session_state["auth_user"] = None

    try:
        init_db()
        ensure_default_admin()
        snapshot = get_dashboard_snapshot()
    except DatabaseError as exc:
        st.error(f"Database initialization error: {exc}")
        st.stop()

    if st.session_state["auth_user"] is None:
        render_landing_and_login()
        return

    current_user_id = st.session_state["auth_user"].get("id")
    try:
        snapshot = get_dashboard_snapshot(user_id=current_user_id)
    except DatabaseError as exc:
        st.error(f"Database error loading user snapshot: {exc}")
        st.stop()

    selected_page = render_sidebar(
        active_page=st.session_state["active_page"],
        total_scans=snapshot["total_scans"],
        auth_user=st.session_state["auth_user"],
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
        "scan_history": render_scan_history_page,
        "reports": render_reports_page,
        "settings": lambda: render_settings_page(snapshot),
    }

    handler = routes.get(st.session_state["active_page"], routes["overview"])
    handler()


if __name__ == "__main__":
    main()
