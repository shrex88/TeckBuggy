"""Landing page and authentication view for SENTINEL AI."""

from __future__ import annotations

import base64

import streamlit as st

from config import APP_NAME, APP_TAGLINE, APP_VERSION, ASSETS_DIR
from database import (
    AuthError,
    authenticate_user,
    register_user,
    reset_scan_workspace_data,
)


def _logo_img_html(size_px: int = 58) -> str:
    logo_path = ASSETS_DIR / "logo.png"
    if not logo_path.exists():
        logo_path = ASSETS_DIR / "logo.jpg"
    if logo_path.exists():
        b64 = base64.b64encode(logo_path.read_bytes()).decode("ascii")
        mime = "image/png" if logo_path.suffix == ".png" else "image/jpeg"
        return (
            f'<img src="data:{mime};base64,{b64}" alt="{APP_NAME} Logo" '
            f'style="width:{size_px}px;height:{size_px}px;border-radius:14px;object-fit:cover;'
            'border:1px solid rgba(0,240,255,0.45);box-shadow:0 0 24px rgba(0,240,255,0.28);" />'
        )
    return '<div style="font-size:2.2rem;">🛡</div>'


def render_landing_and_login() -> None:
    """Render the SENTINEL AI landing page and Sign In / Create Account portal."""
    st.markdown(
        """
        <style>
        [data-testid="stSidebar"], [data-testid="collapsedControl"] {
            display: none !important;
        }
        .sentinel-hero-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 6px 14px;
            border-radius: 999px;
            background: rgba(0, 240, 255, 0.10);
            border: 1px solid rgba(0, 240, 255, 0.30);
            color: #00F0FF;
            font-size: 0.74rem;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            margin-bottom: 16px;
        }
        .sentinel-hero-title {
            font-size: 2.65rem;
            font-weight: 800;
            line-height: 1.12;
            letter-spacing: -0.02em;
            color: #F8FAFC;
            margin: 0 0 12px 0;
        }
        .sentinel-hero-accent {
            background: linear-gradient(90deg, #00F0FF 0%, #8B5CF6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .sentinel-hero-sub {
            color: #94A3B8;
            font-size: 1.02rem;
            line-height: 1.65;
            margin-bottom: 24px;
            max-width: 600px;
        }
        .sentinel-feature-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 14px;
            margin-bottom: 22px;
        }
        .sentinel-feature-card {
            background: rgba(15, 23, 42, 0.72);
            border: 1px solid rgba(148, 163, 184, 0.16);
            border-radius: 14px;
            padding: 16px;
        }
        .sentinel-feature-card h4 {
            margin: 0 0 6px 0;
            font-size: 0.96rem;
            color: #F8FAFC;
        }
        .sentinel-feature-card p {
            margin: 0;
            font-size: 0.84rem;
            color: #94A3B8;
            line-height: 1.45;
        }
        .sentinel-workflow-bar {
            display: grid;
            grid-template-columns: repeat(6, minmax(0, 1fr));
            gap: 8px;
            background: rgba(15, 23, 42, 0.58);
            border: 1px solid rgba(0, 240, 255, 0.18);
            border-radius: 14px;
            padding: 12px 14px;
        }
        .sentinel-wf-step {
            text-align: center;
        }
        .sentinel-wf-step span {
            display: block;
            font-size: 0.7rem;
            font-family: 'JetBrains Mono', monospace;
            color: #00F0FF;
        }
        .sentinel-wf-step strong {
            font-size: 0.8rem;
            color: #E2E8F0;
        }
        .sentinel-login-header {
            background: linear-gradient(135deg, rgba(0,240,255,0.10), rgba(139,92,246,0.12));
            border: 1px solid rgba(0,240,255,0.22);
            border-radius: 14px;
            padding: 16px 18px;
            margin-bottom: 14px;
        }
        .sentinel-section-heading {
            font-size: 1.5rem;
            font-weight: 800;
            color: #F8FAFC;
            margin: 30px 0 16px 0;
            letter-spacing: -0.01em;
            scroll-margin-top: 72px;
            text-align: center;
        }
        .sentinel-top-nav-links {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            padding-top: 6px;
        }
        .sentinel-nav-pill {
            display: inline-flex;
            align-items: center;
            padding: 0.48rem 0.95rem;
            border-radius: 10px;
            background: rgba(15, 23, 42, 0.58);
            border: 1px solid rgba(255, 255, 255, 0.12);
            color: #E2E8F0 !important;
            text-decoration: none !important;
            font-size: 0.84rem;
            font-weight: 600;
            transition: transform 0.25s cubic-bezier(0.16, 1, 0.3, 1), border-color 0.25s ease, box-shadow 0.25s ease;
        }
        .sentinel-nav-pill:hover {
            transform: translateY(-2px);
            border-color: rgba(0, 240, 255, 0.48);
            box-shadow: 0 6px 20px rgba(0, 240, 255, 0.22);
            color: #FFFFFF !important;
        }
        .sentinel-how-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 14px;
            margin-bottom: 24px;
        }
        .sentinel-how-card {
            background: rgba(15, 23, 42, 0.65);
            border: 1px solid rgba(0, 240, 255, 0.18);
            border-radius: 14px;
            padding: 16px;
        }
        .sentinel-how-step {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.72rem;
            font-weight: 700;
            color: #00F0FF;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 6px;
        }
        .sentinel-how-card h4 {
            margin: 0 0 6px 0;
            font-size: 0.95rem;
            color: #F8FAFC;
        }
        .sentinel-how-card p {
            margin: 0;
            font-size: 0.82rem;
            color: #94A3B8;
            line-height: 1.45;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    # Top Landing Bar with Brand, Features, How It Works, Sign In, Create Account, and Icon Theme Toggle
    top_brand, top_links, top_signin, top_register, top_theme = st.columns(
        [1.6, 1.8, 0.85, 1.0, 0.45], gap="small"
    )
    logo_html = _logo_img_html(48)
    with top_brand:
        st.markdown(
            f"""
            <div style="display:flex;align-items:center;gap:12px;">
                {logo_html}
                <div>
                    <div class="sentinel-brand-name" style="font-size:1.25rem;font-weight:800;letter-spacing:0.04em;color:#F8FAFC;">
                        {APP_NAME}
                    </div>
                    <div style="font-size:0.78rem;color:#00F0FF;font-weight:600;">
                        {APP_TAGLINE} · v{APP_VERSION}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with top_links:
        st.markdown(
            """
            <div class="sentinel-top-nav-links">
                <a class="sentinel-nav-pill" href="#platform-features">Features</a>
                <a class="sentinel-nav-pill" href="#how-it-works">How It Works</a>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with top_signin:
        if st.button("Sign In", key="landing_top_signin", type="secondary", use_container_width=True):
            st.session_state["landing_auth_mode"] = "signin"
            st.rerun()
    with top_register:
        if st.button("Create Account", key="landing_top_register", type="primary", use_container_width=True):
            st.session_state["landing_auth_mode"] = "register"
            st.rerun()
    with top_theme:
        current_theme = st.session_state.get("theme_mode", "dark")
        theme_label = "☀️" if current_theme == "dark" else "🌙"
        if st.button(
            theme_label,
            key="btn_toggle_theme_landing",
            type="secondary",
            use_container_width=True,
            help="Switch Light / Dark Mode",
        ):
            st.session_state["theme_mode"] = "light" if current_theme == "dark" else "dark"
            st.rerun()

    st.markdown("<div style='height:0.75rem;'></div>", unsafe_allow_html=True)

    left_col, right_col = st.columns([1.3, 1.0], gap="large")

    with left_col:
        st.markdown(
            """
            <div class="sentinel-hero-badge">AI-Powered Web Application Security Platform</div>
            <h1 class="sentinel-hero-title">
                Detect misconfigurations.<br/>
                <span class="sentinel-hero-accent">Verify every fix with proof.</span>
            </h1>
            <p class="sentinel-hero-sub">
                SENTINEL AI combines deterministic HTTP header, cookie, TLS, and exposed-file scanning
                with OWASP Top 10:2025 risk intelligence, Google Gemini remediation proposals,
                independent confidence scoring, and human-in-the-loop approval.
            </p>
            <div class="sentinel-workflow-bar">
                <div class="sentinel-wf-step"><span>01</span><strong>Detect</strong></div>
                <div class="sentinel-wf-step"><span>02</span><strong>Prioritise</strong></div>
                <div class="sentinel-wf-step"><span>03</span><strong>Propose</strong></div>
                <div class="sentinel-wf-step"><span>04</span><strong>Approve</strong></div>
                <div class="sentinel-wf-step"><span>05</span><strong>Verify</strong></div>
                <div class="sentinel-wf-step"><span>06</span><strong>Report</strong></div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with right_col:
        auth_mode = st.session_state.get("landing_auth_mode", "signin")
        mode_hint = (
            "Create a new personal security workspace."
            if auth_mode == "register"
            else "Sign in to launch scans, review AI remediations, and export audit reports."
        )
        st.markdown(
            f"""
            <div class="sentinel-login-header">
                <div class="sentinel-portal-title" style="font-size:1.15rem;font-weight:700;color:#F8FAFC;margin-bottom:4px;">
                    Workspace Access Portal
                </div>
                <div class="sentinel-portal-sub" style="font-size:0.84rem;color:#94A3B8;">
                    {mode_hint}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if auth_mode == "register":
            tab_register, tab_signin = st.tabs(["Create Account", "Sign In"])
        else:
            tab_signin, tab_register = st.tabs(["Sign In", "Create Account"])

        with tab_signin:
            with st.form("login_form", clear_on_submit=False):
                identifier = st.text_input(
                    "Username or Email",
                    placeholder="admin@sentinel.ai",
                    key="login_identifier",
                )
                password = st.text_input(
                    "Password",
                    type="password",
                    placeholder="Enter your password",
                    key="login_password",
                )
                submitted = st.form_submit_button(
                    "Sign In to Workspace",
                    type="primary",
                    use_container_width=True,
                )
                if submitted:
                    user = authenticate_user(identifier, password)
                    if user is None:
                        st.error("Invalid username/email or password.")
                    else:
                        st.session_state["auth_user"] = user
                        st.session_state["active_page"] = "overview"
                        st.rerun()

            st.caption("Default analyst credentials: `admin@sentinel.ai` / `Sentinel@2026`")

        with tab_register:
            with st.form("register_form", clear_on_submit=True):
                full_name = st.text_input("Full Name", placeholder="Aarav Mehta", key="reg_full_name")
                username = st.text_input("Username", placeholder="amehta", key="reg_username")
                email = st.text_input("Email", placeholder="aarav@sentinel.ai", key="reg_email")
                reg_pass = st.text_input("Password", type="password", key="reg_password")
                reg_confirm = st.text_input("Confirm Password", type="password", key="reg_confirm")
                reg_submitted = st.form_submit_button(
                    "Create Account",
                    type="primary",
                    use_container_width=True,
                )
                if reg_submitted:
                    if reg_pass != reg_confirm:
                        st.error("Passwords do not match.")
                    else:
                        try:
                            user = register_user(
                                username=username,
                                email=email,
                                password=reg_pass,
                                full_name=full_name,
                            )
                            st.session_state["auth_user"] = user
                            st.session_state["active_page"] = "overview"
                            st.rerun()
                        except AuthError as exc:
                            st.error(str(exc))

    # Full-width Features & How It Works sections below the Hero + Portal
    st.markdown(
        """
        <div id="platform-features" class="sentinel-section-heading">Platform Features</div>
        <div class="sentinel-feature-grid">
            <div class="sentinel-feature-card">
                <h4>🛡 OWASP Top 10:2025 Scanner</h4>
                <p>Inspects HTTP security headers, cookie flags (HttpOnly, Secure, SameSite), TLS certificates, and exposed config endpoints for public HTTPS and local targets.</p>
            </div>
            <div class="sentinel-feature-card">
                <h4>🤖 Gemini AI Remediation Copilot</h4>
                <p>Generates framework-ready fixes (Flask, Django, Nginx, Apache, Express) via Google Gemini with deterministic playbook fallback when offline.</p>
            </div>
            <div class="sentinel-feature-card">
                <h4>🎯 Explainable Risk &amp; Confidence Engine</h4>
                <p>Scores findings across 5 weighted risk factors and evaluates remediation safety with 7-factor confidence &amp; regression guardrails.</p>
            </div>
            <div class="sentinel-feature-card">
                <h4>✅ Security Proof &amp; 16-Section PDF Reports</h4>
                <p>Runs before-and-after verification scans to prove vulnerabilities are resolved and exports branded executive PDF audit reports.</p>
            </div>
        </div>

        <div id="how-it-works" class="sentinel-section-heading">How It Works</div>
        <div class="sentinel-how-grid">
            <div class="sentinel-how-card">
                <div class="sentinel-how-step">Step 01</div>
                <h4>Create Account or Sign In</h4>
                <p>Each user gets an isolated workspace in SQLite that preserves all their scan history, findings, and login telemetry.</p>
            </div>
            <div class="sentinel-how-card">
                <div class="sentinel-how-step">Step 02</div>
                <h4>Enter or Upload Target URL</h4>
                <p>Provide a live <code>https://</code> site or local target (or upload a <code>.txt</code>/<code>.csv</code> list) and run a non-destructive scan.</p>
            </div>
            <div class="sentinel-how-card">
                <div class="sentinel-how-step">Step 03</div>
                <h4>Inspect Graphs &amp; AI Fixes</h4>
                <p>Filter findings by Critical &rarr; Low severity, explore risk graphs, and review Gemini AI recommended configuration changes.</p>
            </div>
            <div class="sentinel-how-card">
                <div class="sentinel-how-step">Step 04</div>
                <h4>Approve, Verify &amp; Export</h4>
                <p>Approve fixes in the Governance Centre, verify resolution with Security Proof, and download your PDF report.</p>
            </div>
        </div>
        <div style="height:2.5rem;"></div>
        """,
        unsafe_allow_html=True,
    )
