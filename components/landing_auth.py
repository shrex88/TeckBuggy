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
        </style>
        """,
        unsafe_allow_html=True,
    )

    left_col, right_col = st.columns([1.35, 1.0], gap="large")

    with left_col:
        logo_html = _logo_img_html(58)
        st.markdown(
            f"""
            <div style="display:flex;align-items:center;gap:14px;margin-bottom:18px;">
                {logo_html}
                <div>
                    <div style="font-size:1.35rem;font-weight:800;letter-spacing:0.04em;color:#F8FAFC;">
                        {APP_NAME}
                    </div>
                    <div style="font-size:0.84rem;color:#00F0FF;font-weight:600;">
                        {APP_TAGLINE} · v{APP_VERSION}
                    </div>
                </div>
            </div>
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
            <div class="sentinel-feature-grid">
                <div class="sentinel-feature-card">
                    <h4>🛡 OWASP Top 10:2025 Scanner</h4>
                    <p>Strict local-target validation, header, cookie, TLS, and exposed artifact detection.</p>
                </div>
                <div class="sentinel-feature-card">
                    <h4>🤖 Gemini AI Remediation Copilot</h4>
                    <p>Framework-ready code & config proposals with deterministic fallback when offline.</p>
                </div>
                <div class="sentinel-feature-card">
                    <h4>🎯 Confidence & Safety Engine</h4>
                    <p>7-factor weighted confidence, technical validation, and regression impact checks.</p>
                </div>
                <div class="sentinel-feature-card">
                    <h4>✅ Security Proof & PDF Reports</h4>
                    <p>Before-and-after verification scans, rollback safety, and 16-section PDF reports.</p>
                </div>
            </div>
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
        st.markdown(
            """
            <div class="sentinel-login-header">
                <div style="font-size:1.15rem;font-weight:700;color:#F8FAFC;margin-bottom:4px;">
                    Workspace Access Portal
                </div>
                <div style="font-size:0.84rem;color:#94A3B8;">
                    Sign in to launch scans, review AI remediations, and export audit reports.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

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
