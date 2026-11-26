"""Dashboard and view renderers for SENTINEL AI."""

from __future__ import annotations

import re
from typing import Any

import pandas as pd
import streamlit as st

from components.charts import (
    build_owasp_distribution_chart,
    build_security_score_gauge,
    build_vulnerability_distribution_chart,
)
from config import APP_SUBTITLE, APP_VERSION, DATABASE_PATH
from database import get_latest_benchmark_run, get_user_account_summary, reset_scan_workspace_data


def render_page_header(kicker: str, title: str, subtitle: str, badge: str) -> None:
    """Render a consistent enterprise page header with Dark/Light mode toggle."""
    hdr_col, theme_col = st.columns([11, 0.9], gap="small")
    with hdr_col:
        st.markdown(
            f"""
            <div class="sentinel-header">
                <div>
                    <div class="sentinel-page-kicker">{kicker}</div>
                    <h1 class="sentinel-page-title">{title}</h1>
                    <div class="sentinel-page-subtitle">{subtitle}</div>
                </div>
                <div class="header-pill">● {badge}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with theme_col:
        current_theme = st.session_state.get("theme_mode", "dark")
        toggle_icon = "☀️" if current_theme == "dark" else "🌙"
        safe_key = re.sub(r"[^a-z0-9_]+", "_", title.lower()).strip("_")
        if st.button(
            toggle_icon,
            key=f"btn_header_theme_{safe_key}",
            type="secondary",
            use_container_width=True,
            help="Switch Light / Dark Mode",
        ):
            st.session_state["theme_mode"] = "light" if current_theme == "dark" else "dark"
            st.rerun()


def _render_kpi_cards(snapshot: dict[str, Any]) -> None:
    """Render the four primary security KPI cards from real database values."""
    has_scans = snapshot["has_scans"]
    score = snapshot["overall_security_score"]
    score_display = f"{score:.0f}/100" if (has_scans and score is not None) else "—"
    score_caption = "Latest assessed posture" if has_scans else "Awaiting initial scan"

    total_vulns = snapshot["total_vulnerabilities"]
    critical = snapshot["critical_findings"]
    high = snapshot["high_findings"]

    col1, col2, col3, col4 = st.columns(4, gap="medium")

    with col1:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-top">
                    <span class="kpi-label">Overall Security Score</span>
                    <span class="kpi-icon">◈</span>
                </div>
                <div class="kpi-value">{score_display}</div>
                <div class="kpi-caption">{score_caption}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-top">
                    <span class="kpi-label">Total Vulnerabilities</span>
                    <span class="kpi-icon">⌖</span>
                </div>
                <div class="kpi-value">{total_vulns}</div>
                <div class="kpi-caption">Persisted across {snapshot['total_scans']} scan(s)</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            f"""
            <div class="kpi-card kpi-critical">
                <div class="kpi-top">
                    <span class="kpi-label">Critical Findings</span>
                    <span class="kpi-icon" style="color:#FF3B5C; background:rgba(255,59,92,0.12); border-color:rgba(255,59,92,0.28);">!</span>
                </div>
                <div class="kpi-value">{critical}</div>
                <div class="kpi-caption">Immediate remediation priority</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col4:
        st.markdown(
            f"""
            <div class="kpi-card kpi-high">
                <div class="kpi-top">
                    <span class="kpi-label">High-Risk Findings</span>
                    <span class="kpi-icon" style="color:#FF8A00; background:rgba(255,138,0,0.12); border-color:rgba(255,138,0,0.28);">▲</span>
                </div>
                <div class="kpi-value">{high}</div>
                <div class="kpi-caption">Elevated exploitability exposure</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_overview_dashboard(snapshot: dict[str, Any]) -> None:
    """Render the Overview dashboard backed strictly by SQLite state."""
    render_page_header(
        kicker="SECURITY COMMAND CENTER",
        title="Security Posture Overview",
        subtitle=APP_SUBTITLE,
        badge="LIVE TELEMETRY" if snapshot["has_scans"] else "READY FOR INITIAL SCAN",
    )

    _render_kpi_cards(snapshot)
    st.markdown("<div style='height: 0.75rem;'></div>", unsafe_allow_html=True)

    # Quick Action Bar + Benchmark Summary
    qa1, qa2, qa3 = st.columns(3, gap="medium")
    with qa1:
        if st.button("Start New Scan", key="ov_start_scan", type="primary", use_container_width=True):
            st.session_state["active_page"] = "new_scan"
            st.rerun()
    with qa2:
        if st.button("Security Benchmark", key="ov_benchmark", use_container_width=True):
            st.session_state["active_page"] = "security_benchmark"
            st.rerun()
    with qa3:
        if snapshot["total_vulnerabilities"] > 0:
            if st.button("AI Remediation Copilot", key="ov_ai_remed", use_container_width=True):
                st.session_state["active_page"] = "ai_copilot"
                st.rerun()

    latest_bench = get_latest_benchmark_run()
    if latest_bench is not None:
        b1, b2 = st.columns(2, gap="medium")
        b1.metric("Benchmark · High-Security App A", f"{latest_bench['high_sec_score']:.1f}/100")
        b2.metric("Benchmark · Low-Security App B", f"{latest_bench['low_sec_score']:.1f}/100")

    st.markdown("<div style='height: 0.5rem;'></div>", unsafe_allow_html=True)

    if not snapshot["has_scans"]:
        st.markdown(
            """
            <div class="empty-hero">
                <div class="empty-shield">🛡</div>
                <div class="empty-title">No Security Scans Recorded Yet</div>
                <div class="empty-desc">
                    SENTINEL AI is connected to your local SQLite intelligence store and ready for assessment.
                    No fabricated metrics or synthetic vulnerabilities are displayed. Launch your first scan
                    to populate your security posture gauge, OWASP breakdown, and prioritised remediation queue.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        _, btn_col, _ = st.columns([1.2, 1, 1.2])
        with btn_col:
            if st.button(
                "START YOUR FIRST SCAN",
                key="cta_first_scan",
                type="primary",
                use_container_width=True,
            ):
                st.session_state["active_page"] = "new_scan"
                st.rerun()

        st.markdown("<div style='height: 1rem;'></div>", unsafe_allow_html=True)

    # Row 1: Gauge + Vulnerability Distribution + OWASP Category Distribution
    c1, c2, c3 = st.columns([1, 1, 1.25], gap="medium")

    with c1:
        st.markdown(
            """
            <div class="sentinel-panel">
                <div class="panel-header">
                    <span class="panel-title">Security Score Gauge</span>
                    <span class="panel-badge">POSTURE</span>
                </div>
            """,
            unsafe_allow_html=True,
        )
        st.plotly_chart(
            build_security_score_gauge(snapshot["overall_security_score"]),
            use_container_width=True,
            config={"displayModeBar": False},
        )
        st.markdown("</div>", unsafe_allow_html=True)

    with c2:
        st.markdown(
            """
            <div class="sentinel-panel">
                <div class="panel-header">
                    <span class="panel-title">Vulnerability Distribution</span>
                    <span class="panel-badge">SEVERITY</span>
                </div>
            """,
            unsafe_allow_html=True,
        )
        st.plotly_chart(
            build_vulnerability_distribution_chart(snapshot["severity_counts"]),
            use_container_width=True,
            config={"displayModeBar": False},
        )
        st.markdown("</div>", unsafe_allow_html=True)

    with c3:
        st.markdown(
            """
            <div class="sentinel-panel">
                <div class="panel-header">
                    <span class="panel-title">OWASP Category Distribution</span>
                    <span class="panel-badge">OWASP TOP 10</span>
                </div>
            """,
            unsafe_allow_html=True,
        )
        st.plotly_chart(
            build_owasp_distribution_chart(snapshot["owasp_counts"]),
            use_container_width=True,
            config={"displayModeBar": False},
        )
        st.markdown("</div>", unsafe_allow_html=True)

    # Row 2: Risk Priority Table + Recent Scan Activity & Security Alerts
    left_col, right_col = st.columns([1.45, 1], gap="medium")

    with left_col:
        st.markdown(
            """
            <div class="sentinel-panel">
                <div class="panel-header">
                    <span class="panel-title">Risk Priority Table</span>
                    <span class="panel-badge">TOP FINDINGS</span>
                </div>
            """,
            unsafe_allow_html=True,
        )
        if snapshot["priority_findings"]:
            df_findings = pd.DataFrame(snapshot["priority_findings"])
            st.dataframe(
                df_findings[
                    ["rule_id", "title", "target_path", "severity", "risk_score", "finding_status"]
                ],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info(
                "No findings recorded in the database. Run a security scan in Phase 2 to populate the risk priority table."
            )
        st.markdown("</div>", unsafe_allow_html=True)

    with right_col:
        st.markdown(
            """
            <div class="sentinel-panel">
                <div class="panel-header">
                    <span class="panel-title">Recent Scan Activity</span>
                    <span class="panel-badge">AUDIT LOG</span>
                </div>
            """,
            unsafe_allow_html=True,
        )
        if snapshot["recent_scans"]:
            df_scans = pd.DataFrame(snapshot["recent_scans"])
            st.dataframe(
                df_scans[["target_url", "scan_date", "status", "total_findings"]],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No scan activity logged yet.")
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown(
            """
            <div class="sentinel-panel">
                <div class="panel-header">
                    <span class="panel-title">Security Alerts</span>
                    <span class="panel-badge">HIGH / CRITICAL</span>
                </div>
            """,
            unsafe_allow_html=True,
        )
        if snapshot["security_alerts"]:
            for alert in snapshot["security_alerts"]:
                color = "#FF3B5C" if alert["severity"].lower() == "critical" else "#FF8A00"
                st.markdown(
                    f"""
                    <div class="alert-row">
                        <div>
                            <div style="font-weight:600; font-size:0.86rem; color:#F8FAFC;">{alert['title']}</div>
                            <div style="font-size:0.75rem; color:#94A3B8;">{alert['target_path']}</div>
                        </div>
                        <span class="severity-badge" style="color:{color}; background:rgba(255,59,92,0.12); border:1px solid {color};">
                            {alert['severity']}
                        </span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.info("No active high or critical security alerts.")
        st.markdown("</div>", unsafe_allow_html=True)


def render_coming_soon_page(
    title: str,
    phase: str,
    description: str,
    planned_capabilities: list[str],
) -> None:
    """Render a polished Coming Soon state for Phase 2 / Phase 3 modules."""
    render_page_header(
        kicker="MODULE ROADMAP",
        title=title,
        subtitle=description,
        badge=f"COMING SOON · {phase.upper()}",
    )

    caps_html = "".join(
        f"<li style='margin-bottom:0.45rem; color:#CBD5E1;'>{item}</li>"
        for item in planned_capabilities
    )

    st.markdown(
        f"""
        <div class="coming-soon-card">
            <span class="phase-chip">{phase} · Planned Module</span>
            <h2 style="margin:0 0 0.65rem 0; color:#F8FAFC; font-size:1.35rem;">
                {title} is scheduled for {phase}
            </h2>
            <p style="color:#94A3B8; line-height:1.6; max-width:760px; margin-bottom:1.15rem;">
                {description} This workspace is intentionally reserved in the Phase 1 architecture
                so no simulated or placeholder scan results are shown.
            </p>
            <div style="font-size:0.8rem; font-weight:700; letter-spacing:0.08em; text-transform:uppercase; color:#00F0FF; margin-bottom:0.55rem;">
                Planned Capabilities
            </div>
            <ul style="padding-left:1.2rem; margin:0;">
                {caps_html}
            </ul>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_settings_page(snapshot: dict[str, Any]) -> None:
    """Render the Phase 1 Settings & Environment Status view."""
    render_page_header(
        kicker="PLATFORM CONFIGURATION",
        title="Settings & Environment",
        subtitle="Read-only runtime configuration for Phase 1 foundation services.",
        badge="PHASE 1 ACTIVE",
    )

    current_user = st.session_state.get("auth_user")
    user_id = current_user.get("id") if isinstance(current_user, dict) else None
    account_summary = get_user_account_summary(user_id) if user_id is not None else None
    if account_summary:
        st.markdown(
            f"""
            <div class="sentinel-panel">
                <div class="panel-header">
                    <span class="panel-title">User Account &amp; Real-Time Activity</span>
                    <span class="panel-badge">{account_summary['role'].upper()}</span>
                </div>
                <p style="color:#94A3B8; font-size:0.86rem; margin-bottom:0.45rem;">
                    <strong>User:</strong> {account_summary['full_name']} (<code>@{account_summary['username']}</code>) · {account_summary['email']}
                </p>
                <p style="color:#94A3B8; font-size:0.86rem; margin-bottom:0.45rem;">
                    <strong>Account Created:</strong> <code>{account_summary['created_at']}</code> &nbsp;|&nbsp;
                    <strong>Last Login:</strong> <code>{account_summary['last_login_at']}</code> &nbsp;|&nbsp;
                    <strong>Total Logins:</strong> <code>{account_summary['login_count']}</code>
                </p>
                <p style="color:#94A3B8; font-size:0.86rem; margin-bottom:0;">
                    <strong>Scanned Tests Run:</strong> <code>{account_summary['total_scans']}</code> &nbsp;|&nbsp;
                    <strong>Findings Recorded:</strong> <code>{account_summary['total_findings']}</code> &nbsp;|&nbsp;
                    <strong>Reports Generated:</strong> <code>{account_summary['total_reports']}</code>
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    col1, col2 = st.columns(2, gap="medium")
    with col1:
        st.markdown(
            f"""
            <div class="sentinel-panel">
                <div class="panel-header">
                    <span class="panel-title">Persistence & Database</span>
                    <span class="panel-badge">SQLITE + SQLALCHEMY</span>
                </div>
                <p style="color:#94A3B8; font-size:0.86rem; margin-bottom:0.6rem;">
                    <strong>Database Path:</strong><br/>
                    <code>{DATABASE_PATH}</code>
                </p>
                <p style="color:#94A3B8; font-size:0.86rem; margin-bottom:0.3rem;">
                    <strong>Recorded Scans:</strong> {snapshot['total_scans']}
                </p>
                <p style="color:#94A3B8; font-size:0.86rem; margin-bottom:0;">
                    <strong>Generated Reports:</strong> {snapshot['total_reports']}
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"""
            <div class="sentinel-panel">
                <div class="panel-header">
                    <span class="panel-title">Target Scope & Runtime</span>
                    <span class="panel-badge">PUBLIC &amp; LOCAL</span>
                </div>
                <p style="color:#94A3B8; font-size:0.86rem; margin-bottom:0.6rem;">
                    <strong>Authorised Scope:</strong><br/>
                    Public <code>https://</code> sites, <code>localhost</code>, <code>127.0.0.1</code>, <code>::1</code>, and local network targets
                </p>
                <p style="color:#94A3B8; font-size:0.86rem; margin-bottom:0.3rem;">
                    <strong>Security Mode:</strong> Defensive &amp; Detective Only
                </p>
                <p style="color:#94A3B8; font-size:0.86rem; margin-bottom:0;">
                    <strong>Platform Version:</strong> <code>{APP_VERSION}</code>
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    reset_msg = st.session_state.pop("settings_reset_notice", None)
    if reset_msg:
        st.success(reset_msg)

    st.markdown(
        """
        <div class="sentinel-panel" style="margin-top: 1rem;">
            <div class="panel-header">
                <span class="panel-title">Workspace Data Management</span>
                <span class="panel-badge">USER SESSION RESET</span>
            </div>
            <p style="color:#94A3B8; font-size:0.86rem; margin-bottom:0.2rem;">
                Clear all recorded scans, vulnerability findings, AI remediation proposals,
                confidence evaluations, audit logs, and generated PDF reports while keeping your user account intact.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if st.button("Reset User Data", key="btn_reset_workspace_data", type="primary"):
        current_user = st.session_state.get("auth_user")
        user_id = current_user.get("id") if isinstance(current_user, dict) else None
        reset_scan_workspace_data(user_id=user_id)
        st.session_state["settings_reset_notice"] = (
            "Your workspace data has been reset. You can now run a fresh security scan."
        )
        st.rerun()
