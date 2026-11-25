"""Phase 2 functional views for SENTINEL AI (New Scan, Vulnerabilities, AI Intelligence, Scan History)."""

from __future__ import annotations

import socket
from typing import Any

import pandas as pd
import streamlit as st

from components.charts import build_risk_matrix_chart
from components.dashboard import render_page_header
from config import APPLICATION_PROFILES, OWASP_CATEGORIES
from database import get_all_scans, get_findings, update_finding_status
from intelligence import classify_risk_level
from scanner import TargetValidationError, run_security_scan


def _is_local_demo_reachable() -> bool:
    """Return True if the local demo lab is listening on 127.0.0.1:8000."""
    try:
        with socket.create_connection(("127.0.0.1", 8000), timeout=0.25):
            return True
    except OSError:
        return False


def render_new_scan_page() -> None:
    """Render the interactive New Security Scan view."""
    render_page_header(
        kicker="DEFENSIVE SCANNER ENGINE",
        title="New Security Scan",
        subtitle="Authorised local-only web application security assessment.",
        badge="LOCALHOST ONLY",
    )

    st.markdown(
        """
        <div class="sentinel-panel">
            <div class="panel-header">
                <span class="panel-title">Target Configuration & Safety Policy</span>
                <span class="panel-badge">LOCALHOST / DOCKER ONLY</span>
            </div>
            <p style="color:#94A3B8; font-size:0.86rem; margin-bottom:0;">
                SENTINEL AI enforces strict SSRF and target validation. Only <code>localhost</code>,
                <code>127.0.0.1</code>, <code>::1</code>, and allowlisted local network / Docker test
                services are permitted. External public domains and cloud metadata endpoints are blocked.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns([1.4, 1], gap="medium")
    with col1:
        target_url = st.text_input(
            "Authorised Local Target URL",
            value="http://127.0.0.1:8000",
            key="scan_target_url",
            help="Examples: http://127.0.0.1:8000, http://localhost:8000, or https://localhost:8443",
        )
    with col2:
        app_profile = st.selectbox(
            "Application Profile (Data Sensitivity Assumption)",
            options=list(APPLICATION_PROFILES.keys()),
            index=2,
            key="scan_app_profile",
        )

    st.caption(str(APPLICATION_PROFILES[app_profile]["assumption"]))

    if st.button("Start Scan", key="start_scan_btn", type="primary"):
        progress_bar = st.progress(0.0, text="Initializing defensive scan...")
        status_box = st.empty()

        def _on_progress(pct: float, msg: str) -> None:
            progress_bar.progress(min(max(pct, 0.0), 1.0), text=msg)
            status_box.info(msg)

        try:
            current_user = st.session_state.get("auth_user")
            user_id = current_user.get("id") if isinstance(current_user, dict) else None
            result = run_security_scan(
                target_url=target_url,
                application_profile=app_profile,
                user_id=user_id,
                allow_public=False,
                progress_callback=_on_progress,
            )
            st.session_state["last_scan_result"] = {
                "scan_id": result.scan_id,
                "target_url": result.target_url,
                "security_score": result.security_score,
                "total_findings": result.total_findings,
                "application_profile": result.application_profile,
            }
            status_box.success(
                f"Scan #{result.scan_id} completed for {result.target_url} — "
                f"Security Score: {result.security_score}/100 | Findings: {result.total_findings}"
            )
        except TargetValidationError as exc:
            progress_bar.empty()
            status_box.error(f"Target blocked by security policy: {exc}")
        except Exception as exc:
            progress_bar.empty()
            err_text = str(exc)
            if "Connection refused" in err_text and ("127.0.0.1" in target_url or "localhost" in target_url):
                status_box.error(
                    f"No service is listening on {target_url}. Ensure that local port is running, or scan the built-in local target http://127.0.0.1:8000."
                )
            else:
                status_box.error(f"Scan failed: {exc}")

    last = st.session_state.get("last_scan_result")
    if last:
        st.markdown("<div style='height:0.75rem;'></div>", unsafe_allow_html=True)
        last_findings = get_findings(scan_id=last["scan_id"])
        if last_findings:
            st.markdown(
                f"**Latest Scan Breakdown — `{last['target_url']}` (Score: {last['security_score']}/100 · {last['total_findings']} findings)**"
            )
            st.dataframe(
                pd.DataFrame(last_findings)[
                    ["rule_id", "severity", "risk_score", "title", "target_path", "evidence"]
                ],
                use_container_width=True,
                hide_index=True,
            )
        c_a, c_b = st.columns(2, gap="medium")
        with c_a:
            if st.button("View Findings", key="goto_findings_btn", use_container_width=True):
                st.session_state["active_page"] = "vulnerabilities"
                st.rerun()
        with c_b:
            if st.button("Open Overview Dashboard", key="goto_overview_btn", use_container_width=True):
                st.session_state["active_page"] = "overview"
                st.rerun()


def render_vulnerabilities_page() -> None:
    """Render the persisted Vulnerabilities inventory and Vulnerability Details inspector."""
    render_page_header(
        kicker="FINDINGS & EVIDENCE",
        title="Vulnerabilities",
        subtitle="Genuine security findings persisted in SQLite with OWASP Top 10:2025 mapping.",
        badge="SQLITE BACKED",
    )

    current_user = st.session_state.get("auth_user")
    user_id = current_user.get("id") if isinstance(current_user, dict) else None
    scans = get_all_scans(user_id=user_id)
    if not scans:
        st.info("No scans recorded yet. Run a scan in 'New Security Scan' to populate vulnerabilities.")
        if st.button("START YOUR FIRST SCAN", key="vuln_empty_cta", type="primary"):
            st.session_state["active_page"] = "new_scan"
            st.rerun()
        return

    f1, f2, f3 = st.columns(3, gap="medium")
    with f1:
        scan_options: dict[str, int | None] = {}
        for s in scans:
            scan_options[f"#{s['id']} · {s['target_url']} ({s['scan_date']})"] = s["id"]
        scan_options["All Scans"] = None
        selected_scan_label = st.selectbox("Filter by Scan", list(scan_options.keys()), index=0)
        selected_scan_id = scan_options[selected_scan_label]
    with f2:
        selected_sev = st.selectbox(
            "Filter by Severity",
            ["All", "Critical", "High", "Medium", "Low", "Info"],
        )
    with f3:
        selected_owasp = st.selectbox(
            "Filter by OWASP 2025",
            ["All", *OWASP_CATEGORIES],
        )

    current_user = st.session_state.get("auth_user")
    user_id = current_user.get("id") if isinstance(current_user, dict) else None
    findings = get_findings(
        scan_id=selected_scan_id,
        user_id=user_id if selected_scan_id is None else None,
        severity=selected_sev,
        owasp_category=selected_owasp,
    )

    if not findings:
        st.info("No findings match the selected filters.")
        return

    df = pd.DataFrame(findings)
    st.dataframe(
        df[["scan_id", "id", "rule_id", "title", "severity", "risk_score", "owasp_category", "target_path", "finding_status"]],
        use_container_width=True,
        hide_index=True,
    )

    st.markdown("<div style='height:0.75rem;'></div>", unsafe_allow_html=True)
    st.subheader("Vulnerability Details")

    finding_labels = {
        f"#{f['id']} · [{f['severity']}] {f['rule_id']} — {f['title']}": f
        for f in findings
    }
    chosen_label = st.selectbox("Select a finding to inspect", list(finding_labels.keys()))
    chosen: dict[str, Any] = finding_labels[chosen_label]

    col_left, col_right = st.columns([1.4, 1], gap="medium")
    with col_left:
        st.markdown(
            f"""
            <div class="sentinel-panel">
                <div class="panel-header">
                    <span class="panel-title">{chosen['rule_id']} · {chosen['title']}</span>
                    <span class="panel-badge">{chosen['severity'].upper()}</span>
                </div>
                <p style="color:#94A3B8; font-size:0.86rem;">
                    <strong>Target Path:</strong> <code>{chosen['target_path']}</code><br/>
                    <strong>OWASP Top 10:2025:</strong> {chosen['owasp_category']}<br/>
                    <strong>AI Risk Score:</strong> {chosen['risk_score']:.1f} / 100
                    ({classify_risk_level(chosen['risk_score'])})
                </p>
                <div style="font-size:0.82rem; font-weight:700; color:#00F0FF; margin-top:0.75rem;">
                    Technical Evidence & Risk Explanation
                </div>
                <pre style="white-space:pre-wrap; background:#0B1120; padding:0.75rem; border-radius:8px; color:#CBD5E1; font-size:0.8rem;">{chosen['evidence']}</pre>
                <div style="font-size:0.82rem; font-weight:700; color:#10B981; margin-top:0.75rem;">
                    Recommended Fix
                </div>
                <p style="color:#CBD5E1; font-size:0.86rem;">{chosen['remediation']}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col_right:
        new_status = st.selectbox(
            "Finding Triage Status",
            options=["open", "in_progress", "resolved", "accepted_risk"],
            index=["open", "in_progress", "resolved", "accepted_risk"].index(
                chosen["finding_status"]
                if chosen["finding_status"] in {"open", "in_progress", "resolved", "accepted_risk"}
                else "open"
            ),
            key=f"status_select_{chosen['id']}",
        )
        if st.button("Update Finding Status", key=f"save_status_{chosen['id']}", type="primary"):
            if update_finding_status(chosen["id"], new_status):
                st.success(f"Finding #{chosen['id']} updated to '{new_status}'.")
                st.rerun()


def render_ai_intelligence_page() -> None:
    """Render the AI Risk Intelligence view backed by real scored findings in SQLite."""
    render_page_header(
        kicker="EXPLAINABLE RISK SCORING",
        title="AI Risk Intelligence",
        subtitle="Multi-factor weighted risk scoring (Severity, Exposure, Data Sensitivity, Exploitability, Confidence).",
        badge="RULE-BASED ENGINE",
    )

    current_user = st.session_state.get("auth_user")
    user_id = current_user.get("id") if isinstance(current_user, dict) else None
    findings = get_findings(user_id=user_id)
    if not findings:
        st.info("No findings scored yet. Run a scan in 'New Security Scan' to view AI Risk Intelligence.")
        return

    st.markdown(
        """
        <div class="sentinel-panel">
            <div class="panel-header">
                <span class="panel-title">Risk Scoring Formula</span>
                <span class="panel-badge">TRANSPARENT WEIGHTS</span>
            </div>
            <p style="color:#CBD5E1; font-size:0.88rem; margin-bottom:0;">
                <code>Risk Score = (Severity × 0.30) + (Exposure × 0.25) + (Data Sensitivity × 0.20) + (Exploitability × 0.15) + (Confidence × 0.10)</code>
                <br/><span style="color:#94A3B8; font-size:0.8rem;">
                Risk Levels: 90–100 Critical · 70–89 High · 40–69 Medium · 0–39 Low.
                Data Sensitivity reflects the selected application profile assumption, not proof of actual stored data.
                </span>
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.subheader("Interactive Security Risk Matrix")
    st.plotly_chart(
        build_risk_matrix_chart(findings),
        use_container_width=True,
        config={"displayModeBar": False},
    )

    for f in findings[:15]:
        risk_cat = classify_risk_level(f["risk_score"])
        st.markdown(
            f"""
            <div class="sentinel-panel">
                <div class="panel-header">
                    <span class="panel-title">{f['rule_id']} · {f['title']}</span>
                    <span class="panel-badge">{risk_cat.upper()} · {f['risk_score']:.1f}/100</span>
                </div>
                <p style="color:#94A3B8; font-size:0.84rem; margin-bottom:0.4rem;">
                    <strong>OWASP 2025:</strong> {f['owasp_category']} ·
                    <strong>Target:</strong> <code>{f['target_path']}</code>
                </p>
                <p style="color:#CBD5E1; font-size:0.84rem; margin-bottom:0.4rem;">
                    {f['evidence']}
                </p>
                <p style="color:#00F0FF; font-size:0.82rem; margin-bottom:0;">
                    <strong>Priority & Action:</strong> {f['remediation']}
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_scan_history_page() -> None:
    """Render the chronological Scan History ledger from SQLite with detail inspection."""
    render_page_header(
        kicker="AUDIT LEDGER",
        title="Scan History",
        subtitle="Historical record of all executed local security assessments.",
        badge="PERSISTENT LOG",
    )

    current_user = st.session_state.get("auth_user")
    user_id = current_user.get("id") if isinstance(current_user, dict) else None
    scans = get_all_scans(user_id=user_id)
    if not scans:
        st.info("No scan history recorded yet.")
        return

    df = pd.DataFrame(scans)
    st.dataframe(
        df[["id", "target_url", "scan_date", "security_score", "total_findings", "critical_findings", "status"]],
        use_container_width=True,
        hide_index=True,
    )

    st.markdown("<div style='height:0.75rem;'></div>", unsafe_allow_html=True)
    st.subheader("Open Past Scan Details")
    scan_options = {
        f"Scan #{s['id']} · {s['target_url']} · {s['scan_date']}": s["id"]
        for s in scans
    }
    chosen_label = st.selectbox("Select a past scan", list(scan_options.keys()), key="history_scan_select")
    chosen_id = scan_options[chosen_label]

    scan_findings = get_findings(scan_id=chosen_id)
    if scan_findings:
        st.dataframe(
            pd.DataFrame(scan_findings)[["rule_id", "title", "severity", "risk_score", "owasp_category", "target_path", "finding_status"]],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.success("No vulnerabilities were recorded in this scan.")
