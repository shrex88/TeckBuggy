"""Phase 2 functional views for SENTINEL AI (New Scan, Vulnerabilities, AI Intelligence, Scan History)."""

from __future__ import annotations

import html
import socket
from typing import Any

import pandas as pd
import streamlit as st

from components.charts import (
    build_risk_matrix_chart,
    build_vulnerability_distribution_chart,
)
from components.dashboard import render_page_header
from config import APPLICATION_PROFILES, OWASP_CATEGORIES
from database import get_all_scans, get_findings, update_finding_status
from intelligence import classify_risk_level, is_gemini_configured
from intelligence.gemini_client import request_gemini_json
from remediation import generate_remediation_playbook
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
        subtitle="Non-destructive defensive security assessment for HTTPS websites and local targets.",
        badge="PUBLIC & LOCAL",
    )

    st.markdown(
        """
        <div class="sentinel-panel">
            <div class="panel-header">
                <span class="panel-title">Target Configuration & Safety Policy</span>
                <span class="panel-badge">PUBLIC HTTPS &amp; LOCAL TARGETS</span>
            </div>
            <p style="color:#94A3B8; font-size:0.86rem; margin-bottom:0;">
                SENTINEL AI supports live public <code>https://</code> websites as well as local targets
                (<code>localhost</code>, <code>127.0.0.1</code>, local LAN IPs) while enforcing SSRF safeguards
                against cloud metadata endpoints (<code>169.254.0.0/16</code>) and embedded URL credentials.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns([1.4, 1], gap="medium")
    with col1:
        target_url = st.text_input(
            "Target Application URL",
            value="http://127.0.0.1:8000",
            key="scan_target_url",
            help="Examples: https://example.com, http://127.0.0.1:8000, or https://localhost:8443",
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
                allow_public=True,
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
    if not last:
        current_user = st.session_state.get("auth_user")
        user_id = current_user.get("id") if isinstance(current_user, dict) else None
        user_scans = get_all_scans(user_id=user_id)
        if user_scans:
            latest = user_scans[0]
            last = {
                "scan_id": latest["id"],
                "target_url": latest["target_url"],
                "security_score": latest["security_score"],
                "total_findings": latest["total_findings"],
            }
    if last:
        st.markdown("<div style='height:0.75rem;'></div>", unsafe_allow_html=True)
        last_findings = get_findings(scan_id=last["scan_id"])
        if last_findings:
            st.markdown(
                f"""
                <div class="sentinel-panel">
                    <div class="panel-header">
                        <span class="panel-title">Latest Scan Breakdown — <code>{html.escape(str(last['target_url']))}</code></span>
                        <span class="panel-badge">SCORE: {last['security_score']}/100 · {last['total_findings']} FINDINGS</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            s_col1, s_col2 = st.columns(2, gap="medium")
            with s_col1:
                scan_sev_filter = st.selectbox(
                    "Filter by Severity",
                    ["All", "Critical", "High", "Medium", "Low"],
                    key="scan_results_sev_filter",
                )
            with s_col2:
                scan_sort_order = st.selectbox(
                    "Sort Order",
                    [
                        "Severity (Critical → Low)",
                        "Severity (Low → Critical)",
                        "Risk Score (High → Low)",
                    ],
                    key="scan_results_sort_order",
                )

            severity_counts: dict[str, int] = {}
            for item in last_findings:
                sev_label = str(item.get("severity", "Info"))
                severity_counts[sev_label] = severity_counts.get(sev_label, 0) + 1

            displayed_findings = (
                [f for f in last_findings if str(f.get("severity", "")).lower() == scan_sev_filter.lower()]
                if scan_sev_filter != "All"
                else list(last_findings)
            )
            if scan_sort_order == "Severity (Critical → Low)":
                displayed_findings.sort(
                    key=lambda x: (
                        sev_rank.get(str(x.get("severity", "info")).lower(), 4),
                        -float(x.get("risk_score", 0.0)),
                    )
                )
            elif scan_sort_order == "Severity (Low → Critical)":
                displayed_findings.sort(
                    key=lambda x: (
                        -sev_rank.get(str(x.get("severity", "info")).lower(), 4),
                        float(x.get("risk_score", 0.0)),
                    )
                )
            else:
                displayed_findings.sort(key=lambda x: -float(x.get("risk_score", 0.0)))

            rows_html: list[str] = []
            for item in displayed_findings:
                sev = str(item.get("severity", "Info"))
                sev_cls = sev.lower() if sev.lower() in {"critical", "high", "medium", "low", "info"} else "info"
                risk_val = float(item.get("risk_score", 0.0))
                bar_color = (
                    "#ff3b5c" if risk_val >= 85
                    else "#ff8a00" if risk_val >= 65
                    else "#f5c542" if risk_val >= 40
                    else "#10b981"
                )
                clean_evidence = str(item.get("evidence", "")).split(" [AI Risk Intelligence]")[0]
                rows_html.append(
                    f"""
                    <tr>
                        <td><code>{html.escape(str(item.get('rule_id', '')))}</code></td>
                        <td><span class="severity-badge {sev_cls}">{html.escape(sev)}</span></td>
                        <td>
                            <div class="risk-pill-wrap">
                                <span style="font-weight:700;min-width:38px;">{risk_val:.1f}</span>
                                <div class="risk-bar-track">
                                    <div class="risk-bar-fill" style="width:{min(max(risk_val, 0.0), 100.0):.0f}%;background:{bar_color};"></div>
                                </div>
                            </div>
                        </td>
                        <td style="font-weight:600;color:#f8fafc;">{html.escape(str(item.get('title', '')))}</td>
                        <td><code>{html.escape(str(item.get('target_path', '/')))}</code></td>
                        <td style="color:#94a3b8;font-size:0.8rem;">{html.escape(clean_evidence)}</td>
                    </tr>
                    """
                )

            st.markdown(
                f"""
                <div class="sentinel-table-wrap">
                    <table class="sentinel-glass-table">
                        <thead>
                            <tr>
                                <th>Rule ID</th>
                                <th>Severity</th>
                                <th>Risk Score</th>
                                <th>Finding</th>
                                <th>Path</th>
                                <th>Evidence</th>
                            </tr>
                        </thead>
                        <tbody>
                            {"".join(rows_html)}
                        </tbody>
                    </table>
                </div>
                """,
                unsafe_allow_html=True,
            )

            g1, g2 = st.columns([1.4, 1.0], gap="medium")
            with g1:
                st.markdown(
                    '<div class="sentinel-panel"><div class="panel-header"><span class="panel-title">Risk Score by Finding</span><span class="panel-badge">RISK GRAPH</span></div></div>',
                    unsafe_allow_html=True,
                )
                st.plotly_chart(build_risk_matrix_chart(last_findings), use_container_width=True)
            with g2:
                st.markdown(
                    '<div class="sentinel-panel"><div class="panel-header"><span class="panel-title">Severity Distribution</span><span class="panel-badge">POSTURE SPLIT</span></div></div>',
                    unsafe_allow_html=True,
                )
                st.plotly_chart(build_vulnerability_distribution_chart(severity_counts), use_container_width=True)

            st.markdown(
                """
                <div class="sentinel-panel">
                    <div class="panel-header">
                        <span class="panel-title">AI Suggestions &amp; Required Changes</span>
                        <span class="panel-badge">ACTIONABLE REMEDIATION</span>
                    </div>
                    <p style="color:#94A3B8;font-size:0.85rem;margin-bottom:0;">
                        Prioritized changes required to harden your application based on the detected misconfigurations.
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )

            for item in last_findings[:5]:
                playbook = generate_remediation_playbook(item)
                sev = str(item.get("severity", "Info"))
                st.markdown(
                    f"""
                    <div class="ai-suggestion-card">
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                            <strong style="color:#f8fafc;font-size:0.94rem;">
                                {html.escape(str(item.get('rule_id', '')))} · {html.escape(str(item.get('title', '')))}
                            </strong>
                            <span class="severity-badge {sev.lower() if sev.lower() in {'critical','high','medium','low','info'} else 'info'}">{html.escape(sev)}</span>
                        </div>
                        <div style="color:#cbd5e1;font-size:0.84rem;line-height:1.5;margin-bottom:6px;">
                            <strong>Required Change:</strong> {html.escape(playbook.recommended_fix)}
                        </div>
                        <div style="color:#00f0ff;font-size:0.8rem;font-family:'JetBrains Mono',monospace;">
                            Fix: {html.escape(playbook.corrected_config.splitlines()[0] if playbook.corrected_config else '')}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            if st.button(
                "Generate Gemini AI Action Summary",
                key=f"btn_ai_scan_advice_{last['scan_id']}",
                type="secondary",
            ):
                summary_prompt = (
                    "You are an AppSec engineer. Summarize the top 3 concrete configuration changes "
                    f"needed for {last['target_url']} (score {last['security_score']}/100). "
                    "Findings: "
                    + "; ".join(f"{f['rule_id']} ({f['severity']}): {f['title']}" for f in last_findings[:6])
                    + ". Return JSON with keys: executive_summary (string) and priority_changes (list of 3 strings)."
                )
                with st.spinner("Generating AI remediation summary..."):
                    ai_resp = request_gemini_json(summary_prompt) if is_gemini_configured() else None
                if ai_resp and isinstance(ai_resp.get("priority_changes"), list):
                    st.success(str(ai_resp.get("executive_summary", "AI remediation summary generated.")))
                    for idx, ch in enumerate(ai_resp["priority_changes"][:5], start=1):
                        st.markdown(f"**{idx}.** {ch}")
                else:
                    st.info(
                        "Deterministic AI Plan: 1) Add strict Content-Security-Policy and X-Frame-Options/frame-ancestors headers, "
                        "2) Enforce HTTPS/HSTS and Secure+HttpOnly+SameSite cookie flags, "
                        "3) Add X-Content-Type-Options: nosniff, Referrer-Policy, and Permissions-Policy."
                    )
        else:
            st.success(f"Zero findings detected for {last['target_url']} — Security Score: {last['security_score']}/100.")

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
