"""Enterprise Phase 4+ UI Views for SENTINEL AI.

Covers: Security Benchmark, AI Remediation Copilot, Developer Approval Centre,
Remediation History, and Security Regression Guard.
"""

from __future__ import annotations

import html

import pandas as pd
import streamlit as st

from components.charts import build_benchmark_comparison_chart
from components.dashboard import render_page_header
from config import APPLICATION_PROFILES
from database import get_all_scans, get_audit_logs, get_findings, get_regression_alerts
from intelligence import (
    RegressionGuardError,
    evaluate_remediation_proposal,
    evaluate_security_regression,
    generate_ai_remediation_proposal,
    is_gemini_configured,
    run_security_benchmark,
)
from intelligence.gemini_client import get_last_gemini_status
from remediation import (
    SUPPORTED_FRAMEWORKS,
    ApprovalError,
    RemediationApplyError,
    RemediationValidationError,
    RollbackError,
    apply_approved_remediation,
    list_backups,
    list_proposals,
    rollback_configuration,
    set_proposal_decision,
    verify_remediation_proposal,
)


def render_security_benchmark_page() -> None:
    """Render Side-by-Side Security Benchmark (Target A vs Target B)."""
    render_page_header(
        kicker="COMPARATIVE BENCHMARK",
        title="Security Benchmark",
        subtitle="Compare two authorised local web applications side-by-side using genuine scan results.",
        badge="TARGET A vs TARGET B",
    )

    c1, c2, c3 = st.columns([1.2, 1.2, 1], gap="medium")
    with c1:
        high_url = st.text_input(
            "Application A (High-Security Target URL)",
            value="http://127.0.0.1:8000",
            key="bench_high_url",
        )
    with c2:
        low_url = st.text_input(
            "Application B (Comparison Target URL)",
            value="http://127.0.0.1:3000",
            key="bench_low_url",
        )
    with c3:
        profile = st.selectbox(
            "Benchmark Profile",
            options=list(APPLICATION_PROFILES.keys()),
            index=0,
            key="bench_profile",
        )

    if st.button("Run Security Benchmark", key="run_benchmark_btn", type="primary"):
        with st.spinner("Scanning both local applications and comparing security controls..."):
            bench = run_security_benchmark(
                high_sec_url=high_url,
                low_sec_url=low_url,
                application_profile=profile,
            )
            st.session_state["last_benchmark"] = bench

    bench = st.session_state.get("last_benchmark")
    if bench is None:
        st.info("Click **Run Security Benchmark** to execute genuine scans against both local applications.")
        return

    if bench.high_sec_error:
        st.warning(f"Application A scan note: {bench.high_sec_error}")
    if bench.low_sec_error:
        st.warning(f"Application B scan note: {bench.low_sec_error}")

    m1, m2, m3, m4 = st.columns(4, gap="medium")
    m1.metric("App A Security Score", f"{bench.high_sec_score:.1f}/100")
    m2.metric("App B Security Score", f"{bench.low_sec_score:.1f}/100")
    m3.metric("App A Total Findings", sum(bench.high_sec_severity_counts.values()))
    m4.metric("App B Total Findings", sum(bench.low_sec_severity_counts.values()))

    st.plotly_chart(
        build_benchmark_comparison_chart(
            bench.high_sec_severity_counts,
            bench.low_sec_severity_counts,
        ),
        use_container_width=True,
        config={"displayModeBar": False},
    )

    st.subheader("Security Control Comparison Matrix")
    st.dataframe(pd.DataFrame(bench.control_matrix), use_container_width=True, hide_index=True)


def render_ai_copilot_section(
    findings: list[dict],
    key_prefix: str = "copilot",
    show_section_header: bool = False,
) -> None:
    """Render the interactive AI Remediation Copilot solution generator for a list of findings."""
    if not findings:
        return

    if show_section_header:
        st.markdown(
            f"""
            <div class="sentinel-panel">
                <div class="panel-header">
                    <span class="panel-title">AI Remediation Copilot — Solution &amp; Secure Code</span>
                    <span class="panel-badge">{"GEMINI READY" if is_gemini_configured() else "FALLBACK MODE"}</span>
                </div>
                <p style="color:#94A3B8;font-size:0.85rem;margin-bottom:0;">
                    Select any finding from this scan and your target framework to generate a full AI remediation
                    proposal, before/after configuration diff, and framework-ready secure code.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    c1, c2 = st.columns([1.6, 1], gap="medium")
    with c1:
        finding_map = {
            f"#{f['id']} · [{f['severity']}] {f['rule_id']} — {f['title']} ({f['target_path']})": f
            for f in findings
        }
        chosen_label = st.selectbox(
            "Select Finding to Analyse",
            list(finding_map.keys()),
            key=f"{key_prefix}_finding",
        )
        chosen = finding_map[chosen_label]
    with c2:
        framework = st.selectbox(
            "Target Framework",
            list(SUPPORTED_FRAMEWORKS),
            index=0,
            key=f"{key_prefix}_fw",
        )

    proposal_state_key = f"{key_prefix}_last_proposal"
    if st.button("Generate AI Fix", key=f"{key_prefix}_gen_btn", type="primary"):
        with st.spinner("Generating validated remediation proposal..."):
            proposal = generate_ai_remediation_proposal(chosen, framework=framework)
            st.session_state[proposal_state_key] = proposal
            st.session_state["last_proposal"] = proposal
            if proposal["source"] == "gemini_ai":
                st.success(
                    f"Gemini AI Proposal #{proposal['id']} created · Action: {proposal['action_id']} · Status: {proposal['approval_status']}"
                )
            else:
                st.warning(
                    f"Proposal #{proposal['id']} created using deterministic fallback · {get_last_gemini_status()}"
                )

    proposal = st.session_state.get(proposal_state_key)
    if proposal:
        st.markdown(
            f"""
            <div class="sentinel-panel">
                <div class="panel-header">
                    <span class="panel-title">Proposal #{proposal['id']} · Action {html.escape(str(proposal['action_id']))}</span>
                    <span class="panel-badge">{html.escape(str(proposal['source']).upper())} · {html.escape(str(proposal['approval_status']).upper())}</span>
                </div>
                <p style="color:#CBD5E1; font-size:0.86rem;">
                    <strong>Technical Explanation:</strong> {html.escape(str(proposal['technical_explanation']))}<br/><br/>
                    <strong>Potential Security Impact:</strong> {html.escape(str(proposal['security_impact']))}<br/><br/>
                    <strong>Root Cause:</strong> {html.escape(str(proposal['root_cause']))}<br/><br/>
                    <strong>Recommended Correction:</strong> {html.escape(str(proposal['recommended_correction']))}
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        col_a, col_b = st.columns(2, gap="medium")
        with col_a:
            st.caption("Original Configuration")
            st.code(proposal["original_config"])
        with col_b:
            st.caption("Proposed Corrected Configuration")
            st.code(proposal["corrected_config"])

        st.caption(f"Secure Code Example ({proposal['framework']})")
        st.code(
            proposal["secure_code_example"],
            language="python" if proposal["framework"] in {"Flask", "Django"} else "nginx",
        )

        if st.button("Approve Proposal", key=f"{key_prefix}_approve_btn", type="primary"):
            set_proposal_decision(proposal["id"], decision="Approved")
            proposal["approval_status"] = "Approved"
            st.session_state[proposal_state_key] = proposal
            st.session_state["last_proposal"] = proposal
            st.success(f"Proposal #{proposal['id']} approved! Open Developer Approval Centre to apply or verify.")
            st.rerun()

        if st.button("Open Developer Approval Centre", key=f"{key_prefix}_goto_approval_btn"):
            st.session_state["active_page"] = "approval_centre"
            st.rerun()


def render_ai_copilot_page() -> None:
    """Render Unique Feature 3: SENTINEL AI Remediation Copilot (Gemini + Deterministic Fallback)."""
    render_page_header(
        kicker="ASSISTED REMEDIATION COPILOT",
        title="AI Remediation Copilot",
        subtitle="Generate structured remediation proposals via Google Gemini API (with deterministic fallback). Proposals require explicit developer approval.",
        badge="GEMINI READY" if is_gemini_configured() else "FALLBACK MODE",
    )

    findings = get_findings(user_id=(st.session_state.get("auth_user") or {}).get("id"))
    if not findings:
        st.info("No findings recorded yet. Run a scan first to generate AI remediation proposals.")
        return

    render_ai_copilot_section(findings, key_prefix="copilot", show_section_header=False)


def render_approval_centre_page() -> None:
    """Render Developer Approval Centre & Controlled Execution."""
    render_page_header(
        kicker="HUMAN-IN-THE-LOOP GOVERNANCE",
        title="Developer Approval Centre",
        subtitle="Review, approve/reject, apply allowlisted fixes to authorised local applications, rollback, and verify resolution.",
        badge="ASSISTED MODE",
    )

    proposals = list_proposals(user_id=(st.session_state.get("auth_user") or {}).get("id"))
    if not proposals:
        st.info("No remediation proposals generated yet. Use AI Remediation Copilot to generate proposals.")
        return

    target_url = st.text_input(
        "Authorised Local Target URL",
        value="http://127.0.0.1:8000",
        key="approval_target_url",
    )

    for p in proposals:
        st.markdown(
            f"""
            <div class="sentinel-panel">
                <div class="panel-header">
                    <span class="panel-title">#{p['id']} · {p['rule_id']} — {p['finding_title']}</span>
                    <span class="panel-badge">{p['severity'].upper()} · RISK {p['risk_score']:.1f} · {p['approval_status'].upper()}</span>
                </div>
                <p style="color:#94A3B8; font-size:0.84rem; margin-bottom:0.35rem;">
                    <strong>Action ID:</strong> <code>{p['action_id']}</code> ·
                    <strong>Source:</strong> {p['source']} ·
                    <strong>Verification:</strong> {p['verification_instructions']}
                </p>
                <p style="color:#CBD5E1; font-size:0.84rem; margin-bottom:0;">
                    {p['recommended_correction']}
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        r1_c1, r1_c2, r1_c3 = st.columns(3, gap="small")
        with r1_c1:
            if st.button("View Explanation", key=f"app_exp_{p['id']}", use_container_width=True):
                st.session_state[f"exp_{p['id']}"] = not st.session_state.get(f"exp_{p['id']}", False)
        with r1_c2:
            if st.button("View Configuration", key=f"app_cfg_{p['id']}", use_container_width=True):
                st.session_state[f"cfg_{p['id']}"] = not st.session_state.get(f"cfg_{p['id']}", False)
        with r1_c3:
            if st.button("Evaluate Confidence", key=f"app_conf_{p['id']}", use_container_width=True):
                ev = evaluate_remediation_proposal(p["id"])
                st.session_state[f"conf_msg_{p['id']}"] = ev.explanation

        r2_c1, r2_c2, r2_c3 = st.columns(3, gap="small")
        with r2_c1:
            if st.button("Approve Fix", key=f"approve_{p['id']}", use_container_width=True):
                try:
                    set_proposal_decision(p["id"], decision="Approved")
                    st.rerun()
                except ApprovalError as exc:
                    st.session_state[f"app_err_{p['id']}"] = str(exc)
        with r2_c2:
            if st.button("Reject Fix", key=f"reject_{p['id']}", use_container_width=True):
                try:
                    set_proposal_decision(p["id"], decision="Rejected")
                    st.rerun()
                except ApprovalError as exc:
                    st.session_state[f"app_err_{p['id']}"] = str(exc)
        with r2_c3:
            if st.button("Apply Approved Fix", key=f"apply_{p['id']}", type="primary", use_container_width=True):
                try:
                    res = apply_approved_remediation(p["id"], target_url=target_url)
                    st.session_state.pop(f"app_err_{p['id']}", None)
                    st.session_state[f"app_ok_{p['id']}"] = (
                        f"Applied {res['action_id']} (Backup: {res['backup_uid']}). Status: {res['approval_status']}"
                    )
                    st.rerun()
                except (RemediationValidationError, RemediationApplyError) as exc:
                    st.session_state[f"app_err_{p['id']}"] = str(exc)

        g1, g2, g3 = st.columns(3, gap="small")
        with g1:
            if st.button("Request Modification", key=f"mod_req_{p['id']}", use_container_width=True):
                set_proposal_decision(p["id"], decision="Modification Requested")
                st.rerun()
        with g2:
            if st.button("Save for Later", key=f"save_lat_{p['id']}", use_container_width=True):
                set_proposal_decision(p["id"], decision="Saved for Later")
                st.rerun()
        with g3:
            if p["approval_status"] == "Approved":
                if st.button("Mark Applied Manually", key=f"manual_app_{p['id']}", use_container_width=True):
                    set_proposal_decision(
                        p["id"],
                        decision="Verification Pending",
                        notes=f"Developer applied fix manually to {target_url}.",
                    )
                    st.session_state.pop(f"app_err_{p['id']}", None)
                    st.rerun()

        if st.session_state.get(f"conf_msg_{p['id']}"):
            st.info(st.session_state[f"conf_msg_{p['id']}"])
        if st.session_state.get(f"app_ok_{p['id']}"):
            st.success(st.session_state[f"app_ok_{p['id']}"])
        if st.session_state.get(f"app_err_{p['id']}"):
            st.warning(st.session_state[f"app_err_{p['id']}"])

        if st.session_state.get(f"exp_{p['id']}", False):
            st.info(f"**Explanation:** {p['technical_explanation']}\n\n**Impact:** {p['security_impact']}")
        if st.session_state.get(f"cfg_{p['id']}", False):
            st.code(f"# Original\n{p['original_config']}\n\n# Proposed\n{p['corrected_config']}\n\n# Code\n{p['secure_code_example']}")

        if p["approval_status"] in {"Verification Pending", "Verification Failed"}:
            if st.button("Verify Fix via Fresh Scan", key=f"verify_{p['id']}"):
                with st.spinner("Running fresh defensive scan and Security Proof verification..."):
                    v_res = verify_remediation_proposal(p["id"], target_url=target_url)
                    if v_res["verified"]:
                        st.success(f"Verified! Follow-up Scan #{v_res['followup_scan_id']} confirmed resolution.")
                    else:
                        st.warning(f"Verification Failed on Scan #{v_res['followup_scan_id']}.")
                    st.rerun()


def render_remediation_history_page() -> None:
    """Render Remediation History, Configuration Backups, Rollback Controls, and Audit Trail."""
    render_page_header(
        kicker="SMART ROLLBACK & AUDIT TRAIL",
        title="Remediation History",
        subtitle="Inspect configuration backups, safely roll back applied changes, and review the immutable audit ledger.",
        badge="BACKUP & ROLLBACK",
    )

    st.subheader("Configuration Backups & Smart Rollback")
    backups = list_backups(user_id=(st.session_state.get("auth_user") or {}).get("id"))
    if backups:
        st.dataframe(pd.DataFrame(backups), use_container_width=True, hide_index=True)
        b_map = {
            f"{b['backup_uid']} · {b['action_id']} ({b['setting_key']}: {b['original_value']} -> {b['applied_value']})": b["backup_uid"]
            for b in backups
        }
        chosen_b = st.selectbox("Select Backup to Roll Back", list(b_map.keys()), key="rollback_select")
        if st.button("Rollback Configuration", key="rollback_btn", type="primary"):
            try:
                rb = rollback_configuration(b_map[chosen_b])
                st.success(
                    f"Rolled back {rb['setting_key']} to {rb['restored_value']} (verified={rb['restored_verified']})."
                )
                st.rerun()
            except RollbackError as exc:
                st.error(str(exc))
    else:
        st.info("No configuration backups recorded yet.")

    st.markdown("<div style='height:1rem;'></div>", unsafe_allow_html=True)
    st.subheader("Immutable Governance Audit Log")
    audits = get_audit_logs(user_id=(st.session_state.get("auth_user") or {}).get("id"))
    if audits:
        st.dataframe(pd.DataFrame(audits), use_container_width=True, hide_index=True)
    else:
        st.info("No audit events recorded yet.")


def render_regression_guard_page() -> None:
    """Render Unique Feature 9: Security Regression Guard."""
    render_page_header(
        kicker="CONTINUOUS LOCAL MONITORING",
        title="Security Regression Guard",
        subtitle="Detect returning vulnerabilities, newly introduced misconfigurations, and security score deterioration.",
        badge="REGRESSION GUARD",
    )

    scans = [s for s in get_all_scans(user_id=(st.session_state.get("auth_user") or {}).get("id")) if s["status"] == "completed"]
    if len(scans) < 2:
        st.info("At least two completed scans of the same authorised target are required to run Regression Guard.")
    else:
        scan_map = {
            f"Scan #{s['id']} · {s['target_url']} · Score {s['security_score']}/100 ({s['scan_date']})": s
            for s in scans
        }
        keys = list(scan_map.keys())
        c1, c2 = st.columns(2, gap="medium")
        with c1:
            latest_lbl = st.selectbox("Latest Scan", keys, index=0, key="reg_latest")
        latest_scan = scan_map[latest_lbl]
        comparable_keys = [
            k for k, s in scan_map.items()
            if s["id"] != latest_scan["id"]
            and s["target_url"].rstrip("/") == latest_scan["target_url"].rstrip("/")
        ]
        with c2:
            if comparable_keys:
                base_lbl = st.selectbox("Verified Baseline Scan (Same Target)", comparable_keys, index=0, key="reg_base")
            else:
                st.warning(f"Only 1 completed scan exists for {latest_scan['target_url']}. Run a second scan of this target first.")
                base_lbl = None

        if base_lbl and st.button("Run Regression Check", key="run_reg_btn", type="primary"):
            try:
                rep = evaluate_security_regression(scan_map[base_lbl]["id"], latest_scan["id"])
                st.session_state["last_regression"] = rep
            except RegressionGuardError as exc:
                st.session_state.pop("last_regression", None)
                st.error(str(exc))

    rep = st.session_state.get("last_regression")
    if rep:
        m1, m2, m3 = st.columns(3, gap="medium")
        m1.metric("Score Delta", f"{rep.score_delta:+.1f}")
        m2.metric("Returning Fixed Issues", len(rep.returning_fixed_vulnerabilities))
        m3.metric("Newly Introduced Issues", len(rep.newly_introduced_vulnerabilities))

        if rep.returning_fixed_vulnerabilities:
            st.error("Regression Alert: Previously resolved vulnerabilities have returned!")
            st.dataframe(pd.DataFrame(rep.returning_fixed_vulnerabilities), use_container_width=True, hide_index=True)
        elif rep.newly_introduced_vulnerabilities or rep.score_delta < 0:
            st.warning("Configuration drift detected between baseline and latest scan.")
        else:
            st.success("No security regressions detected.")

    st.subheader("Persisted Regression Alerts")
    alerts = get_regression_alerts()
    if alerts:
        st.dataframe(pd.DataFrame(alerts), use_container_width=True, hide_index=True)
    else:
        st.info("No regression alerts recorded.")
