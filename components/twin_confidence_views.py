"""Streamlit UI views for Security Digital Twin & AI Remediation Confidence Engine."""

from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components.charts import build_security_score_gauge
from components.dashboard import render_page_header
from config import APPLICATION_PROFILES
from database import get_all_scans
from digital_twin import (
    RECOMMENDED_CSP,
    DigitalTwinSnapshotError,
    get_simulation_details,
    list_simulations,
    run_digital_twin_simulation,
)
from intelligence import (
    evaluate_remediation_proposal,
    is_gemini_configured,
    list_confidence_outcomes,
)
from intelligence.gemini_client import request_gemini_text
from remediation import list_proposals


def render_digital_twin_page() -> None:
    """Render Feature 1: Security Digital Twin What-If Simulator."""
    render_page_header(
        kicker="VIRTUAL SECURITY SANDBOX",
        title="Security Digital Twin",
        subtitle="Experiment with CSP and Cookie hardening on an isolated virtual snapshot—never modifying live applications.",
        badge="ISOLATED SIMULATION",
    )

    c1, c2, c3 = st.columns([1.3, 1.1, 1], gap="medium")
    with c1:
        scans = [s for s in get_all_scans() if s["status"] == "completed"]
        scanned_urls = list(dict.fromkeys(s["target_url"] for s in scans))
        if scanned_urls:
            target_url = st.selectbox(
                "Select Scanned Local Application",
                options=scanned_urls,
                key="twin_app_select",
            )
            app_choice = target_url
        else:
            target_url = st.text_input(
                "Authorised Local Application URL",
                value="http://127.0.0.1:8000",
                key="twin_app_input",
            )
            app_choice = target_url
    with c2:
        sim_mode = st.selectbox(
            "What-If Simulation Mode",
            options=["Both (CSP + Cookies)", "CSP Only", "Cookies Only", "Custom"],
            key="twin_mode",
        )
    with c3:
        profile = st.selectbox(
            "Risk Profile",
            options=list(APPLICATION_PROFILES.keys()),
            index=0,
            key="twin_profile",
        )

    with st.expander("Virtual Configuration Editor (CSP & Cookie Controls)", expanded=True):
        proposed_csp = st.text_area(
            "Proposed Content-Security-Policy",
            value=RECOMMENDED_CSP,
            height=72,
            key="twin_csp_input",
        )
        col_a, col_b, col_c, col_d = st.columns(4)
        with col_a:
            report_only = st.checkbox("CSP Report-Only Preview", value=False, key="twin_ro")
        with col_b:
            sec_cookie = st.checkbox("Enable Secure Cookie", value=True, key="twin_sec_c")
        with col_c:
            http_cookie = st.checkbox("Enable HttpOnly Cookie", value=True, key="twin_http_c")
        with col_d:
            samesite = st.selectbox("SameSite Attribute", ["Lax", "Strict", "None", ""], key="twin_ss")

        add_hdrs = st.checkbox(
            "Also simulate X-Frame-Options, nosniff, Referrer-Policy & Permissions-Policy",
            value=True,
            key="twin_add_hdrs",
        )

    if st.button("Run Digital Twin Simulation", key="run_twin_btn", type="primary"):
        try:
            with st.spinner("Creating virtual snapshot and evaluating proposed configuration..."):
                res = run_digital_twin_simulation(
                    target_url=target_url,
                    app_label=app_choice,
                    simulation_mode=sim_mode,
                    proposed_csp=proposed_csp,
                    csp_report_only=report_only,
                    enable_secure_cookie=sec_cookie,
                    enable_httponly_cookie=http_cookie,
                    samesite=samesite,
                    enable_additional_headers=add_hdrs,
                    application_profile=profile,
                )
                st.session_state["last_twin_res"] = res
        except DigitalTwinSnapshotError as exc:
            st.error(str(exc))

    res = st.session_state.get("last_twin_res")
    if res is not None:
        ev = res.evaluation
        m1, m2, m3, m4 = st.columns(4, gap="medium")
        m1.metric("ACTUAL BASELINE SCORE", f"{ev.baseline_score:.1f}/100")
        m2.metric(
            "SIMULATED PROJECTED SCORE",
            f"{ev.projected_score:.1f}/100",
            delta=f"{ev.projected_score - ev.baseline_score:+.1f}",
        )
        m3.metric("Expected Risk Reduction", f"{ev.expected_risk_reduction:.1f} pts")
        m4.metric("Simulation Classification", ev.classification)

        st.info(
            "Note: A **SIMULATED PASS** or **CONDITIONAL** result is a virtual projection only—not actual verification. "
            "Only a follow-up scan in Security Proof verifies real remediation."
        )

        st.subheader("Original vs. Proposed Configuration")
        st.dataframe(
            pd.DataFrame(
                [
                    {"Control": c, "Original": o, "Proposed": p}
                    for c, o, p in res.proposed_changes
                ]
            ),
            use_container_width=True,
            hide_index=True,
        )

        if ev.compatibility_warnings:
            st.subheader(f"Compatibility Warnings ({len(ev.compatibility_warnings)})")
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Domain": w.domain,
                            "Severity": w.severity,
                            "Warning": w.warning_title,
                            "Explanation": w.explanation,
                        }
                        for w in ev.compatibility_warnings
                    ]
                ),
                use_container_width=True,
                hide_index=True,
            )

        if ev.remaining_findings:
            st.subheader(f"Remaining Findings in Simulation ({len(ev.remaining_findings)})")
            st.dataframe(pd.DataFrame(ev.remaining_findings), use_container_width=True, hide_index=True)

        if is_gemini_configured():
            if st.button("Explain Simulation with Gemini", key="twin_gemini_btn"):
                with st.spinner("Asking Gemini to review compatibility & simulation outcome..."):
                    txt = request_gemini_text(
                        f"Briefly explain the compatibility and security implications of this Digital Twin simulation: "
                        f"Target={res.snapshot.target_url}, Mode={res.simulation_mode}, "
                        f"Baseline={ev.baseline_score}, Projected={ev.projected_score}, Classification={ev.classification}."
                    )
                    if txt:
                        st.markdown(txt)

    st.markdown("<div style='height:1rem;'></div>", unsafe_allow_html=True)
    st.subheader("Digital Twin Simulation History")
    sims = list_simulations()
    if sims:
        st.dataframe(
            pd.DataFrame(sims)[
                ["id", "target_url", "simulation_mode", "baseline_score", "projected_score", "classification", "created_at"]
            ],
            use_container_width=True,
            hide_index=True,
        )
        if len(sims) >= 2:
            s_map = {f"Sim #{s['id']} ({s['simulation_mode']} · {s['classification']})": s["id"] for s in sims}
            keys = list(s_map.keys())
            ca, cb = st.columns(2)
            with ca:
                s1 = st.selectbox("Compare Simulation A", keys, index=0, key="cmp_s1")
            with cb:
                s2 = st.selectbox("Compare Simulation B", keys, index=1, key="cmp_s2")
            d1 = get_simulation_details(s_map[s1])
            d2 = get_simulation_details(s_map[s2])
            if d1 and d2:
                st.caption(
                    f"Comparison: Sim #{d1['id']} Projected={d1['projected_score']} ({d1['classification']}) "
                    f"vs Sim #{d2['id']} Projected={d2['projected_score']} ({d2['classification']})"
                )
    else:
        st.info("No Digital Twin simulations recorded yet.")


def render_remediation_confidence_page() -> None:
    """Render Feature 2: AI Remediation Confidence Engine Dashboard."""
    render_page_header(
        kicker="INDEPENDENT PROPOSAL EVALUATION",
        title="Remediation Confidence",
        subtitle="Deterministic technical validation, application safety, regression analysis, and verification status.",
        badge="CONFIDENCE ENGINE",
    )

    proposals = list_proposals()
    if not proposals:
        st.info("No remediation proposals exist yet. Generate a proposal in AI Remediation Copilot first.")
        return

    p_map = {
        f"Proposal #{p['id']} · {p['rule_id']} ({p['action_id']}) — {p['approval_status']}": p
        for p in proposals
    }
    chosen_lbl = st.selectbox("Select Remediation Proposal to Evaluate", list(p_map.keys()), key="conf_prop_select")
    chosen = p_map[chosen_lbl]

    if st.button("Evaluate Proposal Confidence", key="run_conf_btn", type="primary"):
        ev = evaluate_remediation_proposal(chosen["id"])
        st.session_state["last_conf_eval"] = ev

    ev = st.session_state.get("last_conf_eval")
    if ev is not None:
        c1, c2, c3 = st.columns(3, gap="medium")
        c1.metric("REMEDIATION CONFIDENCE", f"{ev.confidence_score:.1f}/100", delta=ev.confidence_level)
        c2.metric("APPLICATION SAFETY", ev.application_safety)
        c3.metric("VERIFICATION STATUS", ev.verification_status)

        st.plotly_chart(
            build_security_score_gauge(ev.confidence_score),
            use_container_width=True,
            config={"displayModeBar": False},
        )

        st.subheader("7-Factor Confidence Breakdown")
        st.dataframe(pd.DataFrame(ev.factors), use_container_width=True, hide_index=True)

        st.subheader("Deterministic Validation Checklist")
        st.dataframe(pd.DataFrame(ev.validation_checks), use_container_width=True, hide_index=True)

        st.subheader("Regression & Side-Effect Analysis")
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Risk Description": r.risk_description,
                        "Potential Impact": r.potential_impact,
                        "Likelihood": r.likelihood,
                        "Required Testing": r.required_testing,
                        "Recommended Action": r.recommended_action,
                    }
                    for r in ev.regression_warnings
                ]
            ),
            use_container_width=True,
            hide_index=True,
        )

    st.markdown("<div style='height:1rem;'></div>", unsafe_allow_html=True)
    st.subheader("Confidence Calibration Outcomes (Predicted vs. Actual Security Proof)")
    outcomes = list_confidence_outcomes()
    if outcomes:
        st.dataframe(pd.DataFrame(outcomes), use_container_width=True, hide_index=True)
    else:
        st.info("Outcomes are recorded automatically when evaluated proposals are verified in Security Proof.")
