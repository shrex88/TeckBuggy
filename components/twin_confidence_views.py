"""Streamlit UI view for AI Remediation Confidence Engine."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from components.charts import build_security_score_gauge
from components.dashboard import render_page_header
from intelligence import evaluate_remediation_proposal, list_confidence_outcomes
from remediation import list_proposals


def render_remediation_confidence_page() -> None:
    """Render AI Remediation Confidence Engine Dashboard."""
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
