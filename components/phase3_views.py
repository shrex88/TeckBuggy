"""Phase 3 functional views: Remediation Centre, Security Proof, and PDF Reports."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

from components.charts import (
    build_security_proof_findings_chart,
    build_security_proof_score_chart,
)
from components.dashboard import render_page_header
from database import get_all_reports, get_all_scans, get_findings, update_finding_status
from intelligence import SecurityProofError, classify_risk_level, compare_scans
from remediation import SUPPORTED_FRAMEWORKS, generate_remediation_playbook
from reporting import ReportGenerationError, generate_pdf_report


def render_remediation_centre_page() -> None:
    """Render the Smart Remediation Centre with framework-specific fixes and controls."""
    render_page_header(
        kicker="SMART REMEDIATION ENGINE",
        title="Remediation Centre",
        subtitle="Developer-ready patches and verification steps. Target applications are never modified automatically.",
        badge="DEFENSIVE GUIDANCE",
    )

    findings = get_findings()
    if not findings:
        st.info("No findings recorded yet. Run a scan in 'New Security Scan' to generate remediation playbooks.")
        return

    framework = st.selectbox(
        "Target Reference Framework / Server",
        options=list(SUPPORTED_FRAMEWORKS),
        index=0,
        key="remediation_framework",
    )

    for f in findings:
        playbook = generate_remediation_playbook(f)
        snippet = playbook.snippets.get(framework, playbook.corrected_config)
        reviewed_badge = "REVIEWED" if f["finding_status"] == "in_progress" else f["finding_status"].upper()
        ai_risk_level = classify_risk_level(playbook.risk_score).upper()

        st.markdown(
            f"""
            <div class="sentinel-panel">
                <div class="panel-header">
                    <span class="panel-title">{playbook.rule_id} · {playbook.finding_title}</span>
                    <span class="panel-badge">AI RISK: {ai_risk_level} ({playbook.risk_score:.1f}/100) · {reviewed_badge}</span>
                </div>
                <p style="color:#CBD5E1; font-size:0.86rem; margin-bottom:0.4rem;">
                    <strong>Recommended Fix:</strong> {playbook.recommended_fix}
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        c1, c2, c3, c4 = st.columns(4, gap="small")
        with c1:
            if st.button("Copy Fix", key=f"copy_fix_{f['id']}", use_container_width=True):
                st.session_state[f"show_copy_{f['id']}"] = True
        with c2:
            if st.button("View Explanation", key=f"view_exp_{f['id']}", use_container_width=True):
                st.session_state[f"show_exp_{f['id']}"] = not st.session_state.get(
                    f"show_exp_{f['id']}", False
                )
        with c3:
            if st.button("View Configuration", key=f"view_cfg_{f['id']}", use_container_width=True):
                st.session_state[f"show_cfg_{f['id']}"] = not st.session_state.get(
                    f"show_cfg_{f['id']}", False
                )
        with c4:
            if st.button("Developer Reviewed", key=f"dev_rev_{f['id']}", use_container_width=True):
                # Marks only as in_progress; resolution is exclusively verified by Security Proof rescan
                update_finding_status(f["id"], "in_progress")
                st.success(
                    f"Finding #{f['id']} marked as Developer Reviewed (in_progress). "
                    "Run a follow-up scan in Security Proof to verify resolution."
                )
                st.rerun()

        if st.session_state.get(f"show_copy_{f['id']}", False):
            st.code(snippet, language="python" if framework in {"Flask", "Django"} else "nginx")

        if st.session_state.get(f"show_exp_{f['id']}", False):
            st.info(
                f"**Technical Explanation:** {playbook.technical_explanation}\n\n"
                f"**Potential Security Impact:** {playbook.security_impact}\n\n"
                f"**Verification:** {playbook.verification_instructions}"
            )

        if st.session_state.get(f"show_cfg_{f['id']}", False):
            st.code(f"# Corrected Header / Policy\n{playbook.corrected_config}\n\n# {framework} Reference\n{snippet}")


def render_security_proof_page() -> None:
    """Render the signature Security Proof before-and-after verification engine."""
    render_page_header(
        kicker="VERIFIED REMEDIATION",
        title="Security Proof",
        subtitle="Compare baseline and follow-up scans to verify genuine vulnerability resolution.",
        badge="BEFORE vs AFTER",
    )

    scans = [s for s in get_all_scans() if s["status"] == "completed"]
    if len(scans) < 2:
        st.info(
            "Security Proof requires at least two completed scans of the same target "
            "(1 initial baseline scan + 1 follow-up scan after applying fixes)."
        )
        return

    scan_labels = {
        f"Scan #{s['id']} · {s['target_url']} · Score {s['security_score']}/100 ({s['scan_date']})": s["id"]
        for s in scans
    }
    keys = list(scan_labels.keys())

    c1, c2 = st.columns(2, gap="medium")
    with c1:
        baseline_label = st.selectbox("Baseline Scan (Before Fix)", keys, index=min(1, len(keys) - 1))
    with c2:
        followup_label = st.selectbox("Follow-Up Scan (After Fix)", keys, index=0)

    if st.button("Verify Security Proof", key="run_security_proof_btn", type="primary"):
        try:
            proof = compare_scans(
                baseline_scan_id=scan_labels[baseline_label],
                followup_scan_id=scan_labels[followup_label],
                mark_verified_resolved=True,
            )
            st.session_state["last_security_proof"] = proof
        except SecurityProofError as exc:
            st.error(str(exc))
            return

    proof = st.session_state.get("last_security_proof")
    if proof is None:
        return

    m1, m2, m3, m4 = st.columns(4, gap="medium")
    m1.metric("Original Security Score", f"{proof.original_security_score:.1f}/100")
    m2.metric(
        "Updated Security Score",
        f"{proof.updated_security_score:.1f}/100",
        delta=f"{proof.updated_security_score - proof.original_security_score:+.1f}",
    )
    m3.metric("Risk Reduction", f"{proof.risk_reduction:.1f} pts")
    m4.metric("Improvement", f"{proof.percentage_improvement:.1f}%")

    ch1, ch2 = st.columns(2, gap="medium")
    with ch1:
        st.plotly_chart(
            build_security_proof_score_chart(
                proof.original_security_score, proof.updated_security_score
            ),
            use_container_width=True,
            config={"displayModeBar": False},
        )
    with ch2:
        st.plotly_chart(
            build_security_proof_findings_chart(
                len(proof.fixed_vulnerabilities),
                len(proof.remaining_vulnerabilities),
                len(proof.newly_discovered_vulnerabilities),
            ),
            use_container_width=True,
            config={"displayModeBar": False},
        )

    st.subheader(f"Verified Fixed Vulnerabilities ({len(proof.fixed_vulnerabilities)})")
    if proof.fixed_vulnerabilities:
        st.dataframe(
            pd.DataFrame(proof.fixed_vulnerabilities)[["rule_id", "title", "target_path", "severity", "risk_score"]],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No vulnerabilities were verified as fixed between these two scans.")

    st.subheader(f"Remaining Vulnerabilities ({len(proof.remaining_vulnerabilities)})")
    if proof.remaining_vulnerabilities:
        st.dataframe(
            pd.DataFrame(proof.remaining_vulnerabilities)[["rule_id", "title", "target_path", "severity", "risk_score"]],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.success("Zero remaining vulnerabilities from the baseline scan!")

    if proof.newly_discovered_vulnerabilities:
        st.subheader(f"Newly Discovered Vulnerabilities ({len(proof.newly_discovered_vulnerabilities)})")
        st.dataframe(
            pd.DataFrame(proof.newly_discovered_vulnerabilities)[["rule_id", "title", "target_path", "severity", "risk_score"]],
            use_container_width=True,
            hide_index=True,
        )


def render_reports_page() -> None:
    """Render PDF report generation and download history."""
    render_page_header(
        kicker="EXECUTIVE & TECHNICAL REPORTING",
        title="Reports",
        subtitle="Generate and download branded PDF security assessment reports from persisted scan data.",
        badge="PDF EXPORT",
    )

    scans = get_all_scans()
    if not scans:
        st.info("No scans available yet. Complete a security scan before generating a PDF report.")
        return

    scan_map = {
        f"Scan #{s['id']} · {s['target_url']} · Score {s['security_score']}/100 ({s['scan_date']})": s["id"]
        for s in scans
    }
    selected_label = st.selectbox("Select Scan to Export", list(scan_map.keys()), key="report_scan_select")
    selected_scan_id = scan_map[selected_label]

    if st.button("Generate PDF Report", key="generate_pdf_btn", type="primary"):
        try:
            with st.spinner("Generating branded PDF security report..."):
                pdf_path = generate_pdf_report(selected_scan_id)
            st.session_state["latest_pdf_path"] = str(pdf_path)
            st.success(f"Report generated: {pdf_path.name}")
        except ReportGenerationError as exc:
            st.error(f"Report generation failed: {exc}")

    latest_pdf = st.session_state.get("latest_pdf_path")
    if latest_pdf and Path(latest_pdf).exists():
        pdf_bytes = Path(latest_pdf).read_bytes()
        st.download_button(
            label="Download PDF Report",
            data=pdf_bytes,
            file_name=Path(latest_pdf).name,
            mime="application/pdf",
            key="download_pdf_btn",
            type="primary",
        )

    st.markdown("<div style='height:1rem;'></div>", unsafe_allow_html=True)
    st.subheader("Generated Report Registry")
    reports = get_all_reports()
    if reports:
        st.dataframe(pd.DataFrame(reports), use_container_width=True, hide_index=True)
    else:
        st.info("No PDF reports generated yet.")
