"""Evidence-Based 16-Section PDF Report Generator for SENTINEL AI."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import select

from config import APP_NAME, APP_TAGLINE, DATABASE_URL, REPORTS_DIR
from database.database import get_session, init_db, save_report_record
from database.models import AuditLog, Finding, RemediationProposal, Scan
from intelligence.security_proof import SecurityProofError, compare_scans


class ReportGenerationError(RuntimeError):
    """Raised when a PDF security report cannot be generated."""


def generate_pdf_report(
    scan_id: int,
    *,
    output_dir: Path = REPORTS_DIR,
    database_url: str = DATABASE_URL,
) -> Path:
    """Generate a 16-section branded PDF security assessment report from real SQLite data."""
    init_db(database_url)
    with get_session(database_url) as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise ReportGenerationError(f"Scan #{scan_id} not found.")

        findings = list(scan.findings)
        scan_data: dict[str, Any] = {
            "id": scan.id,
            "target_url": scan.target_url,
            "scan_date": scan.scan_date.strftime("%Y-%m-%d %H:%M UTC")
            if scan.scan_date
            else "—",
            "security_score": float(scan.security_score or 0.0),
            "total_findings": int(scan.total_findings or len(findings)),
            "status": scan.status,
        }
        findings_list = [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "title": f.title,
                "target_path": f.target_path,
                "severity": f.severity,
                "risk_score": float(f.risk_score or 0.0),
                "owasp_category": f.owasp_category,
                "evidence": f.evidence or "",
                "remediation": f.remediation or "",
                "finding_status": f.finding_status,
            }
            for f in sorted(findings, key=lambda x: float(x.risk_score or 0.0), reverse=True)
        ]

        finding_ids = [f["id"] for f in findings_list]
        proposals = (
            list(
                session.scalars(
                    select(RemediationProposal).where(
                        RemediationProposal.finding_id.in_(finding_ids)
                    )
                ).all()
            )
            if finding_ids
            else []
        )
        proposals_data = [
            {
                "id": p.id,
                "action_id": p.action_id,
                "source": p.source,
                "approval_status": p.approval_status,
                "recommended_correction": p.recommended_correction,
            }
            for p in proposals
        ]

        audits = list(
            session.scalars(
                select(AuditLog).order_by(AuditLog.created_at.desc()).limit(10)
            ).all()
        )
        audit_data = [
            {
                "event_type": a.event_type,
                "action_id": a.action_id or "—",
                "status": a.status,
                "details": a.details,
            }
            for a in audits
        ]

        # Find an earlier completed scan of the same target for before/after comparison
        other_scans = list(
            session.scalars(
                select(Scan)
                .where(
                    Scan.target_url == scan.target_url,
                    Scan.id != scan_id,
                    Scan.status == "completed",
                )
                .order_by(Scan.id.desc())
                .limit(1)
            ).all()
        )
        other_scan_id = other_scans[0].id if other_scans else None

    proof = None
    if other_scan_id is not None:
        try:
            b_id, f_id = (
                (other_scan_id, scan_id) if other_scan_id < scan_id else (scan_id, other_scan_id)
            )
            proof = compare_scans(
                b_id, f_id, mark_verified_resolved=False, database_url=database_url
            )
        except SecurityProofError:
            proof = None

    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    pdf_path = output_dir / f"sentinel_report_scan_{scan_id}_{ts}.pdf"

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "SentinelTitle",
        parent=styles["Title"],
        fontSize=19,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "SentinelSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#0891B2"),
        spaceAfter=12,
    )
    h2_style = ParagraphStyle(
        "SentinelH2",
        parent=styles["Heading2"],
        fontSize=12,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=10,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "SentinelBody",
        parent=styles["Normal"],
        fontSize=9,
        leading=12.5,
        textColor=colors.HexColor("#1E293B"),
        spaceAfter=5,
    )

    story: list[Any] = []

    # 1. SENTINEL AI Branding
    story.append(Paragraph(f"{APP_NAME} — Evidence-Based Security Intelligence Report", title_style))
    story.append(Paragraph(f"{APP_TAGLINE} · Team Tech Buggy · Automated Web Application Security", subtitle_style))

    # 2. Executive Summary
    sev_counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    owasp_counts: dict[str, int] = {}
    for f in findings_list:
        sev = f["severity"] if f["severity"] in sev_counts else "Info"
        sev_counts[sev] += 1
        owasp_counts[f["owasp_category"]] = owasp_counts.get(f["owasp_category"], 0) + 1

    story.append(Paragraph("1. Executive Summary", h2_style))
    story.append(
        Paragraph(
            f"SENTINEL AI completed a defensive security assessment of <b>{escape(scan_data['target_url'])}</b> "
            f"at {escape(scan_data['scan_date'])}. Overall Security Score: <b>{scan_data['security_score']:.1f}/100</b> "
            f"across <b>{scan_data['total_findings']}</b> findings ({sev_counts['Critical']} Critical, "
            f"{sev_counts['High']} High, {sev_counts['Medium']} Medium, {sev_counts['Low']} Low).",
            body_style,
        )
    )

    # 3, 4, 5. Target Application Info, Timestamp & Overall Security Score
    story.append(Paragraph("2. Target Application, Timestamp & Overall Security Score", h2_style))
    meta_table = Table(
        [
            ["Scan ID", f"#{scan_data['id']}", "Target Application", scan_data["target_url"]],
            ["Scan Timestamp", scan_data["scan_date"], "Scan Status", scan_data["status"].upper()],
            ["Security Score", f"{scan_data['security_score']:.1f} / 100", "Total Findings", str(scan_data["total_findings"])],
        ],
        colWidths=[1.3 * inch, 1.8 * inch, 1.3 * inch, 2.3 * inch],
    )
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
                ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#F1F5F9")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(meta_table)

    # 6 & 8. Vulnerability Statistics & OWASP Top 10:2025 Classifications
    story.append(Paragraph("3. Vulnerability Statistics & OWASP Top 10:2025 Classifications", h2_style))
    stat_rows = [["Severity", "Count", "OWASP Top 10:2025 Category", "Findings"]]
    owasp_items = sorted(owasp_counts.items(), key=lambda x: x[1], reverse=True)
    sev_items = list(sev_counts.items())
    for idx in range(max(len(sev_items), len(owasp_items), 1)):
        s_lbl, s_cnt = sev_items[idx] if idx < len(sev_items) else ("", "")
        o_lbl, o_cnt = owasp_items[idx] if idx < len(owasp_items) else ("", "")
        stat_rows.append([str(s_lbl), str(s_cnt), str(o_lbl), str(o_cnt)])
    stat_table = Table(stat_rows, colWidths=[1.2 * inch, 0.8 * inch, 3.7 * inch, 1.0 * inch])
    stat_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(stat_table)

    # 7 & 9. Critical/High Findings & Risk Factor Breakdown
    story.append(Paragraph("4. Critical & High Findings with Risk Factor Breakdown", h2_style))
    high_crit = [f for f in findings_list if f["severity"] in {"Critical", "High"}]
    display_findings = high_crit if high_crit else findings_list
    if not display_findings:
        story.append(Paragraph("No vulnerabilities detected in this scan.", body_style))
    else:
        for f in display_findings:
            story.append(
                Paragraph(
                    f"<b>[{escape(f['severity'].upper())}] {escape(f['rule_id'])} — {escape(f['title'])}</b> "
                    f"(Risk Score: {f['risk_score']:.1f}/100 | Status: {escape(f['finding_status'])})",
                    body_style,
                )
            )
            story.append(Paragraph(f"<b>OWASP 2025:</b> {escape(f['owasp_category'])} · <b>Path:</b> {escape(f['target_path'])}", body_style))
            story.append(Paragraph(f"<b>Evidence & Factor Breakdown:</b> {escape(f['evidence'])}", body_style))
            story.append(Paragraph(f"<b>Remediation:</b> {escape(f['remediation'])}", body_style))

    # 10. Fintech Impact Explanation
    story.append(Paragraph("5. Fintech Impact Explanation", h2_style))
    story.append(
        Paragraph(
            "Under SENTINEL AI's Fintech-aware model, missing security headers (CSP, XFO, nosniff) and "
            "unhardened session cookies elevate exposure of authenticated customer sessions and payment workflows. "
            "Data sensitivity reflects the configured application profile assumption, not proof of actual stored customer data.",
            body_style,
        )
    )

    # 11 & 12. AI Remediation Recommendations & Approved Remediation History
    story.append(Paragraph("6. AI Remediation Recommendations & Approved History", h2_style))
    if proposals_data:
        for p in proposals_data[:10]:
            story.append(
                Paragraph(
                    f"Proposal #{p['id']} · Action <b>{escape(p['action_id'])}</b> ({escape(p['source'])}) — "
                    f"Status: <b>{escape(p['approval_status'])}</b>. {escape(p['recommended_correction'])}",
                    body_style,
                )
            )
    else:
        story.append(Paragraph("No AI remediation proposals recorded for this scan yet.", body_style))

    if audit_data:
        story.append(Paragraph("Recent Governance Audit Events:", body_style))
        for a in audit_data[:5]:
            story.append(Paragraph(f"• [{escape(a['status'])}] {escape(a['event_type'])} ({escape(a['action_id'])}): {escape(a['details'])}", body_style))

    # 13, 14, 15. Before-and-After Comparison, Verified Fixes & Remaining Vulnerabilities
    story.append(Paragraph("7. Before-and-After Security Proof, Verified Fixes & Remaining Vulnerabilities", h2_style))
    if proof is not None:
        story.append(
            Paragraph(
                f"Compared Baseline Scan #{proof.baseline_scan_id} (Score: {proof.original_security_score:.1f}/100) "
                f"vs Follow-Up Scan #{proof.followup_scan_id} (Score: {proof.updated_security_score:.1f}/100). "
                f"Verified Fixed: <b>{len(proof.fixed_vulnerabilities)}</b> · "
                f"Remaining: <b>{len(proof.remaining_vulnerabilities)}</b> · "
                f"Risk Reduction: <b>{proof.risk_reduction:.1f} pts ({proof.percentage_improvement:.1f}%)</b>.",
                body_style,
            )
        )
    else:
        verified_cnt = sum(1 for f in findings_list if f["finding_status"] == "resolved")
        remaining_cnt = len(findings_list) - verified_cnt
        story.append(
            Paragraph(
                f"Verified Resolved Findings: <b>{verified_cnt}</b> · Remaining Open Findings: <b>{remaining_cnt}</b>. "
                "(Run a follow-up scan to enable full Before-and-After Security Proof comparison.)",
                body_style,
            )
        )

    # 16. Final Security Assessment
    story.append(Paragraph("8. Final Security Assessment", h2_style))
    if scan_data["security_score"] >= 90:
        verdict = "Strong security posture with minimal residual configuration risk."
    elif scan_data["security_score"] >= 70:
        verdict = "Moderate security posture; prioritise resolving High-risk misconfigurations and verify via Security Proof."
    else:
        verdict = "Elevated risk posture; immediate remediation of Critical/High findings is recommended followed by Security Proof verification."
    story.append(Paragraph(verdict, body_style))

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        leftMargin=0.65 * inch,
        rightMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
    )
    doc.build(story)

    save_report_record(
        scan_id=scan_id,
        report_path=str(pdf_path),
        database_url=database_url,
    )
    return pdf_path
