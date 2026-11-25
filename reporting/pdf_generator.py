"""Professional PDF Report Generator for SENTINEL AI (Phase 3)."""

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

from config import APP_NAME, APP_TAGLINE, DATABASE_URL, REPORTS_DIR
from database.database import get_session, init_db, save_report_record
from database.models import Finding, Scan


class ReportGenerationError(RuntimeError):
    """Raised when a PDF security report cannot be generated."""


def generate_pdf_report(
    scan_id: int,
    *,
    output_dir: Path = REPORTS_DIR,
    database_url: str = DATABASE_URL,
) -> Path:
    """Generate a branded PDF security assessment report from real SQLite scan data."""
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

    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    pdf_path = output_dir / f"sentinel_report_scan_{scan_id}_{ts}.pdf"

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "SentinelTitle",
        parent=styles["Title"],
        fontSize=20,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "SentinelSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#0891B2"),
        spaceAfter=14,
    )
    h2_style = ParagraphStyle(
        "SentinelH2",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "SentinelBody",
        parent=styles["Normal"],
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#1E293B"),
        spaceAfter=6,
    )

    story: list[Any] = []

    # 1. SENTINEL AI Branding
    story.append(Paragraph(f"{APP_NAME} — Security Assessment Report", title_style))
    story.append(Paragraph(f"{APP_TAGLINE} · Automated Web Application Security Intelligence", subtitle_style))

    # 2. Executive Summary
    sev_counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    owasp_counts: dict[str, int] = {}
    for f in findings_list:
        sev = f["severity"] if f["severity"] in sev_counts else "Info"
        sev_counts[sev] += 1
        cat = f["owasp_category"]
        owasp_counts[cat] = owasp_counts.get(cat, 0) + 1

    story.append(Paragraph("1. Executive Summary", h2_style))
    story.append(
        Paragraph(
            f"SENTINEL AI conducted a defensive security assessment against "
            f"<b>{escape(scan_data['target_url'])}</b> on {escape(scan_data['scan_date'])}. "
            f"The assessment recorded an overall security posture score of "
            f"<b>{scan_data['security_score']:.1f}/100</b> with <b>{scan_data['total_findings']}</b> "
            f"total findings ({sev_counts['Critical']} Critical, {sev_counts['High']} High, "
            f"{sev_counts['Medium']} Medium, {sev_counts['Low']} Low).",
            body_style,
        )
    )

    # 3 & 4. Scan Target Information & Overall Security Score
    story.append(Paragraph("2. Scan Target Information & Overall Security Score", h2_style))
    meta_table = Table(
        [
            ["Scan ID", f"#{scan_data['id']}", "Target URL", scan_data["target_url"]],
            ["Scan Date", scan_data["scan_date"], "Status", scan_data["status"].upper()],
            ["Security Score", f"{scan_data['security_score']:.1f} / 100", "Total Findings", str(scan_data["total_findings"])],
        ],
        colWidths=[1.3 * inch, 1.8 * inch, 1.3 * inch, 2.3 * inch],
    )
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
                ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#F1F5F9")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0F172A")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(meta_table)

    # 5. Vulnerability Statistics & 7. OWASP Classifications
    story.append(Paragraph("3. Vulnerability Statistics & OWASP Top 10:2025 Breakdown", h2_style))
    stat_rows = [["Severity", "Count", "OWASP Top 10:2025 Category", "Findings"]]
    owasp_items = sorted(owasp_counts.items(), key=lambda x: x[1], reverse=True)
    sev_items = list(sev_counts.items())
    max_rows = max(len(sev_items), len(owasp_items), 1)
    for idx in range(max_rows):
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

    # 6. Critical & High Findings + 8. AI Risk Explanations + 9. Remediation Recommendations
    story.append(Paragraph("4. Findings, AI Risk Explanations & Remediation Recommendations", h2_style))
    high_crit = [f for f in findings_list if f["severity"] in {"Critical", "High"}]
    display_findings = high_crit if high_crit else findings_list

    if not display_findings:
        story.append(Paragraph("No vulnerabilities were detected during this scan.", body_style))
    else:
        for f in display_findings:
            story.append(
                Paragraph(
                    f"<b>[{escape(f['severity'].upper())}] {escape(f['rule_id'])} — {escape(f['title'])}</b> "
                    f"(Risk Score: {f['risk_score']:.1f}/100 | Status: {escape(f['finding_status'])})",
                    body_style,
                )
            )
            story.append(
                Paragraph(
                    f"<b>Target:</b> {escape(f['target_path'])} &nbsp;|&nbsp; "
                    f"<b>OWASP 2025:</b> {escape(f['owasp_category'])}",
                    body_style,
                )
            )
            story.append(Paragraph(f"<b>Evidence & AI Risk Analysis:</b> {escape(f['evidence'])}", body_style))
            story.append(Paragraph(f"<b>Remediation:</b> {escape(f['remediation'])}", body_style))
            story.append(Spacer(1, 6))

    # 10. Final Assessment
    story.append(Paragraph("5. Final Assessment", h2_style))
    if scan_data["security_score"] >= 90:
        verdict = "Strong security posture with minimal residual configuration risk."
    elif scan_data["security_score"] >= 70:
        verdict = "Moderate security posture; prioritise resolving High-risk misconfigurations and verify via Security Proof."
    else:
        verdict = "Elevated risk posture; immediate remediation of Critical/High findings is recommended followed by a Security Proof verification scan."
    story.append(Paragraph(verdict, body_style))

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        leftMargin=0.7 * inch,
        rightMargin=0.7 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.7 * inch,
    )
    doc.build(story)

    save_report_record(
        scan_id=scan_id,
        report_path=str(pdf_path),
        database_url=database_url,
    )
    return pdf_path
