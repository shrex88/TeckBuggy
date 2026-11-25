"""REST API Bridge for SENTINEL AI Figma React Frontend.

Exposes all defensive scanning, OWASP 2025, AI risk intelligence, Gemini
copilot, confidence evaluation, approval governance, rollback, Security Proof,
Regression Guard, and PDF reporting endpoints over localhost.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_file

from config import APPLICATION_PROFILES, DATABASE_URL, OWASP_CATEGORIES
from database import (
    get_all_reports,
    get_all_scans,
    get_audit_logs,
    get_dashboard_snapshot,
    get_findings,
    get_regression_alerts,
    init_db,
    update_finding_status,
)
from intelligence import (
    RegressionGuardError,
    SecurityProofError,
    compare_scans,
    evaluate_remediation_proposal,
    evaluate_security_regression,
    generate_ai_remediation_proposal,
    is_gemini_configured,
    list_confidence_outcomes,
    run_security_benchmark,
)
from intelligence.gemini_client import get_last_gemini_status
from remediation import (
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
from reporting import ReportGenerationError, generate_pdf_report
from scanner import TargetValidationError, run_security_scan


def create_api_app(database_url: str = DATABASE_URL) -> Flask:
    """Create the local REST API server for the SENTINEL AI React frontend."""
    dist_dir = Path(__file__).resolve().parent / "frontend" / "dist"
    app = Flask(
        __name__,
        static_folder=str(dist_dir) if dist_dir.exists() else None,
        static_url_path="/",
    )
    init_db(database_url)

    @app.route("/", methods=["GET"])
    def serve_frontend_index() -> Any:
        index_file = dist_dir / "index.html"
        if index_file.exists():
            return send_file(index_file)
        return jsonify({"service": "SENTINEL AI API", "status": "ok"}), 200

    @app.after_request
    def _cors(resp: Any) -> Any:
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,PATCH,OPTIONS"
        return resp

    @app.route("/api/health", methods=["GET"])
    def health() -> Any:
        return jsonify(
            {
                "status": "ok",
                "gemini_configured": is_gemini_configured(),
                "gemini_status": get_last_gemini_status(),
                "profiles": list(APPLICATION_PROFILES.keys()),
                "owasp_categories": OWASP_CATEGORIES,
            }
        ), 200

    @app.route("/api/dashboard", methods=["GET"])
    def dashboard() -> Any:
        snap = get_dashboard_snapshot(database_url)
        snap["gemini_configured"] = is_gemini_configured()
        return jsonify(snap), 200

    @app.route("/api/scans", methods=["GET", "POST"])
    def scans() -> Any:
        if request.method == "GET":
            return jsonify({"scans": get_all_scans(database_url)}), 200

        payload = request.get_json(silent=True) or {}
        target_url = str(payload.get("target_url", "")).strip()
        profile = str(payload.get("application_profile", "General Web Application"))
        try:
            res = run_security_scan(
                target_url=target_url,
                application_profile=profile,
                database_url=database_url,
            )
            return jsonify(
                {
                    "scan_id": res.scan_id,
                    "target_url": res.target_url,
                    "security_score": res.security_score,
                    "total_findings": res.total_findings,
                    "application_profile": res.application_profile,
                }
            ), 201
        except TargetValidationError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            return jsonify({"error": f"Scan failed: {exc}"}), 500

    @app.route("/api/benchmark", methods=["POST"])
    def benchmark() -> Any:
        payload = request.get_json(silent=True) or {}
        high_url = str(payload.get("high_sec_url", "")).strip()
        low_url = str(payload.get("low_sec_url", "")).strip()
        profile = str(payload.get("application_profile", "Fintech / Payment Application"))
        res = run_security_benchmark(
            high_sec_url=high_url,
            low_sec_url=low_url,
            application_profile=profile,
            database_url=database_url,
        )
        return jsonify(
            {
                "benchmark_id": res.benchmark_id,
                "high_sec_score": res.high_sec_score,
                "low_sec_score": res.low_sec_score,
                "high_sec_severity_counts": res.high_sec_severity_counts,
                "low_sec_severity_counts": res.low_sec_severity_counts,
                "control_matrix": res.control_matrix,
                "high_sec_error": res.high_sec_error,
                "low_sec_error": res.low_sec_error,
            }
        ), 200

    @app.route("/api/findings", methods=["GET"])
    def findings() -> Any:
        scan_id_raw = request.args.get("scan_id")
        scan_id = int(scan_id_raw) if scan_id_raw and scan_id_raw.isdigit() else None
        severity = request.args.get("severity")
        owasp = request.args.get("owasp_category")
        return jsonify(
            {
                "findings": get_findings(
                    scan_id=scan_id,
                    severity=severity,
                    owasp_category=owasp,
                    database_url=database_url,
                )
            }
        ), 200

    @app.route("/api/findings/<int:finding_id>", methods=["PATCH"])
    def update_finding(finding_id: int) -> Any:
        payload = request.get_json(silent=True) or {}
        status = str(payload.get("finding_status", "open"))
        ok = update_finding_status(finding_id, status, database_url=database_url)
        if not ok:
            return jsonify({"error": "Finding not found"}), 404
        return jsonify({"updated": True, "finding_id": finding_id, "finding_status": status}), 200

    @app.route("/api/proposals", methods=["GET"])
    def proposals() -> Any:
        return jsonify({"proposals": list_proposals(database_url=database_url)}), 200

    @app.route("/api/proposals/generate", methods=["POST"])
    def generate_proposal() -> Any:
        payload = request.get_json(silent=True) or {}
        finding_id = int(payload.get("finding_id", 0))
        framework = str(payload.get("framework", "Flask"))
        all_f = get_findings(database_url=database_url)
        target_f = next((f for f in all_f if f["id"] == finding_id), None)
        if target_f is None:
            return jsonify({"error": f"Finding #{finding_id} not found"}), 404
        prop = generate_ai_remediation_proposal(
            target_f, framework=framework, database_url=database_url
        )
        prop["gemini_status"] = get_last_gemini_status()
        return jsonify(prop), 201

    @app.route("/api/proposals/<int:proposal_id>/decision", methods=["POST"])
    def proposal_decision(proposal_id: int) -> Any:
        payload = request.get_json(silent=True) or {}
        decision = str(payload.get("decision", ""))
        notes = str(payload.get("notes", ""))
        try:
            res = set_proposal_decision(
                proposal_id, decision=decision, notes=notes, database_url=database_url
            )
            return jsonify(res), 200
        except ApprovalError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.route("/api/proposals/<int:proposal_id>/evaluate", methods=["POST"])
    def evaluate_proposal(proposal_id: int) -> Any:
        try:
            ev = evaluate_remediation_proposal(proposal_id, database_url=database_url)
            return jsonify(
                {
                    "evaluation_id": ev.evaluation_id,
                    "proposal_id": ev.proposal_id,
                    "confidence_score": ev.confidence_score,
                    "confidence_level": ev.confidence_level,
                    "application_safety": ev.application_safety,
                    "verification_status": ev.verification_status,
                    "factors": ev.factors,
                    "validation_checks": ev.validation_checks,
                    "regression_warnings": [
                        {
                            "risk_description": r.risk_description,
                            "potential_impact": r.potential_impact,
                            "likelihood": r.likelihood,
                            "required_testing": r.required_testing,
                            "recommended_action": r.recommended_action,
                        }
                        for r in ev.regression_warnings
                    ],
                    "explanation": ev.explanation,
                }
            ), 200
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404

    @app.route("/api/proposals/<int:proposal_id>/apply", methods=["POST"])
    def apply_proposal(proposal_id: int) -> Any:
        payload = request.get_json(silent=True) or {}
        target_url = str(payload.get("target_url", "")).strip()
        try:
            res = apply_approved_remediation(
                proposal_id, target_url=target_url, database_url=database_url
            )
            return jsonify(res), 200
        except (RemediationValidationError, RemediationApplyError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.route("/api/proposals/<int:proposal_id>/verify", methods=["POST"])
    def verify_proposal(proposal_id: int) -> Any:
        payload = request.get_json(silent=True) or {}
        target_url = str(payload.get("target_url", "")).strip()
        try:
            res = verify_remediation_proposal(
                proposal_id, target_url=target_url, database_url=database_url
            )
            return jsonify(
                {
                    "proposal_id": res["proposal_id"],
                    "verified": res["verified"],
                    "approval_status": res["approval_status"],
                    "followup_scan_id": res["followup_scan_id"],
                }
            ), 200
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400

    @app.route("/api/confidence/outcomes", methods=["GET"])
    def confidence_outcomes() -> Any:
        return jsonify({"outcomes": list_confidence_outcomes(database_url=database_url)}), 200

    @app.route("/api/security-proof", methods=["POST"])
    def security_proof() -> Any:
        payload = request.get_json(silent=True) or {}
        try:
            res = compare_scans(
                int(payload.get("baseline_scan_id", 0)),
                int(payload.get("followup_scan_id", 0)),
                mark_verified_resolved=True,
                database_url=database_url,
            )
            return jsonify(
                {
                    "baseline_scan_id": res.baseline_scan_id,
                    "followup_scan_id": res.followup_scan_id,
                    "target_url": res.target_url,
                    "original_security_score": res.original_security_score,
                    "updated_security_score": res.updated_security_score,
                    "fixed_vulnerabilities": res.fixed_vulnerabilities,
                    "remaining_vulnerabilities": res.remaining_vulnerabilities,
                    "newly_discovered_vulnerabilities": res.newly_discovered_vulnerabilities,
                    "risk_reduction": res.risk_reduction,
                    "percentage_improvement": res.percentage_improvement,
                }
            ), 200
        except SecurityProofError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.route("/api/regression-guard", methods=["GET", "POST"])
    def regression_guard() -> Any:
        if request.method == "GET":
            return jsonify({"alerts": get_regression_alerts(database_url=database_url)}), 200
        payload = request.get_json(silent=True) or {}
        try:
            rep = evaluate_security_regression(
                int(payload.get("baseline_scan_id", 0)),
                int(payload.get("latest_scan_id", 0)),
                database_url=database_url,
            )
            return jsonify(
                {
                    "score_delta": rep.score_delta,
                    "returning_fixed_vulnerabilities": rep.returning_fixed_vulnerabilities,
                    "newly_introduced_vulnerabilities": rep.newly_introduced_vulnerabilities,
                    "alerts_generated": rep.alerts_generated,
                }
            ), 200
        except RegressionGuardError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.route("/api/audit", methods=["GET"])
    def audit() -> Any:
        return jsonify(
            {
                "audit_logs": get_audit_logs(database_url=database_url),
                "backups": list_backups(database_url=database_url),
            }
        ), 200

    @app.route("/api/rollback", methods=["POST"])
    def rollback() -> Any:
        payload = request.get_json(silent=True) or {}
        backup_uid = str(payload.get("backup_uid", "")).strip()
        try:
            res = rollback_configuration(backup_uid, database_url=database_url)
            return jsonify(res), 200
        except RollbackError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.route("/api/reports", methods=["GET"])
    def reports() -> Any:
        return jsonify({"reports": get_all_reports(database_url=database_url)}), 200

    @app.route("/api/reports/<int:scan_id>/pdf", methods=["POST"])
    def generate_report(scan_id: int) -> Any:
        try:
            pdf_path = generate_pdf_report(scan_id, database_url=database_url)
            return jsonify(
                {
                    "scan_id": scan_id,
                    "file_name": pdf_path.name,
                    "report_path": str(pdf_path),
                }
            ), 201
        except ReportGenerationError as exc:
            return jsonify({"error": str(exc)}), 404

    @app.route("/api/reports/<int:report_id>/download", methods=["GET"])
    def download_report(report_id: int) -> Any:
        all_reps = get_all_reports(database_url=database_url)
        rep = next((r for r in all_reps if r["id"] == report_id), None)
        if rep is None or not Path(rep["report_path"]).exists():
            return jsonify({"error": "Report file not found"}), 404
        return send_file(rep["report_path"], as_attachment=True)

    return app


if __name__ == "__main__":
    app = create_api_app()
    host = os.getenv("SENTINEL_API_HOST", "127.0.0.1")
    port = int(os.getenv("SENTINEL_API_PORT", "8501"))
    app.run(host=host, port=port, debug=False)
