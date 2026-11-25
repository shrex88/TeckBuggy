"""Integration tests for the SENTINEL AI REST API bridge (`api_server.py`)."""

from __future__ import annotations

from pathlib import Path

from flask import Flask, Response

from api_server import create_api_app
from database import init_db, reset_engine


def _start_dummy_target() -> Flask:
    """Create a small Flask WSGI app for deterministic scan tests."""
    target = Flask(__name__)

    @target.route("/")
    def index() -> Response:
        resp = Response("ok", status=200)
        resp.set_cookie("session", "abc123")
        return resp

    return target


def test_api_health_and_dashboard(tmp_path: Path) -> None:
    reset_engine()
    db_url = f"sqlite:///{tmp_path / 'api_test.db'}"
    init_db(db_url)
    app = create_api_app(db_url)
    client = app.test_client()

    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.get_json()["status"] == "ok"

    dash = client.get("/api/dashboard")
    assert dash.status_code == 200
    payload = dash.get_json()
    assert payload["has_scans"] is False
    assert payload["total_scans"] == 0


def test_api_scan_validation_rejects_external_host(tmp_path: Path) -> None:
    reset_engine()
    db_url = f"sqlite:///{tmp_path / 'api_validation.db'}"
    app = create_api_app(db_url)
    client = app.test_client()

    res = client.post("/api/scans", json={"target_url": "https://example.com"})
    assert res.status_code == 400
    assert "error" in res.get_json()


def test_api_end_to_end_scan_proposal_confidence_and_pdf(tmp_path: Path, monkeypatch) -> None:
    import threading
    from werkzeug.serving import make_server

    reset_engine()
    db_url = f"sqlite:///{tmp_path / 'api_e2e.db'}"
    app = create_api_app(db_url)
    client = app.test_client()

    dummy_app = _start_dummy_target()
    server = make_server("127.0.0.1", 0, dummy_app)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        # Disable Gemini network calls during deterministic test
        monkeypatch.setenv("GEMINI_API_KEY", "")

        scan_res = client.post("/api/scans", json={"target_url": f"http://127.0.0.1:{port}/"})
        assert scan_res.status_code == 201
        scan_data = scan_res.get_json()
        scan_id = scan_data["scan_id"]
        assert scan_data["total_findings"] >= 1

        dash_res = client.get("/api/dashboard")
        assert dash_res.status_code == 200
        assert dash_res.get_json()["has_scans"] is True

        findings_res = client.get("/api/findings")
        assert findings_res.status_code == 200
        findings = findings_res.get_json()["findings"]
        assert len(findings) >= 1
        finding_id = findings[0]["id"]

        prop_res = client.post(
            "/api/proposals/generate",
            json={"finding_id": finding_id, "framework": "Flask"},
        )
        assert prop_res.status_code == 201
        proposal_id = prop_res.get_json()["id"]

        eval_res = client.post(f"/api/proposals/{proposal_id}/evaluate", json={})
        assert eval_res.status_code == 200
        eval_data = eval_res.get_json()
        assert "confidence_score" in eval_data

        pdf_res = client.post(f"/api/reports/{scan_id}/pdf", json={})
        assert pdf_res.status_code == 201
        assert Path(pdf_res.get_json()["report_path"]).exists()

        reports_res = client.get("/api/reports")
        assert reports_res.status_code == 200
        report_id = reports_res.get_json()["reports"][0]["id"]

        dl_res = client.get(f"/api/reports/{report_id}/download")
        assert dl_res.status_code == 200
        assert dl_res.data[:4] == b"%PDF"
    finally:
        server.shutdown()
