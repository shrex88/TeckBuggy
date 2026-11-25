"""Shared in-test Flask fixtures for SENTINEL AI automated test suite."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from flask import Flask, jsonify, make_response, request

from config import ALLOWLISTED_ACTIONS, REMEDIATION_API_TOKEN

ACTION_TO_SETTING: dict[str, tuple[str, bool]] = {
    "ENABLE_CSP": ("csp_enabled", True),
    "ENABLE_FRAME_PROTECTION": ("x_frame_options_enabled", True),
    "ENABLE_NOSNIFF": ("x_content_type_options_enabled", True),
    "ENABLE_REFERRER_POLICY": ("referrer_policy_enabled", True),
    "ENABLE_PERMISSIONS_POLICY": ("permissions_policy_enabled", True),
    "ENABLE_HTTPONLY_COOKIE": ("cookie_httponly_enabled", True),
    "ENABLE_SECURE_COOKIE": ("cookie_secure_enabled", True),
    "CONFIGURE_SAMESITE": ("cookie_samesite_enabled", True),
    "DISABLE_SYNTHETIC_CONFIG_EXPOSURE": ("expose_config_endpoint", False),
    "ENABLE_TLS_TEST_CONFIGURATION": ("tls_test_metadata_enabled", True),
}

FORBIDDEN_KEYS = frozenset({"command", "shell", "code", "script", "python", "file_path", "path"})


def create_test_high_sec_app() -> Flask:
    """Ephemeral hardened Flask app for unit/integration testing."""
    app = Flask(__name__)

    @app.after_request
    def _headers(resp: Any) -> Any:
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"
        )
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return resp

    @app.route("/", methods=["GET"])
    def _index() -> Any:
        return jsonify({"status": "ok"}), 200

    @app.route("/session-test", methods=["GET"])
    def _sess() -> Any:
        resp = make_response(jsonify({"ok": True}), 200)
        resp.set_cookie("sentinel_secure_session", "tok", httponly=True, secure=True, samesite="Lax")
        return resp

    return app


def create_test_low_sec_app() -> Flask:
    """Ephemeral misconfigured Flask app with remediation API for unit/integration testing."""
    app = Flask(__name__)
    settings: dict[str, Any] = {
        "missing_security_headers": True,
        "insecure_cookie_flags": True,
        "expose_config_endpoint": True,
        "csp_enabled": False,
        "x_frame_options_enabled": False,
        "x_content_type_options_enabled": False,
        "referrer_policy_enabled": False,
        "permissions_policy_enabled": False,
        "cookie_httponly_enabled": False,
        "cookie_secure_enabled": False,
        "cookie_samesite_enabled": False,
        "tls_test_metadata_enabled": False,
    }
    app.config["LAB_SETTINGS"] = settings
    app.config["LAB_BACKUPS"] = {}

    def _auth() -> bool:
        return request.headers.get("X-Sentinel-Approval-Token", "") == REMEDIATION_API_TOKEN

    @app.after_request
    def _headers(resp: Any) -> Any:
        bulk = not settings.get("missing_security_headers", True)
        if bulk or settings.get("x_content_type_options_enabled"):
            resp.headers["X-Content-Type-Options"] = "nosniff"
        if bulk or settings.get("x_frame_options_enabled"):
            resp.headers["X-Frame-Options"] = "DENY"
        if bulk or settings.get("referrer_policy_enabled"):
            resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if bulk or settings.get("csp_enabled"):
            resp.headers["Content-Security-Policy"] = "default-src 'self'"
        if bulk or settings.get("permissions_policy_enabled"):
            resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return resp

    @app.route("/", methods=["GET"])
    def _index() -> Any:
        return jsonify({"service": "test-target"}), 200

    @app.route("/session-test", methods=["GET"])
    def _sess() -> Any:
        bulk_insec = bool(settings.get("insecure_cookie_flags", True))
        httponly = (not bulk_insec) or bool(settings.get("cookie_httponly_enabled"))
        secure = (not bulk_insec) or bool(settings.get("cookie_secure_enabled"))
        samesite = "Lax" if ((not bulk_insec) or bool(settings.get("cookie_samesite_enabled"))) else None
        resp = make_response(jsonify({"ok": True}), 200)
        resp.set_cookie("sentinel_demo_session", "tok", httponly=httponly, secure=secure, samesite=samesite)
        return resp

    @app.route("/config.json", methods=["GET"])
    def _cfg() -> Any:
        if not settings.get("expose_config_endpoint", True):
            return jsonify({"error": "disabled"}), 404
        return jsonify({"warning": "SYNTHETIC_TEST_DATA_ONLY"}), 200

    @app.route("/lab/settings", methods=["POST"])
    def _lab_settings() -> Any:
        payload = request.get_json(silent=True) or {}
        for k in settings:
            if k in payload and isinstance(payload[k], bool):
                settings[k] = payload[k]
        return jsonify({"lab_settings": settings}), 200

    @app.route("/api/remediation/status", methods=["GET"])
    def _status() -> Any:
        if not _auth():
            return jsonify({"error": "Unauthorized"}), 401
        return jsonify({"lab_settings": settings, "allowlisted_actions": sorted(ALLOWLISTED_ACTIONS)}), 200

    @app.route("/api/remediation/apply", methods=["POST"])
    def _apply() -> Any:
        if not _auth():
            return jsonify({"error": "Unauthorized"}), 401
        payload = request.get_json(silent=True) or {}
        if FORBIDDEN_KEYS.intersection(payload.keys()):
            return jsonify({"error": "Forbidden keys"}), 400
        action_id = str(payload.get("action_id", "")).upper()
        if action_id not in ACTION_TO_SETTING:
            return jsonify({"error": "Unknown action"}), 400
        key, val = ACTION_TO_SETTING[action_id]
        bkp = str(payload.get("backup_uid") or f"bkp-{uuid.uuid4().hex[:8]}")
        orig = bool(settings[key])
        app.config["LAB_BACKUPS"][bkp] = {"setting_key": key, "original_value": orig, "created_at": datetime.now(timezone.utc).isoformat()}
        settings[key] = val
        return jsonify({"status": "applied", "setting_key": key, "original_value": orig, "applied_value": val, "backup_uid": bkp}), 200

    @app.route("/api/remediation/rollback", methods=["POST"])
    def _rb() -> Any:
        if not _auth():
            return jsonify({"error": "Unauthorized"}), 401
        bkp = str((request.get_json(silent=True) or {}).get("backup_uid", ""))
        entry = app.config["LAB_BACKUPS"].get(bkp)
        if not entry:
            return jsonify({"error": "Not found"}), 404
        settings[entry["setting_key"]] = entry["original_value"]
        return jsonify({"status": "rolled_back", "restored_value": entry["original_value"]}), 200

    return app
