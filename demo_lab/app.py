"""Application B: Isolated Low-Security Local Demonstration Lab (Flask).

Provides a strictly local, configurable test target with synthetic data only,
plus an allowlisted, token-protected local remediation API for Phase 4+.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any

from flask import Flask, jsonify, make_response, request

from config import ALLOWLISTED_ACTIONS, REMEDIATION_API_TOKEN

DEFAULT_LAB_CONFIG: dict[str, Any] = {
    "missing_security_headers": True,
    "insecure_cookie_flags": True,
    "expose_config_endpoint": True,
    # Granular per-control flags managed by the allowlisted remediation API
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

FORBIDDEN_PAYLOAD_KEYS = frozenset({"command", "shell", "code", "script", "python", "file_path", "path"})


def create_demo_app(initial_config: dict[str, Any] | None = None) -> Flask:
    """Create and configure the isolated local Low-Security Flask demonstration lab."""
    app = Flask(__name__)
    lab_config: dict[str, Any] = {**DEFAULT_LAB_CONFIG}
    if initial_config:
        lab_config.update(initial_config)

    app.config["LAB_SETTINGS"] = lab_config
    app.config["LAB_BACKUPS"] = {}
    app.config["LAB_AUDIT"] = []
    app.config["APP_IDENTITY"] = "SENTINEL_LOW_SECURITY_DEMO_LAB"

    def _record_audit(event: str, action_id: str | None, status: str, detail: str) -> None:
        app.config["LAB_AUDIT"].append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": event,
                "action_id": action_id,
                "status": status,
                "detail": detail,
            }
        )

    def _is_authorized_remediation_request() -> bool:
        remote = (request.remote_addr or "").strip()
        if remote not in {"127.0.0.1", "::1", "localhost", ""}:
            return False
        token = request.headers.get("X-Sentinel-Approval-Token", "")
        return bool(token) and token == REMEDIATION_API_TOKEN

    @app.after_request
    def apply_configured_headers(response: Any) -> Any:
        settings = app.config["LAB_SETTINGS"]
        bulk_hardened = not settings.get("missing_security_headers", True)

        if bulk_hardened or settings.get("x_content_type_options_enabled", False):
            response.headers["X-Content-Type-Options"] = "nosniff"
        if bulk_hardened or settings.get("x_frame_options_enabled", False):
            response.headers["X-Frame-Options"] = "DENY"
        if bulk_hardened or settings.get("referrer_policy_enabled", False):
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if bulk_hardened or settings.get("csp_enabled", False):
            response.headers["Content-Security-Policy"] = "default-src 'self'"
        if bulk_hardened or settings.get("permissions_policy_enabled", False):
            response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if bulk_hardened:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.route("/", methods=["GET"])
    def index() -> Any:
        settings = app.config["LAB_SETTINGS"]
        return (
            jsonify(
                {
                    "service": "SENTINEL AI Local Demonstration Lab (Application B)",
                    "app_identity": app.config["APP_IDENTITY"],
                    "scope": "localhost-only synthetic test environment",
                    "synthetic": True,
                    "active_lab_settings": settings,
                    "endpoints": [
                        "/",
                        "/health",
                        "/session-test",
                        "/config.json",
                        "/lab/settings",
                        "/api/remediation/status",
                    ],
                }
            ),
            200,
        )

    @app.route("/health", methods=["GET"])
    def health() -> Any:
        return jsonify({"status": "ok", "environment": "local_demo_lab"}), 200

    @app.route("/session-test", methods=["GET"])
    def session_test() -> Any:
        settings = app.config["LAB_SETTINGS"]
        bulk_insecure = bool(settings.get("insecure_cookie_flags", True))

        httponly = (not bulk_insecure) or bool(settings.get("cookie_httponly_enabled", False))
        secure = (not bulk_insecure) or bool(settings.get("cookie_secure_enabled", False))
        samesite = "Lax" if ((not bulk_insecure) or bool(settings.get("cookie_samesite_enabled", False))) else None

        resp = make_response(
            jsonify(
                {
                    "message": "Synthetic test session cookie issued.",
                    "httponly": httponly,
                    "secure": secure,
                    "samesite": samesite,
                }
            ),
            200,
        )
        resp.set_cookie(
            key="sentinel_demo_session",
            value="synthetic-session-token-0001",
            httponly=httponly,
            secure=secure,
            samesite=samesite,
        )
        return resp

    @app.route("/config.json", methods=["GET"])
    def exposed_config() -> Any:
        settings = app.config["LAB_SETTINGS"]
        if not settings.get("expose_config_endpoint", True):
            return jsonify({"error": "Configuration endpoint disabled"}), 404

        return (
            jsonify(
                {
                    "warning": "SYNTHETIC_TEST_DATA_ONLY",
                    "app_name": "DemoLabApp",
                    "environment": "local-test",
                    "synthetic_api_key": "SYNTHETIC_DEMO_KEY_NOT_REAL_0000",
                    "debug_mode": True,
                    "allowed_hosts": ["127.0.0.1", "localhost"],
                }
            ),
            200,
        )

    @app.route("/lab/settings", methods=["GET", "POST"])
    def manage_lab_settings() -> Any:
        settings = app.config["LAB_SETTINGS"]
        if request.method == "POST":
            payload = request.get_json(silent=True) or {}
            for key in DEFAULT_LAB_CONFIG:
                if key in payload and isinstance(payload[key], bool):
                    settings[key] = payload[key]
        return jsonify({"lab_settings": settings}), 200

    # --- Allowlisted, Token-Protected Local Remediation API (Unique Feature 4) ---

    @app.route("/api/remediation/status", methods=["GET"])
    def remediation_status() -> Any:
        if not _is_authorized_remediation_request():
            return jsonify({"error": "Unauthorized: invalid or missing lab approval token"}), 401
        return (
            jsonify(
                {
                    "app_identity": app.config["APP_IDENTITY"],
                    "allowlisted_actions": sorted(ALLOWLISTED_ACTIONS.keys()),
                    "lab_settings": app.config["LAB_SETTINGS"],
                    "backup_count": len(app.config["LAB_BACKUPS"]),
                }
            ),
            200,
        )

    @app.route("/api/remediation/audit", methods=["GET"])
    def remediation_audit() -> Any:
        if not _is_authorized_remediation_request():
            return jsonify({"error": "Unauthorized: invalid or missing lab approval token"}), 401
        return jsonify({"audit_trail": list(app.config["LAB_AUDIT"])}), 200

    @app.route("/api/remediation/preview", methods=["POST"])
    def remediation_preview() -> Any:
        if not _is_authorized_remediation_request():
            return jsonify({"error": "Unauthorized: invalid or missing lab approval token"}), 401
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Invalid JSON schema"}), 400
        if FORBIDDEN_PAYLOAD_KEYS.intersection(payload.keys()):
            return jsonify({"error": "Rejected: arbitrary code/path/command fields are forbidden"}), 400

        action_id = str(payload.get("action_id", "")).strip().upper()
        if action_id not in ACTION_TO_SETTING:
            return jsonify({"error": f"Rejected unknown action_id: {action_id}"}), 400

        setting_key, target_val = ACTION_TO_SETTING[action_id]
        current_val = bool(app.config["LAB_SETTINGS"].get(setting_key, False))
        return (
            jsonify(
                {
                    "action_id": action_id,
                    "setting_key": setting_key,
                    "current_value": current_val,
                    "proposed_value": target_val,
                    "app_identity": app.config["APP_IDENTITY"],
                }
            ),
            200,
        )

    @app.route("/api/remediation/apply", methods=["POST"])
    def remediation_apply() -> Any:
        if not _is_authorized_remediation_request():
            return jsonify({"error": "Unauthorized: invalid or missing lab approval token"}), 401

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Invalid JSON schema"}), 400
        if FORBIDDEN_PAYLOAD_KEYS.intersection(payload.keys()):
            _record_audit("APPLY_REJECTED", payload.get("action_id"), "rejected", "Forbidden payload keys")
            return jsonify({"error": "Rejected: arbitrary code/path/command fields are forbidden"}), 400

        if payload.get("developer_approved") is not True:
            _record_audit("APPLY_REJECTED", payload.get("action_id"), "rejected", "Missing developer approval")
            return jsonify({"error": "Rejected: explicit developer_approved=true is required"}), 403

        if payload.get("target_identity") not in {None, app.config["APP_IDENTITY"]}:
            return jsonify({"error": "Rejected: target identity mismatch"}), 403

        action_id = str(payload.get("action_id", "")).strip().upper()
        if action_id not in ACTION_TO_SETTING:
            _record_audit("APPLY_REJECTED", action_id, "rejected", "Unknown action_id")
            return jsonify({"error": f"Rejected unknown action_id: {action_id}"}), 400

        setting_key, target_val = ACTION_TO_SETTING[action_id]
        settings = app.config["LAB_SETTINGS"]
        current_val = bool(settings.get(setting_key, False))
        if current_val == target_val:
            return (
                jsonify(
                    {
                        "error": f"Conflict: setting '{setting_key}' is already {target_val}",
                        "action_id": action_id,
                    }
                ),
                409,
            )

        backup_uid = str(payload.get("backup_uid") or f"bkp-{uuid.uuid4().hex[:12]}")
        app.config["LAB_BACKUPS"][backup_uid] = {
            "backup_uid": backup_uid,
            "action_id": action_id,
            "setting_key": setting_key,
            "original_value": current_val,
            "applied_value": target_val,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        settings[setting_key] = target_val
        _record_audit(
            "REMEDIATION_APPLIED",
            action_id,
            "applied",
            f"Changed {setting_key} from {current_val} to {target_val} (backup={backup_uid})",
        )
        return (
            jsonify(
                {
                    "status": "applied",
                    "action_id": action_id,
                    "setting_key": setting_key,
                    "original_value": current_val,
                    "applied_value": target_val,
                    "backup_uid": backup_uid,
                }
            ),
            200,
        )

    @app.route("/api/remediation/rollback", methods=["POST"])
    def remediation_rollback() -> Any:
        if not _is_authorized_remediation_request():
            return jsonify({"error": "Unauthorized: invalid or missing lab approval token"}), 401

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Invalid JSON schema"}), 400

        backup_uid = str(payload.get("backup_uid", "")).strip()
        backup = app.config["LAB_BACKUPS"].get(backup_uid)
        if not backup:
            return jsonify({"error": f"Backup '{backup_uid}' not found"}), 404

        setting_key = backup["setting_key"]
        original_val = backup["original_value"]
        app.config["LAB_SETTINGS"][setting_key] = original_val
        _record_audit(
            "REMEDIATION_ROLLED_BACK",
            backup["action_id"],
            "rolled_back",
            f"Restored {setting_key} to {original_val} from {backup_uid}",
        )
        return (
            jsonify(
                {
                    "status": "rolled_back",
                    "backup_uid": backup_uid,
                    "setting_key": setting_key,
                    "restored_value": original_val,
                    "current_value": app.config["LAB_SETTINGS"][setting_key],
                }
            ),
            200,
        )

    return app


app = create_demo_app()


if __name__ == "__main__":
    host = os.getenv("SENTINEL_DEMO_HOST", "127.0.0.1")
    port = int(os.getenv("SENTINEL_DEMO_PORT", "5050"))
    allowed_bind = {"127.0.0.1", "localhost"}
    if os.getenv("SENTINEL_DOCKER_MODE") == "1":
        allowed_bind.add("0.0.0.0")
    if host not in allowed_bind:
        raise ValueError("Demo lab is restricted to local loopback interfaces only.")
    app.run(host=host, port=port, debug=False)
