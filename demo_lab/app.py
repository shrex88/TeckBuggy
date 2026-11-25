"""Isolated Local Demonstration Lab (Flask) for SENTINEL AI.

Provides a strictly local, configurable test target with synthetic data only.
"""

from __future__ import annotations

import os
from typing import Any

from flask import Flask, jsonify, make_response, request


DEFAULT_LAB_CONFIG: dict[str, Any] = {
    "missing_security_headers": True,
    "insecure_cookie_flags": True,
    "expose_config_endpoint": True,
}


def create_demo_app(initial_config: dict[str, Any] | None = None) -> Flask:
    """Create and configure the isolated local Flask demonstration lab."""
    app = Flask(__name__)
    lab_config: dict[str, Any] = {**DEFAULT_LAB_CONFIG}
    if initial_config:
        lab_config.update(initial_config)

    app.config["LAB_SETTINGS"] = lab_config

    @app.after_request
    def apply_configured_headers(response: Any) -> Any:
        settings = app.config["LAB_SETTINGS"]
        if not settings.get("missing_security_headers", True):
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            response.headers["Content-Security-Policy"] = "default-src 'self'"
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.route("/", methods=["GET"])
    def index() -> Any:
        settings = app.config["LAB_SETTINGS"]
        resp = make_response(
            jsonify(
                {
                    "service": "SENTINEL AI Local Demonstration Lab",
                    "scope": "localhost-only synthetic test environment",
                    "synthetic": True,
                    "active_lab_settings": settings,
                    "endpoints": [
                        "/",
                        "/health",
                        "/session-test",
                        "/config.json",
                        "/lab/settings",
                    ],
                }
            ),
            200,
        )
        return resp

    @app.route("/health", methods=["GET"])
    def health() -> Any:
        return jsonify({"status": "ok", "environment": "local_demo_lab"}), 200

    @app.route("/session-test", methods=["GET"])
    def session_test() -> Any:
        settings = app.config["LAB_SETTINGS"]
        insecure_cookies = bool(settings.get("insecure_cookie_flags", True))

        resp = make_response(
            jsonify(
                {
                    "message": "Synthetic test session cookie issued.",
                    "insecure_cookie_flags": insecure_cookies,
                }
            ),
            200,
        )
        resp.set_cookie(
            key="sentinel_demo_session",
            value="synthetic-session-token-0001",
            httponly=not insecure_cookies,
            secure=not insecure_cookies,
            samesite=None if insecure_cookies else "Lax",
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
