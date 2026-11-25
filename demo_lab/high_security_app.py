"""Application A: High-Security Local Reference Application (Read-Only).

Demonstrates properly configured security controls on 127.0.0.1:5051 so SENTINEL AI
can benchmark secure vs. insecure applications without false positives.
Does NOT expose any remediation or configuration-mutation endpoints.
"""

from __future__ import annotations

import os
from typing import Any

from flask import Flask, jsonify, make_response


def create_high_security_app() -> Flask:
    """Create the read-only hardened local Flask reference application."""
    app = Flask(__name__)

    @app.after_request
    def apply_hardened_headers(response: Any) -> Any:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response

    @app.route("/", methods=["GET"])
    def index() -> Any:
        return (
            jsonify(
                {
                    "service": "SENTINEL AI High-Security Reference App (Application A)",
                    "role": "read_only_benchmark_target",
                    "remediation_supported": False,
                    "synthetic": True,
                }
            ),
            200,
        )

    @app.route("/health", methods=["GET"])
    def health() -> Any:
        return jsonify({"status": "ok", "environment": "high_security_reference"}), 200

    @app.route("/session-test", methods=["GET"])
    def session_test() -> Any:
        resp = make_response(
            jsonify({"message": "Hardened synthetic session cookie issued."}),
            200,
        )
        resp.set_cookie(
            key="sentinel_secure_session",
            value="synthetic-hardened-token-0001",
            httponly=True,
            secure=True,
            samesite="Lax",
        )
        return resp

    return app


app = create_high_security_app()


if __name__ == "__main__":
    host = os.getenv("SENTINEL_HIGH_SEC_HOST", "127.0.0.1")
    port = int(os.getenv("SENTINEL_HIGH_SEC_PORT", "5051"))
    allowed_bind = {"127.0.0.1", "localhost"}
    if os.getenv("SENTINEL_DOCKER_MODE") == "1":
        allowed_bind.add("0.0.0.0")
    if host not in allowed_bind:
        raise ValueError("High-security reference app is restricted to local loopback interfaces.")
    app.run(host=host, port=port, debug=False)
