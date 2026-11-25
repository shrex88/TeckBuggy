"""Central configuration for SENTINEL AI."""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR: Path = Path(__file__).resolve().parent
DATA_DIR: Path = BASE_DIR / "data"
ASSETS_DIR: Path = BASE_DIR / "assets"
REPORTS_DIR: Path = DATA_DIR / "reports"

APP_NAME: str = "SENTINEL AI"
APP_TAGLINE: str = "Detect. Prioritise. Protect."
APP_SUBTITLE: str = "AI-Powered Web Application Security Intelligence Platform"
APP_VERSION: str = "1.0.0"

DATABASE_PATH: Path = DATA_DIR / "sentinel_ai.db"
DATABASE_URL: str = os.getenv(
    "SENTINEL_DATABASE_URL",
    f"sqlite:///{DATABASE_PATH.as_posix()}",
)

REMEDIATION_API_TOKEN: str = os.getenv(
    "SENTINEL_REMEDIATION_TOKEN",
    "sentinel-local-lab-approval-token",
)

ALLOWLISTED_ACTIONS: dict[str, dict[str, str]] = {
    "ENABLE_CSP": {
        "rule_id": "HDR-001",
        "setting": "csp_enabled",
        "description": "Enable Content-Security-Policy header on responses.",
    },
    "ENABLE_FRAME_PROTECTION": {
        "rule_id": "HDR-003",
        "setting": "x_frame_options_enabled",
        "description": "Enable X-Frame-Options: DENY clickjacking protection.",
    },
    "ENABLE_NOSNIFF": {
        "rule_id": "HDR-004",
        "setting": "x_content_type_options_enabled",
        "description": "Enable X-Content-Type-Options: nosniff header.",
    },
    "ENABLE_REFERRER_POLICY": {
        "rule_id": "HDR-005",
        "setting": "referrer_policy_enabled",
        "description": "Enable Referrer-Policy: strict-origin-when-cross-origin.",
    },
    "ENABLE_PERMISSIONS_POLICY": {
        "rule_id": "HDR-006",
        "setting": "permissions_policy_enabled",
        "description": "Enable restrictive Permissions-Policy header.",
    },
    "ENABLE_HTTPONLY_COOKIE": {
        "rule_id": "COOKIE-001",
        "setting": "cookie_httponly_enabled",
        "description": "Enforce HttpOnly flag on synthetic session cookies.",
    },
    "ENABLE_SECURE_COOKIE": {
        "rule_id": "COOKIE-002",
        "setting": "cookie_secure_enabled",
        "description": "Enforce Secure flag on synthetic session cookies.",
    },
    "CONFIGURE_SAMESITE": {
        "rule_id": "COOKIE-003",
        "setting": "cookie_samesite_enabled",
        "description": "Enforce SameSite=Lax on synthetic session cookies.",
    },
    "DISABLE_SYNTHETIC_CONFIG_EXPOSURE": {
        "rule_id": "FILE-002",
        "setting": "expose_config_endpoint",
        "description": "Disable public /config.json synthetic configuration endpoint.",
    },
    "ENABLE_TLS_TEST_CONFIGURATION": {
        "rule_id": "TLS-000",
        "setting": "tls_test_metadata_enabled",
        "description": "Enable local TLS test configuration flag.",
    },
}

# Strict local target allowlist & HTTP safety limits (Phase 2)
ALLOWED_LOCAL_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1"})
ALLOWED_DOCKER_HOSTS: frozenset[str] = frozenset(
    h.strip().lower()
    for h in os.getenv("SENTINEL_ALLOWED_DOCKER_HOSTS", "demo-lab,sentinel-demo-lab").split(",")
    if h.strip()
)
DEFAULT_REQUEST_TIMEOUT: float = 5.0
MAX_REDIRECTS: int = 3
MAX_RESPONSE_BYTES: int = 512 * 1024  # 512 KB cap for defensive inspection
MAX_REQUESTS_PER_SCAN: int = 20

APPLICATION_PROFILES: dict[str, dict[str, object]] = {
    "Fintech / Payment Application": {
        "data_sensitivity": 95.0,
        "assumption": "Configured assumption: high-sensitivity financial/payment context (not proof of actual stored data).",
    },
    "Customer Portal": {
        "data_sensitivity": 75.0,
        "assumption": "Configured assumption: authenticated user/PII portal context (not proof of actual stored data).",
    },
    "General Web Application": {
        "data_sensitivity": 50.0,
        "assumption": "Configured assumption: standard public/internal web application context.",
    },
}

NAV_SECTIONS: list[dict[str, str]] = [
    {"id": "overview", "label": "Overview", "icon": "◈", "phase": "Core"},
    {"id": "new_scan", "label": "New Security Scan", "icon": "⌖", "phase": "Scanner"},
    {"id": "security_benchmark", "label": "Security Benchmark", "icon": "⚖", "phase": "Benchmark"},
    {"id": "vulnerabilities", "label": "Vulnerabilities", "icon": "⚠", "phase": "Findings"},
    {"id": "ai_intelligence", "label": "AI Risk Intelligence", "icon": "✦", "phase": "Risk"},
    {"id": "ai_copilot", "label": "AI Remediation Copilot", "icon": "✧", "phase": "Gemini"},
    {"id": "digital_twin", "label": "Security Digital Twin", "icon": "❖", "phase": "Twin"},
    {"id": "remediation_confidence", "label": "Remediation Confidence", "icon": "◎", "phase": "Confidence"},
    {"id": "approval_centre", "label": "Developer Approval Centre", "icon": "✔", "phase": "Governance"},
    {"id": "remediation_history", "label": "Remediation History", "icon": "↺", "phase": "Audit"},
    {"id": "security_proof", "label": "Security Proof", "icon": "✓", "phase": "Verify"},
    {"id": "regression_guard", "label": "Security Regression Guard", "icon": "⚑", "phase": "Guard"},
    {"id": "learning_mode", "label": "Security Learning Mode", "icon": "★", "phase": "Learn"},
    {"id": "scan_history", "label": "Scan History", "icon": "◷", "phase": "Ledger"},
    {"id": "reports", "label": "Reports", "icon": "▤", "phase": "PDF"},
    {"id": "settings", "label": "Settings", "icon": "⚙", "phase": "Config"},
]

SEVERITY_COLORS: dict[str, str] = {
    "Critical": "#FF3B5C",
    "High": "#FF8A00",
    "Medium": "#F5C542",
    "Low": "#00F0FF",
    "Info": "#8B5CF6",
}

OWASP_CATEGORIES: list[str] = [
    "A01:2025 - Broken Access Control",
    "A02:2025 - Security Misconfiguration",
    "A03:2025 - Software Supply Chain Failures",
    "A04:2025 - Cryptographic Failures",
    "A05:2025 - Injection",
    "A06:2025 - Insecure Design",
    "A07:2025 - Authentication Failures",
    "A08:2025 - Software or Data Integrity Failures",
    "A09:2025 - Security Logging and Alerting Failures",
    "A10:2025 - Mishandling of Exceptional Conditions",
]
