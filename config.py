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

DEMO_LAB_HOST: str = os.getenv("SENTINEL_DEMO_HOST", "127.0.0.1")
DEMO_LAB_PORT: int = int(os.getenv("SENTINEL_DEMO_PORT", "5050"))

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
    {"id": "overview", "label": "Overview", "icon": "◈", "phase": "Phase 1"},
    {"id": "new_scan", "label": "New Security Scan", "icon": "⌖", "phase": "Phase 2"},
    {"id": "vulnerabilities", "label": "Vulnerabilities", "icon": "⚠", "phase": "Phase 2"},
    {"id": "ai_intelligence", "label": "AI Risk Intelligence", "icon": "✦", "phase": "Phase 3"},
    {"id": "remediation", "label": "Remediation Centre", "icon": "⚒", "phase": "Phase 3"},
    {"id": "security_proof", "label": "Security Proof", "icon": "✓", "phase": "Phase 3"},
    {"id": "scan_history", "label": "Scan History", "icon": "◷", "phase": "Phase 2"},
    {"id": "reports", "label": "Reports", "icon": "▤", "phase": "Phase 3"},
    {"id": "settings", "label": "Settings", "icon": "⚙", "phase": "Phase 1"},
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
