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
APP_VERSION: str = "0.1.0-phase1"

DATABASE_PATH: Path = DATA_DIR / "sentinel_ai.db"
DATABASE_URL: str = os.getenv(
    "SENTINEL_DATABASE_URL",
    f"sqlite:///{DATABASE_PATH.as_posix()}",
)

DEMO_LAB_HOST: str = os.getenv("SENTINEL_DEMO_HOST", "127.0.0.1")
DEMO_LAB_PORT: int = int(os.getenv("SENTINEL_DEMO_PORT", "5050"))

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
    "A01:2021 - Broken Access Control",
    "A02:2021 - Cryptographic Failures",
    "A03:2021 - Injection",
    "A04:2021 - Insecure Design",
    "A05:2021 - Security Misconfiguration",
    "A06:2021 - Vulnerable and Outdated Components",
    "A07:2021 - Identification and Authentication Failures",
    "A08:2021 - Software and Data Integrity Failures",
    "A09:2021 - Security Logging and Monitoring Failures",
    "A10:2021 - Server-Side Request Forgery",
]
