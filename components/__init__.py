"""UI components package for SENTINEL AI."""

from components.dashboard import (
    render_coming_soon_page,
    render_overview_dashboard,
    render_settings_page,
)
from components.phase2_views import (
    render_ai_intelligence_page,
    render_new_scan_page,
    render_scan_history_page,
    render_vulnerabilities_page,
)
from components.sidebar import render_sidebar

__all__ = [
    "render_ai_intelligence_page",
    "render_coming_soon_page",
    "render_new_scan_page",
    "render_overview_dashboard",
    "render_scan_history_page",
    "render_settings_page",
    "render_sidebar",
    "render_vulnerabilities_page",
]
