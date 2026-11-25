"""UI components package for SENTINEL AI."""

from components.dashboard import (
    render_coming_soon_page,
    render_overview_dashboard,
    render_settings_page,
)
from components.enterprise_views import (
    render_ai_copilot_page,
    render_approval_centre_page,
    render_regression_guard_page,
    render_remediation_history_page,
    render_security_benchmark_page,
)
from components.learning_views import render_learning_mode_page
from components.phase2_views import (
    render_ai_intelligence_page,
    render_new_scan_page,
    render_scan_history_page,
    render_vulnerabilities_page,
)
from components.phase3_views import (
    render_remediation_centre_page,
    render_reports_page,
    render_security_proof_page,
)
from components.sidebar import render_sidebar
from components.twin_confidence_views import render_remediation_confidence_page

__all__ = [
    "render_ai_copilot_page",
    "render_ai_intelligence_page",
    "render_approval_centre_page",
    "render_coming_soon_page",
    "render_learning_mode_page",
    "render_new_scan_page",
    "render_overview_dashboard",
    "render_regression_guard_page",
    "render_remediation_centre_page",
    "render_remediation_confidence_page",
    "render_remediation_history_page",
    "render_reports_page",
    "render_scan_history_page",
    "render_security_benchmark_page",
    "render_security_proof_page",
    "render_settings_page",
    "render_sidebar",
    "render_vulnerabilities_page",
]
