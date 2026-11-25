"""Report generation package for SENTINEL AI (Phase 3)."""

from reporting.pdf_generator import ReportGenerationError, generate_pdf_report

__all__ = [
    "ReportGenerationError",
    "generate_pdf_report",
]
