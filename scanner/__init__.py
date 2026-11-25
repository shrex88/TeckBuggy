"""Security scanning engine package for SENTINEL AI (Phase 2)."""

from scanner.cookie_scanner import analyze_set_cookie_headers, scan_cookies
from scanner.exposed_file_scanner import PREDEFINED_EXPOSED_PATHS, scan_exposed_files
from scanner.header_scanner import analyze_headers, scan_headers
from scanner.models import StandardFinding
from scanner.orchestrator import ScanExecutionResult, run_security_scan
from scanner.target_validator import TargetValidationError, ValidatedTarget, validate_target_url
from scanner.tls_scanner import inspect_tls_endpoint, scan_tls

__all__ = [
    "PREDEFINED_EXPOSED_PATHS",
    "ScanExecutionResult",
    "StandardFinding",
    "TargetValidationError",
    "ValidatedTarget",
    "analyze_headers",
    "analyze_set_cookie_headers",
    "inspect_tls_endpoint",
    "run_security_scan",
    "scan_cookies",
    "scan_exposed_files",
    "scan_headers",
    "scan_tls",
    "validate_target_url",
]
