"""AI Risk Intelligence & OWASP 2025 Mapping package for SENTINEL AI."""

from intelligence.ai_remediation import (
    generate_ai_remediation_proposal,
    validate_gemini_proposal_payload,
)
from intelligence.benchmark import (
    BenchmarkComparison,
    run_security_benchmark,
)
from intelligence.gemini_client import is_gemini_configured
from intelligence.owasp_mapper import (
    OWASP_A02_MISCONFIG,
    OWASP_A04_CRYPTO,
    OWASP_A07_AUTH,
    map_finding_to_owasp,
)
from intelligence.regression_guard import (
    RegressionGuardError,
    RegressionReport,
    evaluate_security_regression,
)
from intelligence.remediation_confidence import (
    ConfidenceAssessment,
    classify_confidence_level,
    evaluate_remediation_proposal,
    list_confidence_outcomes,
    record_confidence_outcome,
)
from intelligence.risk_engine import (
    RiskAssessment,
    assess_finding_risk,
    build_fintech_impact_analysis,
    classify_risk_level,
    compute_overall_security_score,
)
from intelligence.security_proof import (
    SecurityProofError,
    SecurityProofResult,
    compare_scans,
)

__all__ = [
    "BenchmarkComparison",
    "ConfidenceAssessment",
    "OWASP_A02_MISCONFIG",
    "OWASP_A04_CRYPTO",
    "OWASP_A07_AUTH",
    "RegressionGuardError",
    "RegressionReport",
    "RiskAssessment",
    "SecurityProofError",
    "SecurityProofResult",
    "assess_finding_risk",
    "build_fintech_impact_analysis",
    "classify_confidence_level",
    "classify_risk_level",
    "compare_scans",
    "compute_overall_security_score",
    "evaluate_remediation_proposal",
    "evaluate_security_regression",
    "generate_ai_remediation_proposal",
    "is_gemini_configured",
    "list_confidence_outcomes",
    "map_finding_to_owasp",
    "record_confidence_outcome",
    "run_security_benchmark",
    "validate_gemini_proposal_payload",
]
