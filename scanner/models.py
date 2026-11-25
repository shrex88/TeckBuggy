"""Standardised finding data structures for SENTINEL AI scanners."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class StandardFinding:
    """Structured finding returned by every Phase 2 scanning module."""

    rule_id: str
    title: str
    category: str
    severity: str
    target_path: str
    evidence: str
    description: str
    remediation_reference: str
    owasp_mapping: str = ""
    confidence: float = 90.0
    exposure: float = 75.0
    exploitability: float = 55.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize finding into a plain dictionary."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "target_path": self.target_path,
            "evidence": self.evidence,
            "description": self.description,
            "remediation_reference": self.remediation_reference,
            "owasp_mapping": self.owasp_mapping,
            "confidence": self.confidence,
            "exposure": self.exposure,
            "exploitability": self.exploitability,
            "metadata": dict(self.metadata),
        }
