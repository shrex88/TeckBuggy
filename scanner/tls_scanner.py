"""Safe TLS & Certificate Inspection Scanner for SENTINEL AI."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from config import DEFAULT_REQUEST_TIMEOUT
from scanner.models import StandardFinding
from scanner.target_validator import ValidatedTarget, validate_target_url

WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}


def _parse_cert_expiry(not_after: str | None) -> datetime | None:
    if not not_after:
        return None
    try:
        dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def inspect_tls_endpoint(
    hostname: str,
    port: int,
    *,
    timeout: float = DEFAULT_REQUEST_TIMEOUT,
) -> list[StandardFinding]:
    """Inspect an authorised local HTTPS endpoint using strict certificate verification."""
    findings: list[StandardFinding] = []
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                protocol = tls_sock.version() or "Unknown"
                cert: dict[str, Any] = tls_sock.getpeercert() or {}

                if protocol in WEAK_TLS_VERSIONS:
                    findings.append(
                        StandardFinding(
                            rule_id="TLS-001",
                            title=f"Deprecated TLS Protocol Negotiated ({protocol})",
                            category="TLS / Transport Security",
                            severity="High",
                            target_path=f"https://{hostname}:{port}",
                            evidence=f"TLS handshake negotiated deprecated protocol {protocol}.",
                            description=(
                                "Legacy SSL/TLS versions (TLS 1.0/1.1) have known cryptographic "
                                "weaknesses and are deprecated."
                            ),
                            remediation_reference="Disable TLS 1.0/1.1 and enforce TLS 1.2 or TLS 1.3.",
                            confidence=98.0,
                            exposure=85.0,
                            exploitability=65.0,
                            metadata={"protocol": protocol},
                        )
                    )

                expiry_dt = _parse_cert_expiry(cert.get("notAfter"))
                if expiry_dt is not None:
                    days_remaining = (expiry_dt - datetime.now(timezone.utc)).days
                    if days_remaining < 0:
                        findings.append(
                            StandardFinding(
                                rule_id="TLS-002",
                                title="Expired TLS Certificate",
                                category="TLS / Transport Security",
                                severity="Critical",
                                target_path=f"https://{hostname}:{port}",
                                evidence=f"Certificate expired on {cert.get('notAfter')}.",
                                description="The server presented an expired X.509 certificate.",
                                remediation_reference="Renew and deploy a valid TLS certificate.",
                                confidence=100.0,
                                exposure=90.0,
                                exploitability=70.0,
                                metadata={"notAfter": cert.get("notAfter")},
                            )
                        )
                    elif days_remaining <= 30:
                        findings.append(
                            StandardFinding(
                                rule_id="TLS-003",
                                title="TLS Certificate Expiring Soon",
                                category="TLS / Transport Security",
                                severity="Medium",
                                target_path=f"https://{hostname}:{port}",
                                evidence=(
                                    f"Certificate expires in {days_remaining} day(s) "
                                    f"({cert.get('notAfter')})."
                                ),
                                description="TLS certificate is nearing expiration.",
                                remediation_reference="Schedule certificate renewal before expiry.",
                                confidence=95.0,
                                exposure=70.0,
                                exploitability=30.0,
                                metadata={"days_remaining": days_remaining},
                            )
                        )

    except ssl.SSLCertVerificationError as exc:
        findings.append(
            StandardFinding(
                rule_id="TLS-004",
                title="Untrusted or Invalid TLS Certificate",
                category="TLS / Transport Security",
                severity="High",
                target_path=f"https://{hostname}:{port}",
                evidence=f"Strict TLS certificate verification failed: {exc}",
                description=(
                    "The HTTPS endpoint presented a certificate that failed trust or hostname "
                    "verification (e.g., self-signed, untrusted CA, or SAN mismatch)."
                ),
                remediation_reference=(
                    "Configure a trusted certificate with matching Subject Alternative Name (SAN)."
                ),
                confidence=98.0,
                exposure=85.0,
                exploitability=60.0,
            )
        )
    except (ssl.SSLError, OSError) as exc:
        findings.append(
            StandardFinding(
                rule_id="TLS-005",
                title="TLS Handshake Inspection Error",
                category="TLS / Transport Security",
                severity="Medium",
                target_path=f"https://{hostname}:{port}",
                evidence=f"Unable to complete TLS handshake: {exc}",
                description="The HTTPS endpoint could not complete a standard TLS handshake.",
                remediation_reference="Verify TLS listener configuration and supported cipher suites.",
                confidence=80.0,
                exposure=70.0,
                exploitability=40.0,
            )
        )

    return findings


def scan_tls(
    target_url: str,
    *,
    validated: ValidatedTarget | None = None,
) -> list[StandardFinding]:
    """Run TLS checks on HTTPS targets, or record unencrypted HTTP transport finding."""
    vt = validated or validate_target_url(target_url)
    if vt.scheme != "https":
        return [
            StandardFinding(
                rule_id="TLS-000",
                title="Unencrypted HTTP Transport (No TLS)",
                category="TLS / Transport Security",
                severity="Medium",
                target_path=vt.base_path,
                evidence=f"Target '{vt.normalized_url}' uses plain http:// without TLS encryption.",
                description=(
                    "Traffic to this local endpoint is transmitted without TLS transport encryption."
                ),
                remediation_reference="Enable HTTPS with TLS 1.2+ for non-loopback or production deployments.",
                confidence=100.0,
                exposure=75.0,
                exploitability=50.0,
            )
        ]

    return inspect_tls_endpoint(vt.hostname, vt.port)
