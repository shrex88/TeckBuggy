"""Strict authorised local target validation & SSRF prevention."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Any, Callable, Iterable
from urllib.parse import urljoin, urlparse

import requests

from config import (
    ALLOW_PUBLIC_TARGETS,
    ALLOWED_DOCKER_HOSTS,
    ALLOWED_LOCAL_HOSTS,
    DEFAULT_REQUEST_TIMEOUT,
    MAX_REDIRECTS,
    MAX_RESPONSE_BYTES,
)

ResolverFn = Callable[[str, int], list[tuple[Any, ...]]]


class TargetValidationError(ValueError):
    """Raised when a scan target or redirect violates local-only security policy."""


@dataclass(frozen=True)
class ValidatedTarget:
    """Represents a validated, authorised local scan target."""

    normalized_url: str
    scheme: str
    hostname: str
    port: int
    resolved_ip: str
    base_path: str


def _is_loopback_ip(ip_str: str) -> bool:
    """Return True if the IP address is strictly a loopback address."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_loopback
    except ValueError:
        return False


def _is_private_docker_ip(ip_str: str) -> bool:
    """Return True if the IP is an RFC1918/link-local-excluded Docker bridge address."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        # Explicitly block cloud metadata 169.254.0.0/16 and public IPs
        if ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
            return False
        return ip_obj.is_private and not ip_obj.is_global
    except ValueError:
        return False


def validate_target_url(
    raw_url: str,
    *,
    allowed_docker_hosts: Iterable[str] = ALLOWED_DOCKER_HOSTS,
    allow_public: bool | None = None,
    resolver: ResolverFn | None = None,
) -> ValidatedTarget:
    """Validate that a target URL is an authorised local, Docker service, or verified public web target.

    Prevents internal cloud metadata (169.254.169.254), non-HTTP schemes,
    embedded credentials, and DNS rebinding to internal metadata.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise TargetValidationError("Target URL must be a non-empty string.")

    cleaned = raw_url.strip()
    if "://" not in cleaned and cleaned.lower().startswith(("localhost", "127.0.0.1", "[::1]")):
        cleaned = f"http://{cleaned}"
    parsed = urlparse(cleaned)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise TargetValidationError(
            f"Unsupported URL scheme '{parsed.scheme}'. Only http:// and https:// are permitted."
        )

    if parsed.username or parsed.password:
        raise TargetValidationError("Embedded credentials in target URL are not permitted.")

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise TargetValidationError("Target URL must include a valid hostname.")

    docker_allowlist = {h.strip().lower() for h in allowed_docker_hosts if h.strip()}
    is_standard_local = hostname in ALLOWED_LOCAL_HOSTS
    is_docker_allowed = hostname in docker_allowlist
    can_allow_public = ALLOW_PUBLIC_TARGETS if allow_public is None else allow_public

    if not (is_standard_local or is_docker_allowed or can_allow_public):
        raise TargetValidationError(
            f"Target host '{hostname}' is not authorised. Only localhost, 127.0.0.1, ::1, "
            "and explicitly allowlisted local Docker test services are allowed."
        )

    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise TargetValidationError(f"Invalid port in target URL: {exc}") from exc

    if port < 1 or port > 65535:
        raise TargetValidationError(f"Port {port} is out of valid range (1-65535).")

    resolve_fn = resolver or socket.getaddrinfo
    try:
        addr_info = resolve_fn(hostname, port)
    except OSError as exc:
        raise TargetValidationError(
            f"DNS resolution failed for host '{hostname}': {exc}"
        ) from exc

    resolved_ips: list[str] = []
    for entry in addr_info:
        sockaddr = entry[4]
        if sockaddr:
            resolved_ips.append(str(sockaddr[0]).split("%")[0])

    if not resolved_ips:
        raise TargetValidationError(f"No IP addresses resolved for '{hostname}'.")

    # Anti-SSRF & cloud metadata protection: always block link-local (169.254.*)
    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
                raise TargetValidationError(
                    f"Forbidden address '{ip_str}' (link-local/metadata/multicast is blocked)."
                )
        except ValueError:
            pass

        if is_standard_local:
            if not (_is_loopback_ip(ip_str) or _is_private_docker_ip(ip_str)):
                raise TargetValidationError(
                    f"DNS rebinding blocked: '{hostname}' resolved to non-loopback IP '{ip_str}'."
                )
        elif is_docker_allowed:
            if not (_is_loopback_ip(ip_str) or _is_private_docker_ip(ip_str)):
                raise TargetValidationError(
                    f"DNS rebinding blocked: Docker host '{hostname}' resolved to non-local IP '{ip_str}'."
                )

    base_path = parsed.path or "/"
    host_fmt = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    port_suffix = "" if port == default_port else f":{port}"
    normalized = f"{parsed.scheme.lower()}://{host_fmt}{port_suffix}{base_path}"
    if parsed.query:
        normalized = f"{normalized}?{parsed.query}"

    return ValidatedTarget(
        normalized_url=normalized,
        scheme=parsed.scheme.lower(),
        hostname=hostname,
        port=port,
        resolved_ip=resolved_ips[0],
        base_path=base_path,
    )


def safe_fetch(
    url: str,
    *,
    method: str = "GET",
    timeout: float = DEFAULT_REQUEST_TIMEOUT,
    max_redirects: int = MAX_REDIRECTS,
    max_bytes: int = MAX_RESPONSE_BYTES,
    session: requests.Session | None = None,
    allowed_docker_hosts: Iterable[str] = ALLOWED_DOCKER_HOSTS,
    allow_public: bool | None = None,
    resolver: ResolverFn | None = None,
) -> requests.Response:
    """Perform an SSRF-safe HTTP request with redirect validation, timeouts, and size caps."""
    current_url = url
    http_session = session or requests.Session()

    for hop in range(max_redirects + 1):
        validated = validate_target_url(
            current_url,
            allowed_docker_hosts=allowed_docker_hosts,
            allow_public=allow_public,
            resolver=resolver,
        )
        try:
            resp = http_session.request(
                method=method.upper(),
                url=validated.normalized_url,
                timeout=timeout,
                allow_redirects=False,
                stream=True,
            )
        except requests.exceptions.SSLError:
            if validated.hostname in ALLOWED_LOCAL_HOSTS and validated.scheme == "https":
                resp = http_session.request(
                    method=method.upper(),
                    url=validated.normalized_url,
                    timeout=timeout,
                    allow_redirects=False,
                    stream=True,
                    verify=False,
                )
            else:
                raise

        # Read up to max_bytes safely
        chunks: list[bytes] = []
        total_read = 0
        for chunk in resp.iter_content(chunk_size=8192):
            if not chunk:
                continue
            remaining = max_bytes - total_read
            if remaining <= 0:
                break
            chunks.append(chunk[:remaining])
            total_read += len(chunks[-1])
            if total_read >= max_bytes:
                break
        resp._content = b"".join(chunks)

        if resp.is_redirect or resp.is_permanent_redirect:
            location = resp.headers.get("Location")
            if not location:
                return resp
            if hop >= max_redirects:
                raise TargetValidationError(
                    f"Maximum redirect limit ({max_redirects}) exceeded."
                )
            current_url = urljoin(validated.normalized_url, location)
            # Validate redirect target immediately before next hop
            validate_target_url(
                current_url,
                allowed_docker_hosts=allowed_docker_hosts,
                allow_public=allow_public,
                resolver=resolver,
            )
            continue

        return resp

    raise TargetValidationError("Redirect loop aborted.")
