"""Official Google Gen AI SDK client wrapper for SENTINEL AI.

Reads GEMINI_API_KEY from environment / .env only and fails gracefully
when unconfigured or unreachable.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from dotenv import load_dotenv

load_dotenv()

_LAST_GEMINI_STATUS: str = "Not invoked yet"
DEFAULT_GEMINI_MODEL: str = "gemini-2.5-flash"
FALLBACK_GEMINI_MODELS: tuple[str, ...] = (
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
    "gemini-3-flash-preview",
    "gemini-3.1-flash-lite",
)


def _get_secret_or_env(key: str) -> str:
    """Read a config value from environment variables first, then Streamlit secrets."""
    val = (os.getenv(key) or "").strip()
    if val:
        return val
    try:
        import streamlit as st

        secret_val = st.secrets.get(key)
        if secret_val is not None:
            return str(secret_val).strip()
    except Exception:
        pass
    return ""


def _candidate_models(model: str | None = None) -> list[str]:
    """Return deduplicated ordered Gemini model candidates."""
    primary = (model or _get_secret_or_env("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL).strip()
    if primary == "gemini-4-hydrogen":
        primary = DEFAULT_GEMINI_MODEL
    candidates: list[str] = []
    for m in (primary, *FALLBACK_GEMINI_MODELS):
        if m and m not in candidates:
            candidates.append(m)
    return candidates


def is_gemini_configured() -> bool:
    """Return True if a non-empty GEMINI_API_KEY is available in env or secrets."""
    return bool(_get_secret_or_env("GEMINI_API_KEY"))


def get_last_gemini_status() -> str:
    """Return a human-readable status message from the most recent Gemini API call."""
    return _LAST_GEMINI_STATUS


def _extract_json_dict(raw_text: str) -> dict[str, Any] | None:
    """Parse a JSON object directly or from markdown code fences."""
    cleaned = raw_text.strip()
    if not cleaned:
        return None
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    if match:
        try:
            parsed = json.loads(match.group(0))
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return None
    return None


def request_gemini_json(
    prompt: str,
    *,
    model: str | None = None,
) -> dict[str, Any] | None:
    """Send a structured JSON prompt to Gemini via google-genai SDK.

    Tries the configured model first, then safe fallback models on transient
    availability errors, returning None if all fail.
    """
    global _LAST_GEMINI_STATUS

    api_key = _get_secret_or_env("GEMINI_API_KEY")
    if not api_key:
        _LAST_GEMINI_STATUS = "GEMINI_API_KEY not configured; using deterministic fallback."
        return None

    candidates = _candidate_models(model)

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(
            api_key=api_key,
            http_options=types.HttpOptions(timeout=30000),
        )
    except Exception as exc:
        _LAST_GEMINI_STATUS = f"Gemini client init error: {type(exc).__name__}"
        return None

    last_err = ""
    for candidate in candidates:
        try:
            response = client.models.generate_content(
                model=candidate,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    temperature=0.2,
                ),
            )
            parsed = _extract_json_dict(getattr(response, "text", None) or "")
            if parsed is not None:
                _LAST_GEMINI_STATUS = f"Connected to {candidate}"
                return parsed
            last_err = f"{candidate} returned non-JSON output"
        except Exception as exc:
            last_err = f"{candidate}: {type(exc).__name__} ({str(exc)[:140]})"
            continue

    _LAST_GEMINI_STATUS = f"Gemini temporarily unavailable ({last_err}); using deterministic fallback."
    return None


def request_gemini_text(
    prompt: str,
    *,
    model: str | None = None,
) -> str | None:
    """Send a plain-text prompt to Gemini via google-genai SDK with resilient fallback."""
    global _LAST_GEMINI_STATUS

    api_key = _get_secret_or_env("GEMINI_API_KEY")
    if not api_key:
        _LAST_GEMINI_STATUS = "GEMINI_API_KEY not configured; using deterministic fallback."
        return None

    candidates = _candidate_models(model)

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(
            api_key=api_key,
            http_options=types.HttpOptions(timeout=30000),
        )
    except Exception as exc:
        _LAST_GEMINI_STATUS = f"Gemini client init error: {type(exc).__name__}"
        return None

    last_err = ""
    for candidate in candidates:
        try:
            response = client.models.generate_content(
                model=candidate,
                contents=prompt,
                config=types.GenerateContentConfig(temperature=0.3),
            )
            text = (getattr(response, "text", None) or "").strip()
            if text:
                _LAST_GEMINI_STATUS = f"Connected to {candidate}"
                return text
        except Exception as exc:
            last_err = f"{candidate}: {type(exc).__name__}"
            continue

    _LAST_GEMINI_STATUS = f"Gemini temporarily unavailable ({last_err}); using deterministic fallback."
    return None
