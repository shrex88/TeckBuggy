"""Official Google Gen AI SDK client wrapper for SENTINEL AI.

Reads GEMINI_API_KEY from environment / .env only and fails gracefully
when unconfigured or unreachable.
"""

from __future__ import annotations

import json
import os
from typing import Any

from dotenv import load_dotenv

load_dotenv()


def is_gemini_configured() -> bool:
    """Return True if a non-empty GEMINI_API_KEY is available in the environment."""
    return bool((os.getenv("GEMINI_API_KEY") or "").strip())


def request_gemini_json(
    prompt: str,
    *,
    model: str | None = None,
) -> dict[str, Any] | None:
    """Send a structured JSON prompt to Gemini via google-genai SDK.

    Returns parsed JSON dict on success, or None when API key is missing
    or an API/parsing error occurs.
    """
    api_key = (os.getenv("GEMINI_API_KEY") or "").strip()
    if not api_key:
        return None

    chosen_model = (model or os.getenv("GEMINI_MODEL") or "gemini-2.5-flash").strip()

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=chosen_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                temperature=0.2,
            ),
        )
        raw_text = (getattr(response, "text", None) or "").strip()
        if not raw_text:
            return None
        parsed = json.loads(raw_text)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None
