"""Interactive Gemini AI Security Tutor for Security Learning Mode."""

from __future__ import annotations

from config import DATABASE_URL
from database.database import get_findings
from intelligence.gemini_client import is_gemini_configured, request_gemini_text
from learning.lesson_generator import get_lesson


def ask_security_tutor(
    *,
    question: str,
    learning_level: str = "BEGINNER",
    rule_id: str = "HDR-001",
    database_url: str = DATABASE_URL,
) -> dict[str, str]:
    """Answer a developer's security question grounded in real SQLite findings."""
    clean_q = (question or "").strip()
    if not clean_q:
        return {"source": "deterministic", "answer": "Please enter a security question."}

    # Ground tutor in actual persisted findings (never invent findings)
    real_findings = get_findings(database_url=database_url)[:5]
    findings_context = (
        "\n".join(
            f"- {f['rule_id']} ({f['severity']}) at {f['target_path']}: {f['title']}"
            for f in real_findings
        )
        if real_findings
        else "No scans have been recorded in SQLite yet."
    )

    if is_gemini_configured():
        prompt = (
            f"You are SENTINEL AI Security Tutor. Adapt your answer to the {learning_level} level.\n"
            "Rules:\n"
            "1. Only reference actual findings listed below if asked about the user's application; never invent findings.\n"
            "2. Provide clear, defensive-only explanations and Flask/Django/Apache/Nginx examples when relevant.\n\n"
            f"Selected Lesson Topic: {rule_id}\n"
            f"Actual Recorded Findings in SQLite:\n{findings_context}\n\n"
            f"Developer Question: {clean_q}"
        )
        ai_reply = request_gemini_text(prompt)
        if ai_reply:
            return {"source": "gemini_ai", "answer": ai_reply}

    # Deterministic fallback grounded in lesson & actual findings
    lesson = get_lesson(rule_id, learning_level=learning_level)
    fallback = (
        f"**[{learning_level} Tutor · Deterministic Mode]**\n\n"
        f"**Topic:** {lesson.vulnerability_name} ({lesson.owasp_mapping})\n\n"
        f"{lesson.simple_explanation}\n\n"
        f"**Technical Detail:** {lesson.technical_explanation}\n\n"
        f"**Secure Example:** `{lesson.secure_example}`\n\n"
        f"**Flask Reference:**\n```python\n{lesson.framework_implementations.get('Flask', '')}\n```\n\n"
        f"**Actual Recorded Findings Context:**\n{findings_context}"
    )
    return {"source": "rule_based_fallback", "answer": fallback}
