"""Interactive Security Quiz Engine for Security Learning Mode."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from config import DATABASE_URL
from database.database import get_session, init_db
from database.models import QuizAttempt
from learning.progress_tracker import add_learning_points, award_achievement


@dataclass(frozen=True)
class QuizQuestion:
    """Single quiz question supporting MCQ, True/False, and Scenario formats."""

    qid: str
    topic: str
    difficulty: str
    question_type: str
    prompt: str
    options: list[str]
    correct_answer: str
    explanation: str


QUIZ_BANK: list[QuizQuestion] = [
    QuizQuestion(
        qid="Q1",
        topic="Cookie Security",
        difficulty="BEGINNER",
        question_type="Multiple Choice",
        prompt="What is the primary purpose of the HttpOnly cookie attribute?",
        options=[
            "Encrypt the cookie on disk",
            "Prevent client-side JavaScript from reading the cookie via document.cookie",
            "Force the cookie to expire in 5 minutes",
            "Compress the cookie header",
        ],
        correct_answer="Prevent client-side JavaScript from reading the cookie via document.cookie",
        explanation="HttpOnly blocks JavaScript access to cookies, reducing the impact of XSS cookie theft.",
    ),
    QuizQuestion(
        qid="Q2",
        topic="Cookie Security",
        difficulty="BEGINNER",
        question_type="True/False",
        prompt="True or False: A cookie marked Secure can safely be relied upon to work over plain http:// in production.",
        options=["True", "False"],
        correct_answer="False",
        explanation="Secure instructs browsers to transmit the cookie only over encrypted HTTPS connections.",
    ),
    QuizQuestion(
        qid="Q3",
        topic="Content-Security-Policy",
        difficulty="INTERMEDIATE",
        question_type="Multiple Choice",
        prompt="What does `default-src 'self'` do in a Content-Security-Policy header?",
        options=[
            "Allows scripts from any external domain",
            "Restricts resource loading by default to the application's own origin",
            "Disables TLS verification",
            "Allows inline eval() calls",
        ],
        correct_answer="Restricts resource loading by default to the application's own origin",
        explanation="'self' restricts resource loading to the same scheme, host, and port as the document.",
    ),
    QuizQuestion(
        qid="Q4",
        topic="Content-Security-Policy",
        difficulty="INTERMEDIATE",
        question_type="Multiple Choice",
        prompt="Which CSP directive specifically protects against Clickjacking by controlling iframe embedding?",
        options=["object-src", "img-src", "frame-ancestors", "base-uri"],
        correct_answer="frame-ancestors",
        explanation="frame-ancestors specifies valid parents that may embed the page in <frame> or <iframe>.",
    ),
    QuizQuestion(
        qid="Q5",
        topic="TLS & Transport Security",
        difficulty="BEGINNER",
        question_type="Multiple Choice",
        prompt="Why is HTTPS (TLS 1.2/1.3) critical for payment and authentication applications?",
        options=[
            "It makes HTML render faster",
            "It encrypts traffic in transit and authenticates the server via certificates",
            "It replaces the need for server-side validation",
            "It disables cookies",
        ],
        correct_answer="It encrypts traffic in transit and authenticates the server via certificates",
        explanation="TLS protects confidentiality and integrity in transit and prevents eavesdropping or tampering.",
    ),
    QuizQuestion(
        qid="Q6",
        topic="Exposed Configuration",
        difficulty="ADVANCED",
        question_type="Scenario",
        prompt="Scenario: Your scanner detects HTTP 200 (application/json) at /config.json on a local app. What is the safest remediation?",
        options=[
            "Rename /config.json to /config2.json",
            "Disable unauthenticated access (return 404/403) and keep secrets out of web-accessible routes",
            "Add 'unsafe-inline' to CSP",
            "Mark the finding resolved without rescanning",
        ],
        correct_answer="Disable unauthenticated access (return 404/403) and keep secrets out of web-accessible routes",
        explanation="Security by obscurity (renaming) is insufficient; remove or restrict sensitive endpoints and verify via rescan.",
    ),
]


def get_quiz_questions(difficulty: str = "ALL") -> list[QuizQuestion]:
    """Filter quiz questions by difficulty level or return all."""
    diff = (difficulty or "ALL").upper()
    if diff == "ALL":
        return list(QUIZ_BANK)
    return [q for q in QUIZ_BANK if q.difficulty == diff]


def submit_quiz_attempt(
    *,
    answers: dict[str, str],
    difficulty: str = "ALL",
    topic: str = "Web Security Fundamentals",
    learner_id: str = "default",
    database_url: str = DATABASE_URL,
) -> dict[str, Any]:
    """Score submitted answers, persist QuizAttempt, and award points/badges."""
    questions = get_quiz_questions(difficulty)
    correct = 0
    details: list[dict[str, Any]] = []

    for q in questions:
        chosen = answers.get(q.qid, "")
        is_correct = chosen == q.correct_answer
        if is_correct:
            correct += 1
        details.append(
            {
                "qid": q.qid,
                "prompt": q.prompt,
                "chosen": chosen,
                "correct_answer": q.correct_answer,
                "is_correct": is_correct,
                "explanation": q.explanation,
            }
        )

    total = len(questions)
    init_db(database_url)
    with get_session(database_url) as session:
        session.add(
            QuizAttempt(
                learner_id=learner_id,
                topic=topic,
                difficulty=difficulty,
                score=correct,
                total_questions=total,
            )
        )

    if correct > 0:
        add_learning_points(correct * 10, learner_id=learner_id, database_url=database_url)
    if total > 0 and correct == total:
        award_achievement(
            badge_id="OWASP_EXPLORER",
            badge_name="OWASP Explorer",
            reason=f"Scored {correct}/{total} on Security Learning Mode quiz.",
            learner_id=learner_id,
            database_url=database_url,
        )

    return {
        "score": correct,
        "total": total,
        "percentage": round((correct / total) * 100.0, 1) if total else 0.0,
        "details": details,
    }
