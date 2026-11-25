"""Learning Progress & Gamification Tracker for Security Learning Mode."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from config import DATABASE_URL
from database.database import get_session, init_db
from database.models import (
    Achievement,
    LearningProfile,
    LearningProgress,
    PracticalExercise,
    QuizAttempt,
)


def _get_or_create_profile(session: Any, learner_id: str) -> LearningProfile:
    prof = session.scalar(
        select(LearningProfile).where(LearningProfile.learner_id == learner_id)
    )
    if prof is None:
        prof = LearningProfile(learner_id=learner_id, learning_level="BEGINNER", points=0)
        session.add(prof)
        session.flush()
    return prof


def set_learning_level(
    learning_level: str,
    *,
    learner_id: str = "default",
    database_url: str = DATABASE_URL,
) -> None:
    """Persist the developer's selected learning level."""
    init_db(database_url)
    with get_session(database_url) as session:
        prof = _get_or_create_profile(session, learner_id)
        prof.learning_level = learning_level.upper()
        prof.updated_at = datetime.now(timezone.utc)


def add_learning_points(
    points: int,
    *,
    learner_id: str = "default",
    database_url: str = DATABASE_URL,
) -> int:
    """Add learning points and return the updated total."""
    init_db(database_url)
    with get_session(database_url) as session:
        prof = _get_or_create_profile(session, learner_id)
        prof.points = int(prof.points or 0) + max(0, int(points))
        prof.updated_at = datetime.now(timezone.utc)
        return int(prof.points)


def mark_lesson_completed(
    rule_id: str,
    learning_level: str,
    *,
    learner_id: str = "default",
    database_url: str = DATABASE_URL,
) -> bool:
    """Record lesson completion once and award points."""
    init_db(database_url)
    with get_session(database_url) as session:
        existing = session.scalar(
            select(LearningProgress).where(
                LearningProgress.learner_id == learner_id,
                LearningProgress.rule_id == rule_id.upper(),
            )
        )
        if existing is not None:
            return False
        session.add(
            LearningProgress(
                learner_id=learner_id,
                rule_id=rule_id.upper(),
                learning_level=learning_level.upper(),
            )
        )
    add_learning_points(15, learner_id=learner_id, database_url=database_url)
    return True


def award_achievement(
    *,
    badge_id: str,
    badge_name: str,
    reason: str,
    learner_id: str = "default",
    database_url: str = DATABASE_URL,
) -> bool:
    """Award an achievement badge if not already earned."""
    init_db(database_url)
    with get_session(database_url) as session:
        existing = session.scalar(
            select(Achievement).where(
                Achievement.learner_id == learner_id,
                Achievement.badge_id == badge_id,
            )
        )
        if existing is not None:
            return False
        session.add(
            Achievement(
                learner_id=learner_id,
                badge_id=badge_id,
                badge_name=badge_name,
                reason=reason,
            )
        )
        return True


def get_learning_dashboard_state(
    *,
    learner_id: str = "default",
    database_url: str = DATABASE_URL,
) -> dict[str, Any]:
    """Fetch genuine learning progress, quiz attempts, exercises, and badges."""
    init_db(database_url)
    with get_session(database_url) as session:
        prof = _get_or_create_profile(session, learner_id)
        lessons = list(
            session.scalars(
                select(LearningProgress).where(LearningProgress.learner_id == learner_id)
            ).all()
        )
        quizzes = list(
            session.scalars(
                select(QuizAttempt)
                .where(QuizAttempt.learner_id == learner_id)
                .order_by(QuizAttempt.attempted_at.desc())
            ).all()
        )
        exercises = list(
            session.scalars(
                select(PracticalExercise).where(PracticalExercise.learner_id == learner_id)
            ).all()
        )
        badges = list(
            session.scalars(
                select(Achievement)
                .where(Achievement.learner_id == learner_id)
                .order_by(Achievement.earned_at.desc())
            ).all()
        )

        pts = int(prof.points or 0)
        skill_tier = (
            "Security Architect" if pts >= 150 else ("AppSec Practitioner" if pts >= 60 else "AppSec Apprentice")
        )

        return {
            "learning_level": prof.learning_level,
            "points": pts,
            "skill_tier": skill_tier,
            "completed_lessons": [l.rule_id for l in lessons],
            "quiz_attempts": [
                {
                    "topic": q.topic,
                    "difficulty": q.difficulty,
                    "score": q.score,
                    "total": q.total_questions,
                    "attempted_at": q.attempted_at.strftime("%Y-%m-%d %H:%M UTC") if q.attempted_at else "—",
                }
                for q in quizzes
            ],
            "completed_exercises": [
                {
                    "challenge_id": e.challenge_id,
                    "rule_id": e.rule_id,
                    "status": e.status,
                    "verified_scan_id": e.verified_scan_id,
                }
                for e in exercises
                if e.status == "verified"
            ],
            "achievements": [
                {
                    "badge_id": b.badge_id,
                    "badge_name": b.badge_name,
                    "reason": b.reason,
                    "earned_at": b.earned_at.strftime("%Y-%m-%d %H:%M UTC") if b.earned_at else "—",
                }
                for b in badges
            ],
        }
