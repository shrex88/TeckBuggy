"""Unified facade for SENTINEL AI Security Learning Mode."""

from learning.challenge_engine import CHALLENGES, SecurityChallenge, verify_practical_challenge
from learning.lesson_generator import LEARNING_LEVELS, SecurityLesson, get_lesson, list_lesson_topics
from learning.progress_tracker import (
    add_learning_points,
    award_achievement,
    get_learning_dashboard_state,
    mark_lesson_completed,
    set_learning_level,
)
from learning.quiz_engine import QUIZ_BANK, QuizQuestion, get_quiz_questions, submit_quiz_attempt
from learning.security_tutor import ask_security_tutor

__all__ = [
    "CHALLENGES",
    "LEARNING_LEVELS",
    "QUIZ_BANK",
    "QuizQuestion",
    "SecurityChallenge",
    "SecurityLesson",
    "add_learning_points",
    "ask_security_tutor",
    "award_achievement",
    "get_learning_dashboard_state",
    "get_lesson",
    "get_quiz_questions",
    "list_lesson_topics",
    "mark_lesson_completed",
    "set_learning_level",
    "submit_quiz_attempt",
    "verify_practical_challenge",
]
