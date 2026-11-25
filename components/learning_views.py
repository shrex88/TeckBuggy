"""Streamlit UI view for Feature 3: Security Learning Mode."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from components.dashboard import render_page_header
from database import get_all_scans
from learning import (
    CHALLENGES,
    LEARNING_LEVELS,
    ask_security_tutor,
    get_learning_dashboard_state,
    get_lesson,
    get_quiz_questions,
    list_lesson_topics,
    mark_lesson_completed,
    set_learning_level,
    submit_quiz_attempt,
    verify_practical_challenge,
)
from remediation import SUPPORTED_FRAMEWORKS


def render_learning_mode_page() -> None:
    """Render Feature 3: Interactive Security Learning Mode."""
    render_page_header(
        kicker="INTERACTIVE APPSEC ACADEMY",
        title="Security Learning Mode",
        subtitle="Personalized lessons, Gemini AI Security Tutor, quizzes, hands-on local lab challenges, and verified achievements.",
        badge="LEARNING MODE",
    )

    state = get_learning_dashboard_state()
    m1, m2, m3, m4 = st.columns(4, gap="medium")
    m1.metric("Learning Level", state["learning_level"])
    m2.metric("Skill Tier", state["skill_tier"])
    m3.metric("Learning Points", state["points"])
    m4.metric("Badges Earned", len(state["achievements"]))

    col_lvl, _ = st.columns([1, 2])
    with col_lvl:
        chosen_level = st.selectbox(
            "Select Personalized Learning Level",
            options=list(LEARNING_LEVELS),
            index=list(LEARNING_LEVELS).index(
                state["learning_level"] if state["learning_level"] in LEARNING_LEVELS else "BEGINNER"
            ),
            key="learn_level_select",
        )
        if chosen_level != state["learning_level"]:
            set_learning_level(chosen_level)
            st.rerun()

    tab_lessons, tab_tutor, tab_quiz, tab_lab, tab_progress = st.tabs(
        ["Vulnerability Lessons", "AI Security Tutor", "Interactive Quizzes", "Hands-On Lab", "Progress & Badges"]
    )

    with tab_lessons:
        topics = list_lesson_topics()
        topic_map = {f"{t['rule_id']} · {t['title']} ({t['severity']})": t["rule_id"] for t in topics}
        sel_topic = st.selectbox("Select Vulnerability Lesson", list(topic_map.keys()), key="lesson_select")
        lesson = get_lesson(topic_map[sel_topic], learning_level=chosen_level)

        st.markdown(
            f"""
            <div class="sentinel-panel">
                <div class="panel-header">
                    <span class="panel-title">{lesson.vulnerability_name}</span>
                    <span class="panel-badge">{lesson.owasp_mapping} · {lesson.learning_level}</span>
                </div>
                <p style="color:#CBD5E1; font-size:0.88rem;">
                    <strong>Simple Explanation:</strong> {lesson.simple_explanation}<br/><br/>
                    <strong>Technical Explanation:</strong> {lesson.technical_explanation}<br/><br/>
                    <strong>Root Cause:</strong> {lesson.root_cause}<br/><br/>
                    <strong>Security Impact:</strong> {lesson.security_impact}
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        ca, cb = st.columns(2)
        with ca:
            st.caption("Insecure Configuration Example")
            st.code(lesson.insecure_example)
        with cb:
            st.caption("Secure Configuration Example")
            st.code(lesson.secure_example)

        fw = st.selectbox("Framework Implementation", list(SUPPORTED_FRAMEWORKS), key="lesson_fw")
        st.code(lesson.framework_implementations.get(fw, lesson.secure_example))

        st.write("**Prevention Strategies:**")
        for p in lesson.prevention_strategies:
            st.write(f"- {p}")
        st.caption(f"**Verification Steps:** {lesson.verification_steps}")

        if st.button("Mark Lesson Completed (+15 pts)", key="complete_lesson_btn", type="primary"):
            if mark_lesson_completed(lesson.rule_id, chosen_level):
                st.success(f"Lesson {lesson.rule_id} marked completed! +15 points awarded.")
                st.rerun()
            else:
                st.info("You have already completed this lesson.")

    with tab_tutor:
        st.caption("Ask SENTINEL AI Security Tutor about findings, OWASP categories, or framework hardening.")
        tutor_topic = st.selectbox("Context Topic", list(topic_map.keys()), key="tutor_topic")
        question = st.text_area(
            "Your Security Question",
            placeholder="e.g., Why is HttpOnly important for our Flask session cookie?",
            key="tutor_question",
        )
        if st.button("Ask AI Security Tutor", key="ask_tutor_btn", type="primary"):
            with st.spinner("Consulting SENTINEL AI Security Tutor..."):
                reply = ask_security_tutor(
                    question=question,
                    learning_level=chosen_level,
                    rule_id=topic_map[tutor_topic],
                )
                st.caption(f"Response Source: {reply['source']}")
                st.markdown(reply["answer"])

    with tab_quiz:
        diff = st.selectbox("Quiz Difficulty", ["ALL", "BEGINNER", "INTERMEDIATE", "ADVANCED"], key="quiz_diff")
        questions = get_quiz_questions(diff)
        answers: dict[str, str] = {}
        for q in questions:
            answers[q.qid] = st.radio(
                f"{q.qid} [{q.question_type}]: {q.prompt}",
                options=q.options,
                key=f"quiz_{q.qid}",
            )
        if st.button("Submit Quiz", key="submit_quiz_btn", type="primary"):
            res = submit_quiz_attempt(answers=answers, difficulty=diff)
            st.success(f"Score: {res['score']} / {res['total']} ({res['percentage']}%)")
            for d in res["details"]:
                if d["is_correct"]:
                    st.write(f"✓ **{d['qid']}** Correct — {d['explanation']}")
                else:
                    st.write(f"✗ **{d['qid']}** Incorrect (Expected: `{d['correct_answer']}`) — {d['explanation']}")

    with tab_lab:
        st.caption("Complete real hands-on remediation challenges against the Low-Security Local Demo Lab.")
        scans = [s for s in get_all_scans() if s["status"] == "completed"]
        if not scans:
            st.info("Run a baseline scan of Application B (127.0.0.1:5050) first to unlock hands-on challenges.")
        else:
            scan_map = {f"Scan #{s['id']} · {s['target_url']} ({s['scan_date']})": s for s in scans}
            base_lbl = st.selectbox("Select Baseline Scan", list(scan_map.keys()), key="chal_base_scan")
            chosen_scan = scan_map[base_lbl]
            for ch in CHALLENGES:
                with st.expander(f"{ch.title} ({ch.rule_id}) · Badge: {ch.badge_name}", expanded=True):
                    for step in ch.instructions:
                        st.write(step)
                    if st.button(f"Verify '{ch.title}' via Rescan", key=f"verify_{ch.challenge_id}"):
                        with st.spinner("Running fresh scan and verifying via Security Proof..."):
                            v = verify_practical_challenge(
                                challenge_id=ch.challenge_id,
                                baseline_scan_id=chosen_scan["id"],
                                target_url=chosen_scan["target_url"],
                            )
                            if v["verified"]:
                                st.success(v["message"])
                            else:
                                st.warning(v["message"])

    with tab_progress:
        st.subheader("Achievement Badges")
        if state["achievements"]:
            st.dataframe(pd.DataFrame(state["achievements"]), use_container_width=True, hide_index=True)
        else:
            st.info("Complete quizzes (100%) or verify hands-on lab challenges to earn badges.")

        st.subheader("Completed Lessons")
        st.write(", ".join(state["completed_lessons"]) if state["completed_lessons"] else "No lessons completed yet.")

        st.subheader("Quiz History")
        if state["quiz_attempts"]:
            st.dataframe(pd.DataFrame(state["quiz_attempts"]), use_container_width=True, hide_index=True)
        else:
            st.info("No quiz attempts recorded yet.")
