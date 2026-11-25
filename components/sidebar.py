"""Sidebar navigation component for SENTINEL AI."""

from __future__ import annotations

import streamlit as st

from config import APP_NAME, APP_TAGLINE, APP_VERSION, NAV_SECTIONS


def render_sidebar(active_page: str, total_scans: int) -> str:
    """Render the Sentinel AI sidebar and return the selected section ID."""
    with st.sidebar:
        st.markdown(
            f"""
            <div class="sidebar-brand">
                <div class="sidebar-brand-row">
                    <div class="brand-shield">🛡</div>
                    <div>
                        <div class="brand-title">{APP_NAME}</div>
                        <div class="brand-tagline">{APP_TAGLINE}</div>
                    </div>
                </div>
            </div>
            <div class="nav-section-label">Security Workspace</div>
            """,
            unsafe_allow_html=True,
        )

        selected = active_page
        for item in NAV_SECTIONS:
            is_active = item["id"] == active_page
            btn_type = "primary" if is_active else "secondary"
            label = f"{item['icon']}  {item['label']}"
            if st.button(
                label,
                key=f"nav_{item['id']}",
                type=btn_type,
                use_container_width=True,
            ):
                selected = item["id"]

        st.markdown(
            f"""
            <div class="sidebar-footer-card">
                <div style="font-weight:600; color:#F8FAFC; margin-bottom:4px;">
                    <span class="status-dot"></span>SQLite Storage Ready
                </div>
                <div>Recorded Scans: <strong style="color:#00F0FF;">{total_scans}</strong></div>
                <div style="color:#64748B; margin-top:4px; font-family:'JetBrains Mono', monospace;">
                    v{APP_VERSION}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    return selected
