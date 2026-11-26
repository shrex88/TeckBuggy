"""Sidebar navigation component for SENTINEL AI."""

from __future__ import annotations

import base64

from typing import Any, Optional

import streamlit as st

from config import APP_NAME, APP_TAGLINE, APP_VERSION, ASSETS_DIR, NAV_SECTIONS


def _brand_logo_html() -> str:
    logo_path = ASSETS_DIR / "logo.png"
    if not logo_path.exists():
        logo_path = ASSETS_DIR / "logo.jpg"
    if logo_path.exists():
        b64 = base64.b64encode(logo_path.read_bytes()).decode("ascii")
        mime = "image/png" if logo_path.suffix == ".png" else "image/jpeg"
        return (
            f'<img src="data:{mime};base64,{b64}" alt="{APP_NAME} Logo" '
            'style="width:42px;height:42px;border-radius:10px;object-fit:cover;'
            'border:1px solid rgba(0,240,255,0.45);box-shadow:0 0 18px rgba(0,240,255,0.22);" />'
        )
    return '<div class="brand-shield">🛡</div>'


def render_sidebar(
    active_page: str,
    total_scans: int,
    auth_user: Optional[dict[str, Any]] = None,
) -> str:
    """Render the Sentinel AI sidebar and return the selected section ID."""
    logo_html = _brand_logo_html()
    with st.sidebar:
        st.markdown(
            f"""
            <div class="sidebar-brand">
                <div class="sidebar-brand-row">
                    {logo_html}
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

        if auth_user:
            display_name = auth_user.get("full_name") or auth_user.get("username", "Analyst")
            role = auth_user.get("role", "Security Analyst")
            st.markdown(
                f"""
                <div class="sidebar-user-card" style="margin-top:10px;padding:10px 12px;border-radius:10px;
                    background:rgba(15,23,42,0.65);border:1px solid rgba(148,163,184,0.16);
                    font-size:0.8rem;">
                    <div style="font-weight:600;">{display_name}</div>
                    <div style="opacity:0.75;font-size:0.74rem;">{role}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            current_theme = st.session_state.get("theme_mode", "dark")
            toggle_label = "☀ Light Mode" if current_theme == "dark" else "🌙 Dark Mode"
            if st.button(toggle_label, key="btn_toggle_theme_sidebar", type="secondary", use_container_width=True):
                st.session_state["theme_mode"] = "light" if current_theme == "dark" else "dark"
                st.rerun()
            if st.button("Sign Out", key="nav_logout", type="secondary", use_container_width=True):
                st.session_state["auth_user"] = None
                st.session_state["active_page"] = "overview"
                st.rerun()

    return selected
