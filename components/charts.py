"""Plotly chart builders for the SENTINEL AI dashboard."""

from __future__ import annotations

from typing import Optional

import plotly.graph_objects as go

from config import SEVERITY_COLORS


def _apply_dark_layout(fig: go.Figure, height: int = 290) -> go.Figure:
    """Apply consistent Sentinel AI dark theme styling to a Plotly figure."""
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color="#CBD5E1", size=12),
        margin=dict(l=16, r=16, t=24, b=16),
        height=height,
    )
    return fig


def build_security_score_gauge(score: Optional[float]) -> go.Figure:
    """Build the Security Score gauge chart (handles None cleanly)."""
    display_value = float(score) if score is not None else 0.0
    bar_color = "#334155" if score is None else "#00F0FF"
    if score is not None:
        if score < 50:
            bar_color = "#FF3B5C"
        elif score < 75:
            bar_color = "#FF8A00"
        elif score < 90:
            bar_color = "#F5C542"
        else:
            bar_color = "#10B981"

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=display_value,
            number={
                "suffix": " / 100" if score is not None else "",
                "font": {"size": 28, "color": "#F8FAFC" if score is not None else "#64748B"},
            },
            title={
                "text": "Posture Index" if score is not None else "Awaiting First Scan",
                "font": {"size": 13, "color": "#94A3B8"},
            },
            gauge={
                "axis": {
                    "range": [0, 100],
                    "tickwidth": 1,
                    "tickcolor": "#475569",
                    "tickfont": {"color": "#64748B", "size": 10},
                },
                "bar": {"color": bar_color, "thickness": 0.72},
                "bgcolor": "rgba(15, 23, 42, 0.85)",
                "borderwidth": 1,
                "bordercolor": "rgba(148, 163, 184, 0.18)",
                "steps": [
                    {"range": [0, 50], "color": "rgba(255, 59, 92, 0.08)"},
                    {"range": [50, 75], "color": "rgba(255, 138, 0, 0.08)"},
                    {"range": [75, 100], "color": "rgba(0, 240, 255, 0.08)"},
                ],
            },
        )
    )
    return _apply_dark_layout(fig, height=270)


def build_vulnerability_distribution_chart(severity_counts: dict[str, int]) -> go.Figure:
    """Build a donut chart of findings by severity."""
    ordered = ["Critical", "High", "Medium", "Low", "Info"]
    labels = [sev for sev in ordered if severity_counts.get(sev, 0) > 0]
    values = [severity_counts[sev] for sev in labels]

    if not values:
        fig = go.Figure()
        fig.add_annotation(
            text="No vulnerability data recorded yet",
            x=0.5,
            y=0.5,
            showarrow=False,
            font=dict(size=13, color="#64748B"),
        )
        fig.update_xaxes(visible=False)
        fig.update_yaxes(visible=False)
        return _apply_dark_layout(fig, height=270)

    colors = [SEVERITY_COLORS.get(lbl, "#8B5CF6") for lbl in labels]
    fig = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=0.62,
                marker=dict(colors=colors, line=dict(color="#0B1120", width=2)),
                textinfo="label+value",
                textfont=dict(size=12, color="#F8FAFC"),
            )
        ]
    )
    fig.update_layout(showlegend=False)
    return _apply_dark_layout(fig, height=270)


def build_owasp_distribution_chart(owasp_counts: dict[str, int]) -> go.Figure:
    """Build a horizontal bar chart of findings grouped by OWASP Top 10 category."""
    if not owasp_counts:
        fig = go.Figure()
        fig.add_annotation(
            text="OWASP category distribution will appear after your first scan",
            x=0.5,
            y=0.5,
            showarrow=False,
            font=dict(size=13, color="#64748B"),
        )
        fig.update_xaxes(visible=False)
        fig.update_yaxes(visible=False)
        return _apply_dark_layout(fig, height=270)

    sorted_items = sorted(owasp_counts.items(), key=lambda x: x[1])
    categories = [item[0] for item in sorted_items]
    counts = [item[1] for item in sorted_items]

    fig = go.Figure(
        go.Bar(
            x=counts,
            y=categories,
            orientation="h",
            marker=dict(
                color="#8B5CF6",
                line=dict(color="#00F0FF", width=1),
            ),
            text=counts,
            textposition="auto",
        )
    )
    fig.update_xaxes(
        gridcolor="rgba(148, 163, 184, 0.1)",
        zeroline=False,
        dtick=1,
    )
    fig.update_yaxes(gridcolor="rgba(0,0,0,0)")
    return _apply_dark_layout(fig, height=270)


def build_security_proof_score_chart(original_score: float, updated_score: float) -> go.Figure:
    """Build a Before vs After Security Score comparison bar chart."""
    fig = go.Figure(
        data=[
            go.Bar(
                x=["Original Scan", "Follow-Up Scan"],
                y=[original_score, updated_score],
                marker=dict(
                    color=["#8B5CF6", "#00F0FF"],
                    line=dict(color="#F8FAFC", width=1),
                ),
                text=[f"{original_score:.1f}", f"{updated_score:.1f}"],
                textposition="auto",
            )
        ]
    )
    fig.update_yaxes(range=[0, 105], gridcolor="rgba(148, 163, 184, 0.1)")
    return _apply_dark_layout(fig, height=270)


def build_security_proof_findings_chart(
    fixed_count: int,
    remaining_count: int,
    new_count: int,
) -> go.Figure:
    """Build a Security Proof findings outcome breakdown chart."""
    fig = go.Figure(
        data=[
            go.Bar(
                x=["Fixed (Verified)", "Remaining", "Newly Discovered"],
                y=[fixed_count, remaining_count, new_count],
                marker=dict(color=["#10B981", "#F5C542", "#FF3B5C"]),
                text=[fixed_count, remaining_count, new_count],
                textposition="auto",
            )
        ]
    )
    fig.update_yaxes(dtick=1, gridcolor="rgba(148, 163, 184, 0.1)")
    return _apply_dark_layout(fig, height=270)
