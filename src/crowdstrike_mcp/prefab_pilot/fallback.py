"""
Text-fallback renderer for the model / non-rendering hosts.

Keep this self-contained: Claude Code users see ONLY this text, so it must
not reference the UI. No "see the chart above" phrasing.
"""

from __future__ import annotations

from crowdstrike_mcp.prefab_pilot.summary import QuerySummary


def summary_to_text(summary: QuerySummary, query: str) -> str:
    """Render a query summary as a self-contained text block."""
    lines: list[str] = [
        f"NGSIEM query: {query}",
        f"Result: {summary.row_count} events",
    ]

    if summary.time_range is not None:
        start, end = summary.time_range
        lines.append(f"Time range: {start} → {end}")

    if summary.top_host is not None:
        host, count = summary.top_host
        lines.append(f"Top host: {host} ({count} events)")

    if summary.top_event_name is not None:
        name, count = summary.top_event_name
        lines.append(f"Top event_simpleName: {name} ({count} events)")

    if summary.hourly_buckets:
        peak = max(summary.hourly_buckets, key=lambda b: b["count"])
        lines.append(f"Peak hour: {peak['hour']} ({peak['count']} events)")

    return "\n".join(lines)
