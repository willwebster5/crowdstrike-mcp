"""Tests for the text-fallback summary.

When the host can't render Prefab (e.g. Claude Code), this string is what
the model sees. It must be self-contained — not say "see the table" when
there's no table to see.
"""

from __future__ import annotations

from crowdstrike_mcp.prefab_pilot.fallback import summary_to_text
from crowdstrike_mcp.prefab_pilot.summary import QuerySummary


def test_text_fallback_for_empty_result():
    summary = QuerySummary(row_count=0)
    text = summary_to_text(summary, query="#repo=fdr")
    assert "0 events" in text
    assert "#repo=fdr" in text


def test_text_fallback_includes_row_count_and_query():
    summary = QuerySummary(row_count=42)
    text = summary_to_text(summary, query="#repo=fdr event_simpleName=ProcessRollup2")
    assert "42 events" in text
    assert "#repo=fdr event_simpleName=ProcessRollup2" in text


def test_text_fallback_includes_top_host_when_present():
    summary = QuerySummary(row_count=10, top_host=("SRV-DB01", 7))
    text = summary_to_text(summary, query="q")
    assert "SRV-DB01" in text
    assert "7" in text


def test_text_fallback_includes_top_event_name_when_present():
    summary = QuerySummary(row_count=10, top_event_name=("ProcessRollup2", 9))
    text = summary_to_text(summary, query="q")
    assert "ProcessRollup2" in text
    assert "9" in text


def test_text_fallback_includes_time_range_when_present():
    summary = QuerySummary(
        row_count=10,
        time_range=("2026-04-22T00:00:00+00:00", "2026-04-22T23:59:59+00:00"),
    )
    text = summary_to_text(summary, query="q")
    assert "2026-04-22T00:00:00+00:00" in text
    assert "2026-04-22T23:59:59+00:00" in text


def test_text_fallback_never_refers_to_invisible_ui():
    summary = QuerySummary(row_count=5, top_host=("H", 3))
    text = summary_to_text(summary, query="q").lower()
    for forbidden in ["see the table", "see the chart", "rendered above", "[rendered prefab ui]"]:
        assert forbidden not in text, f"fallback should not reference UI: {forbidden!r}"
