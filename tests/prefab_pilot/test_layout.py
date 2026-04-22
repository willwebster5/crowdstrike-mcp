"""Smoke tests for Prefab layout assembly.

We can't render these in a host, so tests verify:
  - the builder returns a Component tree without raising
  - the top-level structure has the expected sections in order
  - the component types are what we expect
  - the table rows and chart data come from the input, not hardcoded
  - the empty-result case still returns a valid, non-crashing tree
"""

from __future__ import annotations

from crowdstrike_mcp.prefab_pilot.layout import build_ngsiem_query_layout
from crowdstrike_mcp.prefab_pilot.mock_data import generate_process_events
from crowdstrike_mcp.prefab_pilot.summary import summarize_events


def _child_types(layout) -> list[str]:
    return [c.type for c in layout.children]


def test_layout_builds_without_raising():
    events = generate_process_events(count=30, seed=1)
    summary = summarize_events(events)
    layout = build_ngsiem_query_layout(events=events, query="#repo=fdr", summary=summary)
    assert layout is not None


def test_layout_root_is_column():
    events = generate_process_events(count=5, seed=1)
    summary = summarize_events(events)
    layout = build_ngsiem_query_layout(events=events, query="q", summary=summary)
    assert layout.type == "Column"


def test_layout_includes_heading_summary_chart_and_table_in_order():
    events = generate_process_events(count=30, seed=1)
    summary = summarize_events(events)
    layout = build_ngsiem_query_layout(events=events, query="q", summary=summary)
    types = _child_types(layout)
    assert types[0] == "Heading"
    assert "Card" in types
    assert "BarChart" in types
    assert "DataTable" in types
    assert types.index("Card") < types.index("BarChart") < types.index("DataTable")


def test_layout_table_rows_come_from_events():
    events = generate_process_events(count=7, seed=1)
    summary = summarize_events(events)
    layout = build_ngsiem_query_layout(events=events, query="q", summary=summary)
    table = next(c for c in layout.children if c.type == "DataTable")
    assert len(table.rows) == 7
    assert table.rows[0]["ComputerName"] == events[0]["ComputerName"]


def test_layout_table_has_expected_columns():
    events = generate_process_events(count=3, seed=1)
    summary = summarize_events(events)
    layout = build_ngsiem_query_layout(events=events, query="q", summary=summary)
    table = next(c for c in layout.children if c.type == "DataTable")
    column_keys = {col.key for col in table.columns}
    assert {"@timestamp", "ComputerName", "event_simpleName", "UserName"}.issubset(column_keys)


def test_layout_chart_data_reflects_hourly_buckets():
    events = generate_process_events(count=30, seed=1)
    summary = summarize_events(events)
    layout = build_ngsiem_query_layout(events=events, query="q", summary=summary)
    chart = next(c for c in layout.children if c.type == "BarChart")
    assert chart.data == summary.hourly_buckets


def test_layout_omits_chart_when_no_events():
    summary = summarize_events([])
    layout = build_ngsiem_query_layout(events=[], query="q", summary=summary)
    types = _child_types(layout)
    assert "BarChart" not in types
    assert "Heading" in types


def test_layout_heading_mentions_row_count():
    events = generate_process_events(count=42, seed=1)
    summary = summarize_events(events)
    layout = build_ngsiem_query_layout(events=events, query="q", summary=summary)
    heading = layout.children[0]
    assert heading.type == "Heading"
    assert "42" in heading.content


def test_layout_serializes_cleanly():
    events = generate_process_events(count=5, seed=1)
    summary = summarize_events(events)
    layout = build_ngsiem_query_layout(events=events, query="q", summary=summary)
    # serialize_as_any preserves polymorphic child fields the host renderer needs
    dumped = layout.model_dump(serialize_as_any=True)
    assert dumped["type"] == "Column"
    assert all("type" in child for child in dumped["children"])
