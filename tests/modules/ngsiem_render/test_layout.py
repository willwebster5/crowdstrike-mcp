"""Smoke tests for Prefab layout assembly.

We can't render these in a host, so tests verify:
  - the builder returns a Component tree without raising
  - the top-level structure has the expected sections in order
  - the component types are what we expect
  - the table rows and chart data come from the input, not hardcoded
  - the empty-result case still returns a valid, non-crashing tree
"""

from __future__ import annotations

from crowdstrike_mcp.modules.ngsiem_render.layout import build_ngsiem_query_layout
from crowdstrike_mcp.modules.ngsiem_render.mock_data import generate_process_events
from crowdstrike_mcp.modules.ngsiem_render.summary import WidgetType, summarize_events


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
    # Rows are sanitized (# and @ stripped) so column keys live in the same namespace.
    assert {"timestamp", "ComputerName", "event_simpleName", "UserName"}.issubset(column_keys)


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


def test_layout_timechart_uses_area_chart_not_bar_chart():
    # timechart() returns _bucket + _count rows. Layout picks AreaChart
    # (>100 bars is an unreadable wall, AreaChart reads the trend at a glance)
    # and skips the raw bucket table entirely.
    events = [
        {"_bucket": 1776470400000 + i * 3_600_000, "_count": 10 + i}
        for i in range(168)
    ]
    summary = summarize_events(events)
    assert summary.widget_type == WidgetType.TIMECHART
    layout = build_ngsiem_query_layout(events=events, query="...| timechart()", summary=summary)
    types = _child_types(layout)
    assert "AreaChart" in types
    assert "BarChart" not in types
    assert "DataTable" not in types  # timechart suppresses raw bucket rows


def test_layout_non_timechart_still_uses_bar_chart():
    events = generate_process_events(count=10, seed=1)
    summary = summarize_events(events)
    assert summary.widget_type == WidgetType.RAW_EVENTS
    layout = build_ngsiem_query_layout(events=events, query="q", summary=summary)
    types = _child_types(layout)
    assert "BarChart" in types
    assert "AreaChart" not in types


def _find_first(node, type_name: str):
    """Walk a Component tree and return the first node with `c.type == type_name`."""
    if getattr(node, "type", None) == type_name:
        return node
    children = getattr(node, "children", None) or []
    for child in children:
        found = _find_first(child, type_name)
        if found is not None:
            return found
    return None


def test_layout_single_value_renders_metric_no_table():
    # `count()` aggregates return one row with a single numeric column.
    events = [{"_count": 12345}]
    summary = summarize_events(events)
    assert summary.widget_type == WidgetType.SINGLE_VALUE
    layout = build_ngsiem_query_layout(events=events, query="...| count()", summary=summary)
    types = _child_types(layout)
    # Metric is wrapped in a Card for visual presence (prefab idiom — bare
    # Metric renders small/uncentered).
    assert "Card" in types
    assert "DataTable" not in types
    metric = _find_first(layout, "Metric")
    assert metric is not None
    # Layout formats the number with commas for readability before handing it
    # to the renderer — large counts like "320,559" are far easier to scan.
    assert metric.value == "12,345"


def test_layout_single_value_uses_string_field_as_label_when_present():
    # 1-row groupBy with a category — label should be the category value,
    # not the humanized numeric field name.
    events = [{"repo": "fdr", "_count": 999}]
    summary = summarize_events(events)
    assert summary.widget_type == WidgetType.SINGLE_VALUE
    layout = build_ngsiem_query_layout(events=events, query="q", summary=summary)
    metric = _find_first(layout, "Metric")
    assert metric is not None
    assert metric.label == "fdr"
    assert metric.value == "999"


def test_layout_pie_candidate_renders_pie_alongside_table():
    # Small-N category aggregate — show pie for shape-at-a-glance plus the
    # table for exact values.
    events = [
        {"event_simpleName": "ProcessRollup2", "_count": 100},
        {"event_simpleName": "DnsRequest", "_count": 60},
        {"event_simpleName": "NetworkConnectIP4", "_count": 30},
    ]
    summary = summarize_events(events)
    assert summary.widget_type == WidgetType.PIE_CANDIDATE
    layout = build_ngsiem_query_layout(events=events, query="q", summary=summary)
    types = _child_types(layout)
    assert "PieChart" in types
    assert "DataTable" in types
    pie = next(c for c in layout.children if c.type == "PieChart")
    assert pie.data == [
        {"name": "ProcessRollup2", "value": 100},
        {"name": "DnsRequest", "value": 60},
        {"name": "NetworkConnectIP4", "value": 30},
    ]
    assert pie.data_key == "value"
    assert pie.name_key == "name"


def test_layout_pie_skipped_for_large_aggregate():
    # >20 rows = too many slices to read; fall back to plain table.
    events = [{"event_simpleName": f"Event{i}", "_count": i + 1} for i in range(25)]
    summary = summarize_events(events)
    assert summary.widget_type == WidgetType.AGGREGATE_TABLE
    layout = build_ngsiem_query_layout(events=events, query="q", summary=summary)
    types = _child_types(layout)
    assert "PieChart" not in types
    assert "DataTable" in types


def test_layout_scatter_renders_scatter_chart_alongside_table():
    events = [
        {"ComputerName": f"HOST-{i:02d}", "_count": i * 5, "avg_RPort": i * 11}
        for i in range(1, 11)
    ]
    summary = summarize_events(events)
    assert summary.widget_type == WidgetType.SCATTER
    layout = build_ngsiem_query_layout(events=events, query="q", summary=summary)
    types = _child_types(layout)
    assert "ScatterChart" in types
    assert "DataTable" in types
    chart = next(c for c in layout.children if c.type == "ScatterChart")
    # Axis fields match the sanitized keys in scatter_data.
    assert chart.x_axis == "count"
    assert chart.y_axis == "avg_RPort"
    assert len(chart.data) == 10


def test_layout_multi_series_timechart_uses_stacked_area_chart():
    # `timechart(... by=event_simpleName)` returns _bucket + one numeric column
    # per series value. AreaChart with multiple ChartSeries, stacked.
    events = [
        {"_bucket": 1776470400000 + i * 3_600_000, "ProcessRollup2": 10 + i, "DnsRequest": 5 + i}
        for i in range(24)
    ]
    summary = summarize_events(events)
    assert summary.widget_type == WidgetType.TIMECHART_MULTI
    layout = build_ngsiem_query_layout(events=events, query="...| timechart(by=...)", summary=summary)
    types = _child_types(layout)
    assert "AreaChart" in types
    assert "DataTable" not in types
    chart = next(c for c in layout.children if c.type == "AreaChart")
    series_keys = {s.data_key for s in chart.series}
    assert series_keys == {"ProcessRollup2", "DnsRequest"}
    assert chart.stacked is True


def test_layout_single_event_with_timestamp_is_not_single_value():
    # Regression: a 1-row live response (e.g. fixture for live-path test) has
    # @timestamp as int epoch — must NOT trip SINGLE_VALUE detection or the
    # raw event will render as a Metric and the row data disappears.
    events = [
        {"ComputerName": "LIVE-HOST-01", "event_simpleName": "ProcessRollup2",
         "@timestamp": 1776470400000, "UserName": "jdoe"}
    ]
    summary = summarize_events(events)
    assert summary.widget_type == WidgetType.RAW_EVENTS
    layout = build_ngsiem_query_layout(events=events, query="q", summary=summary)
    types = _child_types(layout)
    assert "Metric" not in types
    assert "DataTable" in types


def test_layout_data_table_wires_row_click_to_drilldown_tool():
    # Clicking a row in any DataTable should invoke ngsiem_query_drilldown with
    # the row dict as $event. The action's tool name is the hash-prefixed
    # wire-format name — pre-computed by hashed_backend_name(app, tool) so the
    # call dispatches correctly when FastMCP's auto-resolver isn't in the path.
    from fastmcp.server.providers.addressing import hashed_backend_name

    events = generate_process_events(count=5, seed=1)
    summary = summarize_events(events)
    layout = build_ngsiem_query_layout(events=events, query="q", summary=summary)
    table = next(c for c in layout.children if c.type == "DataTable")
    expected_name = hashed_backend_name("crowdstrike-falcon", "ngsiem_query_drilldown")
    assert table.on_row_click is not None
    assert table.on_row_click.tool == expected_name
    assert table.on_row_click.arguments == {"row": "{{ $event }}"}


def test_layout_serializes_cleanly():
    events = generate_process_events(count=5, seed=1)
    summary = summarize_events(events)
    layout = build_ngsiem_query_layout(events=events, query="q", summary=summary)
    # serialize_as_any preserves polymorphic child fields the host renderer needs
    dumped = layout.model_dump(serialize_as_any=True)
    assert dumped["type"] == "Column"
    assert all("type" in child for child in dumped["children"])
