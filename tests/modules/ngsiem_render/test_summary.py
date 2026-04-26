"""Tests for the model-facing summary reducer.

This is the code path that keeps the full NGSIEM result out of the model's
context. Correctness here matters more than the UI assembly — the summary is
what the model actually reasons over.
"""

from __future__ import annotations

import pytest

from crowdstrike_mcp.modules.ngsiem_render.mock_data import generate_process_events
from crowdstrike_mcp.modules.ngsiem_render.summary import WidgetType, summarize_events


def test_summarize_events_reports_total_count():
    events = generate_process_events(count=75, seed=1)
    summary = summarize_events(events)
    assert summary.row_count == 75


def test_summarize_events_handles_empty_input():
    summary = summarize_events([])
    assert summary.row_count == 0
    assert summary.top_host is None
    assert summary.top_event_name is None
    assert summary.time_range is None


def test_summarize_events_finds_top_host():
    events = [
        {"ComputerName": "A", "event_simpleName": "X", "@timestamp": "2026-04-22T00:00:00+00:00"},
        {"ComputerName": "A", "event_simpleName": "X", "@timestamp": "2026-04-22T00:01:00+00:00"},
        {"ComputerName": "A", "event_simpleName": "X", "@timestamp": "2026-04-22T00:02:00+00:00"},
        {"ComputerName": "B", "event_simpleName": "X", "@timestamp": "2026-04-22T00:03:00+00:00"},
    ]
    summary = summarize_events(events)
    assert summary.top_host == ("A", 3)


def test_summarize_events_finds_top_event_name():
    events = [
        {"ComputerName": "H", "event_simpleName": "ProcessRollup2", "@timestamp": "2026-04-22T00:00:00+00:00"},
        {"ComputerName": "H", "event_simpleName": "ProcessRollup2", "@timestamp": "2026-04-22T00:01:00+00:00"},
        {"ComputerName": "H", "event_simpleName": "DnsRequest", "@timestamp": "2026-04-22T00:02:00+00:00"},
    ]
    summary = summarize_events(events)
    assert summary.top_event_name == ("ProcessRollup2", 2)


def test_summarize_events_reports_time_range_from_first_and_last():
    events = [
        {"ComputerName": "H", "event_simpleName": "X", "@timestamp": "2026-04-22T00:00:00+00:00"},
        {"ComputerName": "H", "event_simpleName": "X", "@timestamp": "2026-04-22T01:00:00+00:00"},
        {"ComputerName": "H", "event_simpleName": "X", "@timestamp": "2026-04-22T02:00:00+00:00"},
    ]
    summary = summarize_events(events)
    assert summary.time_range == ("2026-04-22T00:00:00+00:00", "2026-04-22T02:00:00+00:00")


def test_summarize_events_produces_hourly_buckets_for_chart():
    events = [
        {"ComputerName": "H", "event_simpleName": "X", "@timestamp": "2026-04-22T00:00:00+00:00"},
        {"ComputerName": "H", "event_simpleName": "X", "@timestamp": "2026-04-22T00:30:00+00:00"},
        {"ComputerName": "H", "event_simpleName": "X", "@timestamp": "2026-04-22T01:05:00+00:00"},
    ]
    summary = summarize_events(events)
    assert summary.hourly_buckets == [
        {"hour": "2026-04-22T00:00:00+00:00", "count": 2},
        {"hour": "2026-04-22T01:00:00+00:00", "count": 1},
    ]


def test_query_summary_is_immutable():
    summary = summarize_events([])
    with pytest.raises(Exception):
        summary.row_count = 999  # type: ignore[misc]


# --------------------------------------------------------------------------
# Live-shape tolerance: the NGSIEM/Humio API returns @timestamp as epoch
# milliseconds (int), not an ISO string. Records may also be missing fields
# or carry None values. summarize_events must not raise on any of these.
# --------------------------------------------------------------------------


def test_summarize_events_accepts_int_epoch_millis_timestamp():
    # 2026-04-22T00:00:00Z and 2026-04-22T01:30:00Z as epoch ms
    events = [
        {"ComputerName": "H", "event_simpleName": "X", "@timestamp": 1776470400000},
        {"ComputerName": "H", "event_simpleName": "X", "@timestamp": 1776475800000},
    ]
    summary = summarize_events(events)
    assert summary.row_count == 2
    # Two events, one hour apart → two buckets
    assert len(summary.hourly_buckets) == 2
    assert all(b["count"] == 1 for b in summary.hourly_buckets)


def test_summarize_events_accepts_numeric_string_epoch_millis():
    events = [
        {"ComputerName": "H", "event_simpleName": "X", "@timestamp": "1776470400000"},
        {"ComputerName": "H", "event_simpleName": "X", "@timestamp": "1776470400000"},
    ]
    summary = summarize_events(events)
    assert summary.row_count == 2
    assert len(summary.hourly_buckets) == 1
    assert summary.hourly_buckets[0]["count"] == 2


def test_summarize_events_skips_events_with_missing_timestamp():
    events = [
        {"ComputerName": "H", "event_simpleName": "X"},
        {"ComputerName": "H", "event_simpleName": "X", "@timestamp": 1776470400000},
    ]
    summary = summarize_events(events)
    assert summary.row_count == 2
    assert len(summary.hourly_buckets) == 1


def test_summarize_events_skips_events_with_none_timestamp():
    events = [
        {"ComputerName": "H", "event_simpleName": "X", "@timestamp": None},
        {"ComputerName": "H", "event_simpleName": "X", "@timestamp": 1776470400000},
    ]
    summary = summarize_events(events)
    assert summary.row_count == 2
    assert len(summary.hourly_buckets) == 1


def test_summarize_events_skips_events_with_garbage_timestamp():
    events = [
        {"ComputerName": "H", "event_simpleName": "X", "@timestamp": "not-a-timestamp"},
        {"ComputerName": "H", "event_simpleName": "X", "@timestamp": 1776470400000},
    ]
    summary = summarize_events(events)
    assert summary.row_count == 2
    # Garbage skipped; only the one valid event contributes to the bucket
    assert len(summary.hourly_buckets) == 1
    assert summary.hourly_buckets[0]["count"] == 1


def test_summarize_events_tolerates_missing_host_and_event_name():
    events = [
        {"@timestamp": 1776470400000},
        {"ComputerName": None, "event_simpleName": None, "@timestamp": 1776470400000},
    ]
    summary = summarize_events(events)
    assert summary.row_count == 2
    assert summary.top_host is None
    assert summary.top_event_name is None


# --------------------------------------------------------------------------
# WidgetType detection — single source of truth for the layout dispatch
# --------------------------------------------------------------------------


def test_widget_type_raw_events_for_process_schema():
    events = generate_process_events(count=10, seed=1)
    assert summarize_events(events).widget_type == WidgetType.RAW_EVENTS


def test_widget_type_timechart_for_bucket_count():
    events = [{"_bucket": 1776470400000 + i * 3_600_000, "_count": i} for i in range(24)]
    assert summarize_events(events).widget_type == WidgetType.TIMECHART


def test_widget_type_timechart_multi_for_bucket_with_multiple_series():
    events = [{"_bucket": 1776470400000 + i * 3_600_000, "ProcessRollup2": i, "DnsRequest": i + 1} for i in range(24)]
    summary = summarize_events(events)
    assert summary.widget_type == WidgetType.TIMECHART_MULTI
    assert set(summary.series_keys) == {"ProcessRollup2", "DnsRequest"}


def test_widget_type_single_value_for_count_aggregate():
    events = [{"_count": 12345}]
    summary = summarize_events(events)
    assert summary.widget_type == WidgetType.SINGLE_VALUE
    assert summary.single_value == 12345
    assert summary.single_value_label == "Count"


def test_widget_type_single_value_uses_string_label_when_present():
    events = [{"repo": "fdr", "_count": 999}]
    summary = summarize_events(events)
    assert summary.widget_type == WidgetType.SINGLE_VALUE
    assert summary.single_value_label == "fdr"


def test_widget_type_scatter_for_label_plus_two_numerics():
    # Aggregate with one host label + count + avg(RPort) — scatter wins over
    # pie because there's a real second axis worth plotting.
    events = [{"ComputerName": f"HOST-{i:02d}", "_count": i * 5, "avg_RPort": i * 11} for i in range(1, 11)]
    summary = summarize_events(events)
    assert summary.widget_type == WidgetType.SCATTER
    # Axis keys are sanitized (sigils stripped) but underscores preserved —
    # the chart data dict uses these as JSON keys, so spaces would be awkward.
    assert summary.scatter_x == "count"
    assert summary.scatter_y == "avg_RPort"
    assert len(summary.scatter_data) == 10
    # Each row carries x, y, and the label — values coerced to numbers.
    first = summary.scatter_data[0]
    assert first == {"count": 5, "avg_RPort": 11, "ComputerName": "HOST-01"}


def test_widget_type_scatter_handles_logscale_string_numerics():
    # LogScale ships values as strings — same coercion path as pie/timechart.
    events = [{"ComputerName": f"H-{i}", "_count": str(i * 3), "rps": str(i * 7)} for i in range(1, 6)]
    summary = summarize_events(events)
    assert summary.widget_type == WidgetType.SCATTER
    assert all(isinstance(p["count"], (int, float)) for p in summary.scatter_data)
    assert all(isinstance(p["rps"], (int, float)) for p in summary.scatter_data)


def test_widget_type_scatter_falls_back_under_min_rows():
    # 2 rows isn't a useful scatter — should land in PIE or AGGREGATE land.
    events = [
        {"ComputerName": "A", "_count": 1, "rps": 2},
        {"ComputerName": "B", "_count": 3, "rps": 4},
    ]
    assert summarize_events(events).widget_type != WidgetType.SCATTER


def test_widget_type_pie_still_wins_for_single_numeric():
    # 1 numeric + 1 label = pie territory; scatter detection must not trigger.
    events = [{"event_simpleName": f"E{i}", "_count": i * 10} for i in range(1, 6)]
    assert summarize_events(events).widget_type == WidgetType.PIE_CANDIDATE


def test_widget_type_pie_candidate_for_small_n_aggregate():
    events = [
        {"event_simpleName": "ProcessRollup2", "_count": 100},
        {"event_simpleName": "DnsRequest", "_count": 60},
        {"event_simpleName": "NetworkConnectIP4", "_count": 30},
    ]
    summary = summarize_events(events)
    assert summary.widget_type == WidgetType.PIE_CANDIDATE
    assert summary.pie_data == [
        {"name": "ProcessRollup2", "value": 100},
        {"name": "DnsRequest", "value": 60},
        {"name": "NetworkConnectIP4", "value": 30},
    ]


def test_widget_type_aggregate_table_for_large_aggregate():
    # >20 rows tips the pie threshold — too many slices to read.
    events = [{"event_simpleName": f"Event{i}", "_count": i + 1} for i in range(25)]
    assert summarize_events(events).widget_type == WidgetType.AGGREGATE_TABLE


def test_widget_type_single_event_with_timestamp_is_raw_events():
    # Regression: the live-path test fixture is exactly this — one event with
    # @timestamp as int epoch. Must NOT trip SINGLE_VALUE (numeric @timestamp
    # would otherwise count as the only numeric field).
    events = [{"ComputerName": "LIVE-HOST-01", "event_simpleName": "ProcessRollup2", "@timestamp": 1776470400000, "UserName": "jdoe"}]
    assert summarize_events(events).widget_type == WidgetType.RAW_EVENTS


def test_widget_type_single_value_handles_logscale_string_count():
    # Regression: LogScale ships event field values as strings. {_count: "315841"}
    # was being misclassified as AGGREGATE_TABLE because _is_numeric rejected
    # numeric strings. Now `_count` is treated as numeric and the value is
    # coerced to a real int on the QuerySummary.
    events = [{"_count": "315841"}]
    summary = summarize_events(events)
    assert summary.widget_type == WidgetType.SINGLE_VALUE
    assert summary.single_value == 315841
    assert summary.single_value_label == "Count"


def test_widget_type_pie_candidate_handles_logscale_string_counts():
    # Same regression as above for groupBy results: numeric counts arrive as
    # strings and the pie slice values must end up as numbers, not strings,
    # or Recharts gives every slice the same angle.
    events = [
        {"_count": "184", "#event_simpleName": "ZipFileWritten"},
        {"_count": "92", "#event_simpleName": "ProcessRollup2"},
        {"_count": "47", "#event_simpleName": "DnsRequest"},
    ]
    summary = summarize_events(events)
    assert summary.widget_type == WidgetType.PIE_CANDIDATE
    # Values are coerced to ints; names are the actual category strings.
    assert summary.pie_data == [
        {"name": "ZipFileWritten", "value": 184},
        {"name": "ProcessRollup2", "value": 92},
        {"name": "DnsRequest", "value": 47},
    ]


def test_widget_type_timechart_handles_logscale_string_count():
    # _bucket may also come back with string counts. Coerce so the AreaChart
    # plots actual y-values.
    events = [
        {"_bucket": "1776470400000", "_count": "10"},
        {"_bucket": "1776474000000", "_count": "25"},
    ]
    summary = summarize_events(events)
    assert summary.widget_type == WidgetType.TIMECHART
    assert [b["count"] for b in summary.hourly_buckets] == [10, 25]


def test_is_timechart_property_covers_both_timechart_variants():
    single = [{"_bucket": 1776470400000, "_count": 5}]
    multi = [{"_bucket": 1776470400000, "a": 1, "b": 2}]
    assert summarize_events(single).is_timechart is True
    assert summarize_events(multi).is_timechart is True
    assert summarize_events(generate_process_events(count=5, seed=1)).is_timechart is False


def test_summarize_events_mixed_timestamp_shapes_produce_sensible_range():
    # One ISO string, one epoch int — the reducer should normalize both.
    events = [
        {"ComputerName": "H", "event_simpleName": "X", "@timestamp": "2026-04-22T00:00:00+00:00"},
        {"ComputerName": "H", "event_simpleName": "X", "@timestamp": 1776474000000},  # +1h
    ]
    summary = summarize_events(events)
    assert summary.row_count == 2
    assert summary.time_range is not None
    start, end = summary.time_range
    assert start < end
