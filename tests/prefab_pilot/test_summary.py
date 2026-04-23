"""Tests for the model-facing summary reducer.

This is the code path that keeps the full NGSIEM result out of the model's
context. Correctness here matters more than the UI assembly — the summary is
what the model actually reasons over.
"""

from __future__ import annotations

import pytest

from crowdstrike_mcp.prefab_pilot.mock_data import generate_process_events
from crowdstrike_mcp.prefab_pilot.summary import summarize_events


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
