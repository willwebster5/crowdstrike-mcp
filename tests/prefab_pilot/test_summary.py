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
