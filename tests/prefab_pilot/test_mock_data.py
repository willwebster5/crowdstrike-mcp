"""Tests for the mock NGSIEM data source used by the Prefab pilot."""

from __future__ import annotations

from crowdstrike_mcp.prefab_pilot.mock_data import generate_process_events


def test_generate_process_events_returns_requested_count():
    events = generate_process_events(count=50, seed=1)
    assert len(events) == 50


def test_generate_process_events_is_deterministic_with_seed():
    a = generate_process_events(count=20, seed=42)
    b = generate_process_events(count=20, seed=42)
    assert a == b


def test_generate_process_events_differs_with_different_seed():
    a = generate_process_events(count=20, seed=1)
    b = generate_process_events(count=20, seed=2)
    assert a != b


def test_generate_process_events_has_required_ngsiem_fields():
    events = generate_process_events(count=5, seed=1)
    required = {
        "@timestamp",
        "aid",
        "ComputerName",
        "event_simpleName",
        "UserName",
        "ImageFileName",
    }
    for event in events:
        missing = required - event.keys()
        assert not missing, f"event missing fields: {missing}"


def test_generate_process_events_timestamps_are_monotonic_ascending():
    events = generate_process_events(count=30, seed=7)
    timestamps = [e["@timestamp"] for e in events]
    assert timestamps == sorted(timestamps)


def test_generate_process_events_host_pool_is_bounded():
    events = generate_process_events(count=100, seed=3)
    unique_hosts = {e["ComputerName"] for e in events}
    assert 2 <= len(unique_hosts) <= 8, f"host pool out of expected range: {len(unique_hosts)}"


def test_generate_process_events_event_names_are_ngsiem_valid():
    events = generate_process_events(count=100, seed=3)
    valid_event_names = {
        "ProcessRollup2",
        "NetworkConnectIP4",
        "DnsRequest",
        "FileOpenInfo",
        "RegistryOperationDetectInfo",
    }
    for event in events:
        assert event["event_simpleName"] in valid_event_names
