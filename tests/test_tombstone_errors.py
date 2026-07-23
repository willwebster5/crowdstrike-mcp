"""get_stored_response miss errors use tombstones to guide regeneration."""

import asyncio
from datetime import timedelta

import pytest

from crowdstrike_mcp.modules.response_store import ResponseStoreModule
from crowdstrike_mcp.response_store import ResponseStore


@pytest.fixture
def module(mock_client):
    return ResponseStoreModule(mock_client)


def _expire(ref_id):
    entry = ResponseStore._sessions["local"][ref_id]
    entry.timestamp -= timedelta(seconds=ResponseStore._ttl_seconds + 1)


class TestTombstoneErrors:
    def test_ttl_expired_ref_names_tool_and_context(self, module):
        ref = ResponseStore.store(
            {"events": [{"a": 1}]}, "ngsiem_query", {"query": "#type=x | tail(5)"}
        )
        _expire(ref)
        result = asyncio.run(module.get_stored_response(ref_id=ref))
        assert "expired" in result
        assert "25-min TTL" in result
        assert "ngsiem_query" in result
        assert "#type=x | tail(5)" in result
        assert "re-run" in result

    def test_lru_evicted_ref_says_evicted(self, module):
        first = ResponseStore.store({"events": []}, "get_alerts", {"filter": "sev:high"})
        for _ in range(ResponseStore._max_entries):
            ResponseStore.store({"events": []}, "ngsiem_query", {})
        result = asyncio.run(module.get_stored_response(ref_id=first))
        assert "evicted to make room" in result
        assert "get_alerts" in result
        assert "sev:high" in result

    def test_unknown_ref_keeps_existing_error(self, module):
        ResponseStore.store({"events": []}, "ngsiem_query", {})
        result = asyncio.run(module.get_stored_response(ref_id="resp_999"))
        assert "not found" in result
        assert "Available: resp_001" in result

    def test_expired_ref_with_messy_query_stays_single_line(self, module):
        messy_query = ("#type=x\n| tail(5)\n  | table(a, b, c) " * 20)
        ref = ResponseStore.store(
            {"events": [{"a": 1}]}, "ngsiem_query", {"query": messy_query}
        )
        _expire(ref)
        result = asyncio.run(module.get_stored_response(ref_id=ref))
        assert "\n" not in result
        assert "re-run" in result
        assert len(result) < 400
