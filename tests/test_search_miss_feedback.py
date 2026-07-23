"""Search misses report scan scope, match semantics, and available fields."""

import asyncio
import json

import pytest

from crowdstrike_mcp.modules.response_store import ResponseStoreModule
from crowdstrike_mcp.response_store import ResponseStore


@pytest.fixture
def module(mock_client):
    return ResponseStoreModule(mock_client)


class TestSearchMissFeedback:
    def test_miss_reports_scope_semantics_and_fields(self, module):
        ref = ResponseStore.store(
            {"events": [{"user": "alice", "ip": "1.1.1.1"}, {"user": "bob", "ip": "2.2.2.2"}]},
            tool_name="ngsiem_query",
        )
        result = asyncio.run(module.get_stored_response(ref_id=ref, search="jetbrain"))
        assert "No records matching 'jetbrain'" in result
        assert "searched 2 records" in result
        assert "case-insensitive substring" in result
        assert "Available fields: user, ip" in result
        assert "Tip:" in result

    def test_match_path_unchanged(self, module):
        ref = ResponseStore.store({"events": [{"user": "alice"}]}, tool_name="ngsiem_query")
        result = asyncio.run(module.get_stored_response(ref_id=ref, search="alice"))
        assert json.loads(result) == [{"user": "alice"}]
