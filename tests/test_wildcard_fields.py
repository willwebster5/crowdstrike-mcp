"""Tests for fields="*" wildcard — full-record paging through the fields path."""

import asyncio
import json

import pytest

from crowdstrike_mcp.modules.response_store import ResponseStoreModule
from crowdstrike_mcp.response_store import ResponseStore


@pytest.fixture
def module(mock_client):
    return ResponseStoreModule(mock_client)


def _store(records):
    return ResponseStore.store({"events": records}, tool_name="ngsiem_query")


class TestWildcardFields:
    def test_wildcard_returns_full_records(self, module):
        ref = _store([{"a": 1, "b": {"c": 2}}, {"a": 3, "b": {"c": 4}}])
        result = asyncio.run(module.get_stored_response(ref_id=ref, fields="*"))
        data = json.loads(result)
        assert data == [{"a": 1, "b": {"c": 2}}, {"a": 3, "b": {"c": 4}}]

    def test_wildcard_mixed_with_fields_is_wildcard(self, module):
        ref = _store([{"a": 1, "b": 2}])
        result = asyncio.run(module.get_stored_response(ref_id=ref, fields="*,a"))
        assert json.loads(result) == [{"a": 1, "b": 2}]

    def test_wildcard_pages_with_offset_and_max_results(self, module):
        ref = _store([{"i": n} for n in range(10)])
        page1 = asyncio.run(module.get_stored_response(ref_id=ref, fields="*", max_results=4))
        assert "[page: records 0–3 of 10" in page1
        assert "next offset=4" in page1
        page2 = asyncio.run(
            module.get_stored_response(ref_id=ref, fields="*", max_results=4, offset=4)
        )
        assert "[page: records 4–7 of 10" in page2

    def test_wildcard_respects_byte_budget(self, module):
        big = "x" * 6000
        ref = _store([{"i": n, "blob": big} for n in range(6)])
        result = asyncio.run(module.get_stored_response(ref_id=ref, fields="*", max_results=6))
        assert "[page:" in result
        body = result.split("\n", 1)[1]
        assert len(body) <= ResponseStoreModule._PAGE_BYTE_BUDGET + 100

    def test_wildcard_no_all_null_warning_for_none_valued_records(self, module):
        ref = _store([{"a": None}, {"a": None}])
        result = asyncio.run(module.get_stored_response(ref_id=ref, fields="*"))
        assert "Warning" not in result
        assert json.loads(result) == [{"a": None}, {"a": None}]

    def test_wildcard_with_search_returns_full_matches(self, module):
        ref = _store([{"name": "alpha", "x": 1}, {"name": "beta", "x": 2}])
        result = asyncio.run(
            module.get_stored_response(ref_id=ref, search="beta", fields="*")
        )
        assert json.loads(result) == [{"name": "beta", "x": 2}]

    def test_wildcard_with_record_index_returns_single_record(self, module):
        ref = _store([{"a": 1}, {"a": 2}])
        result = asyncio.run(
            module.get_stored_response(ref_id=ref, record_index=1, fields="*")
        )
        assert json.loads(result) == {"a": 2}
