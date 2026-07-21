"""Tests for get_stored_response array-indexed field paths (issue #43).

`fields` selectors like `Ngsiem.event.usernames[3]` previously walked to a
literal key named `usernames[3]`, missed, and returned None silently. The
caller could not tell "field absent" from "selector syntax unsupported".
Bracket indexing is now resolved against list values.
"""

import asyncio
import json

import pytest

from crowdstrike_mcp.modules.response_store import ResponseStoreModule, _get_nested
from crowdstrike_mcp.response_store import ResponseStore


@pytest.fixture
def response_store_module(mock_client):
    return ResponseStoreModule(mock_client)


class TestGetNestedArrayIndex:
    def test_bracket_index_into_nested_list(self):
        rec = {"Ngsiem": {"event": {"usernames": ["a", "b", "c", "d", "e"]}}}
        assert _get_nested(rec, "Ngsiem.event.usernames[3]") == "d"

    def test_bracket_index_first_element(self):
        rec = {"Ngsiem": {"event": {"usernames": ["a", "b"]}}}
        assert _get_nested(rec, "Ngsiem.event.usernames[0]") == "a"

    def test_bracket_index_out_of_range_returns_none(self):
        rec = {"Ngsiem": {"event": {"usernames": ["a", "b"]}}}
        assert _get_nested(rec, "Ngsiem.event.usernames[5]") is None

    def test_bracket_index_on_top_level_list(self):
        rec = {"ips": ["10.0.0.1", "10.0.0.2"]}
        assert _get_nested(rec, "ips[1]") == "10.0.0.2"

    def test_index_then_key_after_bracket(self):
        rec = {"events": [{"name": "first"}, {"name": "second"}]}
        assert _get_nested(rec, "events[1].name") == "second"

    def test_no_bracket_still_returns_whole_list(self):
        rec = {"Ngsiem": {"event": {"usernames": ["a", "b"]}}}
        assert _get_nested(rec, "Ngsiem.event.usernames") == ["a", "b"]

    def test_flat_dotted_key_still_wins(self):
        # ngsiem_query stores flat dotted keys; literal lookup must still work.
        rec = {"source.ip": "1.2.3.4"}
        assert _get_nested(rec, "source.ip") == "1.2.3.4"

    def test_bracket_index_on_non_list_returns_none(self):
        rec = {"a": {"b": "scalar"}}
        assert _get_nested(rec, "a.b[0]") is None


class TestFieldsProjectionArrayIndex:
    def test_fields_projection_resolves_array_index(self, response_store_module):
        ref_id = ResponseStore.store(
            {"events": [{"Ngsiem": {"event": {"usernames": ["u0", "u1", "u2", "u3"]}}}]},
            tool_name="alert_analysis",
        )
        result = asyncio.run(response_store_module.get_stored_response(ref_id=ref_id, fields="Ngsiem.event.usernames[3]"))
        payload = json.loads(result)
        assert payload[0]["Ngsiem.event.usernames[3]"] == "u3"
