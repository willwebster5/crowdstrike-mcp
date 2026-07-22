"""Tests for ngsiem_query full-value rendering + always-store (issue #40).

Small result sets previously had no route to a full field value: the inline
renderer capped every value at ~200 chars, and the store only engaged when the
*total* response was large. Now `full=True` renders long values inline, and
every ngsiem_query result is stored so get_stored_response is always available.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from crowdstrike_mcp.response_store import ResponseStore, select_records


@pytest.fixture
def ngsiem_module(mock_client):
    with patch("crowdstrike_mcp.modules.ngsiem.NGSIEM") as MockNGSIEM:
        mock_falcon = MagicMock()
        MockNGSIEM.return_value = mock_falcon
        from crowdstrike_mcp.modules.ngsiem import NGSIEMModule

        module = NGSIEMModule(mock_client)
        module._service = lambda cls: mock_falcon
        module.falcon = mock_falcon
        return module


def _wire_search(mock_falcon, events):
    mock_falcon.start_search.return_value = {"status_code": 200, "resources": {"id": "SID-1"}}
    mock_falcon.get_search_status.return_value = {
        "status_code": 200,
        "body": {"done": True, "cancelled": False, "events": events},
    }


LONG_RAW = '{"time":1784,"event":{"payload":"' + ("A" * 500) + '"}}'


class TestFullFlag:
    def test_default_truncates_long_value_inline(self, ngsiem_module):
        _wire_search(ngsiem_module.falcon, [{"@rawstring": LONG_RAW}])
        out = asyncio.run(ngsiem_module.ngsiem_query("#repo=x | head(1)"))
        assert "..." in out
        assert LONG_RAW not in out  # full value not present when truncated

    def test_full_flag_renders_untruncated_value_inline(self, ngsiem_module):
        _wire_search(ngsiem_module.falcon, [{"@rawstring": LONG_RAW}])
        out = asyncio.run(ngsiem_module.ngsiem_query("#repo=x | head(1)", full=True))
        assert LONG_RAW in out


class TestAlwaysStore:
    def test_small_result_is_stored_with_ref(self, ngsiem_module):
        _wire_search(ngsiem_module.falcon, [{"@rawstring": LONG_RAW}])
        out = asyncio.run(ngsiem_module.ngsiem_query("#repo=x | head(1)"))
        refs = ResponseStore.list_refs()
        assert len(refs) == 1
        assert "Structured data available" in out or refs[0]["ref_id"] in out

    def test_stored_small_result_returns_full_rawstring(self, ngsiem_module):
        _wire_search(ngsiem_module.falcon, [{"@rawstring": LONG_RAW}])
        asyncio.run(ngsiem_module.ngsiem_query("#repo=x | head(1)"))
        ref_id = ResponseStore.list_refs()[0]["ref_id"]
        stored = ResponseStore.get(ref_id)
        events = select_records(stored.data)
        assert events[0]["@rawstring"] == LONG_RAW

    def test_empty_result_not_stored(self, ngsiem_module):
        _wire_search(ngsiem_module.falcon, [])
        asyncio.run(ngsiem_module.ngsiem_query("#repo=x | head(1)"))
        assert ResponseStore.list_refs() == []
